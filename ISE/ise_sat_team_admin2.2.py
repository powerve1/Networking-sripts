#!/usr/bin/env python3
"""
Cisco ISE Device Admin authorization-rule automation
=====================================================

Creates or updates the SAT-TEAM-ADMIN TACACS+ authorization rule in the
non-default Device Admin policy set that:

  1. contains DEVICE:Device Type conditions, and
  2. contains the largest number of non-default authorization rules.

The rule is placed at rank 0 and uses:

  InternalUser:IdentityGroup == User Identity Groups:SAT-TEAM
  AND
  (
      Network Access:Device IP Address == 10.248.<ISE second octet>.10 OR
      Network Access:Device IP Address == 10.248.<ISE second octet>.11 OR
      Network Access:Device IP Address == 10.248.<ISE second octet>.9  OR
      Network Access:Device IP Address == 10.<ISE second octet>.200.26 OR
      Network Access:Device IP Address == 10.<ISE second octet>.200.25 OR
      Network Access:Device IP Address == 10.<ISE second octet>.0.27
  )

Authorization results:
  SAT-TEAM-ADMIN:
    Command set: Permit_All_Commands (resolved case-insensitively)
    TACACS profile: sat_team_admin profile
    Default privilege: 15
    Maximum privilege: 15

  SAT-TEAM-READ-ONLY:
    Rank: 1, immediately below SAT-TEAM-ADMIN
    Identity group: SAT-TEAM
    Device Type conditions, command set and shell profile are copied
    from the unique NOC switch read-only rule that contains no Device IP match.

Safety:
  * Every execution starts with a complete audit/pre-check.
  * No configuration is changed unless every deployment passes the audit.
  * After a successful audit, the operator must type YES to apply.
  * --force can bypass the prompt for controlled unattended execution.
  * Existing policy data is saved as rollback JSON before writes.
  * Ambiguous policy-set or object discovery stops the deployment.
  * The script is idempotent: create, update, or skip as appropriate.

Tested design target:
  Cisco ISE 3.3+ OpenAPI on TCP/443 and ERS/OpenAPI API Gateway enabled.

IMPORTANT:
Cisco has changed some ERS/OpenAPI response wrappers across releases. This
script normalizes the common response formats and logs raw error responses.
Run --audit-only first against a lab or one deployment.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import getpass
import html
import ipaddress
import json
import logging
import os
import re
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

import requests
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning


# ---------------------------------------------------------------------------
# User-adjustable constants
# ---------------------------------------------------------------------------

RULE_NAME = "SAT-TEAM-ADMIN"
READ_ONLY_RULE_NAME = "SAT-TEAM-READ-ONLY"
IDENTITY_GROUP_NAME = "SAT-TEAM"
TACACS_PROFILE_NAME = "sat_team_admin profile"
COMMAND_SET_SEARCH_NAME = "permit_all_commands"
DEFAULT_PRIVILEGE = 15
MAXIMUM_PRIVILEGE = 15

POLICY_SET_ENDPOINT = "/api/v1/policy/device-admin/policy-set"
TACACS_PROFILE_ERS_ENDPOINT = "/ers/config/tacacsprofile"
TACACS_COMMAND_SET_ERS_ENDPOINT = "/ers/config/tacacscommandsets"
IDENTITY_GROUP_ERS_ENDPOINT = "/ers/config/identitygroup"

# OpenAPI condition names, as displayed by ISE.
IDENTITY_DICTIONARY = "InternalUser"
IDENTITY_ATTRIBUTE = "IdentityGroup"
IP_DICTIONARY = "Network Access"
IP_ATTRIBUTE = "Device IP Address"
DEVICE_DICTIONARY = "DEVICE"
DEVICE_TYPE_ATTRIBUTE = "Device Type"
NOC_IDENTITY_GROUP_NAME = "NOC"

DEFAULT_TIMEOUT = 180
DEFAULT_WORKERS = 4
USER_AGENT = "ise-sat-team-admin-automation/2.5"

WRITE_LOCK = threading.Lock()


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class HostResult:
    host: str
    status: str = "FAILED"
    mode: str = "AUDIT"
    selected_policy_set: str = ""
    selected_policy_set_id: str = ""
    authorization_rule_count: int = 0
    generated_ips: list[str] = field(default_factory=list)
    identity_group: str = ""
    command_set: str = ""
    tacacs_profile: str = ""
    rule_action: str = ""
    read_only_rule_action: str = ""
    read_only_template_rule: str = ""
    read_only_command_set: str = ""
    read_only_profile: str = ""
    profile_action: str = ""
    backup_file: str = ""
    message: str = ""
    elapsed_seconds: float = 0.0


class ISEError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Logging and file helpers
# ---------------------------------------------------------------------------

def configure_logging(output_dir: Path, verbose: bool) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_file = output_dir / f"ise_sat_team_admin_{datetime.now():%Y%m%d_%H%M%S}.log"

    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    root = logging.getLogger()
    root.setLevel(level)
    root.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    return log_file


def safe_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False, sort_keys=True)


def write_csv_report(path: Path, results: list[HostResult]) -> None:
    import csv

    fields = list(asdict(HostResult(host="")).keys())
    with path.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            row = asdict(result)
            row["generated_ips"] = "; ".join(result.generated_ips)
            writer.writerow(row)


def write_html_report(
    path: Path,
    title: str,
    results: list[HostResult],
    log_file: Path,
) -> None:
    """Create a standalone HTML report without external dependencies."""
    passed = sum(item.status == "SUCCESS" for item in results)
    failed = len(results) - passed

    rows = []
    for item in results:
        status_class = "ok" if item.status == "SUCCESS" else "failed"
        ips = "<br>".join(html.escape(ip) for ip in item.generated_ips) or "-"
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.host)}</td>"
            f"<td class='{status_class}'>{html.escape(item.status)}</td>"
            f"<td>{html.escape(item.mode)}</td>"
            f"<td>{html.escape(item.selected_policy_set or '-')}</td>"
            f"<td>{item.authorization_rule_count}</td>"
            f"<td>{html.escape(item.identity_group or '-')}</td>"
            f"<td>{html.escape(item.command_set or '-')}</td>"
            f"<td>{html.escape(item.profile_action or '-')}</td>"
            f"<td>{html.escape(item.rule_action or '-')}</td>"
            f"<td>{html.escape(item.read_only_template_rule or '-')}</td>"
            f"<td>{html.escape(item.read_only_command_set or '-')}</td>"
            f"<td>{html.escape(item.read_only_profile or '-')}</td>"
            f"<td>{html.escape(item.read_only_rule_action or '-')}</td>"
            f"<td>{ips}</td>"
            f"<td>{html.escape(item.message or '-')}</td>"
            "</tr>"
        )

    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    document = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 28px; color: #202124; }}
h1 {{ margin-bottom: 4px; }}
.meta {{ color: #5f6368; margin-bottom: 20px; }}
.summary {{ display: flex; gap: 16px; margin: 18px 0; }}
.card {{ border: 1px solid #dadce0; border-radius: 8px; padding: 12px 18px; }}
table {{ border-collapse: collapse; width: 100%; font-size: 13px; }}
th, td {{ border: 1px solid #dadce0; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #f1f3f4; }}
.ok {{ font-weight: bold; color: #137333; }}
.failed {{ font-weight: bold; color: #c5221f; }}
code {{ background: #f1f3f4; padding: 2px 4px; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<div class="meta">Generated: {generated}<br>Log: {html.escape(str(log_file))}</div>
<div class="summary">
  <div class="card"><strong>Total</strong><br>{len(results)}</div>
  <div class="card"><strong>Passed</strong><br>{passed}</div>
  <div class="card"><strong>Failed</strong><br>{failed}</div>
</div>
<table>
<thead>
<tr>
<th>Host</th><th>Status</th><th>Phase</th><th>Policy Set</th>
<th>AuthZ Rules</th><th>Identity Group</th><th>Command Set</th>
<th>Profile Action</th><th>Admin Rule</th><th>RO Template</th>
<th>RO Command Set</th><th>RO Profile</th><th>RO Rule</th>
<th>Generated IPs</th><th>Message</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""
    path.write_text(document, encoding="utf-8")


class Console:
    RESET = "[0m"
    RED = "[31m"
    GREEN = "[32m"
    YELLOW = "[33m"
    CYAN = "[36m"
    BOLD = "[1m"

    @staticmethod
    def enable_windows_ansi() -> None:
        if os.name == "nt":
            os.system("")

    @classmethod
    def color(cls, value: str, code: str) -> str:
        return f"{code}{value}{cls.RESET}"

    @classmethod
    def success(cls, value: str) -> str:
        return cls.color(value, cls.GREEN)

    @classmethod
    def warning(cls, value: str) -> str:
        return cls.color(value, cls.YELLOW)

    @classmethod
    def error(cls, value: str) -> str:
        return cls.color(value, cls.RED)

    @classmethod
    def heading(cls, value: str) -> str:
        return cls.color(value, cls.CYAN + cls.BOLD)


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

def normalize_host(raw: str) -> str:
    value = raw.strip()
    value = re.sub(r"^https?://", "", value, flags=re.IGNORECASE)
    value = value.split("/")[0]
    value = value.split(":")[0]

    try:
        ipaddress.ip_address(value)
    except ValueError:
        # Hostnames are allowed, but dynamic IP generation requires an IPv4
        # address in the host file.
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", value):
            raise ValueError(f"Invalid ISE host: {raw!r}")
    return value


def load_hosts(path: Path) -> list[str]:
    if not path.exists():
        raise FileNotFoundError(f"Host file not found: {path}")

    hosts: list[str] = []
    seen: set[str] = set()

    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue

            # Accept either one IP/hostname per line or CSV where first field is host.
            candidate = line.split(",", 1)[0].strip()
            try:
                host = normalize_host(candidate)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_number}: {exc}") from exc

            key = host.lower()
            if key not in seen:
                seen.add(key)
                hosts.append(host)

    if not hosts:
        raise ValueError(f"No ISE hosts found in {path}")
    return hosts


def generate_device_ips(ise_host: str) -> list[str]:
    try:
        address = ipaddress.ip_address(ise_host)
    except ValueError as exc:
        raise ISEError(
            f"Dynamic IP generation requires the ISE host entry to be an IPv4 "
            f"address, not hostname {ise_host!r}."
        ) from exc

    if address.version != 4:
        raise ISEError(f"ISE host must be IPv4 for octet derivation: {ise_host}")

    second_octet = str(address).split(".")[1]
    return [
        f"10.248.{second_octet}.10",
        f"10.248.{second_octet}.11",
        f"10.248.{second_octet}.9",
        f"10.{second_octet}.200.26",
        f"10.{second_octet}.200.25",
        f"10.{second_octet}.0.27",
    ]


# ---------------------------------------------------------------------------
# Generic Cisco ISE REST client
# ---------------------------------------------------------------------------

class ISEClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        verify_ssl: bool,
        timeout: int,
    ) -> None:
        self.host = host
        self.base_url = f"https://{host}"
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.auth = HTTPBasicAuth(username, password)
        self.session.verify = verify_ssl
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            }
        )

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: Iterable[int] = (200,),
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[dict[str, Any]] = None,
    ) -> requests.Response:
        url = path if path.startswith("https://") else f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json_body,
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise ISEError(f"{self.host}: {method} {path} failed: {exc}") from exc

        if response.status_code not in set(expected):
            body = response.text[:4000]
            raise ISEError(
                f"{self.host}: {method} {path} returned HTTP "
                f"{response.status_code}: {body}"
            )
        return response

    def get_json(
        self,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        expected: Iterable[int] = (200,),
    ) -> dict[str, Any]:
        response = self.request("GET", path, params=params, expected=expected)
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError as exc:
            raise ISEError(
                f"{self.host}: GET {path} did not return JSON: "
                f"{response.text[:1000]}"
            ) from exc

    def post_json(
        self,
        path: str,
        body: dict[str, Any],
        *,
        expected: Iterable[int] = (200, 201),
    ) -> dict[str, Any]:
        response = self.request(
            "POST", path, json_body=body, expected=expected
        )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}

    def put_json(
        self,
        path: str,
        body: dict[str, Any],
        *,
        expected: Iterable[int] = (200, 201, 204),
    ) -> dict[str, Any]:
        response = self.request(
            "PUT", path, json_body=body, expected=expected
        )
        if not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            return {"raw": response.text}


# ---------------------------------------------------------------------------
# Response normalization
# ---------------------------------------------------------------------------

def openapi_items(payload: dict[str, Any]) -> list[dict[str, Any]]:
    response = payload.get("response", payload)
    if isinstance(response, list):
        return [item for item in response if isinstance(item, dict)]
    if isinstance(response, dict):
        return [response]
    return []


def ers_resources(payload: dict[str, Any]) -> list[dict[str, Any]]:
    search_result = payload.get("SearchResult", payload.get("searchResult", {}))
    resources = search_result.get("resources", []) if isinstance(search_result, dict) else []
    return [item for item in resources if isinstance(item, dict)]


def ers_entity(payload: dict[str, Any], possible_keys: Iterable[str]) -> dict[str, Any]:
    for key in possible_keys:
        value = payload.get(key)
        if isinstance(value, dict):
            return value

    # Some releases wrap under ERSResponse.
    wrapper = payload.get("ERSResponse")
    if isinstance(wrapper, dict):
        for key in possible_keys:
            value = wrapper.get(key)
            if isinstance(value, dict):
                return value

    return payload if isinstance(payload, dict) else {}


def find_name(item: dict[str, Any]) -> str:
    for key in ("name", "Name"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    return ""


def find_id(item: dict[str, Any]) -> str:
    for key in ("id", "Id", "ID"):
        value = item.get(key)
        if isinstance(value, str):
            return value
    return ""


# ---------------------------------------------------------------------------
# ERS discovery
# ---------------------------------------------------------------------------

def paged_ers_search(client: ISEClient, endpoint: str, size: int = 100) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    page = 1

    while True:
        payload = client.get_json(endpoint, params={"size": size, "page": page})
        current = ers_resources(payload)
        resources.extend(current)

        search_result = payload.get("SearchResult", payload.get("searchResult", {}))
        total = 0
        if isinstance(search_result, dict):
            try:
                total = int(search_result.get("total", 0))
            except (TypeError, ValueError):
                total = 0

        if not current or (total and len(resources) >= total) or len(current) < size:
            break
        page += 1

    return resources


def resolve_unique_ers_object(
    client: ISEClient,
    endpoint: str,
    requested_name: str,
    entity_keys: Iterable[str],
) -> dict[str, Any]:
    resources = paged_ers_search(client, endpoint)
    matches = [
        item for item in resources
        if find_name(item).casefold() == requested_name.casefold()
    ]

    if not matches:
        raise ISEError(
            f"Required object {requested_name!r} was not found at {endpoint}."
        )
    if len(matches) > 1:
        names = ", ".join(f"{find_name(x)} ({find_id(x)})" for x in matches)
        raise ISEError(
            f"Ambiguous object lookup for {requested_name!r}: {names}"
        )

    object_id = find_id(matches[0])
    if not object_id:
        raise ISEError(f"ISE returned object without an ID: {matches[0]}")

    payload = client.get_json(f"{endpoint}/{object_id}")
    entity = ers_entity(payload, entity_keys)
    if not find_id(entity):
        entity["id"] = object_id
    if not find_name(entity):
        entity["name"] = find_name(matches[0])
    return entity


def try_resolve_identity_group(client: ISEClient) -> dict[str, Any]:
    # Internal user identity groups are exposed by ERS as identitygroup.
    return resolve_unique_ers_object(
        client,
        IDENTITY_GROUP_ERS_ENDPOINT,
        IDENTITY_GROUP_NAME,
        ("IdentityGroup", "identityGroup"),
    )


def resolve_command_set(client: ISEClient) -> dict[str, Any]:
    return resolve_unique_ers_object(
        client,
        TACACS_COMMAND_SET_ERS_ENDPOINT,
        COMMAND_SET_SEARCH_NAME,
        ("TacacsCommandSets", "TacacsCommandSet", "tacacsCommandSets"),
    )


def find_profile_if_present(client: ISEClient) -> Optional[dict[str, Any]]:
    resources = paged_ers_search(client, TACACS_PROFILE_ERS_ENDPOINT)
    matches = [
        item for item in resources
        if find_name(item).casefold() == TACACS_PROFILE_NAME.casefold()
    ]
    if not matches:
        return None
    if len(matches) > 1:
        raise ISEError(
            f"More than one TACACS profile matches {TACACS_PROFILE_NAME!r}."
        )

    profile_id = find_id(matches[0])
    payload = client.get_json(f"{TACACS_PROFILE_ERS_ENDPOINT}/{profile_id}")
    return ers_entity(
        payload,
        ("TacacsProfile", "tacacsProfile", "TacacsProfiles"),
    )


# ---------------------------------------------------------------------------
# Policy-set discovery
# ---------------------------------------------------------------------------

def contains_device_type_condition(value: Any) -> bool:
    if isinstance(value, dict):
        dictionary = str(value.get("dictionaryName", "")).casefold()
        attribute = str(value.get("attributeName", "")).casefold()
        if dictionary == "device" and attribute == "device type":
            return True
        return any(contains_device_type_condition(child) for child in value.values())

    if isinstance(value, list):
        return any(contains_device_type_condition(child) for child in value)

    if isinstance(value, str):
        normalized = value.casefold()
        return "device type" in normalized and "device" in normalized

    return False


def get_authorization_rules(
    client: ISEClient,
    policy_set_id: str,
) -> list[dict[str, Any]]:
    endpoint = f"{POLICY_SET_ENDPOINT}/{policy_set_id}/authorization"
    return openapi_items(client.get_json(endpoint))


def select_target_policy_set(
    client: ISEClient,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    policy_sets = openapi_items(client.get_json(POLICY_SET_ENDPOINT))
    if not policy_sets:
        raise ISEError("ISE returned no Device Admin policy sets.")

    evaluated: list[dict[str, Any]] = []

    for policy_set in policy_sets:
        if policy_set.get("default") is True or find_name(policy_set).casefold() == "default":
            continue

        policy_id = find_id(policy_set)
        if not policy_id:
            continue

        # Read full representation when available because list payloads can be abbreviated.
        try:
            full_items = openapi_items(
                client.get_json(f"{POLICY_SET_ENDPOINT}/{policy_id}")
            )
            full = full_items[0] if full_items else policy_set
        except ISEError:
            full = policy_set

        rules = get_authorization_rules(client, policy_id)
        non_default_rules = [
            r for r in rules
            if not bool(r.get("rule", {}).get("default"))
        ]
        has_device_types = contains_device_type_condition(full.get("condition"))

        evaluated.append(
            {
                "policy": full,
                "rules": rules,
                "has_device_types": has_device_types,
                "rule_count": len(non_default_rules),
            }
        )

    device_type_candidates = [x for x in evaluated if x["has_device_types"]]
    if not device_type_candidates:
        details = ", ".join(
            f"{find_name(x['policy'])}={x['rule_count']} rules"
            for x in evaluated
        ) or "none"
        raise ISEError(
            "No non-default Device Admin policy set containing DEVICE:Device Type "
            f"conditions was found. Evaluated: {details}"
        )

    max_count = max(x["rule_count"] for x in device_type_candidates)
    winners = [x for x in device_type_candidates if x["rule_count"] == max_count]

    if len(winners) != 1:
        names = ", ".join(
            f"{find_name(x['policy'])} ({x['rule_count']} rules)"
            for x in winners
        )
        raise ISEError(
            "Target policy-set discovery is ambiguous. Equal top candidates: "
            f"{names}. Use --policy-set-name to select explicitly."
        )

    winner = winners[0]
    return winner["policy"], winner["rules"], evaluated


def select_named_policy_set(
    client: ISEClient,
    requested_name: str,
) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    policy_sets = openapi_items(client.get_json(POLICY_SET_ENDPOINT))
    matches = [
        p for p in policy_sets
        if find_name(p).casefold() == requested_name.casefold()
    ]
    if not matches:
        raise ISEError(f"Policy set {requested_name!r} was not found.")
    if len(matches) > 1:
        raise ISEError(f"Multiple policy sets match {requested_name!r}.")

    policy = matches[0]
    policy_id = find_id(policy)
    rules = get_authorization_rules(client, policy_id)
    return policy, rules, []


# ---------------------------------------------------------------------------
# Condition and payload construction
# ---------------------------------------------------------------------------

def condition_attribute(
    dictionary_name: str,
    attribute_name: str,
    attribute_value: str,
) -> dict[str, Any]:
    return {
        "conditionType": "ConditionAttributes",
        "isNegate": False,
        "dictionaryName": dictionary_name,
        "attributeName": attribute_name,
        "operator": "equals",
        "dictionaryValue": None,
        "attributeValue": attribute_value,
    }


def condition_block(
    operator: str,
    children: list[dict[str, Any]],
) -> dict[str, Any]:
    if len(children) < 2:
        raise ValueError("A condition block requires at least two children.")
    return {
        "conditionType": "ConditionAndBlock" if operator.upper() == "AND"
        else "ConditionOrBlock",
        "isNegate": False,
        "children": children,
    }


def build_rule_condition(device_ips: list[str]) -> dict[str, Any]:
    identity = condition_attribute(
        IDENTITY_DICTIONARY,
        IDENTITY_ATTRIBUTE,
        f"User Identity Groups:{IDENTITY_GROUP_NAME}",
    )

    ip_conditions = [
        condition_attribute(IP_DICTIONARY, IP_ATTRIBUTE, ip)
        for ip in device_ips
    ]
    return condition_block(
        "AND",
        [
            identity,
            condition_block("OR", ip_conditions),
        ],
    )



def iter_condition_attributes(value: Any) -> Iterable[dict[str, Any]]:
    """Yield every ConditionAttributes leaf from a nested ISE condition tree."""
    if isinstance(value, dict):
        if value.get("conditionType") == "ConditionAttributes":
            yield value
        for child in value.values():
            yield from iter_condition_attributes(child)
    elif isinstance(value, list):
        for child in value:
            yield from iter_condition_attributes(child)


def normalized_object_name(value: str) -> str:
    """Normalize object names such as READ-ONLY, READ_ONLY, and Read Only."""
    return re.sub(r"[^a-z0-9]+", "", value.casefold())


def condition_has_identity_group(condition: Any, group_name: str) -> bool:
    """
    Match an internal identity-group condition across common ISE schemas.

    Depending on ISE release and endpoint serialization, the GUI condition:

        User Identity Groups:NOC

    may be represented as either:

        InternalUser : IdentityGroup
        IdentityGroup : Name

    This matcher accepts both forms and compares the final group component.
    """
    expected = normalized_object_name(group_name)

    for leaf in iter_condition_attributes(condition):
        dictionary = str(leaf.get("dictionaryName", "")).casefold()
        attribute = str(leaf.get("attributeName", "")).casefold()
        value = str(
            leaf.get("attributeValue")
            or leaf.get("dictionaryValue")
            or ""
        )

        supported_pair = (
            dictionary == IDENTITY_DICTIONARY.casefold()
            and attribute == IDENTITY_ATTRIBUTE.casefold()
        ) or (
            dictionary == "identitygroup"
            and attribute == "name"
        )

        if not supported_pair:
            continue

        final_component = value.split(":")[-1].split("#")[-1]
        if normalized_object_name(final_component) == expected:
            return True

    return False


def condition_has_device_ip(condition: Any) -> bool:
    for leaf in iter_condition_attributes(condition):
        dictionary = str(leaf.get("dictionaryName", "")).casefold()
        attribute = str(leaf.get("attributeName", "")).casefold()
        if dictionary == IP_DICTIONARY.casefold() and attribute == IP_ATTRIBUTE.casefold():
            return True
    return False


def extract_all_device_type_conditions(
    condition: Any,
) -> list[dict[str, Any]]:
    """
    Extract every DEVICE:Device Type condition from a template rule.

    This supports both specific values such as CORE-SWITCH/SWITCHES and broad
    values such as All Device Types.
    """
    matches: list[dict[str, Any]] = []
    for leaf in iter_condition_attributes(condition):
        dictionary = str(leaf.get("dictionaryName", "")).casefold()
        attribute = str(leaf.get("attributeName", "")).casefold()
        if (
            dictionary == DEVICE_DICTIONARY.casefold()
            and attribute == DEVICE_TYPE_ATTRIBUTE.casefold()
        ):
            matches.append(json.loads(json.dumps(leaf)))
    return matches


def command_names_from_rule(rule: dict[str, Any]) -> list[str]:
    commands = rule.get("commands", [])
    if isinstance(commands, str):
        return [commands]
    if isinstance(commands, list):
        return [str(item) for item in commands]
    return []


def summarize_authorization_rule(item: dict[str, Any]) -> dict[str, Any]:
    rule = item.get("rule", {})
    condition = rule.get("condition", {})
    leaves = list(iter_condition_attributes(condition))
    return {
        "name": str(rule.get("name", "")),
        "commands": command_names_from_rule(item),
        "profile": str(item.get("profile", "")),
        "identity_leaves": [
            {
                "dictionary": leaf.get("dictionaryName"),
                "attribute": leaf.get("attributeName"),
                "value": leaf.get("attributeValue") or leaf.get("dictionaryValue"),
            }
            for leaf in leaves
            if "identity" in str(leaf.get("dictionaryName", "")).casefold()
            or "group" in str(leaf.get("dictionaryName", "")).casefold()
        ],
        "device_type_leaves": [
            {
                "dictionary": leaf.get("dictionaryName"),
                "attribute": leaf.get("attributeName"),
                "value": leaf.get("attributeValue") or leaf.get("dictionaryValue"),
            }
            for leaf in leaves
            if str(leaf.get("attributeName", "")).casefold() == "device type"
        ],
        "has_device_ip": condition_has_device_ip(condition),
    }


def find_noc_read_only_template(
    rules: list[dict[str, Any]],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """
    Find the best NOC IOS read-only Device Admin template with no IP match.

    Some deployments do not include the NOC identity-group condition inside
    every authorization rule. In those deployments, NOC is represented by the
    rule name, such as NOC-IOS, while the rule condition contains only Device
    Type values.

    A candidate is therefore considered NOC-related when either:
      * its condition explicitly matches the NOC identity group, or
      * its rule name contains the standalone token NOC.

    A valid candidate must also:
      * contain one or more DEVICE:Device Type conditions,
      * contain no Network Access:Device IP Address condition,
      * have at least one command set,
      * have a TACACS shell profile.

    Candidate scoring strongly prefers the IOS read-only rule:
      * READ-ONLY command set
      * IOS shell profile
      * IOS in the rule name
      * switch-related Device Type values
    """
    candidates: list[
        tuple[int, dict[str, Any], list[dict[str, Any]], list[str]]
    ] = []

    for item in rules:
        rule = item.get("rule", {})
        if rule.get("default"):
            continue

        rule_name = str(rule.get("name", ""))
        condition = rule.get("condition", {})

        explicit_noc = condition_has_identity_group(
            condition, NOC_IDENTITY_GROUP_NAME
        )
        noc_name_token = bool(
            re.search(r"(^|[^A-Za-z0-9])NOC([^A-Za-z0-9]|$)", rule_name, re.I)
        )
        if not (explicit_noc or noc_name_token):
            continue

        if condition_has_device_ip(condition):
            continue

        commands = command_names_from_rule(item)
        profile = str(item.get("profile", "")).strip()
        if not commands or not profile:
            continue

        device_types = extract_all_device_type_conditions(condition)
        if not device_types:
            continue

        device_values = [
            str(
                leaf.get("attributeValue")
                or leaf.get("dictionaryValue")
                or ""
            )
            for leaf in device_types
        ]

        score = 0

        if explicit_noc:
            score += 20
        if noc_name_token:
            score += 20

        if any(
            normalized_object_name(name) == "readonly"
            for name in commands
        ):
            score += 200

        if profile.casefold() == "ios":
            score += 150
        elif "ios" in profile.casefold():
            score += 100

        if "ios" in rule_name.casefold():
            score += 100
        if "access" in rule_name.casefold():
            score += 20

        switch_values = [
            value for value in device_values
            if "switch" in value.casefold()
        ]
        if switch_values:
            score += 100 + len(switch_values)
        else:
            score += len(device_types)

        candidates.append((score, item, device_types, device_values))

    if not candidates:
        noc_like = []
        for item in rules:
            summary = summarize_authorization_rule(item)
            serialized = json.dumps(summary, ensure_ascii=False).casefold()
            if "noc" in serialized:
                noc_like.append(summary)

        diagnostics = json.dumps(
            noc_like[:10],
            ensure_ascii=False,
            sort_keys=True,
        )
        raise ISEError(
            "No suitable NOC IOS read-only template was found. The script "
            "accepts either an explicit NOC identity condition or a rule name "
            "containing NOC. The rule must include Device Type conditions, "
            "have a command set and shell profile, and contain no Device IP "
            f"condition. NOC-like rule diagnostics: {diagnostics}"
        )

    candidates.sort(key=lambda entry: entry[0], reverse=True)
    top_score = candidates[0][0]
    winners = [entry for entry in candidates if entry[0] == top_score]

    if len(winners) > 1:
        names = ", ".join(
            str(item.get("rule", {}).get("name", "<unnamed>"))
            for _, item, _, _ in winners
        )
        raise ISEError(
            "Multiple equally suitable NOC IOS templates were found: "
            f"{names}. The script will not choose arbitrarily."
        )

    _, selected_rule, device_types, _ = winners[0]
    return selected_rule, device_types


def build_read_only_condition(
    switch_device_type_conditions: list[dict[str, Any]],
) -> dict[str, Any]:
    identity = condition_attribute(
        IDENTITY_DICTIONARY,
        IDENTITY_ATTRIBUTE,
        f"User Identity Groups:{IDENTITY_GROUP_NAME}",
    )

    if len(switch_device_type_conditions) == 1:
        device_condition = switch_device_type_conditions[0]
    else:
        device_condition = condition_block("OR", switch_device_type_conditions)

    return condition_block("AND", [identity, device_condition])


def build_read_only_authorization_payload(
    template_rule: dict[str, Any],
    switch_device_type_conditions: list[dict[str, Any]],
    rank: int = 1,
) -> dict[str, Any]:
    commands = command_names_from_rule(template_rule)
    profile = template_rule.get("profile")

    if not commands:
        raise ISEError("The selected NOC template has no command set.")
    if not isinstance(profile, str) or not profile.strip():
        raise ISEError("The selected NOC template has no TACACS shell profile.")

    return {
        "rule": {
            "default": False,
            "name": READ_ONLY_RULE_NAME,
            "rank": rank,
            "state": "enabled",
            "condition": build_read_only_condition(
                switch_device_type_conditions
            ),
        },
        "commands": commands,
        "profile": profile,
    }


def build_authorization_payload(
    device_ips: list[str],
    exact_command_set_name: str,
    rank: int = 0,
) -> dict[str, Any]:
    return {
        "rule": {
            "default": False,
            "name": RULE_NAME,
            "rank": rank,
            "state": "enabled",
            "condition": build_rule_condition(device_ips),
        },
        "commands": [exact_command_set_name],
        "profile": TACACS_PROFILE_NAME,
    }


def build_tacacs_profile_entity(existing_id: Optional[str] = None) -> dict[str, Any]:
    """
    ERS TACACS profile payload.

    ISE represents shell attributes using customAttributes. The value below
    configures both default and maximum privilege to 15. Some ISE releases
    serialize the same data with an additional taskAttribute structure; the
    API accepts customAttributes on current 3.x releases.

    The --audit-only mode prints this planned entity before any write.
    """
    entity: dict[str, Any] = {
        "name": TACACS_PROFILE_NAME,
        "description": (
            "Managed by ise_sat_team_admin.py; Cisco IOS shell privilege 15"
        ),
        "sessionAttributes": {
            "sessionAttributeList": [
                {
                    "type": "MANDATORY",
                    "name": "default-privilege",
                    "value": str(DEFAULT_PRIVILEGE),
                },
                {
                    "type": "MANDATORY",
                    "name": "maximum-privilege",
                    "value": str(MAXIMUM_PRIVILEGE),
                },
            ]
        },
    }
    if existing_id:
        entity["id"] = existing_id
    return {"TacacsProfile": entity}


def normalize_for_compare(value: Any) -> Any:
    ignored = {
        "id", "link", "hitCounts", "hits", "default",
        "description", "rank",
    }
    if isinstance(value, dict):
        return {
            key: normalize_for_compare(child)
            for key, child in sorted(value.items())
            if key not in ignored
        }
    if isinstance(value, list):
        normalized = [normalize_for_compare(x) for x in value]
        return sorted(normalized, key=lambda x: json.dumps(x, sort_keys=True))
    if isinstance(value, str):
        return value.casefold()
    return value


def existing_rule_named(
    rules: list[dict[str, Any]],
    rule_name: str,
) -> Optional[dict[str, Any]]:
    matches = [
        item for item in rules
        if str(item.get("rule", {}).get("name", "")).casefold()
        == rule_name.casefold()
    ]
    if len(matches) > 1:
        raise ISEError(
            f"Multiple authorization rules named {rule_name!r} were found "
            "inside the selected policy set."
        )
    return matches[0] if matches else None


# ---------------------------------------------------------------------------
# Change application
# ---------------------------------------------------------------------------

def ensure_tacacs_profile(
    client: ISEClient,
    apply_changes: bool,
) -> tuple[str, dict[str, Any]]:
    existing = find_profile_if_present(client)

    if existing is None:
        desired = build_tacacs_profile_entity()
        if not apply_changes:
            return "WOULD_CREATE", desired
        response = client.post_json(
            TACACS_PROFILE_ERS_ENDPOINT,
            desired,
            expected=(200, 201),
        )
        return "CREATED", response

    existing_id = find_id(existing)
    desired = build_tacacs_profile_entity(existing_id)

    # Profile schemas can differ slightly. We intentionally update an existing
    # managed-name profile during --apply so both privilege values are enforced.
    if not apply_changes:
        return "WOULD_UPDATE", desired

    response = client.put_json(
        f"{TACACS_PROFILE_ERS_ENDPOINT}/{existing_id}",
        desired,
        expected=(200, 201, 204),
    )
    return "UPDATED", response


def ensure_authorization_rule(
    client: ISEClient,
    policy_set_id: str,
    existing_rules: list[dict[str, Any]],
    desired_payload: dict[str, Any],
    apply_changes: bool,
    rule_name: str,
    expected_rank: int,
) -> tuple[str, dict[str, Any]]:
    existing = existing_rule_named(existing_rules, rule_name)
    base_endpoint = (
        f"{POLICY_SET_ENDPOINT}/{policy_set_id}/authorization"
    )

    if existing is None:
        if not apply_changes:
            return "WOULD_CREATE", desired_payload
        response = client.post_json(
            base_endpoint,
            desired_payload,
            expected=(200, 201),
        )
        return "CREATED", response

    rule_id = str(existing.get("rule", {}).get("id", ""))
    if not rule_id:
        raise ISEError(f"Existing {rule_name} rule has no ID.")

    desired_with_id = json.loads(json.dumps(desired_payload))
    desired_with_id["rule"]["id"] = rule_id

    same = normalize_for_compare(existing) == normalize_for_compare(desired_with_id)
    rank_is_correct = existing.get("rule", {}).get("rank") == expected_rank

    if same and rank_is_correct:
        return "COMPLIANT", existing

    if not apply_changes:
        return "WOULD_UPDATE", desired_with_id

    response = client.put_json(
        f"{base_endpoint}/{rule_id}",
        desired_with_id,
        expected=(200, 201, 204),
    )
    return "UPDATED", response


# ---------------------------------------------------------------------------
# Per-host orchestration
# ---------------------------------------------------------------------------

def process_host(
    host: str,
    username: str,
    password: str,
    verify_ssl: bool,
    timeout: int,
    apply_changes: bool,
    output_dir: Path,
    policy_set_name: Optional[str],
    progress_label: str = "",
) -> HostResult:
    started = time.monotonic()
    result = HostResult(
        host=host,
        mode="APPLY" if apply_changes else "AUDIT",
    )
    log = logging.getLogger(__name__)

    try:
        log.info("%s%s | Starting %s", progress_label, host, result.mode)
        device_ips = generate_device_ips(host)
        result.generated_ips = device_ips
        log.info("%s | Generated device IPs: %s", host, ", ".join(device_ips))

        client = ISEClient(
            host=host,
            username=username,
            password=password,
            verify_ssl=verify_ssl,
            timeout=timeout,
        )

        # Connectivity/API validation.
        client.get_json(POLICY_SET_ENDPOINT)

        identity_group = try_resolve_identity_group(client)
        result.identity_group = find_name(identity_group) or IDENTITY_GROUP_NAME
        log.info(
            "%s | Identity group resolved: %s",
            host,
            result.identity_group,
        )

        command_set = resolve_command_set(client)
        exact_command_name = find_name(command_set)
        result.command_set = exact_command_name
        log.info("%s | Command set resolved: %s", host, exact_command_name)

        if policy_set_name:
            policy_set, rules, evaluated = select_named_policy_set(
                client, policy_set_name
            )
        else:
            policy_set, rules, evaluated = select_target_policy_set(client)

        policy_id = find_id(policy_set)
        policy_name = find_name(policy_set)
        result.selected_policy_set = policy_name
        result.selected_policy_set_id = policy_id
        result.authorization_rule_count = len(
            [r for r in rules if not r.get("rule", {}).get("default")]
        )
        log.info(
            "%s | Selected policy set: %s | non-default authorization rules=%d",
            host,
            policy_name,
            result.authorization_rule_count,
        )

        existing_profile = find_profile_if_present(client)
        existing_rule = existing_rule_named(rules, RULE_NAME)
        existing_read_only_rule = existing_rule_named(
            rules, READ_ONLY_RULE_NAME
        )

        noc_template, switch_device_types = find_noc_read_only_template(rules)
        template_rule_name = str(
            noc_template.get("rule", {}).get("name", "")
        )
        result.read_only_template_rule = template_rule_name
        result.read_only_command_set = ", ".join(
            command_names_from_rule(noc_template)
        )
        result.read_only_profile = str(noc_template.get("profile", ""))

        log.info(
            "%s | NOC read-only template: %s | commands=%s | profile=%s",
            host,
            template_rule_name,
            result.read_only_command_set,
            result.read_only_profile,
        )

        desired_rule = build_authorization_payload(
            device_ips=device_ips,
            exact_command_set_name=exact_command_name,
            rank=0,
        )
        desired_read_only_rule = build_read_only_authorization_payload(
            template_rule=noc_template,
            switch_device_type_conditions=switch_device_types,
            rank=1,
        )

        backup = {
            "created_at": datetime.now().isoformat(),
            "host": host,
            "mode": result.mode,
            "selected_policy_set": policy_set,
            "existing_authorization_rules": rules,
            "existing_sat_team_admin_rule": existing_rule,
            "existing_sat_team_read_only_rule": existing_read_only_rule,
            "noc_read_only_template_rule": noc_template,
            "existing_tacacs_profile": existing_profile,
            "resolved_identity_group": identity_group,
            "resolved_command_set": command_set,
            "desired_sat_team_admin_rule": desired_rule,
            "desired_sat_team_read_only_rule": desired_read_only_rule,
            "evaluated_policy_sets": evaluated,
        }
        backup_file = (
            output_dir
            / "rollback"
            / f"{safe_filename(host)}_{result.mode.lower()}_{datetime.now():%Y%m%d_%H%M%S}.json"
        )
        write_json(backup_file, backup)
        result.backup_file = str(backup_file)

        profile_action, _ = ensure_tacacs_profile(
            client, apply_changes=apply_changes
        )
        result.profile_action = profile_action
        result.tacacs_profile = TACACS_PROFILE_NAME
        log.info("%s | TACACS profile action: %s", host, profile_action)

        rule_action, _ = ensure_authorization_rule(
            client=client,
            policy_set_id=policy_id,
            existing_rules=rules,
            desired_payload=desired_rule,
            apply_changes=apply_changes,
            rule_name=RULE_NAME,
            expected_rank=0,
        )
        result.rule_action = rule_action
        log.info(
            "%s | %s action: %s",
            host,
            RULE_NAME,
            rule_action,
        )

        read_only_action, _ = ensure_authorization_rule(
            client=client,
            policy_set_id=policy_id,
            existing_rules=rules,
            desired_payload=desired_read_only_rule,
            apply_changes=apply_changes,
            rule_name=READ_ONLY_RULE_NAME,
            expected_rank=1,
        )
        result.read_only_rule_action = read_only_action
        log.info(
            "%s | %s action: %s",
            host,
            READ_ONLY_RULE_NAME,
            read_only_action,
        )

        result.status = "SUCCESS"
        result.message = (
            f"Policy set={policy_name}; profile={profile_action}; "
            f"admin_rule={rule_action}; "
            f"read_only_rule={read_only_action}; "
            f"template={template_rule_name}"
        )

    except Exception as exc:
        result.status = "FAILED"
        result.message = str(exc)
        log.exception("%s | FAILED: %s", host, exc)

    finally:
        result.elapsed_seconds = round(time.monotonic() - started, 2)

    return result


# ---------------------------------------------------------------------------
# Console summaries and orchestration
# ---------------------------------------------------------------------------

def run_phase(
    *,
    hosts: list[str],
    username: str,
    password: str,
    verify_ssl: bool,
    timeout: int,
    apply_changes: bool,
    output_dir: Path,
    policy_set_name: Optional[str],
    workers: int,
) -> list[HostResult]:
    phase = "APPLY" if apply_changes else "AUDIT"
    results: list[HostResult] = []

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, workers)
    ) as executor:
        future_map = {}
        total = len(hosts)

        for index, host in enumerate(hosts, start=1):
            progress_label = f"[{phase} {index}/{total}] "
            future = executor.submit(
                process_host,
                host,
                username,
                password,
                verify_ssl,
                timeout,
                apply_changes,
                output_dir,
                policy_set_name,
                progress_label,
            )
            future_map[future] = host

        for future in concurrent.futures.as_completed(future_map):
            host = future_map[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append(
                    HostResult(
                        host=host,
                        status="FAILED",
                        mode=phase,
                        message=f"Unhandled worker exception: {exc}",
                    )
                )

    results.sort(key=lambda item: item.host)
    return results


def print_deployment_plan(results: list[HostResult]) -> None:
    print()
    print(Console.heading("=" * 78))
    print(Console.heading("DEPLOYMENT PLAN"))
    print(Console.heading("=" * 78))

    for index, item in enumerate(results, start=1):
        status = (
            Console.success("PASS")
            if item.status == "SUCCESS"
            else Console.error("FAILED")
        )
        print()
        print(f"[{index}/{len(results)}] {item.host} | {status}")
        print(f"  Policy set       : {item.selected_policy_set or '-'}")
        print(f"  Existing AuthZ   : {item.authorization_rule_count}")
        print(f"  Identity group   : {item.identity_group or '-'}")
        print(f"  Command set      : {item.command_set or '-'}")
        print(f"  TACACS profile   : {TACACS_PROFILE_NAME}")
        print(f"  Profile action   : {item.profile_action or '-'}")
        print(f"  Admin rule action: {item.rule_action or '-'}")
        print(f"  RO template rule : {item.read_only_template_rule or '-'}")
        print(f"  RO command set   : {item.read_only_command_set or '-'}")
        print(f"  RO shell profile : {item.read_only_profile or '-'}")
        print(f"  RO rule action   : {item.read_only_rule_action or '-'}")
        print("  Generated IPs    :")
        for ip in item.generated_ips:
            print(f"      - {ip}")
        if item.message:
            print(f"  Detail           : {item.message}")

    print()
    print(Console.heading("=" * 78))


def print_phase_summary(
    phase_name: str,
    results: list[HostResult],
) -> tuple[int, int]:
    successful = sum(item.status == "SUCCESS" for item in results)
    failed = len(results) - successful

    print()
    print(Console.heading("=" * 78))
    print(Console.heading(f"{phase_name} SUMMARY"))
    print(Console.heading("=" * 78))
    print(f"Deployments checked : {len(results)}")
    print(f"Passed              : {Console.success(str(successful))}")
    failed_value = Console.error(str(failed)) if failed else Console.success("0")
    print(f"Failed              : {failed_value}")

    for item in results:
        marker = (
            Console.success("PASS")
            if item.status == "SUCCESS"
            else Console.error("FAILED")
        )
        print(
            f"{item.host:<15} | {marker:<20} | "
            f"policy={item.selected_policy_set or '-'} | "
            f"profile={item.profile_action or '-'} | "
            f"admin={item.rule_action or '-'} | "
            f"read-only={item.read_only_rule_action or '-'}"
        )
        if item.status != "SUCCESS":
            print(f"  Reason: {item.message}")

    print(Console.heading("=" * 78))
    return successful, failed


def save_phase_reports(
    output_dir: Path,
    phase_name: str,
    results: list[HostResult],
    log_file: Path,
) -> tuple[Path, Path, Path]:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    prefix = f"ise_sat_team_{phase_name.lower()}_{timestamp}"

    json_report = output_dir / f"{prefix}.json"
    csv_report = output_dir / f"{prefix}.csv"
    html_report = output_dir / f"{prefix}.html"

    write_json(json_report, [asdict(item) for item in results])
    write_csv_report(csv_report, results)
    write_html_report(
        html_report,
        f"Cisco ISE SAT-TEAM {phase_name.title()} Report",
        results,
        log_file,
    )
    return json_report, csv_report, html_report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Audit every deployment, display a deployment plan, and request "
            "confirmation before creating the SAT-TEAM-ADMIN Device Admin rule."
        )
    )
    parser.add_argument(
        "--hosts-file",
        default="ise_hosts.txt",
        help="ISE Primary PAN IPv4 addresses. Default: ise_hosts.txt",
    )
    parser.add_argument(
        "--username",
        default=os.getenv("ISE_USERNAME", ""),
        help="ISE API username. Can also use ISE_USERNAME.",
    )
    parser.add_argument(
        "--password",
        default=os.getenv("ISE_PASSWORD", ""),
        help=(
            "ISE API password. Prefer ISE_PASSWORD or the interactive prompt."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help=(
            "Compatibility option. The script still performs the audit and "
            "requires YES before applying. Use --force to bypass confirmation."
        ),
    )
    parser.add_argument(
        "--audit-only",
        action="store_true",
        help="Run the audit and generate reports, but never prompt or apply.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "After every deployment passes audit, apply without asking for YES. "
            "Intended for controlled automation."
        ),
    )
    parser.add_argument(
        "--policy-set-name",
        help=(
            "Optional exact policy-set name override. Without it, the script "
            "discovers the device-type policy set with the most AuthZ rules."
        ),
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"Concurrent deployments. Default: {DEFAULT_WORKERS}",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Per-request timeout seconds. Default: {DEFAULT_TIMEOUT}",
    )
    parser.add_argument(
        "--verify-ssl",
        action="store_true",
        help="Verify the ISE HTTPS certificate. Default is disabled.",
    )
    parser.add_argument(
        "--output-dir",
        default="ise_sat_team_output",
        help="Logs, rollback files, and reports directory.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    Console.enable_windows_ansi()

    if args.audit_only and args.force:
        print(Console.error("--audit-only and --force cannot be used together."))
        return 2

    output_dir = Path(args.output_dir).resolve()
    log_file = configure_logging(output_dir, args.verbose)
    log = logging.getLogger(__name__)

    if not args.verify_ssl:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

    try:
        hosts = load_hosts(Path(args.hosts_file))
    except Exception as exc:
        log.error("Unable to load hosts: %s", exc)
        return 2

    username = args.username.strip() or input("ISE API username: ").strip()
    password = args.password or getpass.getpass("ISE API password: ")

    if not username or not password:
        log.error("Username and password are required.")
        return 2

    print(Console.heading("=" * 78))
    print(Console.heading("Cisco ISE SAT-TEAM Device Admin Automation v2.5"))
    print(Console.heading("=" * 78))
    print(f"Hosts             : {len(hosts)}")
    print(f"Workers           : {max(1, args.workers)}")
    print(f"Policy selection  : {args.policy_set_name or 'Automatic discovery'}")
    print(f"Admin rule        : {RULE_NAME}")
    print(f"Read-only rule    : {READ_ONLY_RULE_NAME}")
    print(f"Admin profile     : {TACACS_PROFILE_NAME}")
    print(f"Command set search: {COMMAND_SET_SEARCH_NAME}")
    print()
    print(Console.warning("Phase 1: AUDIT/PRE-CHECK. No changes will be made."))

    audit_results = run_phase(
        hosts=hosts,
        username=username,
        password=password,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
        apply_changes=False,
        output_dir=output_dir,
        policy_set_name=args.policy_set_name,
        workers=args.workers,
    )

    audit_json, audit_csv, audit_html = save_phase_reports(
        output_dir,
        "audit",
        audit_results,
        log_file,
    )

    print_deployment_plan(audit_results)
    _, audit_failed = print_phase_summary("AUDIT", audit_results)

    print(f"Audit JSON report : {audit_json}")
    print(f"Audit CSV report  : {audit_csv}")
    print(f"Audit HTML report : {audit_html}")
    print(f"Execution log     : {log_file}")

    if audit_failed:
        print()
        print(
            Console.error(
                "Deployment cancelled. Every ISE deployment must pass the "
                "audit before any configuration is changed."
            )
        )
        return 1

    if args.audit_only:
        print()
        print(Console.success("Audit completed successfully. No changes were made."))
        return 0

    print()
    print(Console.success("All deployments passed the audit."))
    print("No configuration changes have been made yet.")

    if args.force:
        confirmation = "YES"
        print(
            Console.warning(
                "--force specified: confirmation prompt bypassed. "
                "Beginning apply phase."
            )
        )
    else:
        print()
        confirmation = input(
            "Type YES to apply the deployment plan, or press Enter to cancel: "
        ).strip()

    if confirmation != "YES":
        print()
        print(Console.warning("Operation cancelled. No changes were made."))
        return 0

    print()
    print(Console.warning("Phase 2: APPLY. Configuration changes will now be sent."))

    apply_results = run_phase(
        hosts=hosts,
        username=username,
        password=password,
        verify_ssl=args.verify_ssl,
        timeout=args.timeout,
        apply_changes=True,
        output_dir=output_dir,
        policy_set_name=args.policy_set_name,
        workers=args.workers,
    )

    apply_json, apply_csv, apply_html = save_phase_reports(
        output_dir,
        "apply",
        apply_results,
        log_file,
    )

    _, apply_failed = print_phase_summary("APPLY", apply_results)
    print(f"Apply JSON report : {apply_json}")
    print(f"Apply CSV report  : {apply_csv}")
    print(f"Apply HTML report : {apply_html}")
    print(f"Rollback directory: {output_dir / 'rollback'}")
    print(f"Execution log     : {log_file}")

    created = sum(
        item.profile_action == "CREATED"
        or item.rule_action == "CREATED"
        or item.read_only_rule_action == "CREATED"
        for item in apply_results
    )
    updated = sum(
        item.profile_action == "UPDATED"
        or item.rule_action == "UPDATED"
        or item.read_only_rule_action == "UPDATED"
        for item in apply_results
    )
    skipped = sum(
        item.rule_action == "COMPLIANT"
        and item.read_only_rule_action == "COMPLIANT"
        for item in apply_results
    )

    print()
    print(Console.heading("DEPLOYMENT RESULT"))
    print(f"Hosts processed : {len(apply_results)}")
    print(f"Created         : {created}")
    print(f"Updated         : {updated}")
    print(f"Compliant/skip  : {skipped}")
    print(
        f"Failed          : "
        f"{Console.error(str(apply_failed)) if apply_failed else Console.success('0')}"
    )

    if apply_failed:
        print(
            Console.error(
                "One or more apply operations failed. Review the log and "
                "per-host rollback JSON before making additional changes."
            )
        )
        return 1

    print(Console.success("Deployment completed successfully."))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
