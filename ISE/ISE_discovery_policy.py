#!/usr/bin/env python3
"""
Cisco ISE - Device Admin Discovery + Drift Report

READ-ONLY SCRIPT.

What it does:
- Reads ISE hosts from ise_hosts.txt
- Connects to ISE ERS API on port 9060
- Discovers TACACS / Device Admin objects
- Compares discovered names against a local standard mapping file
- Generates:
    1. Full inventory CSV
    2. Drift report CSV
    3. Failure report CSV
    4. Execution log

Files:
- ise_hosts.txt
- ise_device_admin_standard.json
- ise_device_admin_inventory.csv
- ise_device_admin_drift_report.csv
- ise_device_admin_failures.csv
- ise_device_admin_discovery.log
"""

import csv
import datetime
import getpass
import json
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOSTS_FILE = "ise_hosts.txt"
STANDARD_FILE = "ise_device_admin_standard.json"

LOG_FILE = "ise_device_admin_discovery.log"
INVENTORY_CSV = "ise_device_admin_inventory.csv"
DRIFT_CSV = "ise_device_admin_drift_report.csv"
FAILURES_CSV = "ise_device_admin_failures.csv"

PORT = 9060
TIMEOUT_SEC = 60

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# The script tries multiple possible ERS paths because ISE versions can expose
# Device Admin resources differently.
OBJECT_ENDPOINTS = {
    "tacacs_command_set": [
        "/ers/config/tacacscommandsets",
        "/ers/config/tacacscommandset",
    ],
    "tacacs_shell_profile": [
        "/ers/config/tacacsprofile",
        "/ers/config/tacacsprofiles",
    ],
    "device_admin_policy_set": [
        "/ers/config/deviceadminpolicyset",
        "/ers/config/tacacspolicyset",
    ],
    "device_admin_condition": [
        "/ers/config/tacacscondition",
        "/ers/config/condition",
    ],
}


DEFAULT_STANDARD = {
    "tacacs_command_set": {
        "CMDSET_TACACS_FULL_ACCESS": {
            "aliases": [
                "Permit_All",
                "Full Access",
                "Allow All Commands",
                "TACACS Full Access"
            ]
        },
        "CMDSET_TACACS_READ_ONLY": {
            "aliases": [
                "Read Only",
                "Readonly",
                "Show Commands Only",
                "TACACS Read Only"
            ]
        }
    },
    "tacacs_shell_profile": {
        "SHELL_TACACS_PRIV15": {
            "aliases": [
                "Device_Admin_Priv15",
                "Privilege_15",
                "Priv15",
                "TACACS Priv 15"
            ]
        },
        "SHELL_TACACS_READONLY": {
            "aliases": [
                "Read Only Shell",
                "Privilege_1",
                "Priv1",
                "TACACS Read Only"
            ]
        }
    },
    "device_admin_policy_set": {
        "PS_TACACS_DEVICE_ADMIN_STANDARD": {
            "aliases": [
                "Device Admin",
                "TACACS Policy Set",
                "Device Administration",
                "Network Device Admin"
            ]
        }
    },
    "device_admin_condition": {
        "COND_TACACS_NETWORK_DEVICES": {
            "aliases": [
                "Network Devices",
                "TACACS Devices",
                "All Network Gear"
            ]
        },
        "COND_TACACS_AD_NETADMINS": {
            "aliases": [
                "Network Admins",
                "NetOps Admins",
                "AD Network Admins"
            ]
        }
    }
}


def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(message: str) -> None:
    entry = f"[{now_ts()}] {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    print(entry, flush=True)


def safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


def format_error_detail(resp: requests.Response) -> str:
    j = safe_json(resp)

    if j:
        return f"HTTP {resp.status_code} - {json.dumps(j, ensure_ascii=False)}"

    txt = (resp.text or "").strip()

    if txt:
        if len(txt) > 600:
            txt = txt[:600] + "...(truncated)"
        return f"HTTP {resp.status_code} - {txt}"

    return f"HTTP {resp.status_code} - No response body"


def load_hosts(file_path: str) -> list[str]:
    p = Path(file_path)

    if not p.exists():
        raise FileNotFoundError(f"Hosts file not found: {file_path}")

    hosts = []

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()

        if line:
            hosts.append(line)

    return list(dict.fromkeys(hosts))


def is_ipv4(host: str) -> bool:
    parts = host.split(".")

    if len(parts) != 4:
        return False

    for p in parts:
        if not p.isdigit():
            return False

        n = int(p)

        if n < 0 or n > 255:
            return False

    return True


def fallback_to_dot9(host: str) -> str | None:
    if not is_ipv4(host):
        return None

    parts = host.split(".")

    if parts[3] == "9":
        return None

    return ".".join(parts[:3] + ["9"])


def ensure_standard_file() -> None:
    p = Path(STANDARD_FILE)

    if p.exists():
        return

    p.write_text(
        json.dumps(DEFAULT_STANDARD, indent=4),
        encoding="utf-8"
    )

    log_event(f"Created default standard mapping file: {STANDARD_FILE}")


def load_standard() -> dict:
    ensure_standard_file()

    with open(STANDARD_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_name(name: str) -> str:
    return (
        name.strip()
        .lower()
        .replace("_", "")
        .replace("-", "")
        .replace(" ", "")
    )


def build_alias_index(standard: dict) -> dict:
    index = {}

    for object_type, canonical_objects in standard.items():
        index[object_type] = {}

        for canonical_name, data in canonical_objects.items():
            names = [canonical_name]
            names.extend(data.get("aliases", []))

            for name in names:
                index[object_type][normalize_name(name)] = canonical_name

    return index


def extract_resources(body: dict) -> list[dict]:
    """
    Most ISE ERS list responses look like:
    {
        "SearchResult": {
            "resources": [
                {
                    "id": "...",
                    "name": "...",
                    "description": "...",
                    "link": {...}
                }
            ]
        }
    }
    """

    search_result = body.get("SearchResult", {})
    resources = search_result.get("resources", [])

    if isinstance(resources, list):
        return resources

    return []


def get_next_page_url(body: dict) -> str | None:
    search_result = body.get("SearchResult", {})
    next_page = search_result.get("nextPage", {})

    if isinstance(next_page, dict):
        href = next_page.get("href")
        if href:
            return href

    return None


def discover_endpoint(
    session: requests.Session,
    base: str,
    endpoint: str,
) -> tuple[bool, list[dict], str]:

    all_resources = []
    url = f"{base}{endpoint}?size=100&page=1"

    while url:
        r = session.get(url, timeout=TIMEOUT_SEC)

        if r.status_code == 200:
            body = safe_json(r)
            resources = extract_resources(body)
            all_resources.extend(resources)

            next_url = get_next_page_url(body)
            url = next_url if next_url else None
            continue

        if r.status_code == 404:
            return False, [], "Endpoint not found"

        return False, [], format_error_detail(r)

    return True, all_resources, "OK"


def discover_object_type(
    session: requests.Session,
    base: str,
    object_type: str,
) -> tuple[list[dict], str, str]:

    endpoints = OBJECT_ENDPOINTS.get(object_type, [])

    last_reason = "No endpoint configured"

    for endpoint in endpoints:
        ok, resources, reason = discover_endpoint(
            session=session,
            base=base,
            endpoint=endpoint,
        )

        if ok:
            return resources, endpoint, "OK"

        last_reason = reason

    return [], "", last_reason


def discover_host(
    session: requests.Session,
    host: str,
    standard_index: dict,
) -> tuple[list[dict], list[dict], list[dict]]:

    inventory_rows = []
    drift_rows = []
    failure_rows = []

    base = f"https://{host}:{PORT}"

    log_event("------------------------------------------------------------")
    log_event(f"Starting discovery for ISE host {host}")
    log_event("------------------------------------------------------------")

    for object_type in OBJECT_ENDPOINTS.keys():
        try:
            resources, endpoint_used, reason = discover_object_type(
                session=session,
                base=base,
                object_type=object_type,
            )

            if reason != "OK":
                failure_rows.append({
                    "host": host,
                    "object_type": object_type,
                    "endpoint": "",
                    "reason": reason,
                })
                log_event(f"FAILED: {host} {object_type} - {reason}")
                continue

            log_event(
                f"SUCCESS: {host} {object_type} - "
                f"{len(resources)} object(s) discovered via {endpoint_used}"
            )

            for item in resources:
                object_id = item.get("id", "")
                name = item.get("name", "")
                description = item.get("description", "")

                normalized = normalize_name(name)
                canonical_match = standard_index.get(object_type, {}).get(normalized, "")

                if canonical_match:
                    drift_status = (
                        "MATCH_CANONICAL"
                        if name == canonical_match
                        else "MATCH_ALIAS_RENAME_RECOMMENDED"
                    )
                else:
                    drift_status = "UNMAPPED_OBJECT"

                inventory_rows.append({
                    "host": host,
                    "object_type": object_type,
                    "object_id": object_id,
                    "current_name": name,
                    "description": description,
                    "endpoint_used": endpoint_used,
                    "canonical_match": canonical_match,
                    "drift_status": drift_status,
                })

                if drift_status != "MATCH_CANONICAL":
                    drift_rows.append({
                        "host": host,
                        "object_type": object_type,
                        "object_id": object_id,
                        "current_name": name,
                        "canonical_match": canonical_match,
                        "drift_status": drift_status,
                        "recommendation": build_recommendation(
                            drift_status=drift_status,
                            current_name=name,
                            canonical_match=canonical_match,
                            object_type=object_type,
                        ),
                    })

        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.SSLError,
        ) as e:
            reason = f"Connection/SSL/timeout error: {str(e)}"
            failure_rows.append({
                "host": host,
                "object_type": object_type,
                "endpoint": "",
                "reason": reason,
            })
            log_event(f"FAILED: {host} {object_type} - {reason}")

        except Exception as e:
            reason = f"Unexpected error: {str(e)}"
            failure_rows.append({
                "host": host,
                "object_type": object_type,
                "endpoint": "",
                "reason": reason,
            })
            log_event(f"FAILED: {host} {object_type} - {reason}")

    return inventory_rows, drift_rows, failure_rows


def build_recommendation(
    drift_status: str,
    current_name: str,
    canonical_match: str,
    object_type: str,
) -> str:

    if drift_status == "MATCH_ALIAS_RENAME_RECOMMENDED":
        return (
            f"Object matches standard by alias. Consider renaming "
            f"'{current_name}' to canonical name '{canonical_match}'."
        )

    if drift_status == "UNMAPPED_OBJECT":
        return (
            f"Object is not mapped to any standard {object_type}. "
            f"Review whether it should be added as an alias, renamed, or retired."
        )

    return "No action required."


def write_csv(path: str, rows: list[dict], fieldnames: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            extrasaction="ignore",
        )

        writer.writeheader()

        for row in rows:
            writer.writerow(row)


def main() -> int:
    print("ISE Device Admin Discovery + Drift Report started...", flush=True)

    api_user = input("Enter ISE ERS API username: ").strip()
    api_pass = getpass.getpass("Enter ISE ERS API password: ")

    if not api_user:
        print("ERROR: API username is required.")
        return 2

    if not api_pass:
        print("ERROR: API password is required.")
        return 2

    try:
        ise_hosts = load_hosts(HOSTS_FILE)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    if not ise_hosts:
        print(f"ERROR: No hosts found in {HOSTS_FILE}")
        return 2

    standard = load_standard()
    standard_index = build_alias_index(standard)

    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False

    all_inventory = []
    all_drift = []
    all_failures = []

    log_event("============================================================")
    log_event(f"Starting Device Admin discovery for {len(ise_hosts)} ISE host(s)")
    log_event("============================================================")

    for host in ise_hosts:
        primary_inventory = []
        primary_drift = []
        primary_failures = []

        try:
            primary_inventory, primary_drift, primary_failures = discover_host(
                session=session,
                host=host,
                standard_index=standard_index,
            )

            connection_failures = [
                f for f in primary_failures
                if "Connection/SSL/timeout" in f.get("reason", "")
            ]

            if len(connection_failures) == len(OBJECT_ENDPOINTS):
                fb = fallback_to_dot9(host)

                if fb:
                    log_event(
                        f"INFO: {host} appears unreachable on port {PORT}; "
                        f"retrying fallback {fb}"
                    )

                    fb_inventory, fb_drift, fb_failures = discover_host(
                        session=session,
                        host=fb,
                        standard_index=standard_index,
                    )

                    all_inventory.extend(fb_inventory)
                    all_drift.extend(fb_drift)
                    all_failures.extend(fb_failures)
                    continue

            all_inventory.extend(primary_inventory)
            all_drift.extend(primary_drift)
            all_failures.extend(primary_failures)

        except Exception as e:
            reason = f"Host-level unexpected error: {str(e)}"
            all_failures.append({
                "host": host,
                "object_type": "host",
                "endpoint": "",
                "reason": reason,
            })
            log_event(f"FAILED: {host} - {reason}")

    write_csv(
        INVENTORY_CSV,
        all_inventory,
        [
            "host",
            "object_type",
            "object_id",
            "current_name",
            "description",
            "endpoint_used",
            "canonical_match",
            "drift_status",
        ],
    )

    write_csv(
        DRIFT_CSV,
        all_drift,
        [
            "host",
            "object_type",
            "object_id",
            "current_name",
            "canonical_match",
            "drift_status",
            "recommendation",
        ],
    )

    write_csv(
        FAILURES_CSV,
        all_failures,
        [
            "host",
            "object_type",
            "endpoint",
            "reason",
        ],
    )

    log_event("------------------------------------------------------------")
    log_event(f"Finished discovery.")
    log_event(f"Inventory report : {INVENTORY_CSV}")
    log_event(f"Drift report     : {DRIFT_CSV}")
    log_event(f"Failure report   : {FAILURES_CSV}")
    log_event(f"Detailed log     : {LOG_FILE}")
    log_event("------------------------------------------------------------")

    print("")
    print("Summary")
    print("-------")
    print(f"Inventory objects discovered : {len(all_inventory)}")
    print(f"Drift items found            : {len(all_drift)}")
    print(f"Failures                     : {len(all_failures)}")

    return 0 if not all_failures else 1


if __name__ == "__main__":
    sys.exit(main())