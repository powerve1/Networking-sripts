#!/usr/bin/env python3
"""
Cisco ISE - Pull Internal User Information and Groups via ERS API

Behavior:
- Reads ISE hosts from ise_hosts.txt
- Prompts for ERS API credentials
- Prompts for existing ISE internal username
- Pulls internal user information
- Resolves multiple Identity Groups, including comma-separated group IDs
- Uses .9 fallback if primary fails due to connection/SSL/timeout or HTTP 401
- Logs:
  - ise_user_lookup.log
  - ise_user_lookup_summary.txt
"""

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
LOG_FILE = "ise_user_lookup.log"
SUMMARY_FILE = "ise_user_lookup_summary.txt"

PORT = 9060
TIMEOUT_SEC = 20

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}


def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(message: str) -> None:
    entry = f"[{now_ts()}] {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    print(entry, flush=True)


def load_hosts(file_path: str) -> list[str]:
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Hosts file not found: {file_path}")

    hosts: list[str] = []

    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()

        if not line or line.startswith("#"):
            continue

        if "#" in line:
            line = line.split("#", 1)[0].strip()

        if line:
            hosts.append(line)

    return list(dict.fromkeys(hosts))


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


def should_try_dot9_fallback(http_status: int | None) -> bool:
    return http_status == 401


def parse_identity_groups(raw_groups) -> list[str]:
    """
    ISE may return identityGroups as:
    - single string ID
    - comma-separated string IDs
    - list of strings
    - list of dicts
    """

    if not raw_groups:
        return []

    group_ids = []

    if isinstance(raw_groups, str):
        for item in raw_groups.split(","):
            item = item.strip()
            if item:
                group_ids.append(item)

        return list(dict.fromkeys(group_ids))

    if isinstance(raw_groups, list):
        for item in raw_groups:
            if isinstance(item, str):
                for sub_item in item.split(","):
                    sub_item = sub_item.strip()
                    if sub_item:
                        group_ids.append(sub_item)

            elif isinstance(item, dict):
                gid = item.get("id") or item.get("value")
                if gid:
                    for sub_item in str(gid).split(","):
                        sub_item = sub_item.strip()
                        if sub_item:
                            group_ids.append(sub_item)

        return list(dict.fromkeys(group_ids))

    return []


def get_identity_group_by_id(
    session: requests.Session,
    base: str,
    group_id: str,
) -> tuple[str | None, str]:
    url = f"{base}/ers/config/identitygroup/{group_id}"
    r = session.get(url, timeout=TIMEOUT_SEC)

    if r.status_code == 200:
        body = safe_json(r)
        group_obj = body.get("IdentityGroup", {})
        group_name = group_obj.get("name")

        if group_name:
            return group_name, "OK"

        return None, "Group found but no name returned"

    if r.status_code == 404:
        return None, f"Identity Group ID '{group_id}' not found"

    if r.status_code == 401:
        return None, "HTTP 401 - Unauthorized"

    return None, format_error_detail(r)


def get_internal_user_info(
    session: requests.Session,
    base: str,
    username: str,
) -> tuple[bool, dict | None, str, int | None]:
    url = f"{base}/ers/config/internaluser/name/{username}"
    r = session.get(url, timeout=TIMEOUT_SEC)

    if r.status_code == 200:
        body = safe_json(r)
        user_obj = body.get("InternalUser")

        if not user_obj:
            return False, None, "InternalUser object not found in response", None

        group_ids = parse_identity_groups(user_obj.get("identityGroups"))

        resolved_groups = []

        for group_id in group_ids:
            group_name, group_msg = get_identity_group_by_id(
                session=session,
                base=base,
                group_id=group_id,
            )

            resolved_groups.append(
                {
                    "id": group_id,
                    "name": group_name if group_name else "UNKNOWN",
                    "lookup_status": group_msg,
                }
            )

        user_info = {
            "id": user_obj.get("id"),
            "name": user_obj.get("name"),
            "description": user_obj.get("description"),
            "enabled": user_obj.get("enabled"),
            "email": user_obj.get("email"),
            "firstName": user_obj.get("firstName"),
            "lastName": user_obj.get("lastName"),
            "changePassword": user_obj.get("changePassword"),
            "expiryDateEnabled": user_obj.get("expiryDateEnabled"),
            "expiryDate": user_obj.get("expiryDate"),
            "passwordIDStore": user_obj.get("passwordIDStore"),
            "identityGroups_raw": user_obj.get("identityGroups"),
            "identityGroups_resolved": resolved_groups,
            "raw": user_obj,
        }

        return True, user_info, "OK", None

    if r.status_code == 404:
        return False, None, f"User '{username}' not found", 404

    if r.status_code == 401:
        return False, None, "HTTP 401 - Unauthorized", 401

    return False, None, format_error_detail(r), r.status_code


def print_user_info(host: str, user_info: dict) -> None:
    print("")
    print("=" * 72)
    print(f"ISE Host              : {host}")
    print(f"User ID               : {user_info.get('id')}")
    print(f"Username              : {user_info.get('name')}")
    print(f"Enabled               : {user_info.get('enabled')}")
    print(f"Email                 : {user_info.get('email')}")
    print(f"First Name            : {user_info.get('firstName')}")
    print(f"Last Name             : {user_info.get('lastName')}")
    print(f"Description           : {user_info.get('description')}")
    print(f"Change Password Flag  : {user_info.get('changePassword')}")
    print(f"Expiry Date Enabled   : {user_info.get('expiryDateEnabled')}")
    print(f"Expiry Date           : {user_info.get('expiryDate')}")
    print(f"Password ID Store     : {user_info.get('passwordIDStore')}")
    print("")
    print("Identity Groups:")
    print("-" * 72)

    groups = user_info.get("identityGroups_resolved", [])

    if not groups:
        print("  No identity groups returned.")
    else:
        for g in groups:
            print(f"  Name          : {g.get('name')}")
            print(f"  ID            : {g.get('id')}")
            print(f"  Lookup Status : {g.get('lookup_status')}")
            print("")

    print("=" * 72)
    print("")


def write_summary(
    username: str,
    successes: list[tuple[str, dict]],
    failures: list[tuple[str, str]],
) -> None:
    lines = []

    lines.append(f"ISE Internal User Lookup Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Username   : {username}")
    lines.append(f"Hosts File : {HOSTS_FILE}")
    lines.append("")

    lines.append(f"SUCCESS ({len(successes)}):")

    if successes:
        for host, user_info in successes:
            lines.append("")
            lines.append(f"Host                  : {host}")
            lines.append(f"User ID               : {user_info.get('id')}")
            lines.append(f"Username              : {user_info.get('name')}")
            lines.append(f"Enabled               : {user_info.get('enabled')}")
            lines.append(f"Email                 : {user_info.get('email')}")
            lines.append(f"First Name            : {user_info.get('firstName')}")
            lines.append(f"Last Name             : {user_info.get('lastName')}")
            lines.append(f"Description           : {user_info.get('description')}")
            lines.append(f"Change Password Flag  : {user_info.get('changePassword')}")
            lines.append(f"Expiry Date Enabled   : {user_info.get('expiryDateEnabled')}")
            lines.append(f"Expiry Date           : {user_info.get('expiryDate')}")
            lines.append(f"Password ID Store     : {user_info.get('passwordIDStore')}")
            lines.append("Identity Groups:")

            groups = user_info.get("identityGroups_resolved", [])

            if groups:
                for g in groups:
                    lines.append(f"  - Name: {g.get('name')}")
                    lines.append(f"    ID: {g.get('id')}")
                    lines.append(f"    Lookup Status: {g.get('lookup_status')}")
            else:
                lines.append("  - No identity groups returned.")
    else:
        lines.append("  (none)")

    lines.append("")
    lines.append(f"FAILED ({len(failures)}):")

    if failures:
        for h, reason in failures:
            lines.append(f"  - {h}: {reason}")
    else:
        lines.append("  (none)")

    lines.append("")

    Path(SUMMARY_FILE).write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    print("ISE internal user lookup script started...", flush=True)

    api_user = input("Enter ISE ERS API username: ").strip()
    api_pass = getpass.getpass("Enter ISE ERS API password: ")

    username = input("Enter the ISE internal username to search: ").strip()

    if not api_user:
        print("ERROR: API username is required.")
        return 2

    if not api_pass:
        print("ERROR: API password is required.")
        return 2

    if not username:
        print("ERROR: Username is required.")
        return 2

    try:
        ise_hosts = load_hosts(HOSTS_FILE)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    if not ise_hosts:
        print(f"ERROR: No hosts found in {HOSTS_FILE}")
        return 2

    log_event("------------------------------------------------------------")
    log_event(f"Starting internal user lookup for '{username}'")
    log_event(f"Loaded {len(ise_hosts)} ISE host(s) from {HOSTS_FILE}")
    log_event("------------------------------------------------------------")

    successes: list[tuple[str, dict]] = []
    failures: list[tuple[str, str]] = []

    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False

    for host in ise_hosts:
        primary_base = f"https://{host}:{PORT}"
        fb = fallback_to_dot9(host)
        tried_fallback = False

        try:
            ok, user_info, msg, http_status = get_internal_user_info(
                session=session,
                base=primary_base,
                username=username,
            )

            if ok and user_info:
                log_event(f"SUCCESS: {host} - Found user '{username}'")
                print_user_info(host, user_info)
                successes.append((host, user_info))
                continue

            if fb and should_try_dot9_fallback(http_status):
                log_event(f"INFO: {host} - HTTP {http_status}; retrying fallback {fb}")
                tried_fallback = True
            else:
                log_event(f"FAILED: {host} - {msg}")
                failures.append((host, msg))
                continue

        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.SSLError,
        ):
            if not fb:
                reason = f"Connection failed on port {PORT}; no .9 fallback available"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((host, reason))
                continue

            log_event(f"INFO: {host} - Connection/SSL failed; retrying fallback {fb}")
            tried_fallback = True

        except Exception as e:
            reason = f"Unexpected error: {str(e)}"
            log_event(f"FAILED: {host} - {reason}")
            failures.append((host, reason))
            continue

        if tried_fallback:
            fb_base = f"https://{fb}:{PORT}"

            try:
                ok2, user_info2, msg2, _ = get_internal_user_info(
                    session=session,
                    base=fb_base,
                    username=username,
                )

                if ok2 and user_info2:
                    fallback_host_label = f"{host} fallback {fb}"
                    log_event(f"SUCCESS: {host} - Found user '{username}' via fallback {fb}")
                    print_user_info(fallback_host_label, user_info2)
                    successes.append((fallback_host_label, user_info2))
                else:
                    reason = f"Primary failed; fallback {fb} reached but lookup failed: {msg2}"
                    log_event(f"FAILED: {host} - {reason}")
                    failures.append((host, reason))

            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.SSLError,
            ):
                reason = f"Connection failed to both {host} and fallback {fb} on port {PORT}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((host, reason))

            except Exception as e:
                reason = f"Fallback {fb} unexpected error: {str(e)}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((host, reason))

    write_summary(
        username=username,
        successes=successes,
        failures=failures,
    )

    log_event("------------------------------------------------------------")
    log_event(f"Finished. Success: {len(successes)} | Failed: {len(failures)}")
    log_event(f"Detailed log  : {LOG_FILE}")
    log_event(f"Summary report: {SUMMARY_FILE}")
    log_event("------------------------------------------------------------")

    return 0 if successes else 1


if __name__ == "__main__":
    sys.exit(main())