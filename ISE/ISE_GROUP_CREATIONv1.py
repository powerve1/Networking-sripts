#!/usr/bin/env python3
"""
Cisco ISE - Create User Identity Group via ERS API

Behavior:
- Reads ISE hosts from ise_hosts.txt
- Creates Cisco ISE User Identity Groups through ERS API
- Prompts for group name and description
- Supports single-group creation
- Supports multiple-group creation
- Skips group if it already exists
- Fallback to .9 node if primary fails due to connection/SSL/timeout or HTTP 401
- Writes detailed log and summary report
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
LOG_FILE = "ise_identity_group_creates.log"
SUMMARY_FILE = "ise_identity_group_creates_summary.txt"

PORT = 9060
TIMEOUT_SEC = 60

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


def ask_yes_no(prompt: str, default_yes: bool = False) -> bool:
    default_text = "[Y/n]" if default_yes else "[y/N]"

    while True:
        answer = input(f"{prompt} {default_text}: ").strip().lower()

        if not answer:
            return default_yes

        if answer in ("y", "yes"):
            return True

        if answer in ("n", "no"):
            return False

        print("Please answer yes or no.")


def collect_group_details() -> dict:
    while True:
        group_name = input("Enter the NEW User Identity Group name to create: ").strip()

        if group_name:
            break

        print("ERROR: Group name is required.")

    description = input("Enter the User Identity Group description: ").strip()

    return {
        "group_name": group_name,
        "description": description,
    }


def collect_groups_to_create() -> list[dict]:
    groups: list[dict] = []

    create_multiple = ask_yes_no(
        "Do you want to create multiple User Identity Groups?",
        default_yes=False,
    )

    if not create_multiple:
        groups.append(collect_group_details())
        return groups

    while True:
        groups.append(collect_group_details())

        add_another = ask_yes_no(
            "Add another User Identity Group?",
            default_yes=False,
        )

        if not add_another:
            break

    return groups


def identity_group_exists(
    session: requests.Session,
    base: str,
    group_name: str,
) -> tuple[bool, str | None, str, int | None]:

    url = f"{base}/ers/config/identitygroup/name/{group_name}"

    r = session.get(url, timeout=TIMEOUT_SEC)

    if r.status_code == 200:
        body = safe_json(r)
        gid = body.get("IdentityGroup", {}).get("id")
        return True, gid, "OK", 200

    if r.status_code == 404:
        return False, None, "Not found", 404

    if r.status_code == 401:
        return False, None, "HTTP 401 - Unauthorized", 401

    return False, None, format_error_detail(r), r.status_code


def build_identity_group_payload(
    group_name: str,
    description: str,
) -> dict:

    return {
        "IdentityGroup": {
            "name": group_name,
            "description": description,
        }
    }


def create_identity_group_on_base(
    session: requests.Session,
    base: str,
    group_name: str,
    description: str,
) -> tuple[bool, str, int | None]:

    exists, gid, exists_reason, http_status = identity_group_exists(
        session=session,
        base=base,
        group_name=group_name,
    )

    if exists:
        return False, f"User Identity Group '{group_name}' already exists id={gid}", 409

    if exists_reason != "Not found":
        return False, f"Error checking if group exists: {exists_reason}", http_status

    create_url = f"{base}/ers/config/identitygroup"

    payload = build_identity_group_payload(
        group_name=group_name,
        description=description,
    )

    r_post = session.post(
        create_url,
        json=payload,
        timeout=TIMEOUT_SEC,
    )

    if r_post.status_code in (200, 201):
        return True, (
            f"Created User Identity Group '{group_name}' "
            f"description='{description}'"
        ), None

    return False, format_error_detail(r_post), r_post.status_code


def create_identity_group_across_hosts(
    session: requests.Session,
    ise_hosts: list[str],
    group: dict,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]], list[tuple[str, str]]]:

    successes: list[tuple[str, str]] = []
    failures: list[tuple[str, str, str]] = []
    skipped: list[tuple[str, str]] = []

    group_name = group["group_name"]
    description = group["description"]

    log_event("------------------------------------------------------------")
    log_event(
        f"Starting User Identity Group create for '{group_name}' "
        f"description='{description}'"
    )
    log_event(f"Loaded {len(ise_hosts)} ISE host(s) from {HOSTS_FILE}")
    log_event("------------------------------------------------------------")

    for host in ise_hosts:
        primary_base = f"https://{host}:{PORT}"
        fb = fallback_to_dot9(host)
        tried_fallback = False

        try:
            ok, msg, http_status = create_identity_group_on_base(
                session=session,
                base=primary_base,
                group_name=group_name,
                description=description,
            )

            if ok:
                log_event(f"SUCCESS: {host} - {msg}")
                successes.append((group_name, host))
                continue

            if http_status == 409:
                log_event(f"SKIPPED: {host} - {msg}")
                skipped.append((group_name, host))
                continue

            if fb and should_try_dot9_fallback(http_status):
                log_event(f"INFO: {host} - HTTP {http_status}; retrying fallback {fb}")
                tried_fallback = True
            else:
                log_event(f"FAILED: {host} - {msg}")
                failures.append((group_name, host, msg))
                continue

        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.SSLError,
        ):
            if not fb:
                reason = f"Connection failed on port {PORT}; no .9 fallback available"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((group_name, host, reason))
                continue

            log_event(f"INFO: {host} - Connection/SSL failed; retrying fallback {fb}")
            tried_fallback = True

        except Exception as e:
            reason = f"Unexpected error: {str(e)}"
            log_event(f"FAILED: {host} - {reason}")
            failures.append((group_name, host, reason))
            continue

        if tried_fallback:
            fb_base = f"https://{fb}:{PORT}"

            try:
                ok2, msg2, http_status2 = create_identity_group_on_base(
                    session=session,
                    base=fb_base,
                    group_name=group_name,
                    description=description,
                )

                if ok2:
                    log_event(f"SUCCESS: {host} - {msg2} via fallback {fb}")
                    successes.append((group_name, f"{host} fallback {fb}"))

                elif http_status2 == 409:
                    log_event(f"SKIPPED: {host} - {msg2} via fallback {fb}")
                    skipped.append((group_name, f"{host} fallback {fb}"))

                else:
                    reason = f"Primary failed; fallback {fb} reached but operation failed: {msg2}"
                    log_event(f"FAILED: {host} - {reason}")
                    failures.append((group_name, host, reason))

            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.SSLError,
            ):
                reason = f"Connection failed to both {host} and fallback {fb} on port {PORT}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((group_name, host, reason))

            except Exception as e:
                reason = f"Fallback {fb} unexpected error: {str(e)}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((group_name, host, reason))

    return successes, failures, skipped


def write_summary(
    groups: list[dict],
    successes: list[tuple[str, str]],
    failures: list[tuple[str, str, str]],
    skipped: list[tuple[str, str]],
) -> None:

    lines = []

    lines.append(f"ISE User Identity Group Create Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Hosts File      : {HOSTS_FILE}")
    lines.append(f"Groups Tried    : {len(groups)}")
    lines.append("")

    lines.append("GROUPS:")
    if groups:
        for group in groups:
            lines.append(
                f"  - {group['group_name']} | description={group['description']}"
            )
    else:
        lines.append("  (none)")

    lines.append("")

    lines.append(f"SUCCESS ({len(successes)}):")
    if successes:
        for group_name, host in successes:
            lines.append(f"  - {group_name}: {host}")
    else:
        lines.append("  (none)")

    lines.append("")

    lines.append(f"SKIPPED / ALREADY EXISTS ({len(skipped)}):")
    if skipped:
        for group_name, host in skipped:
            lines.append(f"  - {group_name}: {host}")
    else:
        lines.append("  (none)")

    lines.append("")

    lines.append(f"FAILED ({len(failures)}):")
    if failures:
        for group_name, host, reason in failures:
            lines.append(f"  - {group_name}: {host}: {reason}")
    else:
        lines.append("  (none)")

    lines.append("")

    Path(SUMMARY_FILE).write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    print("ISE User Identity Group creation script started...", flush=True)

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

    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False

    groups = collect_groups_to_create()

    all_successes: list[tuple[str, str]] = []
    all_failures: list[tuple[str, str, str]] = []
    all_skipped: list[tuple[str, str]] = []

    log_event("============================================================")
    log_event(f"Starting batch creation for {len(groups)} User Identity Group(s)")
    log_event("============================================================")

    for group in groups:
        successes, failures, skipped = create_identity_group_across_hosts(
            session=session,
            ise_hosts=ise_hosts,
            group=group,
        )

        all_successes.extend(successes)
        all_failures.extend(failures)
        all_skipped.extend(skipped)

    write_summary(
        groups=groups,
        successes=all_successes,
        failures=all_failures,
        skipped=all_skipped,
    )

    log_event("------------------------------------------------------------")
    log_event(
        f"Finished. Success: {len(all_successes)} | "
        f"Skipped: {len(all_skipped)} | "
        f"Failed: {len(all_failures)}"
    )
    log_event(f"Detailed log  : {LOG_FILE}")
    log_event(f"Summary report: {SUMMARY_FILE}")
    log_event("------------------------------------------------------------")

    return 0 if not all_failures else 1


if __name__ == "__main__":
    sys.exit(main())