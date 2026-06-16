#!/usr/bin/env python3
"""
Cisco ISE - Change Internal User Password / Disable Force Password Change via ERS API

Behavior:
- Reads ISE hosts from ise_hosts.txt
- Prompts for ERS API credentials
- Prompts for existing ISE internal username
- Asks if you want to change the password
    - If YES:
        - Prompts for new password
        - Asks whether to force password change after first login
        - Updates password and changePassword true/false
    - If NO:
        - Asks if you want to disable force password change after first login
        - If YES:
            - Only sets changePassword = false
            - Does NOT modify password
        - If NO:
            - Exits without changes
- Fallback to .9 node if primary fails due to connection/SSL/timeout or HTTP 401
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
LOG_FILE = "ise_user_password_change.log"
SUMMARY_FILE = "ise_user_password_change_summary.txt"

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


def write_summary(
    username: str,
    operation: str,
    force_change_password: bool,
    successes: list[str],
    failures: list[tuple[str, str]],
) -> None:
    lines = []

    lines.append(f"ISE Internal User Update Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Username              : {username}")
    lines.append(f"Operation             : {operation}")
    lines.append(f"changePassword Value  : {force_change_password}")
    lines.append(f"Hosts File            : {HOSTS_FILE}")
    lines.append("")

    lines.append(f"SUCCESS ({len(successes)}):")
    if successes:
        for h in successes:
            lines.append(f"  - {h}")
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


def internal_user_get(
    session: requests.Session,
    base: str,
    username: str,
) -> tuple[dict | None, str | None, str, int | None]:

    url = f"{base}/ers/config/internaluser/name/{username}"
    r = session.get(url, timeout=TIMEOUT_SEC)

    if r.status_code == 200:
        body = safe_json(r)
        user_obj = body.get("InternalUser", {})
        user_id = user_obj.get("id")

        if not user_id:
            return None, None, "InternalUser found but no ID returned", None

        return user_obj, user_id, "OK", None

    if r.status_code == 404:
        return None, None, f"User '{username}' not found", 404

    if r.status_code == 401:
        return None, None, "HTTP 401 - Unauthorized", 401

    return None, None, format_error_detail(r), r.status_code


def build_update_payload(
    existing_user: dict,
    new_password: str | None,
    force_change_password: bool,
    include_force_change_flag: bool = True,
) -> dict:

    internal_user = dict(existing_user)

    # Only update password if user requested password change.
    if new_password is not None:
        internal_user["password"] = new_password

    # Explicitly check or uncheck the force password change option.
    if include_force_change_flag:
        internal_user["changePassword"] = force_change_password

    return {"InternalUser": internal_user}


def is_invalid_property_error(resp: requests.Response) -> bool:
    if resp.status_code != 400:
        return False

    j = safe_json(resp)
    msg_list = j.get("ERSResponse", {}).get("messages", [])

    for m in msg_list:
        title = (m.get("title") or "").lower()

        if "json invalidity" in title or "properties names are correct" in title:
            return True

    return False


def update_user_on_base(
    session: requests.Session,
    base: str,
    username: str,
    new_password: str | None,
    force_change_password: bool,
) -> tuple[bool, str, int | None]:

    existing_user, user_id, get_msg, get_http_status = internal_user_get(
        session=session,
        base=base,
        username=username,
    )

    if not existing_user or not user_id:
        return False, f"Could not get user: {get_msg}", get_http_status

    update_url = f"{base}/ers/config/internaluser/{user_id}"

    payload1 = build_update_payload(
        existing_user=existing_user,
        new_password=new_password,
        force_change_password=force_change_password,
        include_force_change_flag=True,
    )

    r_put = session.put(update_url, json=payload1, timeout=TIMEOUT_SEC)

    if r_put.status_code in (200, 204):
        if new_password is not None:
            action_text = "Password changed"
        else:
            action_text = "Force password change option disabled"

        return True, (
            f"{action_text} for '{username}' "
            f"changePassword={force_change_password}"
        ), None

    # Retry without changePassword only if ISE rejects that property.
    if is_invalid_property_error(r_put):
        payload2 = build_update_payload(
            existing_user=existing_user,
            new_password=new_password,
            force_change_password=False,
            include_force_change_flag=False,
        )

        r_put2 = session.put(update_url, json=payload2, timeout=TIMEOUT_SEC)

        if r_put2.status_code in (200, 204):
            return True, (
                f"User '{username}' updated, but ISE rejected the "
                f"changePassword field. Update completed without that field."
            ), None

        return False, format_error_detail(r_put2), r_put2.status_code

    return False, format_error_detail(r_put), r_put.status_code


def should_try_dot9_fallback(http_status: int | None) -> bool:
    return http_status == 401


def ask_operation() -> tuple[str, str | None, bool]:
    """
    Returns:
        operation, new_password, force_change_password

    operation values:
        change_password
        disable_force_change_only
    """

    change_answer = input("Do you want to change the password? [Y/n]: ").strip().lower()

    if change_answer not in ("n", "no"):
        new_password = getpass.getpass("Enter the NEW temporary password: ")
        confirm_password = getpass.getpass("Confirm the NEW temporary password: ")

        if not new_password:
            print("ERROR: New password cannot be empty.")
            sys.exit(2)

        if new_password != confirm_password:
            print("ERROR: Passwords do not match.")
            sys.exit(2)

        force_answer = input(
            "Force user to change password after first login? [Y/n]: "
        ).strip().lower()

        force_change_password = force_answer not in ("n", "no")

        return "change_password", new_password, force_change_password

    disable_answer = input(
        "Do you want to DISABLE 'Force user to change password after first login'? [y/N]: "
    ).strip().lower()

    if disable_answer in ("y", "yes"):
        return "disable_force_change_only", None, False

    print("No operation selected. Exiting.")
    sys.exit(0)


def main() -> int:
    print("ISE internal user update script started...", flush=True)

    api_user = input("Enter ISE ERS API username: ").strip()
    api_pass = getpass.getpass("Enter ISE ERS API password: ")

    username = input("Enter the EXISTING ISE internal username: ").strip()

    if not api_user:
        print("ERROR: API username is required.")
        return 2

    if not api_pass:
        print("ERROR: API password is required.")
        return 2

    if not username:
        print("ERROR: Existing username is required.")
        return 2

    operation, new_password, force_change_password = ask_operation()

    try:
        ise_hosts = load_hosts(HOSTS_FILE)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    if not ise_hosts:
        print(f"ERROR: No hosts found in {HOSTS_FILE}")
        return 2

    log_event("------------------------------------------------------------")
    log_event(f"Starting update for internal user '{username}'")
    log_event(f"Operation: {operation}")
    log_event(f"changePassword value: {force_change_password}")
    log_event(f"Loaded {len(ise_hosts)} ISE host(s) from {HOSTS_FILE}")
    log_event("------------------------------------------------------------")

    successes: list[str] = []
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
            ok, msg, http_status = update_user_on_base(
                session=session,
                base=primary_base,
                username=username,
                new_password=new_password,
                force_change_password=force_change_password,
            )

            if ok:
                log_event(f"SUCCESS: {host} - {msg}")
                successes.append(host)
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
                ok2, msg2, _ = update_user_on_base(
                    session=session,
                    base=fb_base,
                    username=username,
                    new_password=new_password,
                    force_change_password=force_change_password,
                )

                if ok2:
                    log_event(f"SUCCESS: {host} - {msg2} via fallback {fb}")
                    successes.append(f"{host} fallback {fb}")
                else:
                    reason = f"Primary failed; fallback {fb} reached but operation failed: {msg2}"
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
        operation=operation,
        force_change_password=force_change_password,
        successes=successes,
        failures=failures,
    )

    log_event("------------------------------------------------------------")
    log_event(f"Finished. Success: {len(successes)} | Failed: {len(failures)}")
    log_event(f"Detailed log  : {LOG_FILE}")
    log_event(f"Summary report: {SUMMARY_FILE}")
    log_event("------------------------------------------------------------")

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())