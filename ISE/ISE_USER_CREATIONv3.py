#!/usr/bin/env python3
"""
Cisco ISE - Create Internal User via ERS API (multi-node)

Behavior:
- Reads ISE hosts from ise_hosts.txt
- Creates Cisco ISE Internal User through ERS API
- Prompts whether to force password change after first login
  - Y = sends "changePassword": true
  - n = sends "changePassword": false
- If ISE rejects the changePassword property, retries without it
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
LOG_FILE = "ise_user_creates.log"
SUMMARY_FILE = "ise_user_creates_summary.txt"

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
    new_username: str,
    group_name: str,
    successes: list[str],
    failures: list[tuple[str, str]],
) -> None:
    lines = []
    lines.append(f"ISE Internal User Create Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"New User     : {new_username}")
    lines.append(f"Group        : {group_name}")
    lines.append(f"Hosts File   : {HOSTS_FILE}")
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


def resolve_identity_group_id(
    session: requests.Session,
    base: str,
    group_name: str,
) -> tuple[str | None, str]:
    url = f"{base}/ers/config/identitygroup/name/{group_name}"
    r = session.get(url, timeout=TIMEOUT_SEC)

    if r.status_code == 200:
        body = safe_json(r)
        gid = body.get("IdentityGroup", {}).get("id")
        if gid:
            return gid, "OK"
        return None, "No IdentityGroup.id returned"

    if r.status_code == 401:
        return None, "HTTP 401 - Unauthorized"
    if r.status_code == 404:
        return None, f"HTTP 404 - Identity Group '{group_name}' not found"

    return None, format_error_detail(r)


def internal_user_exists(
    session: requests.Session,
    base: str,
    username: str,
) -> tuple[bool, str | None, str]:
    url = f"{base}/ers/config/internaluser/name/{username}"
    r = session.get(url, timeout=TIMEOUT_SEC)

    if r.status_code == 200:
        body = safe_json(r)
        uid = body.get("InternalUser", {}).get("id")
        return True, uid, "OK"

    if r.status_code == 404:
        return False, None, "Not found"

    if r.status_code == 401:
        return False, None, "HTTP 401 - Unauthorized"

    return False, None, format_error_detail(r)


def build_create_user_payload(
    username: str,
    temp_password: str,
    email: str,
    identity_group_id: str,
    force_change_password: bool,
    include_force_change_flag: bool = True,
) -> dict:
    internal_user = {
        "name": username,
        "password": temp_password,
        "enabled": True,
        "email": email,
        "identityGroups": identity_group_id,
    }

    # Important fix:
    # Y = changePassword true
    # n = changePassword false
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


def create_user_on_base(
    session: requests.Session,
    base: str,
    new_username: str,
    temp_password: str,
    email: str,
    group_name: str,
    force_change_password: bool,
) -> tuple[bool, str, int | None]:

    gid, gid_reason = resolve_identity_group_id(session, base, group_name)
    if not gid:
        http_code = 401 if gid_reason.startswith("HTTP 401") else None
        return False, f"Could not resolve Identity Group ID: {gid_reason}", http_code

    exists, existing_id, exists_reason = internal_user_exists(session, base, new_username)
    if exists:
        return False, f"User '{new_username}' already exists id={existing_id}", 409

    if exists_reason not in ("Not found", "OK"):
        http_code = 401 if "HTTP 401" in exists_reason else None
        return False, f"Error checking if user exists: {exists_reason}", http_code

    create_url = f"{base}/ers/config/internaluser"

    payload1 = build_create_user_payload(
        username=new_username,
        temp_password=temp_password,
        email=email,
        identity_group_id=gid,
        force_change_password=force_change_password,
        include_force_change_flag=True,
    )

    r_post = session.post(create_url, json=payload1, timeout=TIMEOUT_SEC)

    if r_post.status_code in (200, 201):
        return True, (
            f"Created '{new_username}' "
            f"changePassword={force_change_password} "
            f"group='{group_name}'"
        ), None

    # If ISE does not support/rejects the changePassword field, retry without it.
    if is_invalid_property_error(r_post):
        payload2 = build_create_user_payload(
            username=new_username,
            temp_password=temp_password,
            email=email,
            identity_group_id=gid,
            force_change_password=False,
            include_force_change_flag=False,
        )

        r_post2 = session.post(create_url, json=payload2, timeout=TIMEOUT_SEC)

        if r_post2.status_code in (200, 201):
            return True, (
                f"Created '{new_username}' group='{group_name}' "
                f"but ISE rejected changePassword field, so user was created without that field"
            ), None

        return False, format_error_detail(r_post2), r_post2.status_code

    return False, format_error_detail(r_post), r_post.status_code


def should_try_dot9_fallback(http_status: int | None) -> bool:
    return http_status == 401


def ask_force_change_password() -> bool:
    answer = input("Force user to change password after first login? [Y/n]: ").strip().lower()

    if answer in ("n", "no"):
        return False

    return True


def main() -> int:
    print("ISE user creation script started...", flush=True)

    api_user = input("Enter ISE ERS API username: ").strip()
    api_pass = getpass.getpass("Enter ISE ERS API password: ")

    new_username = input("Enter the NEW ISE internal username to create: ").strip()
    temp_password = getpass.getpass("Enter the TEMPORARY password for this user: ")
    confirm_password = getpass.getpass("Confirm the TEMPORARY password: ")

    email = input("Enter the user's email address: ").strip()
    group_name = input("Enter the Identity Group name for this user: ").strip()

    force_change_password = ask_force_change_password()

    if not api_user:
        print("ERROR: API username is required.")
        return 2

    if not api_pass:
        print("ERROR: API password is required.")
        return 2

    if not new_username:
        print("ERROR: New username is required.")
        return 2

    if not temp_password:
        print("ERROR: Temporary password cannot be empty.")
        return 2

    if temp_password != confirm_password:
        print("ERROR: Passwords do not match.")
        return 2

    if not email:
        print("ERROR: Email is required.")
        return 2

    if not group_name:
        print("ERROR: Identity Group name is required.")
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
    log_event(f"Starting internal user create for '{new_username}' group='{group_name}'")
    log_event(f"Force change password after first login: {force_change_password}")
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
            ok, msg, http_status = create_user_on_base(
                session=session,
                base=primary_base,
                new_username=new_username,
                temp_password=temp_password,
                email=email,
                group_name=group_name,
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
                ok2, msg2, _ = create_user_on_base(
                    session=session,
                    base=fb_base,
                    new_username=new_username,
                    temp_password=temp_password,
                    email=email,
                    group_name=group_name,
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

    write_summary(new_username, group_name, successes, failures)

    log_event("------------------------------------------------------------")
    log_event(f"Finished. Success: {len(successes)} | Failed: {len(failures)}")
    log_event(f"Detailed log  : {LOG_FILE}")
    log_event(f"Summary report: {SUMMARY_FILE}")
    log_event("------------------------------------------------------------")

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())