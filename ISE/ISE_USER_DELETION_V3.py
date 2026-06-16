#!/usr/bin/env python3
"""
Cisco ISE - Delete Internal User(s) via ERS API (multi-node)

Features:
- Reads ISE hosts from ise_hosts.txt (supports # comments / blank lines)
- Prompts for API creds
- Prompts for username(s) to delete:
  - Asks if you want to delete more than 1 user
  - If yes, enter comma-separated usernames (e.g., user1,user2,user3)

Fallback logic (same style as your create script):
- If the primary host attempt fails due to:
  - ConnectTimeout / ConnectionError / SSLError
  - OR HTTP 401 Unauthorized
  then retry once using the same IP but forcing last octet to .9
  Example: 10.74.0.10 -> retry 10.74.0.9

Host skip logic (requested):
- If a host hits CONNECTIVITY failures >= 3 times (across users), skip that host
  for the remainder of the run.

What counts as CONNECTIVITY failure:
- requests.exceptions.ConnectTimeout / ConnectionError / SSLError on primary
- requests.exceptions.ConnectTimeout / ConnectionError / SSLError on fallback
- (We do NOT count HTTP errors like 403/404/500 as connectivity failures.)

CSRF/HTML handling (requested):
- If an HTTP 403 returns an HTML page containing "CSRF" + "nonce", we log a clean
  actionable error indicating you're likely hitting the ISE GUI/portal (not ERS)
  or the node is not PAN / ERS not enabled.

Deletion flow:
- For each host, for each user:
  1) GET /ers/config/internaluser/name/{username} to resolve InternalUser.id
     - 404 => already not present (treated as SUCCESS: nothing to delete)
  2) DELETE /ers/config/internaluser/{id}
     - 200/202/204 => deleted (SUCCESS)
     - 404 => not present (SUCCESS)
     - other => FAILED (captures response body)

Logs:
- ise_user_deletes.log
- ise_user_deletes_summary.txt
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
LOG_FILE = "ise_user_deletes.log"
SUMMARY_FILE = "ise_user_deletes_summary.txt"

PORT = 9060
TIMEOUT_SEC = 20

MAX_CONNECT_FAILURES_PER_HOST = 3

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

    # de-dupe preserving order
    return list(dict.fromkeys(hosts))


def safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


def looks_like_csrf_html(resp: requests.Response) -> bool:
    ct = (resp.headers.get("Content-Type") or "").lower()
    if "text/html" in ct or "text/html" in (resp.text or "").lower():
        body = (resp.text or "").lower()
        if "csrf" in body and "nonce" in body:
            return True
    return False


def format_error_detail(resp: requests.Response) -> str:
    # Special-case noisy HTML CSRF pages (common when hitting GUI/portal instead of ERS)
    if resp.status_code == 403 and looks_like_csrf_html(resp):
        return (
            "HTTP 403 - CSRF nonce validation failed (HTML). "
            "This typically means you're hitting the ISE web UI/portal (not ERS), "
            "or the node is not a PAN, or ERS is not enabled. "
            "Verify node persona and ERS Settings; ensure you're calling the PAN ERS endpoint."
        )

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
    """
    If host is IPv4 and last octet is not 9, return same /24 with last octet forced to 9.
    Example: 10.74.0.10 -> 10.74.0.9
    If host is already *.9 or not IPv4, return None.
    """
    if not is_ipv4(host):
        return None
    parts = host.split(".")
    if parts[3] == "9":
        return None
    return ".".join(parts[:3] + ["9"])


def should_try_dot9_fallback(http_status: int | None) -> bool:
    """
    Try fallback on 401 (as requested). Connectivity exceptions always try fallback if applicable.
    """
    return http_status == 401


def internal_user_lookup_by_name(
    session: requests.Session,
    base: str,
    username: str,
) -> tuple[bool, str | None, str, int | None]:
    """
    Lookup InternalUser by name.
    Returns:
      (exists, user_id_if_exists, message, http_status_if_http_else_None)

    Raises:
      requests.exceptions.ConnectTimeout / ConnectionError / SSLError for connectivity issues
    """
    url = f"{base}/ers/config/internaluser/name/{username}"
    r = session.get(url, timeout=TIMEOUT_SEC)

    if r.status_code == 200:
        body = safe_json(r)
        uid = body.get("InternalUser", {}).get("id")
        if uid:
            return True, uid, "OK", None
        return True, None, "Found user but InternalUser.id missing (unexpected payload)", r.status_code

    if r.status_code == 404:
        return False, None, "Not found", None

    if r.status_code == 401:
        return False, None, "HTTP 401 - Unauthorized (check API credentials / ERS privileges)", 401

    return False, None, format_error_detail(r), r.status_code


def delete_internal_user_by_id(
    session: requests.Session,
    base: str,
    user_id: str,
) -> tuple[bool, str, int | None]:
    """
    Delete InternalUser by id.
    Returns:
      (success, message, http_status_if_http_error_else_None)

    Raises:
      requests.exceptions.ConnectTimeout / ConnectionError / SSLError for connectivity issues
    """
    url = f"{base}/ers/config/internaluser/{user_id}"
    r = session.delete(url, timeout=TIMEOUT_SEC)

    if r.status_code in (200, 202, 204):
        return True, "Deleted", None

    if r.status_code == 404:
        return True, "Not found during delete (already removed)", None

    if r.status_code == 401:
        return False, "HTTP 401 - Unauthorized (check API credentials / ERS privileges)", 401

    return False, format_error_detail(r), r.status_code


def delete_user_on_base(
    session: requests.Session,
    base: str,
    username: str,
) -> tuple[bool, str, int | None]:
    """
    Attempt to delete the user against a specific base URL.

    Returns:
      (success, message, http_status_if_http_error_else_None)

    Raises:
      requests.exceptions.ConnectTimeout / ConnectionError / SSLError for connectivity issues
    """
    exists, uid, msg, http_status = internal_user_lookup_by_name(session, base, username)

    if not exists:
        if msg == "Not found":
            return True, f"User '{username}' not found (nothing to delete)", None
        return False, f"Error looking up user '{username}': {msg}", http_status

    if not uid:
        return False, f"User '{username}' lookup returned no id: {msg}", http_status

    ok, del_msg, del_http = delete_internal_user_by_id(session, base, uid)
    if ok:
        return True, f"Deleted user '{username}' (id={uid})", None

    return False, f"Failed to delete user '{username}' (id={uid}): {del_msg}", del_http


def parse_user_list(raw: str) -> list[str]:
    items: list[str] = []
    for part in raw.split(","):
        u = part.strip()
        if u:
            items.append(u)
    return list(dict.fromkeys(items))


def write_summary(
    usernames: list[str],
    successes: list[tuple[str, str]],
    failures: list[tuple[str, str, str]],
    skipped_hosts: list[tuple[str, int]],
) -> None:
    """
    successes: list of (host, username)
    failures : list of (host, username, reason)
    skipped_hosts: list of (host, connect_fail_count)
    """
    lines: list[str] = []
    lines.append(f"ISE Internal User Delete Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Users        : {', '.join(usernames)}")
    lines.append(f"Hosts File   : {HOSTS_FILE}")
    lines.append(f"ConnFailSkip : >= {MAX_CONNECT_FAILURES_PER_HOST} connectivity failures per host")
    lines.append("")

    lines.append(f"SKIPPED HOSTS ({len(skipped_hosts)}):")
    if skipped_hosts:
        for h, c in skipped_hosts:
            lines.append(f"  - {h}: connectivity failures={c}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"SUCCESS ({len(successes)}):")
    if successes:
        for h, u in successes:
            lines.append(f"  - {h}: {u}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"FAILED ({len(failures)}):")
    if failures:
        for h, u, reason in failures:
            lines.append(f"  - {h}: {u} - {reason}")
    else:
        lines.append("  (none)")
    lines.append("")

    Path(SUMMARY_FILE).write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    print("ISE user deletion script started...", flush=True)

    api_user = input("Enter ISE ERS API username: ").strip()
    api_pass = getpass.getpass("Enter ISE ERS API password: ")

    multi = input("Do you want to delete more than 1 user? [y/N]: ").strip().lower()
    if multi == "y":
        raw_users = input("Enter ISE internal usernames to delete (comma-separated): ").strip()
    else:
        raw_users = input("Enter the ISE internal username to delete: ").strip()

    usernames = parse_user_list(raw_users)

    if not api_user:
        print("ERROR: API username is required.")
        return 2
    if not api_pass:
        print("ERROR: API password is required.")
        return 2
    if not usernames:
        print("ERROR: At least one username is required.")
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
    log_event(f"Starting internal user delete for: {', '.join(usernames)}")
    log_event(f"Loaded {len(ise_hosts)} ISE host(s) from {HOSTS_FILE}")
    log_event("------------------------------------------------------------")

    successes: list[tuple[str, str]] = []
    failures: list[tuple[str, str, str]] = []

    # host -> connectivity failure count
    connect_fail_count: dict[str, int] = {h: 0 for h in ise_hosts}
    skipped_hosts_set: set[str] = set()

    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False

    for host in ise_hosts:
        # Host-level skip at the start
        if connect_fail_count.get(host, 0) >= MAX_CONNECT_FAILURES_PER_HOST:
            skipped_hosts_set.add(host)
            log_event(
                f"INFO: {host} - Skipping host for all remaining users (connectivity failures="
                f"{connect_fail_count.get(host, 0)} >= {MAX_CONNECT_FAILURES_PER_HOST})"
            )
            continue

        primary_base = f"https://{host}:{PORT}"
        fb = fallback_to_dot9(host)

        for username in usernames:
            # Skip check before each user
            if connect_fail_count.get(host, 0) >= MAX_CONNECT_FAILURES_PER_HOST:
                skipped_hosts_set.add(host)
                log_event(
                    f"INFO: {host} - Skipping host for remaining users (connectivity failures="
                    f"{connect_fail_count.get(host, 0)} >= {MAX_CONNECT_FAILURES_PER_HOST})"
                )
                break

            tried_fallback = False

            # ---- Attempt primary ----
            try:
                ok, msg, http_status = delete_user_on_base(
                    session=session,
                    base=primary_base,
                    username=username,
                )
                if ok:
                    log_event(f"SUCCESS: {host} - {msg}")
                    successes.append((host, username))
                    continue

                # Primary failed with an HTTP response
                if fb and should_try_dot9_fallback(http_status):
                    log_event(
                        f"INFO: {host} - Received HTTP {http_status}; retrying against fallback {fb} for user '{username}'..."
                    )
                    tried_fallback = True
                else:
                    log_event(f"FAILED: {host} - {msg}")
                    failures.append((host, username, msg))
                    continue

            except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.SSLError):
                # Connectivity fail on primary -> increment count and try fallback if possible
                connect_fail_count[host] = connect_fail_count.get(host, 0) + 1

                # If threshold reached, skip immediately
                if connect_fail_count[host] >= MAX_CONNECT_FAILURES_PER_HOST:
                    skipped_hosts_set.add(host)
                    reason = (
                        f"Connectivity failures reached threshold ({connect_fail_count[host]} >= "
                        f"{MAX_CONNECT_FAILURES_PER_HOST}); skipping host"
                    )
                    log_event(f"FAILED: {host} - {username} - {reason}")
                    failures.append((host, username, reason))
                    break

                if not fb:
                    reason = f"Connection failed (port {PORT}) and no .9 fallback applicable for host '{host}'"
                    log_event(f"FAILED: {host} - {username} - {reason}")
                    failures.append((host, username, reason))
                    continue

                log_event(
                    f"INFO: {host} - Connection/SSL failed; retrying against fallback {fb} for user '{username}'..."
                )
                tried_fallback = True

            except Exception as e:
                reason = f"Unexpected error: {str(e)}"
                log_event(f"FAILED: {host} - {username} - {reason}")
                failures.append((host, username, reason))
                continue

            # ---- Attempt fallback (.9) if needed ----
            if tried_fallback:
                fb_base = f"https://{fb}:{PORT}"
                try:
                    ok2, msg2, _ = delete_user_on_base(
                        session=session,
                        base=fb_base,
                        username=username,
                    )
                    if ok2:
                        log_event(f"SUCCESS: {host} - {msg2} (via fallback {fb})")
                        successes.append((f"{host} (fallback {fb})", username))
                    else:
                        reason = f"Primary failed; fallback {fb} reached but operation failed: {msg2}"
                        log_event(f"FAILED: {host} - {username} - {reason}")
                        failures.append((host, username, reason))

                except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, requests.exceptions.SSLError):
                    # Connectivity fail on fallback too -> increment count
                    connect_fail_count[host] = connect_fail_count.get(host, 0) + 1

                    reason = f"Connection failed to both {host} and fallback {fb} (port {PORT})"
                    log_event(f"FAILED: {host} - {username} - {reason}")
                    failures.append((host, username, reason))

                    # If threshold reached after fallback failure, skip remaining users
                    if connect_fail_count[host] >= MAX_CONNECT_FAILURES_PER_HOST:
                        skipped_hosts_set.add(host)
                        log_event(
                            f"INFO: {host} - Skipping host for remaining users (connectivity failures="
                            f"{connect_fail_count[host]} >= {MAX_CONNECT_FAILURES_PER_HOST})"
                        )
                        break

                except Exception as e:
                    reason = f"Fallback {fb} unexpected error: {str(e)}"
                    log_event(f"FAILED: {host} - {username} - {reason}")
                    failures.append((host, username, reason))

    skipped_hosts = sorted([(h, connect_fail_count.get(h, 0)) for h in skipped_hosts_set], key=lambda x: x[0])
    write_summary(usernames, successes, failures, skipped_hosts)

    log_event("------------------------------------------------------------")
    log_event(f"Finished. Success: {len(successes)} | Failed: {len(failures)}")
    log_event(f"Detailed log  : {LOG_FILE}")
    log_event(f"Summary report: {SUMMARY_FILE}")
    log_event("------------------------------------------------------------")

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
