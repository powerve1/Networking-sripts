#!/usr/bin/env python3
"""
Cisco ISE - Create Internal Users via ERS API from CSV (multi-node)

Behavior:
- Reads ISE hosts from ise_hosts.txt
- Reads users from a CSV file
- Creates Cisco ISE Internal Users through ERS API
- Supports per-user Identity Group, description, email, password, and force password change flag
- If the CSV has blank identity_group values, the script can ask for one shared group
- If the CSV has blank force_change_password values, the script can ask for one shared setting
- If ISE rejects the changePassword property, retries without it
- Fallback to .9 node if primary fails due to connection/SSL/timeout or HTTP 401

Required CSV columns:
- username
- password
- email
- description
- identity_group

Optional CSV column:
- force_change_password    Accepted values: yes/no, y/n, true/false, 1/0

Example CSV:
username,password,email,description,identity_group,force_change_password
jdoe,TempPass123!,jdoe@example.com,Contractor account,Guest Users,yes
asmith,TempPass456!,asmith@example.com,Vendor account,Vendor Users,no
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
LOG_FILE = "ise_user_creates.log"
SUMMARY_FILE = "ise_user_creates_summary.txt"
DEFAULT_USERS_CSV = "ise_users.csv"
CSV_TEMPLATE_FILE = "ise_users_template.csv"

PORT = 9060
TIMEOUT_SEC = 20

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

REQUIRED_CSV_COLUMNS = [
    "username",
    "password",
    "email",
    "description",
    "identity_group",
]
OPTIONAL_CSV_COLUMNS = ["force_change_password"]


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
    created_users: list[dict],
    successes: list[tuple[str, str]],
    failures: list[tuple[str, str, str]],
) -> None:
    lines = []
    lines.append(f"ISE Internal User Create Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Hosts File   : {HOSTS_FILE}")
    lines.append(f"Users Tried  : {len(created_users)}")
    lines.append("")

    lines.append("USERS:")
    if created_users:
        for user in created_users:
            lines.append(
                f"  - {user['username']} | email={user['email']} | "
                f"group={user['group_name']} | description={user['description']} | "
                f"changePassword={user['force_change_password']}"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"SUCCESS ({len(successes)}):")
    if successes:
        for username, host in successes:
            lines.append(f"  - {username}: {host}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"FAILED ({len(failures)}):")
    if failures:
        for username, host, reason in failures:
            lines.append(f"  - {username}: {host}: {reason}")
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
    description: str,
    identity_group_id: str,
    force_change_password: bool,
    include_force_change_flag: bool = True,
) -> dict:
    internal_user = {
        "name": username,
        "password": temp_password,
        "enabled": True,
        "email": email,
        "description": description,
        "identityGroups": identity_group_id,
    }

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
    description: str,
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
        description=description,
        identity_group_id=gid,
        force_change_password=force_change_password,
        include_force_change_flag=True,
    )

    r_post = session.post(create_url, json=payload1, timeout=TIMEOUT_SEC)

    if r_post.status_code in (200, 201):
        return True, (
            f"Created '{new_username}' "
            f"changePassword={force_change_password} "
            f"group='{group_name}' "
            f"description='{description}'"
        ), None

    if is_invalid_property_error(r_post):
        payload2 = build_create_user_payload(
            username=new_username,
            temp_password=temp_password,
            email=email,
            description=description,
            identity_group_id=gid,
            force_change_password=False,
            include_force_change_flag=False,
        )

        r_post2 = session.post(create_url, json=payload2, timeout=TIMEOUT_SEC)

        if r_post2.status_code in (200, 201):
            return True, (
                f"Created '{new_username}' group='{group_name}' description='{description}' "
                f"but ISE rejected changePassword field, so user was created without that field"
            ), None

        return False, format_error_detail(r_post2), r_post2.status_code

    return False, format_error_detail(r_post), r_post.status_code


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


def parse_bool(value: str, field_name: str, row_num: int) -> bool:
    v = (value or "").strip().lower()
    if v in ("y", "yes", "true", "1"):
        return True
    if v in ("n", "no", "false", "0"):
        return False
    raise ValueError(
        f"Row {row_num}: invalid {field_name} value '{value}'. "
        "Use yes/no, y/n, true/false, or 1/0."
    )


def write_csv_template(path: str = CSV_TEMPLATE_FILE) -> None:
    rows = [
        {
            "username": "jdoe",
            "password": "TempPass123!",
            "email": "jdoe@example.com",
            "description": "Contractor account",
            "identity_group": "Guest Users",
            "force_change_password": "yes",
        },
        {
            "username": "asmith",
            "password": "TempPass456!",
            "email": "asmith@example.com",
            "description": "Vendor account",
            "identity_group": "Vendor Users",
            "force_change_password": "no",
        },
    ]

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REQUIRED_CSV_COLUMNS + OPTIONAL_CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def load_users_from_csv(csv_path: str) -> list[dict]:
    p = Path(csv_path)
    if not p.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    users: list[dict] = []

    with open(p, "r", newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            raise ValueError("CSV is empty or missing a header row.")

        fieldnames = [name.strip() for name in reader.fieldnames if name]
        missing = [col for col in REQUIRED_CSV_COLUMNS if col not in fieldnames]
        if missing:
            raise ValueError(
                "CSV is missing required column(s): " + ", ".join(missing) +
                f". Required columns are: {', '.join(REQUIRED_CSV_COLUMNS)}"
            )

        seen_usernames: set[str] = set()

        for row_num, row in enumerate(reader, start=2):
            cleaned = {str(k).strip(): (v or "").strip() for k, v in row.items() if k is not None}

            # Ignore completely blank rows.
            if not any(cleaned.values()):
                continue

            username = cleaned.get("username", "")
            password = cleaned.get("password", "")
            email = cleaned.get("email", "")
            description = cleaned.get("description", "")
            group_name = cleaned.get("identity_group", "")
            force_change_raw = cleaned.get("force_change_password", "")

            row_errors = []
            if not username:
                row_errors.append("username is required")
            if not password:
                row_errors.append("password is required")
            if not email:
                row_errors.append("email is required")
            if username and username.lower() in seen_usernames:
                row_errors.append(f"duplicate username '{username}' in CSV")

            if row_errors:
                raise ValueError(f"Row {row_num}: " + "; ".join(row_errors))

            seen_usernames.add(username.lower())

            users.append(
                {
                    "username": username,
                    "temp_password": password,
                    "email": email,
                    "description": description,
                    "group_name": group_name,
                    "force_change_password": None if not force_change_raw else parse_bool(
                        force_change_raw,
                        "force_change_password",
                        row_num,
                    ),
                    "row_num": row_num,
                }
            )

    if not users:
        raise ValueError("No users found in CSV.")

    return users


def finalize_csv_users(users: list[dict]) -> list[dict]:
    users_missing_group = [u for u in users if not u["group_name"]]
    if users_missing_group:
        use_shared_group = ask_yes_no(
            f"{len(users_missing_group)} CSV user(s) are missing identity_group. Use one shared group for them?",
            default_yes=True,
        )
        if not use_shared_group:
            missing_rows = ", ".join(str(u["row_num"]) for u in users_missing_group)
            raise ValueError(
                f"CSV row(s) missing identity_group: {missing_rows}. "
                "Add identity_group to the CSV or choose the shared-group option."
            )

        while True:
            shared_group = input("Enter the shared Identity Group name: ").strip()
            if shared_group:
                break
            print("ERROR: Identity Group name is required.")

        for user in users_missing_group:
            user["group_name"] = shared_group

    users_missing_force = [u for u in users if u["force_change_password"] is None]
    if users_missing_force:
        shared_force = ask_yes_no(
            f"{len(users_missing_force)} CSV user(s) are missing force_change_password. Force password change for those users?",
            default_yes=True,
        )
        for user in users_missing_force:
            user["force_change_password"] = shared_force

    return users


def create_user_across_hosts(
    session: requests.Session,
    ise_hosts: list[str],
    user: dict,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]]]:
    successes: list[tuple[str, str]] = []
    failures: list[tuple[str, str, str]] = []

    new_username = user["username"]
    temp_password = user["temp_password"]
    email = user["email"]
    description = user["description"]
    group_name = user["group_name"]
    force_change_password = user["force_change_password"]

    log_event("------------------------------------------------------------")
    log_event(
        f"Starting internal user create for '{new_username}' "
        f"group='{group_name}' description='{description}'"
    )
    log_event(f"Force change password after first login: {force_change_password}")
    log_event(f"Loaded {len(ise_hosts)} ISE host(s) from {HOSTS_FILE}")
    log_event("------------------------------------------------------------")

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
                description=description,
                group_name=group_name,
                force_change_password=force_change_password,
            )

            if ok:
                log_event(f"SUCCESS: {host} - {msg}")
                successes.append((new_username, host))
                continue

            if fb and should_try_dot9_fallback(http_status):
                log_event(f"INFO: {host} - HTTP {http_status}; retrying fallback {fb}")
                tried_fallback = True
            else:
                log_event(f"FAILED: {host} - {msg}")
                failures.append((new_username, host, msg))
                continue

        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.SSLError,
        ):
            if not fb:
                reason = f"Connection failed on port {PORT}; no .9 fallback available"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((new_username, host, reason))
                continue

            log_event(f"INFO: {host} - Connection/SSL failed; retrying fallback {fb}")
            tried_fallback = True

        except Exception as e:
            reason = f"Unexpected error: {str(e)}"
            log_event(f"FAILED: {host} - {reason}")
            failures.append((new_username, host, reason))
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
                    description=description,
                    group_name=group_name,
                    force_change_password=force_change_password,
                )

                if ok2:
                    log_event(f"SUCCESS: {host} - {msg2} via fallback {fb}")
                    successes.append((new_username, f"{host} fallback {fb}"))
                else:
                    reason = f"Primary failed; fallback {fb} reached but operation failed: {msg2}"
                    log_event(f"FAILED: {host} - {reason}")
                    failures.append((new_username, host, reason))

            except (
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ConnectionError,
                requests.exceptions.SSLError,
            ):
                reason = f"Connection failed to both {host} and fallback {fb} on port {PORT}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((new_username, host, reason))

            except Exception as e:
                reason = f"Fallback {fb} unexpected error: {str(e)}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((new_username, host, reason))

    return successes, failures


def main() -> int:
    print("ISE CSV user creation script started...", flush=True)
    print(f"Expected CSV columns: {', '.join(REQUIRED_CSV_COLUMNS + OPTIONAL_CSV_COLUMNS)}")

    create_template = ask_yes_no(
        f"Create/update a CSV template file named '{CSV_TEMPLATE_FILE}'?",
        default_yes=False,
    )
    if create_template:
        write_csv_template(CSV_TEMPLATE_FILE)
        print(f"Template written: {CSV_TEMPLATE_FILE}")

    api_user = input("Enter ISE ERS API username: ").strip()
    api_pass = getpass.getpass("Enter ISE ERS API password: ")

    if not api_user:
        print("ERROR: API username is required.")
        return 2

    if not api_pass:
        print("ERROR: API password is required.")
        return 2

    csv_path = input(f"Enter users CSV file path [{DEFAULT_USERS_CSV}]: ").strip() or DEFAULT_USERS_CSV

    try:
        users = finalize_csv_users(load_users_from_csv(csv_path))
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    try:
        ise_hosts = load_hosts(HOSTS_FILE)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    if not ise_hosts:
        print(f"ERROR: No hosts found in {HOSTS_FILE}")
        return 2

    print("")
    print(f"CSV loaded: {csv_path}")
    print(f"Users loaded: {len(users)}")
    print(f"ISE hosts loaded: {len(ise_hosts)}")
    print("")

    proceed = ask_yes_no("Proceed with user creation now?", default_yes=False)
    if not proceed:
        print("Cancelled. No users were created.")
        return 0

    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False

    all_successes: list[tuple[str, str]] = []
    all_failures: list[tuple[str, str, str]] = []

    log_event("============================================================")
    log_event(f"Starting CSV batch creation from '{csv_path}' for {len(users)} user(s)")
    log_event("============================================================")

    for user in users:
        successes, failures = create_user_across_hosts(session, ise_hosts, user)
        all_successes.extend(successes)
        all_failures.extend(failures)

    write_summary(users, all_successes, all_failures)

    log_event("------------------------------------------------------------")
    log_event(f"Finished. Success: {len(all_successes)} | Failed: {len(all_failures)}")
    log_event(f"Detailed log  : {LOG_FILE}")
    log_event(f"Summary report: {SUMMARY_FILE}")
    log_event("------------------------------------------------------------")

    return 0 if not all_failures else 1


if __name__ == "__main__":
    sys.exit(main())
