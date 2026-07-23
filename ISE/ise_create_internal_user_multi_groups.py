#!/usr/bin/env python3
"""
Cisco ISE - Create Internal Users via ERS API from CSV (multi-node, multi-group, threaded)

Behavior:
- Reads ISE hosts from ise_hosts.txt
- Reads users from a CSV file
- Creates Cisco ISE Internal Users through ERS API
- Supports per-user Identity Groups, description, email, password, and force password change flag
- Supports multiple candidate Identity Groups separated by semicolon (;)
- If some listed groups do not exist in ISE, those groups are skipped and the valid existing groups are used
- If the user already exists, the script skips that user on that ISE host instead of failing
- Processes multiple ISE hosts at the same time using ThreadPoolExecutor
- Uses a longer timeout by default to avoid false failures on slow ISE nodes
- If ISE rejects the changePassword property, retries without it
- Fallback to .9 node if primary fails due to connection/SSL/timeout or HTTP 401
- Generates summary and failed-results CSV files

Required CSV columns:
- username
- password
- email
- description
- identity_groups

Optional CSV column:
- force_change_password    Accepted values: yes/no, y/n, true/false, 1/0

Example CSV:
username,password,email,description,identity_groups,force_change_password
jdoe,TempPass123!,jdoe@example.com,Contractor account,Guest Users;VPN Users;Contractors,yes
asmith,TempPass456!,asmith@example.com,Vendor account,Vendor Users;Guest Users,no
"""

import csv
import datetime
import getpass
import json
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HOSTS_FILE = "ise_hosts.txt"
LOG_FILE = "ise_user_creates.log"
SUMMARY_FILE = "ise_user_creates_summary.txt"
FAILED_RESULTS_CSV = "ise_user_creates_failed_results.csv"
DEFAULT_USERS_CSV = "ise_users.csv"
CSV_TEMPLATE_FILE = "ise_users_multigroups_template.csv"

PORT = 9060
DEFAULT_TIMEOUT_SEC = 60
DEFAULT_MAX_WORKERS = 5

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

REQUIRED_CSV_COLUMNS = [
    "username",
    "password",
    "email",
    "description",
    "identity_groups",
]
OPTIONAL_CSV_COLUMNS = ["force_change_password"]

LOG_LOCK = threading.Lock()


def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(message: str) -> None:
    """Thread-safe logger that writes to console and the log file."""
    entry = f"[{now_ts()}] {message}"
    with LOG_LOCK:
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
    users: list[dict],
    created: list[tuple[str, str]],
    skipped: list[tuple[str, str, str]],
    failures: list[tuple[str, str, str]],
    timeout_sec: int,
    max_workers: int,
) -> None:
    lines = []
    lines.append(f"ISE Internal User Create Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Hosts File   : {HOSTS_FILE}")
    lines.append(f"Users Tried  : {len(users)}")
    lines.append(f"Timeout      : {timeout_sec} seconds")
    lines.append(f"Max Workers  : {max_workers}")
    lines.append("")

    lines.append("USERS:")
    if users:
        for user in users:
            lines.append(
                f"  - {user['username']} | email={user['email']} | "
                f"groups={';'.join(user['group_names'])} | description={user['description']} | "
                f"changePassword={user['force_change_password']}"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"CREATED ({len(created)}):")
    if created:
        for username, host in created:
            lines.append(f"  - {username}: {host}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"SKIPPED / ALREADY EXISTS ({len(skipped)}):")
    if skipped:
        for username, host, reason in skipped:
            lines.append(f"  - {username}: {host}: {reason}")
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


def write_failed_results_csv(failures: list[tuple[str, str, str]]) -> None:
    with open(FAILED_RESULTS_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["username", "host", "reason"])
        writer.writeheader()
        for username, host, reason in failures:
            writer.writerow({"username": username, "host": host, "reason": reason})


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


def make_session(api_user: str, api_pass: str) -> requests.Session:
    """Create one Session per worker/thread. requests.Session should not be shared across threads."""
    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False
    return session


def resolve_identity_group_id(
    session: requests.Session,
    base: str,
    group_name: str,
    timeout_sec: int,
) -> tuple[str | None, str]:
    url = f"{base}/ers/config/identitygroup/name/{group_name}"
    r = session.get(url, timeout=timeout_sec)

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
    timeout_sec: int,
) -> tuple[bool, str | None, str]:
    url = f"{base}/ers/config/internaluser/name/{username}"
    r = session.get(url, timeout=timeout_sec)

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


def resolve_existing_identity_group_ids(
    session: requests.Session,
    base: str,
    group_names: list[str],
    timeout_sec: int,
) -> tuple[list[str], list[str], str | None, int | None]:
    valid_group_ids: list[str] = []
    missing_group_names: list[str] = []

    for group_name in group_names:
        gid, gid_reason = resolve_identity_group_id(session, base, group_name, timeout_sec)
        if gid:
            valid_group_ids.append(gid)
            continue

        if "HTTP 404" in gid_reason:
            missing_group_names.append(group_name)
            continue

        http_code = 401 if gid_reason.startswith("HTTP 401") else None
        return [], missing_group_names, (
            f"Could not resolve Identity Group '{group_name}': {gid_reason}"
        ), http_code

    if not valid_group_ids:
        return [], missing_group_names, (
            "None of the requested Identity Groups exist: " + ", ".join(group_names)
        ), 404

    return valid_group_ids, missing_group_names, None, None


def create_user_on_base(
    session: requests.Session,
    base: str,
    new_username: str,
    temp_password: str,
    email: str,
    description: str,
    group_names: list[str],
    force_change_password: bool,
    timeout_sec: int,
) -> tuple[str, str, int | None]:
    """
    Returns: (status, message, http_code)
    status values: created, skipped, failed
    """

    exists, existing_id, exists_reason = internal_user_exists(session, base, new_username, timeout_sec)
    if exists:
        return "skipped", f"User '{new_username}' already exists id={existing_id}", 200

    if exists_reason not in ("Not found", "OK"):
        http_code = 401 if "HTTP 401" in exists_reason else None
        return "failed", f"Error checking if user exists: {exists_reason}", http_code

    valid_group_ids, missing_group_names, group_error, group_http_code = (
        resolve_existing_identity_group_ids(session, base, group_names, timeout_sec)
    )
    if group_error:
        return "failed", group_error, group_http_code

    missing_lookup = {g.lower() for g in missing_group_names}
    valid_group_names = [g for g in group_names if g.lower() not in missing_lookup]
    identity_groups_value = ",".join(valid_group_ids)
    valid_group_names_text = ";".join(valid_group_names)

    if missing_group_names:
        log_event(
            f"WARNING: {base} user='{new_username}' skipping non-existing Identity Group(s): "
            + ", ".join(missing_group_names)
        )

    create_url = f"{base}/ers/config/internaluser"

    payload1 = build_create_user_payload(
        username=new_username,
        temp_password=temp_password,
        email=email,
        description=description,
        identity_group_id=identity_groups_value,
        force_change_password=force_change_password,
        include_force_change_flag=True,
    )

    r_post = session.post(create_url, json=payload1, timeout=timeout_sec)

    if r_post.status_code in (200, 201):
        return "created", (
            f"Created '{new_username}' changePassword={force_change_password} "
            f"groups='{valid_group_names_text}' description='{description}'"
        ), None

    # Race condition protection: if another worker/process created it between GET and POST.
    if r_post.status_code == 409:
        return "skipped", f"User '{new_username}' already exists; skipping", 409

    if is_invalid_property_error(r_post):
        payload2 = build_create_user_payload(
            username=new_username,
            temp_password=temp_password,
            email=email,
            description=description,
            identity_group_id=identity_groups_value,
            force_change_password=False,
            include_force_change_flag=False,
        )

        r_post2 = session.post(create_url, json=payload2, timeout=timeout_sec)

        if r_post2.status_code in (200, 201):
            return "created", (
                f"Created '{new_username}' groups='{valid_group_names_text}' "
                f"description='{description}' but ISE rejected changePassword field, "
                "so user was created without that field"
            ), None

        if r_post2.status_code == 409:
            return "skipped", f"User '{new_username}' already exists; skipping", 409

        return "failed", format_error_detail(r_post2), r_post2.status_code

    return "failed", format_error_detail(r_post), r_post.status_code


def should_try_dot9_fallback(http_status: int | None) -> bool:
    return http_status == 401


def process_one_host_for_user(
    host: str,
    user: dict,
    api_user: str,
    api_pass: str,
    timeout_sec: int,
) -> tuple[str, str, str, str]:
    """
    Process one user against one ISE host.
    Returns: (status, username, host_display, message)
    status values: created, skipped, failed
    """
    session = make_session(api_user, api_pass)

    new_username = user["username"]
    temp_password = user["temp_password"]
    email = user["email"]
    description = user["description"]
    group_names = user["group_names"]
    force_change_password = user["force_change_password"]

    primary_base = f"https://{host}:{PORT}"
    fb = fallback_to_dot9(host)
    tried_fallback = False

    try:
        status, msg, http_status = create_user_on_base(
            session=session,
            base=primary_base,
            new_username=new_username,
            temp_password=temp_password,
            email=email,
            description=description,
            group_names=group_names,
            force_change_password=force_change_password,
            timeout_sec=timeout_sec,
        )

        if status in ("created", "skipped"):
            return status, new_username, host, msg

        if fb and should_try_dot9_fallback(http_status):
            log_event(f"INFO: {host} user='{new_username}' HTTP {http_status}; retrying fallback {fb}")
            tried_fallback = True
        else:
            return "failed", new_username, host, msg

    except (
        requests.exceptions.ConnectTimeout,
        requests.exceptions.ReadTimeout,
        requests.exceptions.ConnectionError,
        requests.exceptions.SSLError,
    ) as e:
        if not fb:
            return "failed", new_username, host, f"Connection/timeout/SSL failed on port {PORT}; no .9 fallback available: {e}"
        log_event(f"INFO: {host} user='{new_username}' connection/timeout/SSL failed; retrying fallback {fb}")
        tried_fallback = True

    except Exception as e:
        return "failed", new_username, host, f"Unexpected error: {str(e)}"

    if tried_fallback:
        fb_base = f"https://{fb}:{PORT}"
        try:
            status2, msg2, _ = create_user_on_base(
                session=session,
                base=fb_base,
                new_username=new_username,
                temp_password=temp_password,
                email=email,
                description=description,
                group_names=group_names,
                force_change_password=force_change_password,
                timeout_sec=timeout_sec,
            )

            if status2 in ("created", "skipped"):
                return status2, new_username, f"{host} fallback {fb}", msg2

            return "failed", new_username, host, f"Primary failed; fallback {fb} reached but operation failed: {msg2}"

        except (
            requests.exceptions.ConnectTimeout,
            requests.exceptions.ReadTimeout,
            requests.exceptions.ConnectionError,
            requests.exceptions.SSLError,
        ) as e:
            return "failed", new_username, host, f"Connection failed to both {host} and fallback {fb} on port {PORT}: {e}"

        except Exception as e:
            return "failed", new_username, host, f"Fallback {fb} unexpected error: {str(e)}"

    return "failed", new_username, host, "Unknown processing state"


def create_user_across_hosts_threaded(
    api_user: str,
    api_pass: str,
    ise_hosts: list[str],
    user: dict,
    timeout_sec: int,
    max_workers: int,
) -> tuple[list[tuple[str, str]], list[tuple[str, str, str]], list[tuple[str, str, str]]]:
    created: list[tuple[str, str]] = []
    skipped: list[tuple[str, str, str]] = []
    failures: list[tuple[str, str, str]] = []

    username = user["username"]
    log_event("------------------------------------------------------------")
    log_event(
        f"Starting user '{username}' across {len(ise_hosts)} ISE host(s) "
        f"with max_workers={max_workers}, timeout={timeout_sec}s"
    )
    log_event("------------------------------------------------------------")

    workers = min(max_workers, len(ise_hosts))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(
                process_one_host_for_user,
                host,
                user,
                api_user,
                api_pass,
                timeout_sec,
            ): host
            for host in ise_hosts
        }

        for future in as_completed(future_map):
            host = future_map[future]
            try:
                status, result_username, result_host, msg = future.result()
            except Exception as e:
                status, result_username, result_host, msg = (
                    "failed",
                    username,
                    host,
                    f"Unhandled thread error: {str(e)}",
                )

            if status == "created":
                log_event(f"SUCCESS: {result_host} - {msg}")
                created.append((result_username, result_host))
            elif status == "skipped":
                log_event(f"SKIPPED: {result_host} - {msg}")
                skipped.append((result_username, result_host, msg))
            else:
                log_event(f"FAILED: {result_host} - {msg}")
                failures.append((result_username, result_host, msg))

    return created, skipped, failures


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


def ask_int(prompt: str, default_value: int, minimum: int = 1, maximum: int | None = None) -> int:
    while True:
        answer = input(f"{prompt} [{default_value}]: ").strip()
        if not answer:
            return default_value
        try:
            value = int(answer)
        except ValueError:
            print("Please enter a valid integer.")
            continue
        if value < minimum:
            print(f"Please enter a value >= {minimum}.")
            continue
        if maximum is not None and value > maximum:
            print(f"Please enter a value <= {maximum}.")
            continue
        return value


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


def parse_group_names(value: str) -> list[str]:
    groups: list[str] = []
    seen: set[str] = set()

    for raw_group in (value or "").split(";"):
        group = raw_group.strip()
        if not group:
            continue
        key = group.lower()
        if key in seen:
            continue
        groups.append(group)
        seen.add(key)

    return groups


def write_csv_template(path: str = CSV_TEMPLATE_FILE) -> None:
    rows = [
        {
            "username": "jdoe",
            "password": "TempPass123!",
            "email": "jdoe@example.com",
            "description": "Contractor account",
            "identity_groups": "Guest Users;VPN Users;Contractors",
            "force_change_password": "yes",
        },
        {
            "username": "asmith",
            "password": "TempPass456!",
            "email": "asmith@example.com",
            "description": "Vendor account",
            "identity_groups": "Vendor Users;Guest Users",
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

            if not any(cleaned.values()):
                continue

            username = cleaned.get("username", "")
            password = cleaned.get("password", "")
            email = cleaned.get("email", "")
            description = cleaned.get("description", "")
            group_names_raw = cleaned.get("identity_groups", "")
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
                    "group_names": parse_group_names(group_names_raw),
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
    users_missing_groups = [u for u in users if not u["group_names"]]
    if users_missing_groups:
        use_shared_groups = ask_yes_no(
            f"{len(users_missing_groups)} CSV user(s) are missing identity_groups. Use one shared group list for them?",
            default_yes=True,
        )
        if not use_shared_groups:
            missing_rows = ", ".join(str(u["row_num"]) for u in users_missing_groups)
            raise ValueError(
                f"CSV row(s) missing identity_groups: {missing_rows}. "
                "Add identity_groups to the CSV or choose the shared-group option."
            )

        while True:
            shared_groups_raw = input(
                "Enter shared Identity Group name(s), separated by semicolon (;): "
            ).strip()
            shared_groups = parse_group_names(shared_groups_raw)
            if shared_groups:
                break
            print("ERROR: At least one Identity Group name is required.")

        for user in users_missing_groups:
            user["group_names"] = shared_groups

    users_missing_force = [u for u in users if u["force_change_password"] is None]
    if users_missing_force:
        shared_force = ask_yes_no(
            f"{len(users_missing_force)} CSV user(s) are missing force_change_password. Force password change for those users?",
            default_yes=True,
        )
        for user in users_missing_force:
            user["force_change_password"] = shared_force

    return users


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

    timeout_sec = ask_int(
        "Enter HTTP timeout in seconds",
        DEFAULT_TIMEOUT_SEC,
        minimum=10,
        maximum=300,
    )

    max_workers = ask_int(
        "Enter max parallel ISE hosts to process at the same time",
        DEFAULT_MAX_WORKERS,
        minimum=1,
        maximum=50,
    )

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

    max_workers = min(max_workers, len(ise_hosts))

    print("")
    print(f"CSV loaded       : {csv_path}")
    print(f"Users loaded     : {len(users)}")
    print(f"ISE hosts loaded : {len(ise_hosts)}")
    print(f"Timeout          : {timeout_sec} seconds")
    print(f"Parallel workers : {max_workers}")
    print("Existing users   : will be SKIPPED, not failed")
    print("")

    proceed = ask_yes_no("Proceed with user creation now?", default_yes=False)
    if not proceed:
        print("Cancelled. No users were created.")
        return 0

    all_created: list[tuple[str, str]] = []
    all_skipped: list[tuple[str, str, str]] = []
    all_failures: list[tuple[str, str, str]] = []

    log_event("============================================================")
    log_event(f"Starting CSV batch creation from '{csv_path}' for {len(users)} user(s)")
    log_event(f"Timeout={timeout_sec}s | max_workers={max_workers}")
    log_event("Existing users will be skipped and counted separately from failures")
    log_event("============================================================")

    for index, user in enumerate(users, start=1):
        log_event(f"Processing user {index}/{len(users)}: {user['username']}")
        created, skipped, failures = create_user_across_hosts_threaded(
            api_user=api_user,
            api_pass=api_pass,
            ise_hosts=ise_hosts,
            user=user,
            timeout_sec=timeout_sec,
            max_workers=max_workers,
        )
        all_created.extend(created)
        all_skipped.extend(skipped)
        all_failures.extend(failures)

    write_summary(users, all_created, all_skipped, all_failures, timeout_sec, max_workers)
    write_failed_results_csv(all_failures)

    log_event("------------------------------------------------------------")
    log_event(
        f"Finished. Created: {len(all_created)} | Skipped/already exists: {len(all_skipped)} | Failed: {len(all_failures)}"
    )
    log_event(f"Detailed log       : {LOG_FILE}")
    log_event(f"Summary report     : {SUMMARY_FILE}")
    log_event(f"Failed results CSV : {FAILED_RESULTS_CSV}")
    log_event("------------------------------------------------------------")

    return 0 if not all_failures else 1


if __name__ == "__main__":
    sys.exit(main())
