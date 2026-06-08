import os
import re
import csv
from collections import defaultdict

# -------------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------------
INPUT_FILE = "SCRT_host_list.txt"
OUTPUT_FILE = "securecrt_import.csv"

SESSIONS_PATH = r"C:\Users\apower\AppData\Roaming\VanDyke\Config\Sessions"

DEFAULT_PROTOCOL = "SSH2"
DEFAULT_EMULATION = "Xterm"
DEFAULT_USERNAME = ""

CLEAN_EXISTING_SESSIONS = True
DELETE_DUPLICATE_EXISTING_SESSIONS = False  # Safer: reports duplicates, does not delete


# -------------------------------------------------------------------------
# REGEX
# -------------------------------------------------------------------------
re_ipv4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)

re_dup_run = re.compile(
    r'_(?P<ip>(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1?\d?\d))(?:_(?P=ip))+'
)

_invalid = r'<>:"/\|?*'
_invalid_re = re.compile(f"[{re.escape(_invalid)}]")


# -------------------------------------------------------------------------
# CLEANUP FUNCTIONS
# -------------------------------------------------------------------------
def sanitize_filename(s: str) -> str:
    s = (s or "").strip()
    s = _invalid_re.sub("-", s)
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s.strip("._- ")


def remove_domain_from_hostname(name: str) -> str:
    parts = [p for p in name.split("_") if p]
    cleaned_parts = []

    for p in parts:
        if re_ipv4.fullmatch(p):
            cleaned_parts.append(p)
        else:
            cleaned_parts.append(p.split(".")[0])

    return "_".join(cleaned_parts)


def collapse_all_duplicate_ip_tokens(name_no_ext: str) -> str:
    prev = None
    cur = name_no_ext

    while prev != cur:
        prev = cur
        cur = re_dup_run.sub(r'_\g<ip>', cur)

    parts = [p for p in cur.split("_") if p]
    seen_ips = set()
    out = []

    for p in parts:
        if re_ipv4.fullmatch(p):
            if p in seen_ips:
                continue
            seen_ips.add(p)

        out.append(p)

    return "_".join(out)


def remove_duplicate_hostname_ip_pairs(name: str) -> str:
    """
    Removes repeated hostname+IP pairs from a session name.

    Example:
        SW01_10.1.1.1_SW01_10.1.1.1 -> SW01_10.1.1.1
        SW01.ncl.com_10.1.1.1_SW01_10.1.1.1 -> SW01_10.1.1.1
    """
    parts = [p for p in name.split("_") if p]

    pairs = []
    i = 0

    while i < len(parts):
        current = parts[i]

        if i + 1 < len(parts) and re_ipv4.fullmatch(parts[i + 1]):
            hostname = current.split(".")[0]
            ip = parts[i + 1]
            pairs.append((hostname, ip))
            i += 2
        else:
            i += 1

    if not pairs:
        return name

    seen = set()
    output = []

    for hostname, ip in pairs:
        key = (hostname.lower(), ip)

        if key in seen:
            continue

        seen.add(key)
        output.extend([hostname, ip])

    return "_".join(output)


def clean_session_name(name: str) -> str:
    cleaned = collapse_all_duplicate_ip_tokens(name)
    cleaned = remove_domain_from_hostname(cleaned)
    cleaned = remove_duplicate_hostname_ip_pairs(cleaned)
    cleaned = sanitize_filename(cleaned)
    return cleaned


def session_key_from_hostname_ip(hostname: str, ip: str):
    clean_hostname = remove_domain_from_hostname(hostname)
    clean_hostname = sanitize_filename(clean_hostname)
    return clean_hostname.lower(), ip


def session_key_from_name(name: str):
    cleaned = clean_session_name(name)
    parts = [p for p in cleaned.split("_") if p]

    if len(parts) >= 2 and re_ipv4.fullmatch(parts[-1]):
        hostname = "_".join(parts[:-1]).lower()
        ip = parts[-1]
        return hostname, ip

    return cleaned.lower(), ""


def next_available_path(root: str, base_name: str) -> str:
    candidate = os.path.join(root, base_name + ".ini")

    if not os.path.exists(candidate):
        return candidate

    i = 2

    while True:
        candidate = os.path.join(root, f"{base_name}_{i}.ini")

        if not os.path.exists(candidate):
            return candidate

        i += 1


# -------------------------------------------------------------------------
# CLEAN EXISTING SECURECRT SESSIONS
# -------------------------------------------------------------------------
def cleanup_existing_securecrt_sessions():
    if not os.path.isdir(SESSIONS_PATH):
        print(f"SecureCRT Sessions path not found: {SESSIONS_PATH}")
        return

    fixed = 0
    skipped = 0
    duplicate_count = 0
    seen_sessions = {}

    for root, _, files in os.walk(SESSIONS_PATH):
        for file in files:
            if not file.lower().endswith(".ini"):
                continue

            base = os.path.splitext(file)[0]

            if file.lower() == "default.ini" or base == "__FolderData__":
                skipped += 1
                continue

            old_path = os.path.join(root, file)
            cleaned = clean_session_name(base)
            key = session_key_from_name(cleaned)

            if key in seen_sessions:
                duplicate_count += 1
                original_path = seen_sessions[key]

                print("Duplicate existing session found:")
                print(f"  Original:  {original_path}")
                print(f"  Duplicate: {old_path}")

                if DELETE_DUPLICATE_EXISTING_SESSIONS:
                    os.remove(old_path)
                    print("  Action: Deleted duplicate")
                else:
                    print("  Action: Skipped duplicate, not deleted")

                continue

            seen_sessions[key] = old_path

            if cleaned == base:
                skipped += 1
                continue

            new_path = next_available_path(root, cleaned)

            os.rename(old_path, new_path)

            seen_sessions[key] = new_path

            print(f"Fixed: {base} -> {os.path.splitext(os.path.basename(new_path))[0]}")
            fixed += 1

    print(
        f"Cleanup done. Fixed={fixed}, "
        f"Skipped={skipped}, Duplicates Found={duplicate_count}"
    )


# -------------------------------------------------------------------------
# INPUT FILE
# -------------------------------------------------------------------------
def create_input_file_if_missing():
    if not os.path.isfile(INPUT_FILE):
        print(f"{INPUT_FILE} not found. Creating one...")

        with open(INPUT_FILE, "w", encoding="utf-8") as f:
            f.write("# Use #FolderName to start a group, then hostname IP lines\n")
            f.write("# Example:\n")
            f.write("#Offices\n")
            f.write("Switch1.company.com 1.1.1.1\n")
            f.write("Router1.company.com 2.2.2.2\n\n")
            f.write("#Callcenter\n")
            f.write("Switch2.company.com 4.4.4.4\n")
            f.write("Router2.company.com 5.5.5.5\n")

        print(f"{INPUT_FILE} created. Edit it, then run the script again.")
        return False

    return True


# -------------------------------------------------------------------------
# PARSE HOST LIST
# -------------------------------------------------------------------------
def parse_host_list():
    folder_devices = defaultdict(list)
    current_folder = None
    seen_sessions = set()
    duplicate_input_count = 0

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            if not line:
                continue

            if line.startswith("//"):
                continue

            if line.startswith("#"):
                folder_name = line[1:].strip()

                if folder_name:
                    current_folder = folder_name

                continue

            if current_folder is None:
                continue

            for sep in [",", ";", "\t"]:
                line = line.replace(sep, " ")

            parts = [p for p in line.split(" ") if p]

            if len(parts) < 2:
                continue

            hostname = parts[0]
            ip = parts[1]

            if not re_ipv4.fullmatch(ip):
                print(f"Skipped invalid IP line: {line}")
                continue

            clean_hostname = remove_domain_from_hostname(hostname)
            clean_hostname = sanitize_filename(clean_hostname)

            session_key = session_key_from_hostname_ip(clean_hostname, ip)

            if session_key in seen_sessions:
                duplicate_input_count += 1
                print(f"Duplicate input skipped: {clean_hostname} {ip}")
                continue

            seen_sessions.add(session_key)

            session_name = f"{clean_hostname}_{ip}"
            session_name = clean_session_name(session_name)

            folder_devices[current_folder].append(
                (clean_hostname, ip, session_name)
            )

    if duplicate_input_count:
        print(f"Duplicate input entries skipped: {duplicate_input_count}")

    return folder_devices


# -------------------------------------------------------------------------
# BUILD SECURECRT CSV
# -------------------------------------------------------------------------
def build_securecrt_csv(folder_devices):
    if not folder_devices:
        print("No valid folder/host entries found. Check your host list format.")
        return

    header = [
        "Hostname/IP Address",
        "Folder",
        "Session Name",
        "Protocol",
        "Emulation",
        "Username",
    ]

    total_sessions = 0

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)

        for folder, devices in folder_devices.items():
            for hostname, ip, session_name in devices:
                writer.writerow(
                    [
                        ip,
                        folder,
                        session_name,
                        DEFAULT_PROTOCOL,
                        DEFAULT_EMULATION,
                        DEFAULT_USERNAME,
                    ]
                )

                total_sessions += 1

    print(f"Created {OUTPUT_FILE} with {total_sessions} unique sessions.")
    print("Import it using SecureCRT: Tools > Import Settings from Text File.")


# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    if not create_input_file_if_missing():
        return

    folder_devices = parse_host_list()
    build_securecrt_csv(folder_devices)

    if CLEAN_EXISTING_SESSIONS:
        cleanup_existing_securecrt_sessions()


if __name__ == "__main__":
    main()