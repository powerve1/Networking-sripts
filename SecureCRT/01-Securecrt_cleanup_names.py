import os
import re

sessions_path = r"C:\Users\apower\AppData\Roaming\VanDyke\Config\Sessions"

# IPv4 detector
re_ipv4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")

# Matches repeated IP tokens separated by underscores:
# _10.1.1.1_10.1.1.1_10.1.1.1  -> _10.1.1.1
re_dup_run = re.compile(
    r'_(?P<ip>(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d))(?:_(?P=ip))+'
)

# Windows-invalid filename chars: \ / : * ? " < > |
_invalid = r'<>:"/\|?*'
_invalid_re = re.compile(f"[{re.escape(_invalid)}]")


def sanitize_filename(s: str) -> str:
    s = (s or "").strip()
    s = _invalid_re.sub("-", s)
    s = re.sub(r"\s+", "_", s)
    s = re.sub(r"_+", "_", s)
    return s.strip("._- ")


def remove_domain_from_hostname(name: str) -> str:
    """
    Removes domain from hostname tokens while keeping IP addresses untouched.

    Example:
        switch01.company.com_10.1.1.1 -> switch01_10.1.1.1
        core01.ncl.com_192.168.1.5 -> core01_192.168.1.5
    """
    parts = [p for p in name.split("_") if p]

    cleaned_parts = []
    for p in parts:
        if re_ipv4.fullmatch(p):
            cleaned_parts.append(p)
        else:
            cleaned_parts.append(p.split(".")[0])

    return "_".join(cleaned_parts)


def collapse_all_duplicate_ip_tokens(name_no_ext: str) -> str:
    # 1) Collapse repeated runs (_ip_ip_ip -> _ip), keep doing until stable
    prev = None
    cur = name_no_ext

    while prev != cur:
        prev = cur
        cur = re_dup_run.sub(r'_\g<ip>', cur)

    # 2) Remove duplicate IP tokens anywhere, keep first occurrence
    parts = [p for p in cur.split("_") if p != ""]
    seen_ips = set()
    out = []

    for p in parts:
        if re_ipv4.fullmatch(p):
            if p in seen_ips:
                continue
            seen_ips.add(p)

        out.append(p)

    return "_".join(out)


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


fixed = 0
skipped = 0

for root, _, files in os.walk(sessions_path):
    for file in files:
        if not file.lower().endswith(".ini"):
            continue

        base = os.path.splitext(file)[0]

        # Skip template & folder metadata
        if file.lower() == "default.ini" or base == "__FolderData__":
            skipped += 1
            continue

        cleaned = collapse_all_duplicate_ip_tokens(base)
        cleaned = remove_domain_from_hostname(cleaned)
        cleaned = sanitize_filename(cleaned)

        if cleaned == base:
            skipped += 1
            continue

        old_path = os.path.join(root, file)
        new_path = next_available_path(root, cleaned)

        os.rename(old_path, new_path)

        print(f"Fixed: {base} -> {os.path.splitext(os.path.basename(new_path))[0]}")
        fixed += 1

print(f"Done. Fixed={fixed}, Skipped={skipped}")