import os
import csv
import re

sessions_path = r"C:\Users\apower\AppData\Roaming\VanDyke\Config\Sessions"
output_csv = r"C:\Users\apower\Downloads\Jump\securecrt_sessions.csv"

# SecureCRT lines look like:
# S:"Hostname"=myhost
# S:"Username"=admin
# S:"Protocol Name"=SSH2
# D:"[SSH2] Port"=00000016  (hex)
# We'll parse S: (string) and D: (dword/hex)

re_string = re.compile(r'^S:"(?P<key>[^"]+)"=(?P<val>.*)$')
re_dword  = re.compile(r'^D:"(?P<key>[^"]+)"=(?P<val>[0-9A-Fa-f]+)$')

def safe_read_lines(path: str):
    # SecureCRT files sometimes have BOM/odd encoding; latin-1 won't choke
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        return f.read().splitlines()

def hex_to_int(s: str):
    try:
        return int(s, 16)
    except Exception:
        return ""

rows = []

for root, _, files in os.walk(sessions_path):
    for file in files:
        if not file.lower().endswith(".ini"):
            continue

        # Optional: skip Default.ini, it's not a session you usually want exported
        if file.lower() == "default.ini":
            continue

        file_path = os.path.join(root, file)
        rel_path = os.path.relpath(file_path, sessions_path)
        session_name = os.path.splitext(rel_path)[0].replace("\\", "/")

        data = {}
        for line in safe_read_lines(file_path):
            m = re_string.match(line)
            if m:
                data[m.group("key")] = m.group("val")
                continue

            m = re_dword.match(line)
            if m:
                data[m.group("key")] = m.group("val")

        hostname = data.get("Hostname", "")
        protocol = data.get("Protocol Name", "")
        username = data.get("Username", "")

        # Port is usually stored under [SSH2] Port as a hex dword
        port_hex = data.get("[SSH2] Port", "")
        port = hex_to_int(port_hex) if port_hex else ""

        rows.append([session_name, hostname, protocol, port, username])

with open(output_csv, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["Session Name", "Hostname", "Protocol", "Port", "Username"])
    w.writerows(rows)

print(f"Exported {len(rows)} sessions to: {output_csv}")
