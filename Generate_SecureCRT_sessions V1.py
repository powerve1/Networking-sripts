import os
import csv
from collections import defaultdict

# -------------------------------------------------------------------------
# CONFIG
# -------------------------------------------------------------------------
INPUT_FILE = "SCRT_host_list.txt"          # Your source file
OUTPUT_FILE = "securecrt_import.csv"  # File to import via SecureCRT Text Import Wizard

# Defaults for SecureCRT import
DEFAULT_PROTOCOL = "SSH2"
DEFAULT_EMULATION = "Xterm"
DEFAULT_USERNAME = ""   # leave empty, or set e.g. "netmgr"


# -------------------------------------------------------------------------
# Create host_list.txt if missing (with your preferred #Folder format)
# -------------------------------------------------------------------------
def create_input_file_if_missing():
    if not os.path.isfile(INPUT_FILE):
        print(f"{INPUT_FILE} not found. Creating one...")

        with open(INPUT_FILE, "w", encoding="utf-8") as f:
            f.write("# Use #FolderName to start a group, then hostname IP lines\n")
            f.write("# Example:\n")
            f.write("#Offices\n")
            f.write("Switch1 1.1.1.1\n")
            f.write("Router1 2.2.2.2\n\n")
            f.write("#Callcenter\n")
            f.write("Switch2 4.4.4.4\n")
            f.write("Router2 5.5.5.5\n")

        print(f"{INPUT_FILE} created. Edit it with your folders and devices, then run again.")
        return False
    return True


# -------------------------------------------------------------------------
# Parse host_list.txt with #Folder sections
# -------------------------------------------------------------------------
def parse_host_list():
    """
    Returns:
        dict[folder_name] -> list of (hostname, ip)
    """
    folder_devices = defaultdict(list)
    current_folder = None

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()

            # Skip empty lines
            if not line:
                continue

            # Folder line: starts with '#'
            if line.startswith("#"):
                folder_name = line[1:].strip()  # remove '#'
                if folder_name:
                    current_folder = folder_name
                continue

            # Comment line style using '//' (optional)
            if line.startswith("//"):
                continue

            # If no folder yet, skip
            if current_folder is None:
                continue

            # Normalize separators between hostname and IP
            for sep in [",", ";", "\t"]:
                line = line.replace(sep, " ")

            parts = [p for p in line.split(" ") if p]
            if len(parts) < 2:
                continue

            hostname, ip = parts[0], parts[1]
            folder_devices[current_folder].append((hostname, ip))

    return folder_devices


# -------------------------------------------------------------------------
# Build securecrt_import.csv
# -------------------------------------------------------------------------
def build_securecrt_csv(folder_devices):
    if not folder_devices:
        print("No valid folder/host entries found. Check your host_list format.")
        return

    # Fields supported by the Text Import Wizard include:
    # Hostname/IP Address, Folder, Session Name, Username, Protocol, Emulation, etc.
    # We'll generate: Hostname/IP Address,Folder,Session Name,Protocol,Emulation,Username
    header = [
        "Hostname/IP Address",
        "Folder",
        "Session Name",
        "Protocol",
        "Emulation",
        "Username",
    ]

    with open(OUTPUT_FILE, "w", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)

        for folder, devices in folder_devices.items():
            for hostname, ip in devices:
                row = [
                    ip,                 # Hostname/IP Address (device IP)
                    folder,             # Folder name in SecureCRT
                    hostname,           # Session Name
                    DEFAULT_PROTOCOL,   # Protocol
                    DEFAULT_EMULATION,  # Emulation
                    DEFAULT_USERNAME,   # Username
                ]
                writer.writerow(row)

    print(f"Created {OUTPUT_FILE} with {sum(len(v) for v in folder_devices.values())} sessions.")
    print("Use SecureCRT's 'Import Settings from Text File...' to import this CSV.")


# -------------------------------------------------------------------------
# Main
# -------------------------------------------------------------------------
def main():
    if not create_input_file_if_missing():
        return

    folder_devices = parse_host_list()
    build_securecrt_csv(folder_devices)


if __name__ == "__main__":
    main()
