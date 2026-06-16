from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
from concurrent.futures import ThreadPoolExecutor, as_completed
from getpass import getpass
from pathlib import Path
from datetime import datetime
import re
import os


# ==========================================================
# SETTINGS
# ==========================================================

DEVICE_FILE = "devices.txt"
MAX_THREADS = 8

DEVICE_TYPE = "cisco_ios"

COMMANDS = [
    "show version",
    "show inventory",
    "show cdp nei",
    "show lldp nei",
    "show mod",
    "show int status",
    "show ip interface brief",
    "show vlan brief",
    "show spanning-tree summary",
    "show etherchannel summary",
    "show environment all",
    "show logging",
    "show run",
]


# ==========================================================
# PATHS
# ==========================================================

DOCUMENTS_PATH = Path.home() / "Documents"
BACKUP_ROOT = DOCUMENTS_PATH / "Fleet Backups"
SUMMARY_FILE = BACKUP_ROOT / f"Fleet_Backup_Summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"


# ==========================================================
# FUNCTIONS
# ==========================================================

def clean_name(value):
    """
    Makes folder and file names Windows-safe.
    """
    return re.sub(r'[\\/*?:"<>|]', "_", value.strip())


def parse_device_file(file_path):
    """
    Reads devices.txt using this format:

    # LOCATION NAME
    device1
    device2

    # ANOTHER LOCATION
    device3
    device4
    """
    devices = []
    current_location = "Unknown_Location"

    with open(file_path, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                current_location = clean_name(line.replace("#", "").strip())
                continue

            device = line.strip()
            devices.append({
                "host": device,
                "location": current_location
            })

    return devices


def get_hostname(connection, fallback_name):
    """
    Tries to get hostname from the device prompt.
    Falls back to the IP/name from the TXT file.
    """
    try:
        prompt = connection.find_prompt()
        hostname = prompt.replace("#", "").replace(">", "").strip()
        return clean_name(hostname) if hostname else clean_name(fallback_name)
    except Exception:
        return clean_name(fallback_name)


def connect_with_fallback(host, primary_creds, secondary_creds):
    """
    Tries primary credentials first.
    If primary authentication fails, it tries secondary credentials.
    """

    credential_attempts = [
        ("PRIMARY", primary_creds),
        ("SECONDARY", secondary_creds),
    ]

    last_auth_error = None

    for credential_name, creds in credential_attempts:
        device = {
            "device_type": DEVICE_TYPE,
            "host": host,
            "username": creds["username"],
            "password": creds["password"],
            "secret": creds["secret"],
            "fast_cli": False,
            "timeout": 30,
            "conn_timeout": 20,
            "banner_timeout": 30,
            "auth_timeout": 30,
        }

        try:
            connection = ConnectHandler(**device)

            if creds["secret"]:
                connection.enable()

            return connection, credential_name

        except NetmikoAuthenticationException as error:
            last_auth_error = error
            continue

    raise NetmikoAuthenticationException(
        f"Authentication failed with both credentials. Last error: {last_auth_error}"
    )


def run_backup(device_info, primary_creds, secondary_creds):
    host = device_info["host"]
    location = device_info["location"]

    result = {
        "host": host,
        "location": location,
        "status": "FAILED",
        "message": "",
        "file": "",
        "credential_used": ""
    }

    try:
        connection, credential_used = connect_with_fallback(
            host,
            primary_creds,
            secondary_creds
        )

        result["credential_used"] = credential_used

        try:
            connection.send_command("terminal length 0")
        except Exception:
            pass

        hostname = get_hostname(connection, host)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        location_folder = BACKUP_ROOT / clean_name(location)
        location_folder.mkdir(parents=True, exist_ok=True)

        output_file = location_folder / f"{hostname}_{host}_{timestamp}.txt"

        full_output = []
        full_output.append("=" * 80)
        full_output.append(f"Device: {hostname}")
        full_output.append(f"IP/Name: {host}")
        full_output.append(f"Location: {location}")
        full_output.append(f"Credential Used: {credential_used}")
        full_output.append(f"Backup Time: {datetime.now()}")
        full_output.append("=" * 80)
        full_output.append("\n")

        for command in COMMANDS:
            full_output.append("\n" + "#" * 80)
            full_output.append(f"# COMMAND: {command}")
            full_output.append("#" * 80 + "\n")

            try:
                output = connection.send_command(
                    command,
                    expect_string=r"#|>",
                    read_timeout=180
                )
                full_output.append(output)
            except Exception as cmd_error:
                full_output.append(f"[ERROR] Failed to run command: {command}")
                full_output.append(str(cmd_error))

        connection.disconnect()

        with open(output_file, "w", encoding="utf-8") as file:
            file.write("\n".join(full_output))

        result["status"] = "SUCCESS"
        result["message"] = "Backup completed"
        result["file"] = str(output_file)

    except NetmikoAuthenticationException:
        result["message"] = "Authentication failed with both primary and secondary credentials"

    except NetmikoTimeoutException:
        result["message"] = "Connection timeout"

    except Exception as error:
        result["message"] = str(error)

    return result


def write_summary(results):
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)

    total = len(results)
    success = len([r for r in results if r["status"] == "SUCCESS"])
    failed = total - success

    lines = []
    lines.append("=" * 80)
    lines.append("Fleet Weekly Backup Summary")
    lines.append(f"Run Time: {datetime.now()}")
    lines.append(f"Total Devices: {total}")
    lines.append(f"Successful: {success}")
    lines.append(f"Failed: {failed}")
    lines.append("=" * 80)
    lines.append("")

    for r in results:
        lines.append(f"[{r['status']}] {r['location']} - {r['host']}")
        lines.append(f"Credential Used: {r['credential_used']}")
        lines.append(f"Message: {r['message']}")

        if r["file"]:
            lines.append(f"File: {r['file']}")

        lines.append("-" * 80)

    with open(SUMMARY_FILE, "w", encoding="utf-8") as file:
        file.write("\n".join(lines))

    return SUMMARY_FILE


# ==========================================================
# MAIN
# ==========================================================

def main():
    print("=" * 80)
    print("Fleet Weekly Network Backup Script")
    print("=" * 80)

    if not os.path.exists(DEVICE_FILE):
        print(f"[ERROR] Device file not found: {DEVICE_FILE}")
        print("Create a devices.txt file in the same folder as this script.")
        return

    BACKUP_ROOT.mkdir(parents=True, exist_ok=True)

    print("\nPrimary Credentials")
    primary_creds = {
        "username": input("Primary Username: "),
        "password": getpass("Primary Password: "),
        "secret": getpass("Primary Enable Secret, press Enter if same/not needed: "),
    }

    print("\nSecondary / Fallback Credentials")
    secondary_creds = {
        "username": input("Secondary Username: "),
        "password": getpass("Secondary Password: "),
        "secret": getpass("Secondary Enable Secret, press Enter if same/not needed: "),
    }

    devices = parse_device_file(DEVICE_FILE)

    if not devices:
        print("[ERROR] No devices found in devices.txt")
        return

    print(f"\nLoaded {len(devices)} devices.")
    print(f"Backup folder: {BACKUP_ROOT}")
    print(f"Running with {MAX_THREADS} threads...\n")

    results = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_device = {
            executor.submit(run_backup, device, primary_creds, secondary_creds): device
            for device in devices
        }

        for future in as_completed(future_to_device):
            result = future.result()
            results.append(result)

            if result["status"] == "SUCCESS":
                print(
                    f"[SUCCESS] {result['location']} - {result['host']} "
                    f"- Credential Used: {result['credential_used']}"
                )
            else:
                print(
                    f"[FAILED]  {result['location']} - {result['host']} "
                    f"- {result['message']}"
                )

    summary_path = write_summary(results)

    print("\n" + "=" * 80)
    print("Execution completed")
    print(f"Summary file: {summary_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()