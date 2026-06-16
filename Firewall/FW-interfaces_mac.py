import re
import getpass
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoTimeoutException,
    NetmikoAuthenticationException,
)

HOSTS_FILE = "FW01.txt"
MAX_THREADS = 8
TARGET_INTERFACE = "802.3ad_Trunk01"


def read_hosts(file_path):
    with open(file_path, "r") as file:
        return [
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        ]


def parse_hostname(output):
    patterns = [
        r"Hostname\s*:\s*([^\r\n]+)",
        r"Host Name\s*:\s*([^\r\n]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return "UNKNOWN"


def is_multi_vdom(output):
    """
    FortiGate examples:
        Virtual domain configuration: multiple
        Virtual domain configuration: disable
    """
    match = re.search(
        r"Virtual\s+domain\s+configuration\s*:\s*([^\r\n]+)",
        output,
        re.IGNORECASE
    )

    if not match:
        return False

    vdom_mode = match.group(1).strip().lower()
    return "multiple" in vdom_mode or "enable" in vdom_mode


def parse_mac_address(output, interface_name):
    """
    Parses MAC from different FortiGate outputs:
        mac=00:09:0f:09:00:1a
        hw_addr=00:09:0f:09:00:1a
        HWaddr 00:09:0F:09:00:1A
        ether 00:09:0f:09:00:1a
        actor mac: 00:09:0f:09:00:1a
    """

    mac_patterns = [
        r"\bmac\s*=\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
        r"\bhw_addr\s*=\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
        r"\bHWaddr\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
        r"\bether\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
        r"\bactor\s+mac\s*:\s*([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
        r"\bCurrent_HWaddr\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
        r"\bPermanent_HWaddr\s+([0-9a-f]{2}(?::[0-9a-f]{2}){5})",
    ]

    for pattern in mac_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1).lower()

    return "N/A"


def enter_root_vdom(ssh):
    ssh.send_command_timing(
        "config vdom",
        read_timeout=30,
        strip_prompt=False,
        strip_command=False,
    )

    ssh.send_command_timing(
        "edit root",
        read_timeout=30,
        strip_prompt=False,
        strip_command=False,
    )


def exit_vdom_context(ssh):
    ssh.send_command_timing(
        "end",
        read_timeout=30,
        strip_prompt=False,
        strip_command=False,
    )


def collect_interface_mac(ssh, interface_name):
    outputs = {}

    commands = [
        f"diagnose netlink interface list name {interface_name}",
        f"fnsysctl ifconfig {interface_name}",
        f"diagnose netlink aggregate name {interface_name}",
        f"get hardware nic {interface_name}",
    ]

    combined_output = ""

    for command in commands:
        output = ssh.send_command_timing(
            command,
            read_timeout=60,
            strip_prompt=False,
            strip_command=False,
        )

        outputs[command] = output
        combined_output += f"\n\n===== {command} =====\n{output}"

        mac = parse_mac_address(output, interface_name)
        if mac != "N/A":
            return mac, combined_output

    return "N/A", combined_output


def connect_and_collect(host, username, password):
    device = {
        "device_type": "fortinet",
        "host": host,
        "username": username,
        "password": password,
        "timeout": 30,
        "banner_timeout": 30,
        "auth_timeout": 30,
        "fast_cli": False,
    }

    result = {
        "IP Address": host,
        "Hostname": "UNKNOWN",
        "Interface": TARGET_INTERFACE,
        "MAC Address": "N/A",
        "VDOM Mode": "UNKNOWN",
        "Status": "FAILED",
        "Failure Reason": "",
        "get system status Output": "",
        "MAC Command Output": "",
    }

    try:
        ssh = ConnectHandler(**device)

        system_status = ssh.send_command_timing(
            "get system status",
            read_timeout=60,
            strip_prompt=False,
            strip_command=False,
        )

        hostname = parse_hostname(system_status)
        multi_vdom = is_multi_vdom(system_status)

        result["Hostname"] = hostname
        result["VDOM Mode"] = "Multi VDOM" if multi_vdom else "No Multi VDOM"
        result["get system status Output"] = system_status

        if multi_vdom:
            enter_root_vdom(ssh)

        mac_address, mac_output = collect_interface_mac(ssh, TARGET_INTERFACE)

        if multi_vdom:
            exit_vdom_context(ssh)

        ssh.disconnect()

        result["MAC Address"] = mac_address
        result["MAC Command Output"] = mac_output

        if mac_address != "N/A":
            result["Status"] = "SUCCESS"
        else:
            result["Status"] = "FAILED"
            result["Failure Reason"] = f"MAC address not found for interface {TARGET_INTERFACE}"

    except NetmikoAuthenticationException:
        result["Failure Reason"] = "Authentication failed"

    except NetmikoTimeoutException:
        result["Failure Reason"] = "SSH timeout / device unreachable"

    except Exception as e:
        result["Failure Reason"] = str(e)

    return result


def export_to_excel(results, excel_file):
    df = pd.DataFrame(results)

    with pd.ExcelWriter(excel_file, engine="openpyxl") as writer:
        df.to_excel(
            writer,
            index=False,
            sheet_name="FortiGate Interface MAC"
        )

        worksheet = writer.sheets["FortiGate Interface MAC"]

        for column_cells in worksheet.columns:
            max_length = 0
            column = column_cells[0].column_letter

            for cell in column_cells:
                try:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                except Exception:
                    pass

            worksheet.column_dimensions[column].width = min(max_length + 2, 80)


def export_summary(results, summary_file):
    success_count = len([r for r in results if r["Status"] == "SUCCESS"])
    failed_count = len([r for r in results if r["Status"] == "FAILED"])

    with open(summary_file, "w") as file:
        file.write("FortiGate Interface MAC Audit Summary\n")
        file.write("=" * 70 + "\n")
        file.write(f"Run Time: {datetime.now()}\n")
        file.write(f"Target Interface: {TARGET_INTERFACE}\n")
        file.write(f"Total Devices: {len(results)}\n")
        file.write(f"Successful: {success_count}\n")
        file.write(f"Failed: {failed_count}\n\n")

        file.write("Successful Devices\n")
        file.write("-" * 70 + "\n")

        for r in results:
            if r["Status"] == "SUCCESS":
                file.write(
                    f"{r['IP Address']} | "
                    f"{r['Hostname']} | "
                    f"{r['Interface']} | "
                    f"{r['MAC Address']} | "
                    f"{r['VDOM Mode']}\n"
                )

        file.write("\nFailed Devices\n")
        file.write("-" * 70 + "\n")

        for r in results:
            if r["Status"] == "FAILED":
                file.write(
                    f"{r['IP Address']} | "
                    f"{r['Hostname']} | "
                    f"Reason: {r['Failure Reason']}\n"
                )


def main():
    print("=" * 70)
    print("FortiGate Interface MAC Audit Script")
    print("=" * 70)

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    try:
        hosts = read_hosts(HOSTS_FILE)
    except FileNotFoundError:
        print(f"\nERROR: {HOSTS_FILE} not found.")
        print("Create the hosts file in the same folder as the script.")
        return

    if not hosts:
        print(f"\nERROR: No hosts found in {HOSTS_FILE}")
        return

    print(f"\nTarget Interface: {TARGET_INTERFACE}")
    print(f"Starting parallel connections, {MAX_THREADS} devices at a time...\n")

    results = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        future_to_host = {
            executor.submit(connect_and_collect, host, username, password): host
            for host in hosts
        }

        for future in as_completed(future_to_host):
            host = future_to_host[future]

            try:
                result = future.result()
                results.append(result)

                if result["Status"] == "SUCCESS":
                    print(
                        f"[SUCCESS] {host} | "
                        f"{result['Hostname']} | "
                        f"{result['Interface']} | "
                        f"MAC: {result['MAC Address']} | "
                        f"{result['VDOM Mode']}"
                    )
                else:
                    print(
                        f"[FAILED]  {host} | "
                        f"{result['Hostname']} | "
                        f"{result['Failure Reason']}"
                    )

            except Exception as e:
                results.append(
                    {
                        "IP Address": host,
                        "Hostname": "UNKNOWN",
                        "Interface": TARGET_INTERFACE,
                        "MAC Address": "N/A",
                        "VDOM Mode": "UNKNOWN",
                        "Status": "FAILED",
                        "Failure Reason": f"Thread exception: {e}",
                        "get system status Output": "",
                        "MAC Command Output": "",
                    }
                )

                print(f"[FAILED]  {host} | Thread exception: {e}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    excel_file = f"FortiGate_Interface_MAC_Audit_{timestamp}.xlsx"
    summary_file = f"FortiGate_Interface_MAC_Summary_{timestamp}.txt"

    export_to_excel(results, excel_file)
    export_summary(results, summary_file)

    print("\n" + "=" * 70)
    print("Execution completed")
    print(f"Excel exported: {excel_file}")
    print(f"Summary exported: {summary_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()