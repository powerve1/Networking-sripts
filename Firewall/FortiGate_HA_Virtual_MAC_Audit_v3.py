import re
import getpass
import pandas as pd
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException

HOSTS_FILE = "FW01.txt"
MAX_THREADS = 8
TARGET_INTERFACE = "802.3ad_Trunk01"
HA_MAC_COMMAND = "diag sys ha mac"

MAC_PATTERN = r"[0-9a-fA-F]{2}(?:[.:][0-9a-fA-F]{2}){5}"
PLACEHOLDER_VMAC = "--.--.--.--.--.--"


def read_hosts(file_path):
    with open(file_path, "r") as file:
        return [
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        ]


def clean_output(output):
    """Remove ANSI/control characters that can break regex parsing."""
    if not output:
        return ""
    output = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", output)
    output = output.replace("\x08", "")
    return output


def parse_hostname(output):
    output = clean_output(output)
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
    output = clean_output(output)
    match = re.search(
        r"Virtual\s+domain\s+configuration\s*:\s*([^\r\n]+)",
        output,
        re.IGNORECASE,
    )
    if not match:
        return False
    vdom_mode = match.group(1).strip().lower()
    return "multiple" in vdom_mode or "enable" in vdom_mode


def normalize_mac(mac_address):
    if not mac_address:
        return "N/A"
    mac_address = mac_address.strip().lower()
    if mac_address == PLACEHOLDER_VMAC:
        return "N/A"
    return mac_address.replace(":", ".")


def send_command_handle_more(ssh, command, read_timeout=120):
    """
    FortiGate diagnostic commands may paginate output with --More--.
    This function keeps sending a space until the complete output is collected.
    """
    output = ssh.send_command_timing(
        command,
        read_timeout=read_timeout,
        strip_prompt=False,
        strip_command=False,
    )

    # Handle FortiGate pager if present.
    safety_counter = 0
    while "--More--" in output and safety_counter < 50:
        output = output.replace("--More--", "")
        more_output = ssh.send_command_timing(
            " ",
            read_timeout=read_timeout,
            strip_prompt=False,
            strip_command=False,
        )
        output += more_output
        safety_counter += 1

    return clean_output(output)


def parse_ha_virtual_mac(output, interface_name):
    """
    Parse the first non-placeholder HA virtual MAC for the target interface.

    Expected line:
      prio=0, phy_index=22, itf_name=802.3ad_Trunk01, mac=e0.23.ff.3b.df.0c, vmac=00.09.0f.09.00.06, linkfail=0

    Returns:
      (virtual_mac, physical_mac, matching_line, all_target_lines)
    """
    output = clean_output(output)
    target_lines = []

    # Very permissive field parser because FortiGate spacing is inconsistent.
    interface_re = re.compile(
        rf"itf_name\s*=\s*{re.escape(interface_name)}(?=\s*,|\s|$)",
        re.IGNORECASE,
    )
    vmac_re = re.compile(rf"vmac\s*=\s*({MAC_PATTERN}|--\.--\.--\.--\.--\.--)", re.IGNORECASE)
    mac_re = re.compile(rf"(?<!v)mac\s*=\s*({MAC_PATTERN})", re.IGNORECASE)

    for raw_line in output.splitlines():
        line = " ".join(raw_line.strip().split())
        if not line:
            continue

        if interface_name.lower() not in line.lower():
            continue

        if not interface_re.search(line):
            continue

        target_lines.append(line)

        vmac_match = vmac_re.search(line)
        if not vmac_match:
            continue

        virtual_mac = normalize_mac(vmac_match.group(1))
        if virtual_mac == "N/A":
            continue

        physical_mac = "N/A"
        mac_match = mac_re.search(line)
        if mac_match:
            physical_mac = normalize_mac(mac_match.group(1))

        return virtual_mac, physical_mac, line, target_lines

    return "N/A", "N/A", "", target_lines

def enter_global_context(ssh):
    output = ""
    output += send_command_handle_more(ssh, "config global", read_timeout=30)
    return output


def exit_config_context(ssh):
    return send_command_handle_more(ssh, "end", read_timeout=30)


def disable_paging_best_effort(ssh):
    """
    Best effort only. If the account cannot change console output, the script still works
    because send_command_handle_more handles --More-- pagination.
    """
    output = ""
    output += send_command_handle_more(ssh, "config system console", read_timeout=30)
    output += send_command_handle_more(ssh, "set output standard", read_timeout=30)
    output += send_command_handle_more(ssh, "end", read_timeout=30)
    return output


def collect_ha_virtual_mac(ssh, interface_name):
    combined_output = ""

    # Disable paging before running a long HA command.
    pager_output = disable_paging_best_effort(ssh)
    combined_output += f"===== disable paging best effort =====\n{pager_output}\n\n"

    global_output = enter_global_context(ssh)
    combined_output += f"===== config global =====\n{global_output}\n\n"

    ha_output = send_command_handle_more(ssh, HA_MAC_COMMAND, read_timeout=180)
    combined_output += f"===== {HA_MAC_COMMAND} =====\n{ha_output}\n\n"

    end_output = exit_config_context(ssh)
    combined_output += f"===== end =====\n{end_output}\n"

    virtual_mac, physical_mac, matched_line, target_lines = parse_ha_virtual_mac(ha_output, interface_name)
    return virtual_mac, physical_mac, matched_line, target_lines, combined_output


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
        "Physical MAC": "N/A",
        "Virtual MAC": "N/A",
        "Matched HA Line": "",
        "Target Interface Lines Found": "",
        "VDOM Mode": "UNKNOWN",
        "Status": "FAILED",
        "Failure Reason": "",
        "get system status Output": "",
        "diag sys ha mac Output": "",
    }

    ssh = None
    try:
        ssh = ConnectHandler(**device)

        system_status = send_command_handle_more(ssh, "get system status", read_timeout=60)
        result["Hostname"] = parse_hostname(system_status)
        result["VDOM Mode"] = "Multi VDOM" if is_multi_vdom(system_status) else "No Multi VDOM"
        result["get system status Output"] = system_status

        virtual_mac, physical_mac, matched_line, target_lines, ha_output = collect_ha_virtual_mac(ssh, TARGET_INTERFACE)

        result["Virtual MAC"] = virtual_mac
        result["Physical MAC"] = physical_mac
        result["Matched HA Line"] = matched_line
        result["Target Interface Lines Found"] = "\n".join(target_lines)
        result["diag sys ha mac Output"] = ha_output

        if virtual_mac != "N/A":
            result["Status"] = "SUCCESS"
        else:
            if target_lines:
                result["Failure Reason"] = (
                    f"Interface {TARGET_INTERFACE} was found, but no non-placeholder vmac was parsed. "
                    f"Check 'Target Interface Lines Found' and 'diag sys ha mac Output' in Excel."
                )
            else:
                result["Failure Reason"] = (
                    f"Interface {TARGET_INTERFACE} was not found in the collected diag sys ha mac output. "
                    f"Check whether output was paginated, truncated, or the account entered global context."
                )

    except NetmikoAuthenticationException:
        result["Failure Reason"] = "Authentication failed"
    except NetmikoTimeoutException:
        result["Failure Reason"] = "SSH timeout / device unreachable"
    except Exception as e:
        result["Failure Reason"] = str(e)
    finally:
        if ssh:
            try:
                ssh.disconnect()
            except Exception:
                pass

    return result


def export_to_excel(results, excel_file):
    df = pd.DataFrame(results)
    preferred_columns = [
        "IP Address",
        "Hostname",
        "Interface",
        "Virtual MAC",
        "Physical MAC",
        "Matched HA Line",
        "Target Interface Lines Found",
        "VDOM Mode",
        "Status",
        "Failure Reason",
        "get system status Output",
        "diag sys ha mac Output",
    ]
    df = df[[column for column in preferred_columns if column in df.columns]]

    with pd.ExcelWriter(excel_file, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="HA Virtual MAC")
        worksheet = writer.sheets["HA Virtual MAC"]
        worksheet.freeze_panes = "A2"
        worksheet.auto_filter.ref = worksheet.dimensions

        for column_cells in worksheet.columns:
            max_length = 0
            column = column_cells[0].column_letter
            for cell in column_cells:
                try:
                    if cell.value:
                        max_length = max(max_length, len(str(cell.value)))
                except Exception:
                    pass
            worksheet.column_dimensions[column].width = min(max_length + 2, 100)


def export_summary(results, summary_file):
    success_count = len([r for r in results if r["Status"] == "SUCCESS"])
    failed_count = len([r for r in results if r["Status"] == "FAILED"])

    with open(summary_file, "w") as file:
        file.write("FortiGate HA Virtual MAC Audit Summary\n")
        file.write("=" * 70 + "\n")
        file.write(f"Run Time: {datetime.now()}\n")
        file.write(f"Command: config global -> {HA_MAC_COMMAND}\n")
        file.write(f"Target Interface: {TARGET_INTERFACE}\n")
        file.write(f"Total Devices: {len(results)}\n")
        file.write(f"Successful: {success_count}\n")
        file.write(f"Failed: {failed_count}\n\n")

        file.write("Devices With Virtual MAC\n")
        file.write("-" * 70 + "\n")
        for r in results:
            if r["Status"] == "SUCCESS":
                file.write(
                    f"{r['IP Address']} | {r['Hostname']} | {r['Interface']} | "
                    f"Virtual MAC: {r['Virtual MAC']} | Physical MAC: {r['Physical MAC']}\n"
                )

        file.write("\nFailed Devices\n")
        file.write("-" * 70 + "\n")
        for r in results:
            if r["Status"] == "FAILED":
                file.write(f"{r['IP Address']} | {r['Hostname']} | Reason: {r['Failure Reason']}\n")
                if r.get("Target Interface Lines Found"):
                    file.write("Target line(s) found:\n")
                    file.write(r["Target Interface Lines Found"] + "\n")


def main():
    print("=" * 70)
    print("FortiGate HA Virtual MAC Audit Script")
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

    print(f"\nCommand: config global -> {HA_MAC_COMMAND}")
    print(f"Target Interface: {TARGET_INTERFACE}")
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
                        f"[SUCCESS] {host} | {result['Hostname']} | {result['Interface']} | "
                        f"Virtual MAC: {result['Virtual MAC']} | Physical MAC: {result['Physical MAC']}"
                    )
                else:
                    print(f"[FAILED]  {host} | {result['Hostname']} | {result['Failure Reason']}")
            except Exception as e:
                results.append({
                    "IP Address": host,
                    "Hostname": "UNKNOWN",
                    "Interface": TARGET_INTERFACE,
                    "Physical MAC": "N/A",
                    "Virtual MAC": "N/A",
                    "Matched HA Line": "",
                    "Target Interface Lines Found": "",
                    "VDOM Mode": "UNKNOWN",
                    "Status": "FAILED",
                    "Failure Reason": f"Thread exception: {e}",
                    "get system status Output": "",
                    "diag sys ha mac Output": "",
                })
                print(f"[FAILED]  {host} | Thread exception: {e}")

    results = sorted(results, key=lambda r: (r.get("Hostname", ""), r.get("IP Address", "")))
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    excel_file = f"FortiGate_HA_Virtual_MAC_Audit_{timestamp}.xlsx"
    summary_file = f"FortiGate_HA_Virtual_MAC_Summary_{timestamp}.txt"

    export_to_excel(results, excel_file)
    export_summary(results, summary_file)

    print("\n" + "=" * 70)
    print("Execution completed")
    print(f"Excel exported: {excel_file}")
    print(f"Summary exported: {summary_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
