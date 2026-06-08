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

HOSTS_FILE = "faz_hosts.txt"
MAX_THREADS = 8


def read_hosts(file_path):
    with open(file_path, "r") as file:
        return [
            line.strip()
            for line in file
            if line.strip() and not line.strip().startswith("#")
        ]


def parse_system_status(output):
    hostname = "UNKNOWN"
    serial = "UNKNOWN"

    hostname_patterns = [
        r"Hostname\s*:\s*([^\r\n]+)",
        r"Host Name\s*:\s*([^\r\n]+)",
    ]

    serial_patterns = [
        r"Serial Number\s*:\s*([^\r\n]+)",
        r"Serial-Number\s*:\s*([^\r\n]+)",
        r"Serial\s*:\s*([^\r\n]+)",
    ]

    for pattern in hostname_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            hostname = match.group(1).strip()
            break

    for pattern in serial_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            serial = match.group(1).strip()
            break

    return hostname, serial


def parse_logvol_average(output):
    values_gb = []

    for line in output.splitlines():
        matches = re.findall(
            r"(\d+(?:\.\d+)?)\s*(KB|MB|GB|TB)",
            line,
            re.IGNORECASE
        )

        for number, unit in matches:
            number = float(number)
            unit = unit.upper()

            if unit == "KB":
                values_gb.append(number / 1024 / 1024)
            elif unit == "MB":
                values_gb.append(number / 1024)
            elif unit == "GB":
                values_gb.append(number)
            elif unit == "TB":
                values_gb.append(number * 1024)

    if not values_gb:
        return "N/A"

    return round(sum(values_gb) / len(values_gb), 2)


def parse_licensed_gb_day(output):
    """
    Parses the FAZ daily log license from 'diag debug vminfo'.

    Expected line example:
        Licensed GB/Day: 100
        Licensed GB/Day : 100.00
        Licensed GB/Day: Unlimited
    """
    patterns = [
        r"Licensed\s+GB\s*/\s*Day\s*:\s*([^\r\n]+)",
        r"Licensed\s+GB\s+Day\s*:\s*([^\r\n]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return "N/A"


def connect_and_collect(host, username, password):
    device = {
        "device_type": "generic",
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
        "Serial Number": "UNKNOWN",
        "Status": "FAILED",
        "Failure Reason": "",
        "Average Log Volume GB": "N/A",
        "Log per day license GB/Day": "N/A",
        "get system status Output": "",
        "diagnose fortilogd logvol-adom all Output": "",
        "diag debug vminfo Output": "",
    }

    try:
        ssh = ConnectHandler(**device)

        system_status = ssh.send_command_timing(
            "get system status",
            read_timeout=60,
            strip_prompt=False,
            strip_command=False,
        )

        logvol_output = ssh.send_command_timing(
            "diagnose fortilogd logvol-adom all",
            read_timeout=120,
            strip_prompt=False,
            strip_command=False,
        )

        vminfo_output = ssh.send_command_timing(
            "diag debug vminfo",
            read_timeout=60,
            strip_prompt=False,
            strip_command=False,
        )

        ssh.disconnect()

        hostname, serial = parse_system_status(system_status)
        average_logvol = parse_logvol_average(logvol_output)
        licensed_gb_day = parse_licensed_gb_day(vminfo_output)

        result["Hostname"] = hostname
        result["Serial Number"] = serial
        result["Status"] = "SUCCESS"
        result["Average Log Volume GB"] = average_logvol
        result["Log per day license GB/Day"] = licensed_gb_day
        result["get system status Output"] = system_status
        result["diagnose fortilogd logvol-adom all Output"] = logvol_output
        result["diag debug vminfo Output"] = vminfo_output

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
            sheet_name="FAZ Log Volume"
        )

        worksheet = writer.sheets["FAZ Log Volume"]

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
        file.write("FortiAnalyzer Log Volume Audit Summary\n")
        file.write("=" * 70 + "\n")
        file.write(f"Run Time: {datetime.now()}\n")
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
                    f"{r['Serial Number']} | "
                    f"Average GB: {r['Average Log Volume GB']} | "
                    f"Licensed GB/Day: {r['Log per day license GB/Day']}\n"
                )

        file.write("\nFailed Devices\n")
        file.write("-" * 70 + "\n")

        for r in results:
            if r["Status"] == "FAILED":
                file.write(
                    f"{r['IP Address']} | "
                    f"Reason: {r['Failure Reason']}\n"
                )


def main():
    print("=" * 70)
    print("FortiAnalyzer Log Volume Audit Script")
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

    print(f"\nStarting parallel connections, {MAX_THREADS} devices at a time...\n")

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
                        f"{result['Serial Number']} | "
                        f"Average GB: {result['Average Log Volume GB']} | "
                        f"Licensed GB/Day: {result['Log per day license GB/Day']}"
                    )
                else:
                    print(f"[FAILED]  {host} | {result['Failure Reason']}")

            except Exception as e:
                results.append(
                    {
                        "IP Address": host,
                        "Hostname": "UNKNOWN",
                        "Serial Number": "UNKNOWN",
                        "Status": "FAILED",
                        "Failure Reason": f"Thread exception: {e}",
                        "Average Log Volume GB": "N/A",
                        "Log per day license GB/Day": "N/A",
                        "get system status Output": "",
                        "diagnose fortilogd logvol-adom all Output": "",
                        "diag debug vminfo Output": "",
                    }
                )

                print(f"[FAILED]  {host} | Thread exception: {e}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    excel_file = f"FAZ_LogVol_Audit_{timestamp}.xlsx"
    summary_file = f"FAZ_Run_Summary_{timestamp}.txt"

    export_to_excel(results, excel_file)
    export_summary(results, summary_file)

    print("\n" + "=" * 70)
    print("Execution completed")
    print(f"Excel exported: {excel_file}")
    print(f"Summary exported: {summary_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
