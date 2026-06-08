from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import getpass
import logging
from datetime import datetime
import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------------------------------------------------------
# Netmiko debug logging (optional but useful)
# -------------------------------------------------------------------------
logging.basicConfig(
    filename="netmiko_lldp_debug.log",
    level=logging.DEBUG
)
logger = logging.getLogger("netmiko")

# -------------------------------------------------------------------------
# Concurrency / SSH limits
# -------------------------------------------------------------------------
SSH_SESSIONS_LIMIT_PER_JUMP = 3   # tune based on your SSH session limits
SAFETY_MARGIN = 1                 # keep 1 session free for manual/debug, etc.


def load_devices(hosts_file: str) -> list[str]:
    """Load device IPs/hostnames from a text file (one per line)."""
    if not os.path.exists(hosts_file):
        raise FileNotFoundError(f"Hosts file not found: {hosts_file}")

    with open(hosts_file, encoding="utf-8") as f:
        devices = [line.strip() for line in f if line.strip()]

    if not devices:
        raise ValueError(f"No devices found in {hosts_file}")

    return devices


def ask_for_jump_host_ips() -> list[str]:
    """
    Ask user if they want 1 or multiple jump hosts, and return a list of IPs.
    Example for multiple: 10.69.0.101,10.69.0.102
    """
    answer = input("Use multiple jump hosts? (y/n): ").strip().lower()
    if answer.startswith("y"):
        raw = input("Enter jump host IPs separated by commas: ").strip()
        jump_host_ips = [ip.strip() for ip in raw.split(",") if ip.strip()]
    else:
        single_ip = input("Enter jump host IP: ").strip()
        jump_host_ips = [single_ip]

    if not jump_host_ips:
        raise ValueError("No jump host IPs provided.")

    print(f"Using {len(jump_host_ips)} jump host(s): {', '.join(jump_host_ips)}")
    return jump_host_ips


def build_jump_hosts(jump_host_ips: list[str], jump_username: str, jump_password: str) -> list[dict]:
    """
    Build a list of jump host connection dicts for Netmiko.
    One dict per jump host IP, with stronger timeout settings.
    """
    jump_hosts = []
    for ip in jump_host_ips:
        jh = {
            "device_type": "cisco_ios_ssh",
            "host": ip,
            "username": jump_username,
            "password": jump_password,

            # ---- Stronger Netmiko / Paramiko timeouts ----
            "conn_timeout": 20,
            "banner_timeout": 60,
            "auth_timeout": 30,
            "global_delay_factor": 2,
            "fast_cli": False,
        }
        jump_hosts.append(jh)
    return jump_hosts


def compute_max_workers(num_jump_hosts: int, num_devices: int) -> int:
    """
    Compute a safe max_workers based on:
    - per-jump-host session limit
    - number of jump hosts
    - safety margin
    """
    sessions_per_jump_safe = max(1, SSH_SESSIONS_LIMIT_PER_JUMP - SAFETY_MARGIN)
    total_safe_sessions = sessions_per_jump_safe * max(1, num_jump_hosts)

    max_workers = min(num_devices, total_safe_sessions)
    if max_workers < 1:
        max_workers = 1

    return max_workers


def login_to_cas_via_jump(jump_host: dict, device: str, device_user: str, device_pass: str):
    """
    SSH to jump host, then TELNET to CAS device from the jump host.

    Returns:
        conn   -> Netmiko connection (to JUMP host, with active telnet session to CAS)
        output -> combined raw login output
    """
    jump_host_thread = dict(jump_host)
    jump_host_thread["session_log"] = f"jump_session_{device}.log"

    print(f"[{device}] Connecting via jump host {jump_host_thread['host']}...")
    conn = ConnectHandler(**jump_host_thread)

    telnet_cmd = f"telnet {device}"
    output = conn.send_command_timing(
        telnet_cmd, strip_command=False, strip_prompt=False, delay_factor=4
    )

    username_sent = False
    password_tries = 0
    seen_login_interaction = False

    for _ in range(40):
        tail = output[-600:].lower()

        # Telnet failure messages
        if (
            "connection refused" in tail
            or "connection closed" in tail
            or "closed by foreign host" in tail
            or "aborted" in tail
            or "unable to connect" in tail
            or "no route to host" in tail
            or "unknown host" in tail
            or "timed out" in tail
        ):
            if not seen_login_interaction:
                conn.disconnect()
                raise RuntimeError(f"Telnet from jump host to {device} failed or was aborted.")

        lines = tail.splitlines()
        last_line = lines[-1] if lines else tail

        # Username/login prompt
        if (
            ("username:" in last_line or "login:" in last_line)
            and "#" not in last_line
            and ">" not in last_line
        ):
            if not username_sent:
                output += conn.send_command_timing(
                    device_user, strip_command=False, strip_prompt=False
                )
                username_sent = True
                seen_login_interaction = True
                continue

        # Password prompt
        if "password:" in last_line and "#" not in last_line and ">" not in last_line:
            if password_tries >= 6:
                conn.disconnect()
                raise RuntimeError(f"Too many password attempts while telnetting to {device}.")
            output += conn.send_command_timing(
                device_pass, strip_command=False, strip_prompt=False
            )
            password_tries += 1
            seen_login_interaction = True
            continue

        # Press return/enter banner
        if "press return" in tail or "press any key" in tail or "press enter" in tail:
            output += conn.send_command_timing(
                "\n", strip_command=False, strip_prompt=False
            )
            seen_login_interaction = True
            continue

        # If we now see a device prompt
        if "#" in tail or ">" in tail:
            break

        # Otherwise, coax next prompt
        output += conn.send_command_timing(
            "\n", strip_command=False, strip_prompt=False
        )

    tail = output[-600:].strip().lower()
    if "#" not in tail and ">" not in tail:
        conn.disconnect()
        raise RuntimeError("Did not reach CAS device prompt via Telnet from jump host.")

    return conn, output


def ensure_enable_mode(conn, enable_password: str, output_prefix: str = ""):
    """
    Make sure we are in enable ('#') mode.
    Try 'enable', send password if prompted.
    """
    output = output_prefix

    # If we're already in '#', skip
    if "#" in output[-400:]:
        return output, True

    output += conn.send_command_timing("enable", strip_command=False, strip_prompt=False)

    for _ in range(8):
        tail = output[-300:].lower()

        if "password:" in tail:
            output += conn.send_command_timing(
                enable_password, strip_command=False, strip_prompt=False
            )
            continue

        if "#" in tail:
            return output, True

        if ">" in tail:
            output += conn.send_command_timing("\n", strip_command=False, strip_prompt=False)
            continue

        break

    tail = output[-300:].lower()
    return output, ("#" in tail)


def extract_total_entries(txt: str) -> int:
    """Parse IOS-style 'Total entries displayed: X' from show lldp neighbors output."""
    if not txt:
        return 0
    for line in reversed(txt.splitlines()):
        if "Total entries displayed" in line:
            try:
                return int(line.split(":")[-1].strip())
            except Exception:
                return 0
    return 0


def enable_lldp_and_collect(device: str, jump_host: dict, device_user: str, device_pass: str):
    """
    For a given CAS device via a specific jump host:
    - Login (telnet from jump host)
    - Ensure enable mode
    - Enable LLDP (best effort)
    - Run 'show lldp neighbors' twice w/ waits; keep the most complete output
    - Return output + chosen lldp neighbors output for separate TXT summary
    """
    max_attempts = 3
    last_exception = None

    for attempt in range(1, max_attempts + 1):
        conn = None
        try:
            print(f"[{device}] LLDP attempt {attempt}/{max_attempts} via jump {jump_host['host']}...")

            conn, login_output = login_to_cas_via_jump(jump_host, device, device_user, device_pass)
            output = login_output

            # No paging + avoid wrapping (best effort)
            output += conn.send_command_timing("terminal length 0", strip_command=False, strip_prompt=False)
            output += conn.send_command_timing("terminal width 512", strip_command=False, strip_prompt=False)

            # Enable mode
            output, in_enable = ensure_enable_mode(conn, device_pass, output_prefix=output)
            if not in_enable:
                conn.disconnect()
                return device, "ERROR", "Could not reach enable mode", output, ""

            # Enable LLDP globally (IOS)
            output += conn.send_command_timing("config terminal", strip_command=False, strip_prompt=False)
            output += conn.send_command_timing("lldp run", strip_command=False, strip_prompt=False)
            output += conn.send_command_timing("end", strip_command=False, strip_prompt=False)

            # Let LLDP populate neighbors, collect twice
            time.sleep(10)
            lldp_1 = conn.send_command_timing("show lldp neighbors", strip_command=False, strip_prompt=False)

            time.sleep(5)
            lldp_2 = conn.send_command_timing("show lldp neighbors", strip_command=False, strip_prompt=False)

            t1 = extract_total_entries(lldp_1)
            t2 = extract_total_entries(lldp_2)

            lldp_neighbors = lldp_2 if t2 >= t1 else lldp_1

            # Log both attempts + selection
            output += "\n\n--- LLDP attempt #1 ---\n" + (lldp_1 or "")
            output += "\n\n--- LLDP attempt #2 ---\n" + (lldp_2 or "")
            output += "\n\n--- LLDP chosen for summary ---\n" + (lldp_neighbors or "")

            conn.disconnect()

            detail = f"Collected 'show lldp neighbors' output successfully (entries {max(t1, t2)})"
            return device, "GOOD", detail, output, lldp_neighbors

        except (NetmikoAuthenticationException, NetmikoTimeoutException, RuntimeError) as e:
            last_exception = e
            print(f"[{device}] Attempt {attempt}/{max_attempts} via {jump_host['host']} failed: {e}")
            try:
                if conn:
                    conn.disconnect()
            except Exception:
                pass

        except Exception as e:
            last_exception = e
            print(f"[{device}] Unexpected failure on attempt {attempt}/{max_attempts} via {jump_host['host']}: {e}")
            try:
                if conn:
                    conn.disconnect()
            except Exception:
                pass

    return device, "ERROR", f"Exception after {max_attempts} attempts: {last_exception}", "", ""


def main():
    # Match your usual working directory convention
    base_dir = "c:/Users/apower/Downloads/Jump"
    hosts_file = os.path.join(base_dir, "host.txt")

    # Output files
    results_path = os.path.join(base_dir, "lldp_results_detailed.txt")
    summary_path = os.path.join(base_dir, "lldp_neighbors_summary.txt")
    good_path = os.path.join(base_dir, "lldp_success.txt")
    bad_path = os.path.join(base_dir, "lldp_failed.txt")

    try:
        devices = load_devices(hosts_file)
    except Exception as e:
        print(f"ERROR: {e}")
        return

    print(f"Loaded {len(devices)} devices from {hosts_file}")

    jump_host_ips = ask_for_jump_host_ips()

    jump_username = input("Jump host username: ").strip()
    jump_password = getpass.getpass("Jump host password: ")
    device_user = input("CAS switch username: ").strip()
    device_pass = getpass.getpass("CAS switch password (and/or enable password): ")

    jump_hosts = build_jump_hosts(jump_host_ips, jump_username, jump_password)

    max_workers = compute_max_workers(len(jump_hosts), len(devices))
    print(
        f"Starting LLDP collection with up to {max_workers} parallel threads "
        f"({len(jump_hosts)} jump host(s), limit {SSH_SESSIONS_LIMIT_PER_JUMP} "
        f"sessions per jump, safety margin {SAFETY_MARGIN})."
    )

    # Ensure output dir exists
    os.makedirs(base_dir, exist_ok=True)

    with open(results_path, "w", encoding="utf-8") as results_file, \
         open(summary_path, "w", encoding="utf-8") as summary_file, \
         open(good_path, "w", encoding="utf-8") as good_file, \
         open(bad_path, "w", encoding="utf-8") as bad_file:

        header = f"===== LLDP run: {datetime.now()} =====\n\n"
        results_file.write(header)
        summary_file.write(header)

        # Round-robin assign devices to jump hosts
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for idx, device in enumerate(devices):
                assigned_jump = jump_hosts[idx % len(jump_hosts)]
                future = executor.submit(
                    enable_lldp_and_collect,
                    device,
                    assigned_jump,
                    device_user,
                    device_pass,
                )
                futures[future] = (device, assigned_jump)

            for future in as_completed(futures):
                device, jh = futures[future]

                try:
                    dev, status, detail, full_output, lldp_neighbors = future.result()
                except Exception as e:
                    dev = device
                    status = "ERROR"
                    detail = f"Unhandled exception: {e}"
                    full_output = ""
                    lldp_neighbors = ""

                line = f"{dev}: {status} - {detail} (via jump {jh['host']})"
                print(line)
                results_file.write(line + "\n")

                if status == "GOOD":
                    good_file.write(dev + "\n")
                else:
                    bad_file.write(dev + "\n")

                # Detailed raw output section
                if full_output:
                    results_file.write(
                        f"\n--- Raw output for {dev} (via {jh['host']}) ---\n"
                        f"{full_output}\n"
                    )

                # Summary file: IP + chosen show lldp neighbors output
                summary_file.write(f"===== {dev} =====\n")
                if lldp_neighbors:
                    summary_file.write(lldp_neighbors.strip() + "\n\n")
                else:
                    summary_file.write("NO LLDP OUTPUT (FAILED OR EMPTY)\n\n")

                results_file.write("\n")

    print("\nLLDP collection completed.")
    print(f"Detailed results saved to {results_path}")
    print(f"LLDP neighbors summary saved to {summary_path}")
    print(f"Successful devices saved to {good_path}")
    print(f"Failed devices saved to {bad_path}")


if __name__ == "__main__":
    main()
