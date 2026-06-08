from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoTimeoutException, NetmikoAuthenticationException
import getpass
import logging
from datetime import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# -------------------------------------------------------------------------
# Netmiko debug logging (optional but useful)
# -------------------------------------------------------------------------
logging.basicConfig(
    filename="netmiko_validation_debug.log",
    level=logging.DEBUG
)
logger = logging.getLogger("netmiko")

# -------------------------------------------------------------------------
# Concurrency / SSH limits
# -------------------------------------------------------------------------
SSH_SESSIONS_LIMIT_PER_JUMP = 4   # per-user session limit per jump host
SAFETY_MARGIN = 1                 # keep 1 session free for manual/debug, etc.


def load_devices(hosts_file):
    """Load device IPs/hostnames from a text file (one per line)."""
    if not os.path.exists(hosts_file):
        raise FileNotFoundError(f"Hosts file not found: {hosts_file}")

    with open(hosts_file, encoding="utf-8") as f:
        devices = [line.strip() for line in f if line.strip()]

    if not devices:
        raise ValueError(f"No devices found in {hosts_file}")

    return devices


def ask_for_jump_host_ips():
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


def build_jump_hosts(jump_host_ips, jump_username, jump_password):
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
            "conn_timeout": 20,        # time to establish TCP/SSH
            "banner_timeout": 60,      # time to wait for big legal banner
            "auth_timeout": 30,        # time for auth
            "global_delay_factor": 2,  # slow down reads a bit globally
            "fast_cli": False,         # safer for weird prompts/banners
        }
        jump_hosts.append(jh)
    return jump_hosts


def compute_max_workers(num_jump_hosts, num_devices):
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


def login_to_cas_via_jump(jump_host, device, device_user, device_pass):
    """SSH to jump host, then SSH to CAS device, return CAS prompt."""
    # Make a copy per-thread so session_log is unique per device
    jump_host_thread = dict(jump_host)
    jump_host_thread["session_log"] = f"jump_session_{device}.log"

    print(f"[{device}] Connecting via jump host {jump_host_thread['host']}...")
    conn = ConnectHandler(**jump_host_thread)

    ssh_cmd = f"ssh -l {device_user} {device}"

    output = conn.send_command_timing(
        ssh_cmd, strip_command=False, strip_prompt=False, delay_factor=4
    )

    password_sent = False
    key_accepted = False
    auth_failed = False

    for _ in range(6):
        tail = output[-200:].lower()

        if not key_accepted and ("yes/no" in tail or "continue connecting" in tail):
            output += conn.send_command_timing("yes", strip_command=False, strip_prompt=False)
            key_accepted = True
            continue

        if "password:" in tail:
            if password_sent:
                auth_failed = True
                break
            output += conn.send_command_timing(device_pass, strip_command=False, strip_prompt=False)
            password_sent = True
            continue

        if "press return" in tail or "press any key" in tail or "press enter" in tail:
            output += conn.send_command_timing("\n", strip_command=False, strip_prompt=False)
            continue

        if "#" in tail or ">" in tail:
            break

        break

    if auth_failed:
        conn.disconnect()
        raise RuntimeError("Authentication failed (password prompt repeated).")

    tail = output[-200:].strip()
    if "#" not in tail and ">" not in tail:
        for _ in range(2):
            output += conn.send_command_timing("\n", strip_command=False, strip_prompt=False)
            tail = output[-200:].strip()
            if "#" in tail or ">" in tail:
                break

    tail = output[-200:].strip()
    if "#" not in tail and ">" not in tail:
        conn.disconnect()
        raise RuntimeError("Did not reach CAS device prompt after login attempts.")

    return conn, output


def validate_device(device, jump_host, device_user, device_pass):
    """Validate netmgr presence with 3 retry attempts, using a specific jump host."""
    max_attempts = 3
    last_exception = None

    for attempt in range(1, max_attempts + 1):
        try:
            print(
                f"[{device}] Validation attempt {attempt}/{max_attempts} "
                f"via jump host {jump_host['host']}..."
            )
            conn, login_output = login_to_cas_via_jump(
                jump_host, device, device_user, device_pass
            )

            output = login_output
            output += conn.send_command_timing("terminal length 0", strip_command=False)
            output += conn.send_command_timing("show run | i username", strip_command=False)

            conn.disconnect()

            if "username netmgr" in output:
                return device, "OK", f"netmgr user found (attempt {attempt})", output
            else:
                return device, "MISSING", f"netmgr user NOT found (attempt {attempt})", output

        except (NetmikoAuthenticationException, NetmikoTimeoutException, RuntimeError) as e:
            last_exception = e
            print(f"[{device}] Attempt {attempt}/{max_attempts} via {jump_host['host']} failed: {e}")

        except Exception as e:
            last_exception = e
            print(f"[{device}] Unexpected failure on attempt {attempt}/{max_attempts} via {jump_host['host']}: {e}")

    return device, "ERROR", f"Exception after {max_attempts} attempts: {last_exception}", ""


def main():
    base_dir = "c:/Users/apower/Downloads/Jump"
    hosts_file = os.path.join(base_dir, "host.txt")
    results_path = os.path.join(base_dir, "validation_results.txt")
    missing_path = os.path.join(base_dir, "missing_netmgr.txt")

    try:
        devices = load_devices(hosts_file)
    except Exception as e:
        print(f"ERROR: {e}")
        return

    print(f"Loaded {len(devices)} devices from {hosts_file}")

    # Ask for jump host IPs (single or multiple)
    jump_host_ips = ask_for_jump_host_ips()

    # Credentials (same for all jump hosts)
    jump_username = input("Jump host username: ")
    jump_password = getpass.getpass("Jump host password: ")
    device_user = input("Cisco device username: ")
    device_pass = getpass.getpass("Cisco device password: ")

    # Build jump host connection dicts
    jump_hosts = build_jump_hosts(jump_host_ips, jump_username, jump_password)

    # Compute safe concurrency
    max_workers = compute_max_workers(len(jump_hosts), len(devices))
    print(
        f"Starting validation with up to {max_workers} parallel threads "
        f"({len(jump_hosts)} jump host(s), limit {SSH_SESSIONS_LIMIT_PER_JUMP} sessions per jump, "
        f"safety margin {SAFETY_MARGIN})."
    )

    results_file = open(results_path, "w", encoding="utf-8")
    missing_file = open(missing_path, "w", encoding="utf-8")

    header = f"===== Validation run: {datetime.now()} =====\n"
    results_file.write(header)
    print(header.strip())

    # Round-robin assign devices to jump hosts
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for idx, device in enumerate(devices):
            assigned_jump = jump_hosts[idx % len(jump_hosts)]
            future = executor.submit(
                validate_device, device, assigned_jump, device_user, device_pass
            )
            futures[future] = (device, assigned_jump)

        for future in as_completed(futures):
            device, jh = futures[future]

            try:
                dev, status, detail, full_output = future.result()
            except Exception as e:
                dev = device
                status = "ERROR"
                detail = f"Unhandled exception: {e}"
                full_output = ""

            line = f"{dev}: {status} - {detail} (via jump {jh['host']})"
            print(line)
            results_file.write(line + "\n")

            if status == "MISSING":
                missing_file.write(dev + "\n")

            if full_output:
                results_file.write(f"\n--- Raw output for {dev} (via {jh['host']}) ---\n{full_output}\n")

    results_file.close()
    missing_file.close()

    print("\nValidation completed.")
    print(f"Results saved to {results_path}")
    print(f"Devices missing netmgr saved to {missing_path}")


if __name__ == "__main__":
    main()
