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
    filename="netmiko_delete_users_debug.log",
    level=logging.DEBUG
)
logger = logging.getLogger("netmiko")

# -------------------------------------------------------------------------
# Concurrency / SSH limits
# -------------------------------------------------------------------------
SSH_SESSIONS_LIMIT_PER_JUMP = 3   # tune based on your SSH session limits
SAFETY_MARGIN = 1                 # keep 1 session free for manual/debug, etc.

TARGET_USERS = ["neteng", "dnaservice", "nclchk"]


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
            "conn_timeout": 20,
            "banner_timeout": 60,
            "auth_timeout": 30,
            "global_delay_factor": 2,
            "fast_cli": False,
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
    """
    SSH to jump host, then TELNET to CAS device from the jump host.

    Steps:
      - open SSH to jump host with Netmiko
      - run 'telnet <device>'
      - handle 'Username:' / 'login:' then 'Password:' prompts
      - loop until we see '>' or '#' from the CAS, AFTER we've seen some
        telnet login interaction (so we don't mistake the jump prompt for CAS)

    Returns:
        conn   -> Netmiko connection (to JUMP host, with active telnet session to CAS)
        output -> combined raw login output
    """
    # Make a copy per-thread so session_log is unique per device
    jump_host_thread = dict(jump_host)
    jump_host_thread["session_log"] = f"jump_session_{device}.log"

    print(f"[{device}] Connecting via jump host {jump_host_thread['host']}...")
    conn = ConnectHandler(**jump_host_thread)

    # ---- Start TELNET from JUMP to CAS ----
    telnet_cmd = f"telnet {device}"
    output = conn.send_command_timing(
        telnet_cmd, strip_command=False, strip_prompt=False, delay_factor=4
    )

    username_sent = False
    password_tries = 0
    seen_login_interaction = False  # flips once we see username/password/banner

    # Give it a generous loop to walk through username/password/banners
    for _ in range(30):
        tail = output[-400:].lower()

        # Check for obvious telnet failure messages first
        if (
            "connection refused" in tail
            or "connection closed" in tail
            or "closed by foreign host" in tail
            or "aborted" in tail
            or "unable to connect" in tail
        ):
            # If we never even did a username/password exchange, treat as failure
            if not seen_login_interaction:
                conn.disconnect()
                raise RuntimeError(
                    f"Telnet from jump host to {device} failed or was aborted."
                )

        # Take the last line for prompt-style checks
        lines = tail.splitlines()
        last_line = lines[-1] if lines else tail

        # 1) Username / login prompt
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

        # 2) Password prompt
        if "password:" in last_line and "#" not in last_line and ">" not in last_line:
            if password_tries >= 5:
                conn.disconnect()
                raise RuntimeError(
                    f"Too many password attempts while telnetting to {device}."
                )
            output += conn.send_command_timing(
                device_pass, strip_command=False, strip_prompt=False
            )
            password_tries += 1
            seen_login_interaction = True
            continue

        # 3) "Press any key/return/enter" banner
        if (
            "press return" in tail
            or "press any key" in tail
            or "press enter" in tail
        ):
            output += conn.send_command_timing(
                "\n", strip_command=False, strip_prompt=False
            )
            seen_login_interaction = True
            continue

        # 4) If we've seen some telnet interaction already and we now see a prompt
        if seen_login_interaction and ("#" in tail or ">" in tail):
            break

        # 5) Otherwise, send a newline to coax the next prompt
        output += conn.send_command_timing(
            "\n", strip_command=False, strip_prompt=False
        )

    # Final sanity check: did we end up on some device prompt?
    tail = output[-400:].strip().lower()
    if "#" not in tail and ">" not in tail:
        conn.disconnect()
        raise RuntimeError(
            "Did not reach CAS device prompt via Telnet from jump host."
        )

    return conn, output


def ensure_enable_mode(conn, device_pass, output_prefix=""):
    """
    Make sure we are in enable ('#') mode.
    Try 'enable', send password if prompted.
    Return combined output and a boolean indicating if we reached '#'.
    """
    output = output_prefix
    output += conn.send_command_timing(
        "enable", strip_command=False, strip_prompt=False
    )

    for _ in range(6):
        tail = output[-200:].lower()

        if "password:" in tail:
            output += conn.send_command_timing(
                device_pass, strip_command=False, strip_prompt=False
            )
            continue

        if "#" in tail:
            return output, True

        if ">" in tail:
            output += conn.send_command_timing(
                "\n", strip_command=False, strip_prompt=False
            )
            continue

        # nothing else obvious, break
        break

    tail = output[-200:].lower()
    return output, ("#" in tail)


def delete_and_validate_device(device, jump_host, device_user, device_pass):
    """
    For a given device via a specific jump host:
    - Log in (Telnet from jump host)
    - Check which target users are present
    - Delete usernames in TARGET_USERS (handling confirm)
    - Validate they are gone

    Returns: (device, status, detail, full_output)

    Status:
      - "GOOD"          -> all target users NOT present after operation
      - "GOOD_NOT_FOUND"-> none of the target users were present to begin with
      - "STILL_PRESENT" -> one or more target users still present after attempts
      - "ERROR"         -> login/exception issues
    """
    max_attempts = 3
    last_exception = None

    for attempt in range(1, max_attempts + 1):
        try:
            print(
                f"[{device}] Delete/validate attempt {attempt}/{max_attempts} "
                f"via jump host {jump_host['host']}..."
            )

            conn, login_output = login_to_cas_via_jump(
                jump_host, device, device_user, device_pass
            )

            output = login_output
            # No paging
            output += conn.send_command_timing(
                "terminal length 0", strip_command=False
            )

            # Pre-check usernames
            pre_show = conn.send_command_timing(
                "show run | i username", strip_command=False
            )
            output += pre_show

            pre_present_users = [u for u in TARGET_USERS if f"username {u}" in pre_show]

            if not pre_present_users:
                # None of the target users exist; good state already
                conn.disconnect()
                detail = (
                    f"None of target users {TARGET_USERS} present (attempt {attempt})"
                )
                return device, "GOOD_NOT_FOUND", detail, output

            # Ensure enable mode
            output, in_enable = ensure_enable_mode(
                conn, device_pass, output_prefix=output
            )
            if not in_enable:
                conn.disconnect()
                detail = "Could not reach enable mode"
                return device, "ERROR", detail, output

            # Enter config mode
            output += conn.send_command_timing(
                "config terminal", strip_command=False, strip_prompt=False
            )

            # Attempt to remove each target user
            for user in TARGET_USERS:
                cmd = f"no username {user}"
                cmd_out = conn.send_command_timing(
                    cmd, strip_command=False, strip_prompt=False
                )

                # Handle confirm prompt like:
                # "Do you want to continue? [confirm]"
                tail = cmd_out[-200:].lower()
                if "[confirm]" in tail or "do you want to continue" in tail:
                    cmd_out += conn.send_command_timing(
                        "\n", strip_command=False, strip_prompt=False
                    )

                output += cmd_out

            # Exit config mode and write memory
            output += conn.send_command_timing(
                "end", strip_command=False, strip_prompt=False
            )
            write_out = conn.send_command_timing(
                "write memory", strip_command=False, strip_prompt=False
            )
            tail = write_out[-200:].lower()
            if "[confirm]" in tail or "proceed" in tail:
                write_out += conn.send_command_timing(
                    "\n", strip_command=False, strip_prompt=False
                )
            output += write_out

            # Post-check usernames
            post_show = conn.send_command_timing(
                "show run | i username", strip_command=False
            )
            output += post_show

            conn.disconnect()

            post_present_users = [
                u for u in TARGET_USERS if f"username {u}" in post_show
            ]

            if not post_present_users:
                detail = (
                    f"All target users {TARGET_USERS} are NOT present "
                    f"after deletion (attempt {attempt})"
                )
                return device, "GOOD", detail, output
            else:
                detail = (
                    f"Some target users still present after deletion: "
                    f"{', '.join(post_present_users)} (attempt {attempt})"
                )
                return device, "STILL_PRESENT", detail, output

        except (NetmikoAuthenticationException, NetmikoTimeoutException, RuntimeError) as e:
            last_exception = e
            print(
                f"[{device}] Attempt {attempt}/{max_attempts} via "
                f"{jump_host['host']} failed: {e}"
            )

        except Exception as e:
            last_exception = e
            print(
                f"[{device}] Unexpected failure on attempt {attempt}/{max_attempts} "
                f"via {jump_host['host']}: {e}"
            )

    # If we got here, all attempts failed
    return (
        device,
        "ERROR",
        f"Exception after {max_attempts} attempts: {last_exception}",
        "",
    )


def main():
    base_dir = "c:/Users/apower/Downloads/Jump"
    hosts_file = os.path.join(base_dir, "host.txt")

    # Output files
    results_path = os.path.join(base_dir, "delete_users_results.txt")
    good_path = os.path.join(base_dir, "users_not_present.txt")
    bad_path = os.path.join(base_dir, "users_present_or_failed.txt")

    try:
        devices = load_devices(hosts_file)
    except Exception as e:
        print(f"ERROR: {e}")
        return

    print(f"Loaded {len(devices)} devices from {hosts_file}")

    # Ask for jump host IPs (single or multiple)
    jump_host_ips = ask_for_jump_host_ips()

    # Credentials (same for all jump hosts and devices)
    jump_username = input("Jump host username: ")
    jump_password = getpass.getpass("Jump host password: ")
    device_user = input("Cisco device username: ")
    device_pass = getpass.getpass("Cisco device password: ")

    # Build jump host connection dicts
    jump_hosts = build_jump_hosts(jump_host_ips, jump_username, jump_password)

    # Compute safe concurrency
    max_workers = compute_max_workers(len(jump_hosts), len(devices))
    print(
        f"Starting delete/validation with up to {max_workers} parallel threads "
        f"({len(jump_hosts)} jump host(s), limit {SSH_SESSIONS_LIMIT_PER_JUMP} "
        f"sessions per jump, safety margin {SAFETY_MARGIN})."
    )

    results_file = open(results_path, "w", encoding="utf-8")
    good_file = open(good_path, "w", encoding="utf-8")
    bad_file = open(bad_path, "w", encoding="utf-8")

    header = f"===== Delete/Validation run: {datetime.now()} =====\n"
    results_file.write(header)
    print(header.strip())
    results_file.write(f"Target users: {', '.join(TARGET_USERS)}\n\n")

    # Round-robin assign devices to jump hosts
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for idx, device in enumerate(devices):
            assigned_jump = jump_hosts[idx % len(jump_hosts)]
            future = executor.submit(
                delete_and_validate_device,
                device,
                assigned_jump,
                device_user,
                device_pass,
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

            # GOOD / GOOD_NOT_FOUND -> all three users not present
            if status in ("GOOD", "GOOD_NOT_FOUND"):
                good_file.write(dev + "\n")
            else:
                # STILL_PRESENT or ERROR -> bad list
                bad_file.write(dev + "\n")

            if full_output:
                results_file.write(
                    f"\n--- Raw output for {dev} (via {jh['host']}) ---\n"
                    f"{full_output}\n"
                )

    results_file.close()
    good_file.close()
    bad_file.close()

    print("\nDelete/validation completed.")
    print(f"Detailed results saved to {results_path}")
    print(
        f"Devices where target users are NOT present saved to {good_path}"
    )
    print(
        f"Devices where users are still present or failed to connect "
        f"saved to {bad_path}"
    )


if __name__ == "__main__":
    main()
