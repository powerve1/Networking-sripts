from netmiko import ConnectHandler
import getpass
import logging
from datetime import datetime
import threading
from queue import Queue
import time

# -------------------------------------------------------------------------
# Netmiko debug logging
# -------------------------------------------------------------------------
logging.basicConfig(
    filename="netmiko_debug.log",
    level=logging.DEBUG
)
logger = logging.getLogger("netmiko")

# Lock to protect writes to results file
write_lock = threading.Lock()


def ssh_to_device_via_jump(jump_conn, device, device_user, device_pass):
    """
    Try to SSH from the jump host into a single device.

    Returns:
        output (str): full interaction log
        reached_prompt (bool): True if we ended up at '>' or '#' prompt
        auth_failed (bool): reserved, currently always False
    """
    ssh_cmd = f"ssh -l {device_user} {device}"

    # Start SSH and gather initial output
    output = jump_conn.send_command_timing(
        ssh_cmd,
        strip_command=False,
        strip_prompt=False,
        delay_factor=4,
    )

    key_accepted = False
    password_tries = 0

    # Handle SSH key + password + "press return" prompts
    for _ in range(6):
        tail = output[-200:]
        tail_lower = tail.lower()
        tail_strip = tail.strip()

        # 1) If we already see a device prompt, stop login loop
        if "#" in tail_strip or ">" in tail_strip:
            break

        # 2) First-time SSH key prompt
        if not key_accepted and ("yes/no" in tail_lower or "continue connecting" in tail_lower):
            output += jump_conn.send_command_timing(
                "yes",
                strip_command=False,
                strip_prompt=False,
                delay_factor=2,
            )
            key_accepted = True
            continue

        # 3) Password prompt (for SSH login) – send password, but limit tries
        if "password:" in tail_lower:
            if password_tries >= 3:
                # Too many tries, treat as failure
                return output, False, False
            output += jump_conn.send_command_timing(
                device_pass,
                strip_command=False,
                strip_prompt=False,
                delay_factor=3,
            )
            password_tries += 1
            continue

        # 4) "Press RETURN"/"Press Enter" prompts
        if (
            "press return" in tail_lower
            or "press any key" in tail_lower
            or "press enter" in tail_lower
        ):
            output += jump_conn.send_command_timing(
                "\n",
                strip_command=False,
                strip_prompt=False,
                delay_factor=2,
            )
            continue

        # 5) Nothing else relevant -> stop looping
        break

    # After the loop, verify we reached some prompt
    tail_strip = output[-200:].strip()
    if "#" not in tail_strip and ">" not in tail_strip:
        # Did not reach any usable prompt
        return output, False, False

    # ---------------------------------------------------------------------
    # Now go to enable mode with SAME password as device_pass
    # ---------------------------------------------------------------------
    output += jump_conn.send_command_timing(
        "enable",
        strip_command=False,
        strip_prompt=False,
        delay_factor=1,
    )

    tail_lower = output[-200:].lower()
    if "password:" in tail_lower:
        # Send enable password (same as switch password)
        output += jump_conn.send_command_timing(
            device_pass,
            strip_command=False,
            strip_prompt=False,
            delay_factor=2,
        )

    # Final check: we should have a usable prompt (ideally '#')
    tail_strip = output[-200:].strip()
    if "#" in tail_strip or ">" in tail_strip:
        return output, True, False

    return output, False, False


def connect_jump_with_retries(jump_host, device, log_text, max_jump_attempts=3):
    """
    Try to connect to the jump host up to max_jump_attempts times.
    Returns a jump_conn or None if all attempts fail.
    """
    thread_name = threading.current_thread().name

    for attempt in range(1, max_jump_attempts + 1):
        try:
            print(
                f"[{thread_name}] Connecting to jump host {jump_host['host']} "
                f"for {device} (attempt {attempt}/{max_jump_attempts})..."
            )
            jump_conn = ConnectHandler(**jump_host)
            return jump_conn

        except Exception as e:
            msg = (
                f"ERROR: Failed to connect to jump host for device {device} "
                f"on attempt {attempt}/{max_jump_attempts}: {e}"
            )
            print(msg)
            log_text.append(msg + "\n")

            if attempt == max_jump_attempts:
                # After last attempt, give up
                fail_msg = (
                    f"ERROR: Could not connect to jump host for {device} "
                    f"after {max_jump_attempts} attempts, skipping device."
                )
                print(fail_msg)
                log_text.append(fail_msg + "\n")
                return None

            # small backoff before retrying
            time.sleep(2)

    return None


def worker(device_queue, jump_host, device_user, device_pass, results_path, max_attempts):
    """
    Thread worker: pulls devices from queue, connects via jump host
    (with retries), then SSHs to device (with retries), pushes config,
    and logs output.
    """
    while True:
        device = device_queue.get()
        if device is None:
            # Sentinel -> stop this worker
            device_queue.task_done()
            break

        log_text = []
        log_text.append(f"\n\n===== Device: {device} =====\n")
        print(f"\n--- [Thread {threading.current_thread().name}] Processing {device} ---")

        # -----------------------------------------------------------------
        # Connect to jump host with retries
        # -----------------------------------------------------------------
        jump_conn = connect_jump_with_retries(
            jump_host=jump_host,
            device=device,
            log_text=log_text,
            max_jump_attempts=3  # <-- 3 attempts to connect to jump
        )

        if jump_conn is None:
            # Failed to connect to jump after retries; log and move on
            with write_lock:
                with open(results_path, "a", encoding="utf-8") as f:
                    f.writelines(log_text)
            device_queue.task_done()
            continue

        # -----------------------------------------------------------------
        # Try up to max_attempts times for this device via the jump host
        # -----------------------------------------------------------------
        for attempt in range(1, max_attempts + 1):
            print(
                f"[{threading.current_thread().name}] Connecting to {device} "
                f"(attempt {attempt}/{max_attempts})..."
            )
            try:
                output, reached_prompt, auth_failed = ssh_to_device_via_jump(
                    jump_conn, device, device_user, device_pass
                )

                # auth_failed is always False in current logic, but keep branch for future
                if auth_failed:
                    msg = f"ERROR: Authentication failed for {device}."
                    print(msg)
                    log_text.append(output + "\n" + msg + "\n")
                    break

                if not reached_prompt:
                    warn = (
                        f"WARNING: Did not reach device prompt on {device} "
                        f"(attempt {attempt}/{max_attempts})."
                    )
                    print(warn)
                    log_text.append(output + "\n" + warn + "\n")

                    if attempt == max_attempts:
                        msg = (
                            f"ERROR: Did not reach device prompt on {device} "
                            f"after {max_attempts} attempts, skipping config."
                        )
                        print(msg)
                        log_text.append(msg + "\n")
                    else:
                        # Small pause/cleanup between attempts (send a newline)
                        jump_conn.send_command_timing(
                            "\n",
                            strip_command=False,
                            strip_prompt=False,
                            delay_factor=1,
                        )
                        time.sleep(1)

                    # Retry if attempts left
                    continue

                # -----------------------------------------------------------------
                # Reached device prompt (with enable) → push config
                # -----------------------------------------------------------------
                output += jump_conn.send_command_timing(
                    "terminal length 0",
                    strip_command=False,
                    strip_prompt=False,
                    delay_factor=1,
                )
                output += jump_conn.send_command_timing(
                    "config t",
                    strip_command=False,
                    strip_prompt=False,
                    delay_factor=1,
                )
                output += jump_conn.send_command_timing(
                    "username netswi privilege 15 secret 5 $1$jpVJ$ETNF3QvXJ5HT/gelEA0mZ.",
                    strip_command=False,
                    strip_prompt=False,
                    delay_factor=1,
                )
                output += jump_conn.send_command_timing(
                    "enable secret 5 $1$y8K7$KFgQaBS8aSMPDNJTDxBAt0",
                    strip_command=False,
                    strip_prompt=False,
                    delay_factor=1,
                )
                output += jump_conn.send_command_timing(
                    "end",
                    strip_command=False,
                    strip_prompt=False,
                    delay_factor=1,
                )
                output += jump_conn.send_command_timing(
                    "write memory",
                    strip_command=False,
                    strip_prompt=False,
                    delay_factor=1,
                )

                print(output)
                log_text.append(output + "\n")
                # Successful config push, no more retries needed
                break

            except Exception as e:
                error_msg = (
                    f"ERROR: Exception while processing {device} "
                    f"on attempt {attempt}/{max_attempts}: {e}"
                )
                print(error_msg)
                log_text.append(error_msg + "\n")

                if attempt == max_attempts:
                    # After max attempts, give up
                    break
                else:
                    time.sleep(1)

        # Close this worker's jump connection
        try:
            jump_conn.disconnect()
        except Exception:
            pass

        # Write all logs for this device in one go (under lock)
        with write_lock:
            with open(results_path, "a", encoding="utf-8") as f:
                f.writelines(log_text)

        device_queue.task_done()


def main():
    # ---------------------------------------------------------------------
    # Jump host details
    # ---------------------------------------------------------------------
    jump_host = {
        "device_type": "cisco_ios_ssh",
        "host": "10.71.0.112",
        "username": input("Jump host username: "),
        "password": getpass.getpass("Jump host password: "),
        "session_log": "jump_session.log",
    }

    # ---------------------------------------------------------------------
    # Cisco device credentials
    # ---------------------------------------------------------------------
    device_user = input("Cisco device username: ")
    device_pass = getpass.getpass("Cisco device password: ")

    hosts_file = "c:/Users/apower/Downloads/Jump/host.txt"
    results_path = "c:/Users/apower/Downloads/Jump/results.txt"

    with open(hosts_file) as f:
        devices = [line.strip() for line in f if line.strip()]

    # Initialize results file
    with open(results_path, "w", encoding="utf-8") as f:
        f.write(f"===== Script run: {datetime.now()} =====\n")

    max_attempts = 3          # retries per device (once on the jump)
    max_workers = 4           # process up to 3 devices in parallel

    # Queue with all devices
    device_queue = Queue()
    for device in devices:
        device_queue.put(device)

    # Start worker threads
    threads = []
    for i in range(max_workers):
        t = threading.Thread(
            target=worker,
            args=(device_queue, jump_host, device_user, device_pass, results_path, max_attempts),
            name=f"Worker-{i+1}",
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Wait until all devices are processed
    device_queue.join()

    # Stop workers (send sentinel)
    for _ in threads:
        device_queue.put(None)
    for t in threads:
        t.join()

    print(f"\nAll outputs saved to {results_path}")


if __name__ == "__main__":
    main()
