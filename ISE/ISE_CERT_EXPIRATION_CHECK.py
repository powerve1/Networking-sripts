#!/usr/bin/env python3
"""
Cisco ISE - Certificate Expiration Report (Admin + EAP)

Goal
- For each ISE host in ise_hosts.txt, identify the System Certificate currently used for:
  - Admin
  - EAP Authentication
- Export a report that includes:
  - Host IP (from ise_hosts.txt)
  - Certificate "friendlyName"
  - Expiration date formatted as "DD Mon YYYY" (e.g., 29 Mar 2026)

How it works (ISE 3.1+ OpenAPI)
1) Uses the ISE API Gateway (port 443) with an OpenAPI admin account.
2) Retrieves the deployment node list:
      GET https://<HOST>/api/v1/deployment/node
   and maps each IP to a node hostname.
3) Retrieves the system certs for that node:
      GET https://<HOST>/api/v1/certs/system-certificate/<NODE-HOSTNAME>
   and finds the cert entries whose "usedBy" includes:
      - "Admin"
      - "EAP Authentication"

References
- Cisco doc: system certificate API + fields 'usedBy' and 'expirationDate'
  https://<ISE>/api/v1/certs/system-certificate/<ISE-Node-Hostname>

Outputs
- ise_cert_expiration_report.csv
- ise_cert_expiration_summary.txt
- ise_cert_expiration.log
"""

import csv
import datetime
import getpass
import json
import sys
from pathlib import Path

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -------------------------------------------------------------------------
# Files / paths
# -------------------------------------------------------------------------
HOSTS_FILE = "ise_hosts.txt"
LOG_FILE = "ise_cert_expiration.log"
CSV_FILE = "ise_cert_expiration_report.csv"
SUMMARY_FILE = "ise_cert_expiration_summary.txt"

# -------------------------------------------------------------------------
# API settings (OpenAPI / API Gateway)
# -------------------------------------------------------------------------
PORT = 443
TIMEOUT_SEC = 25

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}


def now_ts() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(message: str) -> None:
    entry = f"[{now_ts()}] {message}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry + "\n")
    print(entry, flush=True)


def load_hosts(file_path: str) -> list[str]:
    """
    Load ISE hosts from a text file (supports # comments / blank lines).
    Each line should be an IP or resolvable hostname.
    """
    p = Path(file_path)
    if not p.exists():
        raise FileNotFoundError(f"Hosts file not found: {file_path}")

    hosts: list[str] = []
    for raw in p.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "#" in line:
            line = line.split("#", 1)[0].strip()
        if line:
            hosts.append(line)

    # de-dup while preserving order
    return list(dict.fromkeys(hosts))


def safe_json(resp: requests.Response) -> dict:
    try:
        return resp.json()
    except Exception:
        return {}


def format_error_detail(resp: requests.Response) -> str:
    j = safe_json(resp)
    if j:
        return f"HTTP {resp.status_code} - {json.dumps(j, ensure_ascii=False)}"

    txt = (resp.text or "").strip()
    if txt:
        if len(txt) > 600:
            txt = txt[:600] + "...(truncated)"
        return f"HTTP {resp.status_code} - {txt}"

    return f"HTTP {resp.status_code} - No response body"


def parse_ise_expiration_date(raw: str) -> datetime.date | None:
    """
    ISE often returns expirationDate like:
      'Sun Mar 29 01:06:22 CST 2026'

    Python's strptime can choke on arbitrary TZ abbreviations.
    We remove the timezone token and parse:
      'Sun Mar 29 01:06:22 2026'
    """
    if not raw:
        return None

    parts = raw.split()
    # Expected: [Sun, Mar, 29, 01:06:22, CST, 2026] (len=6)
    if len(parts) >= 6:
        # remove timezone token at index 4
        no_tz = " ".join(parts[0:4] + parts[5:6])
        try:
            dt = datetime.datetime.strptime(no_tz, "%a %b %d %H:%M:%S %Y")
            return dt.date()
        except Exception:
            pass

    # Fallback: try a couple of other common layouts without tz
    for fmt in ("%a %b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Y", "%Y-%m-%d"):
        try:
            dt = datetime.datetime.strptime(raw, fmt)
            return dt.date()
        except Exception:
            continue

    return None


def fmt_dd_mon_yyyy(d: datetime.date | None) -> str:
    if not d:
        return "UNKNOWN"
    return d.strftime("%d %b %Y")  # e.g., 29 Mar 2026


def get_deployment_nodes(session: requests.Session, base: str) -> tuple[list[dict] | None, str]:
    """
    Returns list of nodes from:
      GET /api/v1/deployment/node
    """
    url = f"{base}/api/v1/deployment/node"
    r = session.get(url, timeout=TIMEOUT_SEC)
    if r.status_code == 200:
        body = safe_json(r)
        # Most ISE OpenAPI responses use {"response":[...], "version":"..."}
        nodes = body.get("response")
        if isinstance(nodes, list):
            return nodes, "OK"
        return None, "Unexpected payload (missing 'response' list)"
    if r.status_code == 401:
        return None, "Unauthorized (check OpenAPI credentials / privileges)"
    return None, format_error_detail(r)


def resolve_node_hostname_from_ip(nodes: list[dict], host_ip_or_name: str) -> str | None:
    """
    Attempts to find the node hostname corresponding to the host entry.

    Note:
    - If you use hostnames in ise_hosts.txt, this function may not match (no DNS).
      In that case we fall back to trying the cert API using the host entry directly.
    """
    needle = host_ip_or_name.strip().lower()
    for n in nodes:
        ip = str(n.get("ipAddress", "")).strip().lower()
        hn = str(n.get("hostname", "")).strip()
        if ip and ip == needle and hn:
            return hn
    return None


def get_system_certs_for_node(session: requests.Session, base: str, node_hostname: str) -> tuple[list[dict] | None, str]:
    """
    Returns list of certs from:
      GET /api/v1/certs/system-certificate/<node-hostname>
    """
    url = f"{base}/api/v1/certs/system-certificate/{node_hostname}"
    r = session.get(url, timeout=TIMEOUT_SEC)
    if r.status_code == 200:
        body = safe_json(r)
        certs = body.get("response")
        if isinstance(certs, list):
            return certs, "OK"
        return None, "Unexpected payload (missing 'response' list)"
    if r.status_code == 401:
        return None, "Unauthorized (check OpenAPI credentials / privileges)"
    if r.status_code == 404:
        return None, f"Not found (node hostname '{node_hostname}' may be incorrect)"
    return None, format_error_detail(r)


def find_admin_and_eap_certs(certs: list[dict]) -> tuple[dict | None, dict | None]:
    """
    From a list of system cert objects, find the cert used by Admin and EAP Authentication.
    """
    admin_cert = None
    eap_cert = None

    for c in certs:
        used_by = (c.get("usedBy") or "")
        used_by_l = used_by.lower()

        if (admin_cert is None) and ("admin" in used_by_l):
            admin_cert = c
        if (eap_cert is None) and ("eap authentication" in used_by_l or "eap" in used_by_l):
            # Prefer explicit "EAP Authentication" match; 'eap' fallback covers some variants.
            eap_cert = c

    return admin_cert, eap_cert


def write_outputs(rows: list[dict], failures: list[tuple[str, str]]) -> None:
    # CSV
    fieldnames = [
        "host",
        "node_hostname",
        "admin_cert_friendly_name",
        "admin_cert_expires",
        "eap_cert_friendly_name",
        "eap_cert_expires",
    ]
    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})

    # Summary TXT
    lines: list[str] = []
    lines.append(f"ISE Certificate Expiration Summary - {now_ts()}")
    lines.append("=" * 72)
    lines.append("")
    lines.append(f"Hosts File : {HOSTS_FILE}")
    lines.append(f"CSV Output : {CSV_FILE}")
    lines.append(f"Log File   : {LOG_FILE}")
    lines.append("")

    lines.append(f"SUCCESS ({len(rows)}):")
    if rows:
        for r in rows:
            lines.append(
                f"  - {r['host']} ({r['node_hostname']}): "
                f"Admin={r['admin_cert_expires']} | EAP={r['eap_cert_expires']}"
            )
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"FAILED ({len(failures)}):")
    if failures:
        for h, reason in failures:
            lines.append(f"  - {h}: {reason}")
    else:
        lines.append("  (none)")
    lines.append("")

    Path(SUMMARY_FILE).write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    print("ISE certificate expiration report script started...", flush=True)

    api_user = input("Enter ISE OpenAPI username: ").strip()
    api_pass = getpass.getpass("Enter ISE OpenAPI password: ")

    if not api_user:
        print("ERROR: OpenAPI username is required.")
        return 2
    if not api_pass:
        print("ERROR: OpenAPI password is required.")
        return 2

    try:
        ise_hosts = load_hosts(HOSTS_FILE)
    except Exception as e:
        print(f"ERROR: {e}")
        return 2

    if not ise_hosts:
        print(f"ERROR: No hosts found in {HOSTS_FILE}")
        return 2

    log_event("------------------------------------------------------------")
    log_event("Starting certificate expiration report (Admin + EAP)")
    log_event(f"Loaded {len(ise_hosts)} host(s) from {HOSTS_FILE}")
    log_event("------------------------------------------------------------")

    session = requests.Session()
    session.headers.update(HEADERS)
    session.auth = HTTPBasicAuth(api_user, api_pass)
    session.verify = False

    rows: list[dict] = []
    failures: list[tuple[str, str]] = []

    for host in ise_hosts:
        base = f"https://{host}:{PORT}"

        try:
            nodes, nodes_reason = get_deployment_nodes(session, base)
            if not nodes:
                reason = f"Could not retrieve deployment nodes: {nodes_reason}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((host, reason))
                continue

            node_hostname = resolve_node_hostname_from_ip(nodes, host)

            # Fallback: try using the host entry directly as the node identifier
            # (some ISE setups may accept IP/hostname here, or hosts.txt already contains node hostname)
            if not node_hostname:
                node_hostname = host

            certs, certs_reason = get_system_certs_for_node(session, base, node_hostname)
            if not certs:
                reason = f"Could not retrieve system certs for node '{node_hostname}': {certs_reason}"
                log_event(f"FAILED: {host} - {reason}")
                failures.append((host, reason))
                continue

            admin_cert, eap_cert = find_admin_and_eap_certs(certs)

            admin_exp = parse_ise_expiration_date(admin_cert.get("expirationDate") if admin_cert else "")
            eap_exp = parse_ise_expiration_date(eap_cert.get("expirationDate") if eap_cert else "")

            row = {
                "host": host,
                "node_hostname": node_hostname,
                "admin_cert_friendly_name": (admin_cert.get("friendlyName") if admin_cert else "NOT FOUND"),
                "admin_cert_expires": fmt_dd_mon_yyyy(admin_exp),
                "eap_cert_friendly_name": (eap_cert.get("friendlyName") if eap_cert else "NOT FOUND"),
                "eap_cert_expires": fmt_dd_mon_yyyy(eap_exp),
            }
            rows.append(row)

            log_event(
                f"SUCCESS: {host} ({node_hostname}) "
                f"- Admin expires {row['admin_cert_expires']} | EAP expires {row['eap_cert_expires']}"
            )

        except requests.exceptions.ConnectTimeout:
            reason = f"Connection timed out (port {PORT})"
            log_event(f"FAILED: {host} - {reason}")
            failures.append((host, reason))
        except requests.exceptions.ConnectionError:
            reason = f"Connection error (check network/ACL/DNS/port {PORT})"
            log_event(f"FAILED: {host} - {reason}")
            failures.append((host, reason))
        except Exception as e:
            reason = f"Unexpected error: {str(e)}"
            log_event(f"FAILED: {host} - {reason}")
            failures.append((host, reason))

    write_outputs(rows, failures)

    log_event("------------------------------------------------------------")
    log_event(f"Finished. Success: {len(rows)} | Failed: {len(failures)}")
    log_event(f"CSV report     : {CSV_FILE}")
    log_event(f"Summary report : {SUMMARY_FILE}")
    log_event(f"Detailed log   : {LOG_FILE}")
    log_event("------------------------------------------------------------")

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
