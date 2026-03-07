#!/usr/bin/env python3
"""
NetInventory - Lightweight home network scanner and inventory dashboard.
Scans a subnet, tracks hosts, and serves a web dashboard.
"""

import os
import json
import time
import socket
import sqlite3
import threading
import subprocess
import logging
from datetime import datetime
from flask import Flask, jsonify, render_template, request

# ── Configuration ─────────────────────────────────────────────────────────────
SUBNET         = os.environ.get("NETINV_SUBNET",   "192.168.1.0/24")
SCAN_INTERVAL  = int(os.environ.get("NETINV_INTERVAL", "300"))   # seconds
WEB_PORT       = int(os.environ.get("NETINV_PORT",    "8080"))
DB_PATH        = os.environ.get("NETINV_DB",        "/var/lib/netinventory/hosts.db")
LOG_LEVEL      = os.environ.get("NETINV_LOGLEVEL",  "INFO")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("netinventory")

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Database ──────────────────────────────────────────────────────────────────
def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS hosts (
                ip          TEXT PRIMARY KEY,
                mac         TEXT,
                hostname    TEXT,
                vendor      TEXT,
                open_ports  TEXT,
                os_hint     TEXT,
                online      INTEGER DEFAULT 0,
                first_seen  TEXT,
                last_seen   TEXT,
                last_scan   TEXT
            );
            CREATE TABLE IF NOT EXISTS scan_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at  TEXT,
                hosts_up    INTEGER,
                hosts_total INTEGER,
                duration_s  REAL
            );
        """)
    log.info("Database initialised at %s", DB_PATH)

# ── OUI / MAC vendor lookup (offline, bundled subset) ─────────────────────────
# A minimal built-in table covering common home devices.
# Full OUI list can be dropped in as oui.txt (IEEE format) for broader coverage.
BUILTIN_OUI = {
    "00:50:56": "VMware",         "00:0C:29": "VMware",
    "00:1A:11": "Google",         "F4:F5:D8": "Google",
    "B8:27:EB": "Raspberry Pi",   "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",   "28:CD:C1": "Raspberry Pi",
    "00:17:88": "Philips Hue",
    "18:B4:30": "Nest Labs",      "64:16:66": "Nest Labs",
    "AC:84:C6": "Apple",          "F0:18:98": "Apple",
    "A4:C3:F0": "Apple",          "00:1F:F3": "Apple",
    "70:56:81": "Apple",          "D0:03:4B": "Apple",
    "3C:22:FB": "Apple",
    "00:23:14": "Belkin",         "94:10:3E": "Belkin",
    "30:23:03": "Belkin",
    "00:18:E7": "Netgear",        "20:E5:2A": "Netgear",
    "A0:40:A0": "Netgear",
    "C8:3A:35": "Tenda",
    "FC:EC:DA": "Ubiquiti",       "00:27:22": "Ubiquiti",
    "04:18:D6": "Ubiquiti",       "80:2A:A8": "Ubiquiti",
    "00:1D:7E": "Cisco/Linksys",  "00:14:BF": "Cisco/Linksys",
    "00:25:9C": "Cisco",          "70:69:5A": "Cisco",
    "B0:BE:76": "TP-Link",        "98:DA:C4": "TP-Link",
    "50:C7:BF": "TP-Link",        "18:D6:C7": "TP-Link",
    "48:8D:36": "TP-Link",
    "00:50:F2": "Microsoft",      "28:18:78": "Microsoft",
    "00:15:5D": "Microsoft (Hyper-V)",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:1E:C9": "Dell",           "14:18:77": "Dell",
    "F8:DB:88": "Dell",
    "AC:16:2D": "HP",             "3C:D9:2B": "HP",
    "00:24:81": "HP",
    "00:1C:C0": "Samsung",        "CC:07:AB": "Samsung",
    "F4:7B:5E": "Samsung",        "30:07:4D": "Samsung",
    "00:12:FB": "Samsung",
    "00:16:3E": "Xen",
}

OUI_FILE = os.path.join(os.path.dirname(__file__), "oui.txt")
_oui_cache = {}

def load_oui_file():
    """Load IEEE OUI file if present (format: XX-XX-XX   Vendor Name)."""
    if not os.path.exists(OUI_FILE):
        return
    try:
        with open(OUI_FILE) as f:
            for line in f:
                if "(hex)" in line:
                    parts = line.split("(hex)")
                    mac_raw = parts[0].strip().replace("-", ":").upper()
                    vendor  = parts[1].strip() if len(parts) > 1 else "Unknown"
                    _oui_cache[mac_raw] = vendor
        log.info("Loaded %d OUI entries from %s", len(_oui_cache), OUI_FILE)
    except Exception as e:
        log.warning("Could not load OUI file: %s", e)

def lookup_vendor(mac: str) -> str:
    if not mac:
        return "Unknown"
    prefix = mac.upper()[:8]
    if prefix in _oui_cache:
        return _oui_cache[prefix]
    if prefix in BUILTIN_OUI:
        return BUILTIN_OUI[prefix]
    return "Unknown"

# ── Scanner ───────────────────────────────────────────────────────────────────
def run_nmap(subnet: str) -> list[dict]:
    """Run nmap ping+ARP scan, return list of host dicts."""
    try:
        # -sn  : ping scan (no port scan) — fast sweep
        # -O   : OS detection (needs root) — graceful if missing
        # --host-timeout : don't hang on slow hosts
        result = subprocess.run(
            ["nmap", "-sn", "--host-timeout", "2s", "-oX", "-", subnet],
            capture_output=True, text=True, timeout=120
        )
        return parse_nmap_xml(result.stdout)
    except FileNotFoundError:
        log.error("nmap not found — install with: sudo apt install nmap")
        return []
    except subprocess.TimeoutExpired:
        log.warning("nmap scan timed out")
        return []
    except Exception as e:
        log.error("nmap error: %s", e)
        return []

def run_nmap_ports(ip: str) -> list[str]:
    """Quick port scan of common ports for a single online host."""
    common_ports = "21,22,23,25,53,80,443,445,3389,8080,8443,8888,9090,5000,5900,1883,6443"
    try:
        result = subprocess.run(
            ["nmap", "-p", common_ports, "--open", "--host-timeout", "3s", "-oX", "-", ip],
            capture_output=True, text=True, timeout=30
        )
        return parse_open_ports(result.stdout)
    except Exception:
        return []

def parse_nmap_xml(xml: str) -> list[dict]:
    """Parse nmap XML output without external deps."""
    import xml.etree.ElementTree as ET
    hosts = []
    if not xml.strip():
        return hosts
    try:
        root = ET.fromstring(xml)
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is None or status.get("state") != "up":
                continue

            ip  = ""
            mac = ""
            for addr in host_el.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr", "").upper()

            hostname = ""
            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    if hn.get("type") in ("PTR", "user"):
                        hostname = hn.get("name", "")
                        break

            # Try reverse DNS if nmap didn't resolve it
            if not hostname and ip:
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    pass

            os_hint = ""
            osmatch = host_el.find(".//osmatch")
            if osmatch is not None:
                os_hint = osmatch.get("name", "")

            if ip:
                hosts.append({
                    "ip": ip, "mac": mac, "hostname": hostname, "os_hint": os_hint
                })
    except ET.ParseError as e:
        log.warning("XML parse error: %s", e)
    return hosts

def parse_open_ports(xml: str) -> list[str]:
    import xml.etree.ElementTree as ET
    ports = []
    if not xml.strip():
        return ports
    try:
        root = ET.fromstring(xml)
        for port_el in root.findall(".//port"):
            state = port_el.find("state")
            if state is not None and state.get("state") == "open":
                portid  = port_el.get("portid", "")
                svc_el  = port_el.find("service")
                svcname = svc_el.get("name", "") if svc_el is not None else ""
                ports.append(f"{portid}/{svcname}" if svcname else portid)
    except Exception:
        pass
    return ports

def scan_subnet(subnet: str):
    """Full scan cycle: ping sweep + port scan of live hosts → DB update."""
    log.info("Starting scan of %s", subnet)
    start = time.time()
    now   = datetime.utcnow().isoformat(timespec="seconds") + "Z"

    hosts = run_nmap(subnet)
    log.info("Ping sweep found %d hosts up", len(hosts))

    # Mark everything offline first
    with get_db() as conn:
        conn.execute("UPDATE hosts SET online=0, last_scan=?", (now,))

    for h in hosts:
        ip  = h["ip"]
        mac = h["mac"]
        # Port scan each live host
        ports = run_nmap_ports(ip)
        vendor = lookup_vendor(mac)

        with get_db() as conn:
            existing = conn.execute("SELECT first_seen FROM hosts WHERE ip=?", (ip,)).fetchone()
            first_seen = existing["first_seen"] if existing else now

            conn.execute("""
                INSERT INTO hosts (ip, mac, hostname, vendor, open_ports, os_hint, online, first_seen, last_seen, last_scan)
                VALUES (?,?,?,?,?,?,1,?,?,?)
                ON CONFLICT(ip) DO UPDATE SET
                    mac        = excluded.mac,
                    hostname   = excluded.hostname,
                    vendor     = excluded.vendor,
                    open_ports = excluded.open_ports,
                    os_hint    = excluded.os_hint,
                    online     = 1,
                    last_seen  = excluded.last_seen,
                    last_scan  = excluded.last_scan
            """, (ip, mac, h["hostname"], vendor,
                  json.dumps(ports), h["os_hint"],
                  first_seen, now, now))

    duration = round(time.time() - start, 1)
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        conn.execute(
            "INSERT INTO scan_history (scanned_at, hosts_up, hosts_total, duration_s) VALUES (?,?,?,?)",
            (now, len(hosts), total, duration)
        )

    log.info("Scan complete: %d up / %d total in %.1fs", len(hosts), total, duration)

def scanner_loop():
    """Background thread: scan on startup, then every SCAN_INTERVAL seconds."""
    log.info("Scanner thread started — interval=%ds subnet=%s", SCAN_INTERVAL, SUBNET)
    while True:
        try:
            scan_subnet(SUBNET)
        except Exception as e:
            log.exception("Scan error: %s", e)
        time.sleep(SCAN_INTERVAL)

# ── API routes ─────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/hosts")
def api_hosts():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM hosts ORDER BY CAST(SUBSTR(ip, INSTR(ip,'.')+1+INSTR(SUBSTR(ip,INSTR(ip,'.')+1),'.')+INSTR(SUBSTR(ip,INSTR(ip,'.')+1+INSTR(SUBSTR(ip,INSTR(ip,'.')+1),'.')+1),'.'),100) AS INTEGER)"
        ).fetchall()
        hosts = [dict(r) for r in rows]
        for h in hosts:
            try:
                h["open_ports"] = json.loads(h["open_ports"] or "[]")
            except Exception:
                h["open_ports"] = []
    return jsonify(hosts)

@app.route("/api/stats")
def api_stats():
    with get_db() as conn:
        total  = conn.execute("SELECT COUNT(*) FROM hosts").fetchone()[0]
        online = conn.execute("SELECT COUNT(*) FROM hosts WHERE online=1").fetchone()[0]
        last   = conn.execute(
            "SELECT scanned_at, duration_s FROM scan_history ORDER BY id DESC LIMIT 1"
        ).fetchone()
        history = conn.execute(
            "SELECT scanned_at, hosts_up FROM scan_history ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return jsonify({
        "total": total,
        "online": online,
        "offline": total - online,
        "subnet": SUBNET,
        "scan_interval": SCAN_INTERVAL,
        "last_scan": dict(last) if last else None,
        "history": [dict(r) for r in reversed(history)],
    })

@app.route("/api/scan", methods=["POST"])
def api_trigger_scan():
    """Trigger an immediate scan (runs in background)."""
    t = threading.Thread(target=scan_subnet, args=(SUBNET,), daemon=True)
    t.start()
    return jsonify({"status": "scan started"})

# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    load_oui_file()

    scanner = threading.Thread(target=scanner_loop, daemon=True)
    scanner.start()

    log.info("NetInventory dashboard at http://0.0.0.0:%d", WEB_PORT)
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)
