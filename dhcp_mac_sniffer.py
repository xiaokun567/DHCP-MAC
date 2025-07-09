#!/usr/bin/env python3
"""A simple DHCP packet sniffer that captures client MAC addresses and
exposes them via a minimal web UI with click-to-copy functionality.

Usage (requires administrator/root privileges to listen in promiscuous mode):
    python dhcp_mac_sniffer.py --iface <network_interface>

On Windows, make sure Npcap is installed (https://npcap.com/) so Scapy can
capture packets.
"""
from __future__ import annotations

import argparse
import threading
import time
import os
from typing import List, Set, Dict
from collections import OrderedDict
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request

# Scapy imports
from scapy.all import (  # type: ignore
    sniff,  # still used by AsyncSniffer internally
    AsyncSniffer,
    DHCP,
    Ether,
    ARP,
    BOOTP,
    get_if_hwaddr,
    get_if_list,
)

# Try to import Windows-friendly list helper
try:
    from scapy.arch.windows import get_windows_if_list as scapy_win_if_list  # type: ignore
except ImportError:
    scapy_win_if_list = None  # type: ignore

app = Flask(__name__)

# Thread-safe ordered dict of observed MAC -> timestamp string
observed: "OrderedDict[str, str]" = OrderedDict()
lock = threading.Lock()

# Track sniffer state
sniffer_running: bool = False
sniffer_start_time: datetime | None = None
selected_iface: str | None = None

# Async sniffer instance
sniffer: AsyncSniffer | None = None

# Gather host's own MAC addresses to filter them out
own_macs: Set[str] = set()
for _iface in get_if_list():
    try:
        own_macs.add(get_if_hwaddr(_iface).upper())
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Packet sniffer
# ---------------------------------------------------------------------------

def _mac_from_dhcp(pkt):
    try:
        chaddr = pkt[BOOTP].chaddr  # type: ignore[index]
        return ":".join(f"{b:02X}" for b in chaddr[:6])
    except Exception:
        return None


def _process_packet(pkt):
    """Callback for each sniffed packet."""
    mac = None
    if pkt.haslayer(DHCP) and pkt.haslayer(BOOTP):
        mac = _mac_from_dhcp(pkt)
    elif pkt.haslayer(ARP):
        mac = pkt[ARP].hwsrc.upper()
    elif pkt.haslayer(Ether):
        mac = pkt[Ether].src.upper()

    if mac and mac not in own_macs:
        with lock:
            if mac not in observed:
                ts = f"{datetime.now().month}/{datetime.now().day} {datetime.now().hour:02d}:{datetime.now().minute:02d}"
                observed[mac] = ts
                app.logger.info("Discovered MAC: %s at %s", mac, ts)


def start_sniffer(iface: str | None = None):
    """Start sniffing asynchronously on the given interface."""
    global sniffer_running, sniffer_start_time, selected_iface, sniffer

    # If already running, do nothing
    if sniffer_running:
        return

    selected_iface = iface
    sniffer_start_time = datetime.now()

    sniffer = AsyncSniffer(
        prn=_process_packet,
        filter="(udp and (port 67 or port 68)) or arp",
        store=False,
        iface=iface,
    )
    sniffer.start()
    sniffer_running = True


def stop_sniffer():
    """Stop the active sniffer if running."""
    global sniffer_running, sniffer
    if sniffer_running and sniffer is not None:
        try:
            sniffer.stop()
        except Exception as exc:  # noqa: broad-exception-caught
            app.logger.error("Stop sniffer error: %s", exc)
        sniffer_running = False
        sniffer = None


def restart_sniffer(iface: str | None = None):
    """Restart the sniffer on a new interface."""
    stop_sniffer()
    start_sniffer(iface)


# ---------------------------------------------------------------------------
# Flask web UI
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang=\"en\">
<head>
    <meta charset=\"UTF-8\">
    <title>DHCP MAC Sniffer</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2em; }
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        button { padding: 4px 8px; margin-left: 4px; }
        select { padding: 4px; }
    </style>
</head>
<body>
<h2>DHCP MAC Sniffer</h2>

<div style=\"margin-bottom:1em;\">
    <label for=\"iface-select\">Interface:</label>
    <select id=\"iface-select\"></select>
    <button id=\"restart-btn\">Restart</button>
    <button id=\"stop-btn\">Stop</button>
    <button id=\"clear-btn\">Clear MACs</button>
    <button id=\"kill-btn\" style=\"background-color:#e74c3c;color:#fff;\">Kill</button>
</div>

<p id=\"status\">Status: <span style=\"color: gray;\">initializing...</span></p>

<h3>Observed MAC Addresses</h3>
<p>The page updates automatically. Click the copy button to copy a MAC address to your clipboard.</p>

<table id=\"mac-table\">
    <thead>
        <tr><th>No.</th><th>MAC Address</th><th>Time</th><th>Action</th></tr>
    </thead>
    <tbody></tbody>
</table>

<script>
async function fetchInterfaces() {
    const resp = await fetch('/interfaces');
    const ifaces = await resp.json();
    const sel = document.getElementById('iface-select');
    sel.innerHTML = '';
    ifaces.forEach(item => {
        const opt = document.createElement('option');
        opt.value = item.value;
        opt.textContent = item.label;
        sel.appendChild(opt);
    });
}

async function fetchMacs() {
    const resp = await fetch('/macs');
    const macs = await resp.json();
    const tbody = document.querySelector('#mac-table tbody');
    tbody.innerHTML = '';
    macs.forEach((item, idx) => {
        const row = document.createElement('tr');
        const cellIdx = document.createElement('td');
        cellIdx.textContent = idx + 1;
        const cellMac = document.createElement('td');
        cellMac.textContent = item.mac;
        const cellTime = document.createElement('td');
        cellTime.textContent = item.time;
        const cellBtn = document.createElement('td');
        const btn = document.createElement('button');
        btn.textContent = 'Copy';
        btn.onclick = () => navigator.clipboard.writeText(item.mac);
        cellBtn.appendChild(btn);
        row.appendChild(cellIdx);
        row.appendChild(cellMac);
        row.appendChild(cellTime);
        row.appendChild(cellBtn);
        tbody.appendChild(row);
    });
}

async function updateStatus() {
    try {
        const resp = await fetch('/status');
        const data = await resp.json();
        const span = document.querySelector('#status span');
        if (data.running) {
            span.textContent = `Listening on ${data.iface || 'ALL'} (MACs: ${data.mac_count})`;
            span.style.color = 'green';
        } else {
            span.textContent = 'Not listening';
            span.style.color = 'red';
        }
    } catch (e) {
        const span = document.querySelector('#status span');
        span.textContent = 'Error';
        span.style.color = 'red';
    }
}

async function control(action) {
    const raw = document.getElementById('iface-select').value;
    const iface = raw === 'null' || raw === '' ? null : raw;
    await fetch('/control', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: action, iface: iface })
    });
    updateStatus();
}

document.getElementById('restart-btn').onclick = () => control('restart');
document.getElementById('stop-btn').onclick = () => control('stop');
document.getElementById('kill-btn').onclick = () => fetch('/kill', {method:'POST'});
document.getElementById('clear-btn').onclick = () => {
    fetch('/clear', {method:'POST'}).then(fetchMacs);
};

setInterval(fetchMacs, 1000);
setInterval(updateStatus, 1000);

fetchInterfaces().then(() => {
    fetchMacs();
    updateStatus();
});
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route("/macs")
def macs():
    with lock:
        current = [{"mac": m, "time": t} for m, t in observed.items()]
    return jsonify(current)


@app.route("/status")
def status():
    return jsonify(
        running=sniffer_running,
        iface=selected_iface,
        mac_count=len(observed),
        started=str(sniffer_start_time) if sniffer_start_time else None,
    )


@app.route("/interfaces")
def interfaces():
    """Return list of interfaces with friendly labels for dropdown."""
    data = []
    data.append({"value": None, "label": "ALL"})

    if scapy_win_if_list is not None:
        for info in scapy_win_if_list():
            data.append({"value": info.get("name"), "label": info.get("description")})
    else:
        for name in get_if_list():
            data.append({"value": name, "label": name})

    return jsonify(data)


@app.route("/control", methods=["POST"])
def control():
    data = request.get_json(force=True)
    action = data.get("action")
    iface = data.get("iface")
    if iface == "" or iface is None or iface == "null":
        iface = None

    if action == "stop":
        stop_sniffer()
    elif action in ("restart", "start"):
        restart_sniffer(iface)
    return status()


# ---------------------------------------------------------------------------
# Kill route
# ---------------------------------------------------------------------------


@app.route("/kill", methods=["POST"])
def kill():
    """Terminate the Flask process (used by Kill button)."""
    stop_sniffer()

    # Use a timer so response can be sent before exiting
    threading.Timer(0.5, lambda: os._exit(0)).start()
    return jsonify({"status": "terminating"})


# ---------------------------------------------------------------------------
# Clear route
# ---------------------------------------------------------------------------


@app.route("/clear", methods=["POST"])
def clear_macs():
    with lock:
        observed.clear()
    return jsonify({"status": "cleared"})


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Simple DHCP MAC sniffer with web UI")
    parser.add_argument(
        "--iface", "-i", default=None, help="Network interface to listen on (default: all interfaces)"
    )
    parser.add_argument("--port", "-p", type=int, default=8080, help="Web UI port (default: 8080)")
    args = parser.parse_args()

    app.logger.info("Starting DHCP sniffer on interface: %s", args.iface or "ALL")
    start_sniffer(args.iface)
    # Give sniffer some time to start to avoid missing early packets
    time.sleep(0.5)

    app.run(host="0.0.0.0", port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main() 