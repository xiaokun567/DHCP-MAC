# DHCP MAC Sniffer

This project contains a **minimal DHCP packet sniffer** that passively listens
for DHCP traffic on your network, extracts client MAC addresses, and presents
them in a web UI where each MAC address can be copied with a single click.

> ⚠️  The script does **not** respond to DHCP requests; it only observes them.

## Prerequisites

1. **Python 3.8+**
2. **Administrator / root privileges** (required for packet capturing)
3. On Windows, install **Npcap** (https://npcap.com/) and be sure to enable the
   option _“Install Npcap in WinPcap API-compatible Mode”_.

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Usage

```bash
# Run on all interfaces and serve UI on http://localhost:8080
python dhcp_mac_sniffer.py

# Specify a particular interface and custom port
python dhcp_mac_sniffer.py --iface Ethernet --port 8080
```

Open your browser to the indicated address; newly observed MAC addresses will
appear automatically. Click **Copy** next to any address to copy it to your
clipboard.

## How it works

* The script uses **Scapy** to sniff packets with a BPF filter:
  `udp and (port 67 or port 68)`.
* When a packet containing a DHCP layer is seen, the source MAC address is
  extracted from the Ethernet header and stored.
* A lightweight **Flask** server hosts a small HTML page that periodically
  fetches the current list of MAC addresses via AJAX.

Since the program only listens and never transmits, no communication is
established with the client devices. 