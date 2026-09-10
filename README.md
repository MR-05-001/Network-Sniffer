<div align="center">

# Network Sniffer

A standalone, driverless packet analysis and telemetry engine built with Python and CustomTkinter.

[![Python Version](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=flat-square)](https://github.com/)
[![Architecture](https://img.shields.io/badge/Capture-Raw%20Sockets%20(Driverless)-blue?style=flat-square)](https://github.com/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)

</div>

---

## Overview

Network Sniffer provides real-time packet inspection, flow reconstruction, and network telemetry directly via operating-system raw sockets. By using built-in system APIs (`AF_PACKET` on Linux and `SIO_RCVALL` on Windows), it removes the requirement for external capture libraries and kernel drivers like WinPcap or Npcap.

---

## Core Capabilities

| Category | Capability | Technical Details |
| :--- | :--- | :--- |
| **Decoding** | Layer 2 to Layer 7 | Ethernet II, 802.1Q VLAN, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 |
| **Application Layer** | Protocol Identification | DNS queries/responses, HTTP methods, TLS handshakes (SNI), FTP, Telnet |
| **Inspection** | Forensic Tools | Synchronized Hex/ASCII payload viewer, multi-packet TCP stream reassembly |
| **Telemetry** | Live Traffic Metrics | Conversation flows, endpoint metrics (Tx/Rx), throughput, protocol distribution |
| **Security** | Heuristic Detection | TCP SYN flood/port scan detection, unencrypted credential alerts |
| **Storage** | PCAP Interoperability | Native Libpcap reader and writer compatible with Wireshark and tcpdump |

---

## Architecture Pipeline

```text
  [ Network Interface ]
            │
            ▼
    [ Raw Socket ] ────────── (AF_PACKET / SIO_RCVALL Promiscuous Mode)
            │
            ▼
  [ Processing Worker ] ───── (Decode L2-L7, Flow Tracker, Security Heuristics)
            │
   ┌────────┴────────┐
   ▼                 ▼
[ State Store ]   [ UI Queue ]
(Shared Memory)   (Bounded Event Channel)
                     │
                     ▼
             [ CustomTkinter UI ] ── (Treeview Tables, Hex Viewer, Canvas Telemetry)
```

---

## Getting Started

### Prerequisites

* Python 3.8 or higher
* Elevated privileges: **Administrator** (Windows) or **Root** (Linux)

### Installation

```bash
# Clone the repository
git clone [https://github.com/MR-05-001/Network-Sniffer.git](https://github.com/MR-05-001/Network-Sniffer.git)
cd Network-Sniffer

# Install GUI dependency
pip install customtkinter
```

### Launch Instructions

**Linux (Superuser required for raw socket access):**
```bash
sudo python3 Network-Sniffer.py
```

**Windows (Elevated command line required):**
1. Open Command Prompt or PowerShell with **Run as Administrator**.
2. Run:
   ```cmd
   python Network-Sniffer.py
   ```
3. Select the local IP bound to your active network interface and choose **Start**.
---

## License

This project is open-source under the [MIT License](LICENSE).
