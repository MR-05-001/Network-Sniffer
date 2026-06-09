# 🛰️ Network Packet Sniffer - Desktop GUI

A cross-platform, lightweight graphical network packet sniffer written entirely in Python. It captures raw network traffic, decodes standard protocols (TCP, UDP, ICMP), performs basic Deep Packet Inspection (DPI), and visualizes live traffic—all without requiring heavy external dependencies like Scapy or Wireshark.

## Features

* **Cross-Platform**: Works on both Windows and Linux native raw sockets.
* **Zero External Dependencies**: Built entirely using Python's standard library (`socket`, `tkinter`, `struct`).
* **Live Traffic Visualization**: Real-time traffic graph showing packets per second.
* **Deep Packet Inspection**: Basic signature matching for HTTP and DNS/TLS handshakes.
* **Asynchronous DNS Resolution**: Resolves IP addresses to hostnames in the background without freezing the UI.
* **Export Capabilities**: Save captured packets to CSV or Wireshark-compatible PCAP files.
* **Hex & Parsed Views**: Click on any packet to view a formatted hex dump and detailed layer breakdown.

## Prerequisites

* Python 3.x installed.
* `tkinter` (Usually comes pre-installed with standard Python distributions).

## Installation

Clone the repository to your local machine:

```bash
git clone [https://github.com/MR-05-001/network-packet-sniffer.git](https://github.com/MR-05-001/network-packet-sniffer.git)
cd network-packet-sniffer
