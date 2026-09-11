import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import customtkinter as ctk
import socket
import struct
import threading
import datetime
import time
import os
import sys
import queue
import json
import urllib.request
from collections import defaultdict, deque
from typing import Dict, Any, Optional, List, Tuple

# ─── Platform & Constants ────────────────────────────────────────────────────

IS_LINUX = sys.platform.startswith("linux")
IS_WINDOWS = sys.platform.startswith("win")
IS_MAC = sys.platform.startswith("darwin")

# Well-known protocols and ports
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "IPv6-ICMP"}
TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG",
    0x40: "ECE", 0x80: "CWR"
}
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt"
}

# ─── Data Models ─────────────────────────────────────────────────────────────

class PacketInfo:
    __slots__ = [
        'id', 'ts', 'time_str', 'length', 'link_layer', 'network_layer',
        'transport_layer', 'proto_name', 'src_mac', 'dst_mac',
        'src_ip', 'dst_ip', 'sport', 'dport', 'flags', 'ttl',
        'info', 'raw_data', 'app_layer', 'flow_key', 'is_ipv6'
    ]
    def __init__(self):
        self.flags = []
        self.info = ""
        self.app_layer = {}
        self.link_layer = {}
        self.network_layer = {}
        self.transport_layer = {}
        self.is_ipv6 = False
        self.src_ip = ""
        self.dst_ip = ""

# ─── Shared Thread-Safe State ────────────────────────────────────────────────

class SnifferState:
    def __init__(self):
        self.lock = threading.Lock()
        self.packet_store = deque(maxlen=20000)
        self.flows = {}       # flow_key -> dict of stats
        self.endpoints = defaultdict(lambda: {'tx_pkts': 0, 'rx_pkts': 0, 'tx_bytes': 0, 'rx_bytes': 0})
        self.alerts = deque(maxlen=1000)
        self.stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0, 'Bytes': 0}
        self.syn_tracker = defaultdict(list)

        self.dns_cache = {}
        self.dns_queue = queue.Queue()
        self.geoip_cache = {}
        self.geoip_queue = queue.Queue()

    def resolve_ip(self, ip: str) -> str:
        if not ip: return ""
        if ip in self.dns_cache:
            return self.dns_cache[ip]
        self.dns_queue.put(ip)
        self.dns_cache[ip] = ip # Temporary fallback
        return ip

    def resolve_geoip(self, ip: str) -> str:
        if not ip: return "Unknown"
        if ip in ("127.0.0.1", "0.0.0.0") or ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return "Local"
        if ip in self.geoip_cache:
            return self.geoip_cache[ip]
        if ip not in self.geoip_cache:
            self.geoip_cache[ip] = "..."
            self.geoip_queue.put(ip)
        return self.geoip_cache[ip]

STATE = SnifferState()

# Background DNS Resolver
def dns_resolver_worker():
    while True:
        ip = STATE.dns_queue.get()
        try:
            name = socket.gethostbyaddr(ip)[0]
            STATE.dns_cache[ip] = name
        except Exception:
            pass # Keep IP as fallback
        finally:
            STATE.dns_queue.task_done()

def geoip_worker():
    while True:
        ip = STATE.geoip_queue.get()
        try:
            req = urllib.request.Request(f"http://ip-api.com/json/{ip}?fields=country,isp", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=2) as r:
                data = json.loads(r.read().decode())
                STATE.geoip_cache[ip] = f"{data.get('country', 'Unknown')}, {data.get('isp', 'Unknown')}"
        except:
            STATE.geoip_cache[ip] = "Unknown"
        finally:
            STATE.geoip_queue.task_done()

threading.Thread(target=dns_resolver_worker, daemon=True).start()
threading.Thread(target=geoip_worker, daemon=True).start()

# ─── Packet Parsing Engine ───────────────────────────────────────────────────

class PacketParser:
    @staticmethod
    def parse(raw_data: bytes, ts: float, os_is_linux: bool) -> Optional[PacketInfo]:
        pkt = PacketInfo()
        pkt.ts = ts
        pkt.time_str = datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3]
        pkt.length = len(raw_data)
        pkt.raw_data = raw_data

        offset = 0

        # 1. Link Layer (Ethernet) - Linux AF_PACKET includes this, Windows/macOS IP_HDRINCL does not
        if os_is_linux:
            if len(raw_data) < 14: return None
            eth_header = struct.unpack("!6s6sH", raw_data[:14])
            pkt.dst_mac = PacketParser._mac_format(eth_header[0])
            pkt.src_mac = PacketParser._mac_format(eth_header[1])
            eth_type = eth_header[2]
            pkt.link_layer = {"Dst MAC": pkt.dst_mac, "Src MAC": pkt.src_mac, "Type": hex(eth_type)}
            offset = 14
            
            if eth_type == 0x8100: # VLAN
                offset += 4
            elif eth_type == 0x0806: # ARP
                if len(raw_data) >= offset + 28:
                    arp = struct.unpack("!HHBBH6s4s6s4s", raw_data[offset:offset+28])
                    op = arp[4]
                    pkt.src_ip = socket.inet_ntoa(arp[6])
                    pkt.dst_ip = socket.inet_ntoa(arp[8])
                    pkt.proto_name = "ARP"
                    pkt.info = f"Who has {pkt.dst_ip}? Tell {pkt.src_ip}" if op == 1 else f"{pkt.src_ip} is at {PacketParser._mac_format(arp[5])}"
                    pkt.network_layer = {"Hardware": arp[0], "Protocol": hex(arp[1]), "Opcode": op}
                    return pkt
            elif eth_type not in (0x0800, 0x86dd): # Not IPv4/IPv6
                pkt.proto_name = "ETH"
                pkt.info = f"EtherType {hex(eth_type)}"
                return pkt

        # 2. Network Layer
        if len(raw_data) <= offset: return None
        version = raw_data[offset] >> 4

        if version == 4:
            if len(raw_data) < offset + 20: return None
            iph = struct.unpack("!BBHHHBBH4s4s", raw_data[offset:offset+20])
            ihl = (iph[0] & 0xF) * 4
            pkt.ttl = iph[5]
            proto_id = iph[6]
            pkt.src_ip = socket.inet_ntoa(iph[8])
            pkt.dst_ip = socket.inet_ntoa(iph[9])
            pkt.network_layer = {
                "Version": 4, "Header Length": ihl, "TTL": pkt.ttl,
                "Protocol": proto_id, "Source": pkt.src_ip, "Destination": pkt.dst_ip
            }
            offset += ihl
        elif version == 6:
            if len(raw_data) < offset + 40: return None
            ip6h = struct.unpack("!IHBB16s16s", raw_data[offset:offset+40])
            proto_id = ip6h[2]
            pkt.ttl = ip6h[3]
            pkt.src_ip = socket.inet_ntop(socket.AF_INET6, ip6h[4])
            pkt.dst_ip = socket.inet_ntop(socket.AF_INET6, ip6h[5])
            pkt.is_ipv6 = True
            pkt.network_layer = {
                "Version": 6, "Hop Limit": pkt.ttl, "Next Header": proto_id,
                "Source": pkt.src_ip, "Destination": pkt.dst_ip
            }
            offset += 40
        else:
            return None # Not IP or unexpected structure

        pkt.proto_name = PROTO_MAP.get(proto_id, f"#{proto_id}")

        # 3. Transport Layer
        if len(raw_data) <= offset: return pkt
        payload = raw_data[offset:]

        if proto_id == 6: # TCP
            if len(payload) < 20: return pkt
            tcph = struct.unpack("!HHLLBBHHH", payload[:20])
            pkt.sport, pkt.dport = tcph[0], tcph[1]
            pkt.flags = [name for mask, name in TCP_FLAGS.items() if tcph[5] & mask]
            hl = (tcph[4] >> 4) * 4
            pkt.transport_layer = {
                "Source Port": pkt.sport, "Dest Port": pkt.dport,
                "Seq": tcph[2], "Ack": tcph[3], "Window": tcph[6],
                "Flags": ", ".join(pkt.flags)
            }
            pkt.info = f"{pkt.sport} > {pkt.dport} [{','.join(pkt.flags)}] Seq={tcph[2]} Win={tcph[6]}"
            app_data = payload[hl:]
            PacketParser._inspect_app_layer(pkt, app_data, 6)

        elif proto_id == 17: # UDP
            if len(payload) < 8: return pkt
            udph = struct.unpack("!HHHH", payload[:8])
            pkt.sport, pkt.dport = udph[0], udph[1]
            pkt.transport_layer = {
                "Source Port": pkt.sport, "Dest Port": pkt.dport,
                "Length": udph[2], "Checksum": hex(udph[3])
            }
            pkt.info = f"{pkt.sport} > {pkt.dport} Len={udph[2]}"
            app_data = payload[8:]
            PacketParser._inspect_app_layer(pkt, app_data, 17)

        elif proto_id in (1, 58): # ICMP / ICMPv6
            if len(payload) < 4: return pkt
            icmph = struct.unpack("!BBH", payload[:4])
            t = icmph[0]
            pkt.transport_layer = {"Type": t, "Code": icmph[1], "Checksum": hex(icmph[2])}
            if proto_id == 1:
                types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
            else:
                types = {128: "Echo Request", 129: "Echo Reply"}
            pkt.info = types.get(t, f"Type {t}")

        # Define Flow Key (Bidirectional)
        if hasattr(pkt, 'sport'):
            ep1, ep2 = f"{pkt.src_ip}:{pkt.sport}", f"{pkt.dst_ip}:{pkt.dport}"
            pkt.flow_key = (min(ep1, ep2), max(ep1, ep2), pkt.proto_name)
        elif pkt.src_ip and pkt.dst_ip:
            pkt.flow_key = (min(pkt.src_ip, pkt.dst_ip), max(pkt.src_ip, pkt.dst_ip), pkt.proto_name)

        return pkt

    @staticmethod
    def _mac_format(b: bytes) -> str:
        return ':'.join(f'{x:02x}' for x in b)

    @staticmethod
    def _inspect_app_layer(pkt: PacketInfo, data: bytes, proto_id: int):
        if not data: return
        sport, dport = pkt.sport, pkt.dport

        # HTTP
        if sport == 80 or dport == 80:
            idx = data.find(b'\r\n')
            if idx > 0:
                line = data[:idx].decode('utf-8', errors='ignore')
                if any(line.startswith(m) for m in ("GET ", "POST ", "HTTP/")):
                    pkt.app_layer["HTTP"] = line
                    pkt.info = line

        # TLS (SNI Detection)
        elif sport == 443 or dport == 443:
            if len(data) > 5 and data[0] == 0x16 and data[1] == 0x03:
                pkt.app_layer["TLS"] = "TLS Handshake"
                pkt.info = "TLS Client/Server Hello"

        # DNS
        elif (sport == 53 or dport == 53) and proto_id == 17:
            if len(data) >= 12:
                tx_id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
                is_resp = (flags & 0x8000) != 0
                pkt.app_layer["DNS"] = f"TX: 0x{tx_id:04x}, Queries: {qd}, Answers: {an}"

                try:
                    idx = 12
                    qname = []
                    while True:
                        length = data[idx]
                        if length == 0 or idx > len(data)-2: break
                        qname.append(data[idx+1:idx+1+length].decode('utf-8'))
                        idx += length + 1
                    domain = ".".join(qname)
                    if domain:
                        pkt.info = f"DNS {'Response' if is_resp else 'Query'} {domain}"
                        pkt.app_layer["DNS Query"] = domain
                except:
                    pkt.info = f"DNS {'Response' if is_resp else 'Query'} 0x{tx_id:04x}"

        # Cleartext credentials check (FTP/Telnet)
        if sport in (21, 23) or dport in (21, 23):
            text = data.decode('utf-8', errors='ignore').strip()
            if text.lower().startswith("user ") or text.lower().startswith("pass "):
                pkt.app_layer["Cleartext"] = text

# ─── Analysis Engines ────────────────────────────────────────────────────────

class FilterEngine:
    @staticmethod
    def evaluate(pkt: PacketInfo, expr: str) -> bool:
        if not expr: return True
        try:
            expr = expr.lower()
            or_blocks = expr.split(' or ')
            for block in or_blocks:
                and_blocks = block.split(' and ')
                block_match = True
                for cond in and_blocks:
                    if not FilterEngine._check_cond(pkt, cond.strip()):
                        block_match = False
                        break
                if block_match: return True
            return False
        except Exception:
            return False

    @staticmethod
    def _check_cond(pkt: PacketInfo, cond: str) -> bool:
        if '==' in cond: op, func = '==', lambda a, b: a == b
        elif '!=' in cond: op, func = '!=', lambda a, b: a != b
        elif ' contains ' in cond: op, func = ' contains ', lambda a, b: b in str(a).lower()
        else: return False

        parts = cond.split(op, 1)
        if len(parts) != 2: return False
        field, val = parts[0].strip(), parts[1].strip().strip('"\'')

        if field in ('ip', 'src', 'dst'):
            target = ""
            if field == 'ip': target = f"{pkt.src_ip} {pkt.dst_ip}"
            elif field == 'src': target = pkt.src_ip
            elif field == 'dst': target = pkt.dst_ip
            return func(target, val)
        elif field in ('port', 'sport', 'dport'):
            target = -1
            if hasattr(pkt, 'sport'):
                if field == 'port': target = pkt.sport if str(pkt.sport) == val else pkt.dport
                elif field == 'sport': target = pkt.sport
                elif field == 'dport': target = pkt.dport
            return func(str(target), val)
        elif field == 'protocol':
            return func(pkt.proto_name.lower(), val)
        return False

class FlowTracker:
    @staticmethod
    def update(pkt: PacketInfo):
        if not hasattr(pkt, 'flow_key'): return
        
        fk = pkt.flow_key
        with STATE.lock:
            if fk not in STATE.flows:
                STATE.flows[fk] = {
                    'start_ts': pkt.ts, 'last_ts': pkt.ts,
                    'pkts': 0, 'bytes': 0, 'state': 'OPEN'
                }
            f = STATE.flows[fk]
            f['last_ts'] = pkt.ts
            f['pkts'] += 1
            f['bytes'] += pkt.length

            if pkt.proto_name == "TCP" and "FIN" in pkt.flags:
                f['state'] = 'CLOSED'

            # Update endpoints
            if pkt.src_ip:
                STATE.endpoints[pkt.src_ip]['tx_pkts'] += 1
                STATE.endpoints[pkt.src_ip]['tx_bytes'] += pkt.length
            if pkt.dst_ip:
                STATE.endpoints[pkt.dst_ip]['rx_pkts'] += 1
                STATE.endpoints[pkt.dst_ip]['rx_bytes'] += pkt.length

class SecurityAnalyzer:
    @staticmethod
    def inspect(pkt: PacketInfo):
        # Cleartext Alert
        if "Cleartext" in pkt.app_layer:
            SecurityAnalyzer._alert("HIGH", "Cleartext Credentials", f"{pkt.src_ip} sent unencrypted credentials.", pkt)

        # SYN Scan / Flood heuristic
        if pkt.proto_name == "TCP" and pkt.flags == ["SYN"]:
            with STATE.lock:
                now = time.time()
                tracker = STATE.syn_tracker[pkt.src_ip]
                tracker.append(now)
                # Purge old
                while tracker and now - tracker[0] > 5:
                    tracker.pop(0)
                if len(tracker) == 50: # Trigger once per threshold
                    SecurityAnalyzer._alert("MEDIUM", "Potential SYN Scan/Flood", f"{pkt.src_ip} sent high volume of SYNs.", pkt)

    @staticmethod
    def _alert(severity, title, desc, pkt):
        with STATE.lock:
            msg = f"[{severity}] {title}: {desc}"
            if not any(a['msg'] == msg for a in STATE.alerts):
                STATE.alerts.append({'time': pkt.time_str, 'msg': msg, 'severity': severity, 'src': pkt.src_ip})

# ─── Capture Threads ─────────────────────────────────────────────────────────

class CaptureEngine:
    def __init__(self, interface: str, process_queue: queue.Queue):
        self.interface = interface
        self.process_queue = process_queue
        self.running = False
        self.sock = None
        self.thread = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        # Let the capture loop notice `self.running is False` and return.
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

        if self.sock:
            if IS_WINDOWS:
                try:
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def _capture_loop(self):
        try:
            # On Windows and macOS, we use AF_INET. On Linux, we use AF_PACKET.
            if IS_WINDOWS or IS_MAC:
                # Require admin/root privileges
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                
                # Bind to the specific interface if provided, otherwise let OS decide
                if self.interface != "ALL":
                    self.sock.bind((self.interface, 0))
                else:
                    # Windows typically needs an explicit IP to bind for SIO_RCVALL
                    host_ip = socket.gethostbyname(socket.gethostname())
                    self.sock.bind((host_ip, 0))

                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                if IS_WINDOWS:
                    self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                # Linux AF_PACKET captures Ethernet frames
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
                if self.interface != "ALL":
                    self.sock.bind((self.interface, 0))

            self.sock.settimeout(1.0)
            while self.running:
                try:
                    raw, _ = self.sock.recvfrom(65535)
                    self.process_queue.put((raw, time.time()))
                except socket.timeout:
                    continue
                except OSError:
                    # Socket was closed/invalidated
                    break
        except PermissionError as e:
            if self.running: self.process_queue.put(e)
        except OSError as e:
            if self.running: self.process_queue.put(e)

class ProcessWorker(threading.Thread):
    def __init__(self, in_queue: queue.Queue, ui_queue: queue.Queue):
        super().__init__(daemon=True)
        self.in_queue = in_queue
        self.ui_queue = ui_queue
        self.running = True

    def run(self):
        pkt_id = 0
        while self.running:
            try:
                item = self.in_queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if isinstance(item, Exception):
                self.ui_queue.put(item)
                continue

            raw, ts = item
            pkt = PacketParser.parse(raw, ts, IS_LINUX)
            if not pkt: continue

            pkt_id += 1
            pkt.id = pkt_id

            with STATE.lock:
                STATE.packet_store.append(pkt)
                STATE.stats['Total'] += 1
                STATE.stats['Bytes'] += pkt.length
                STATE.stats[pkt.proto_name] = STATE.stats.get(pkt.proto_name, 0) + 1

            FlowTracker.update(pkt)
            SecurityAnalyzer.inspect(pkt)

            # Prevent UI Queue from blowing up memory if UI is slow
            if self.ui_queue.qsize() < 2000:
                self.ui_queue.put(pkt)

# ─── UI Utilities ────────────────────────────────────────────────────────────

def hexdump(src: bytes, length: int = 16) -> str:
    result = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        hexa = ' '.join([f'{b:02X}' for b in chunk])
        text = ''.join([chr(b) if 32 <= b < 127 else '.' for b in chunk])
        result.append(f'{i:04X}   {hexa:<{length*3}}   {text}')
    return '\n'.join(result)

# ─── Main GUI Application ────────────────────────────────────────────────────

class NetworkAnalyzerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Network Protocol Analyzer")
        self.geometry("1400x900")
        self.minsize(1200, 700)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.C_BG = "#0d1117"
        self.C_CARD = "#161b22"
        self.C_HOVER = "#21262d"
        self.C_PRIMARY = "#2f81f7"
        self.C_DANGER = "#f85149"
        self.C_TEXT = "#c9d1d9"
        self.C_MUTED = "#8b949e"
        self.C_GREEN = "#238636"
        self.configure(bg=self.C_BG)

        self.ui_queue = queue.Queue()
        self.process_queue = queue.Queue()
        self.capture_engine = None
        self.process_worker = None
        self.is_capturing = False
        self.filter_str = ""
        self.tree_iids = deque()
        self.traffic_history = deque([0]*60, maxlen=60)
        self.last_total_bytes = 0

        self._init_styles()
        self._build_ui()
        self._poll_ui_queue()
        self._update_dashboard_loop()

    def _init_styles(self):
        self.FONT_MONO = ("Consolas", 11) if IS_WINDOWS else ("Monospace", 11)
        self.FONT_SANS = ("Segoe UI", 11) if IS_WINDOWS else ("Sans", 11)

        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background="#1f1f1f", foreground="#dce4ee", fieldbackground="#1f1f1f", rowheight=28, borderwidth=0, font=self.FONT_MONO)
        style.map("Treeview", background=[("selected", "#1f538d")], foreground=[("selected", "white")])
        style.configure("Treeview.Heading", background="#121212", foreground="#dce4ee", font=self.FONT_SANS, relief="flat", padding=5)
        style.map("Treeview.Heading", background=[("active", "#1f1f1f")])
        style.configure("Vertical.TScrollbar", background="#1f1f1f", troughcolor="#121212", arrowcolor="#dce4ee", borderwidth=0)

    def _get_interfaces(self) -> List[str]:
        if IS_WINDOWS or IS_MAC:
            try:
                addrs = socket.getaddrinfo(socket.gethostname(), None)
                ifaces = list(set([a[4][0] for a in addrs if a[0] == socket.AF_INET]))
                # If we couldn't resolve, try 127.0.0.1
                return ifaces if ifaces else ["127.0.0.1"]
            except OSError:
                return ["127.0.0.1"]
        else:
            try: return ["ALL"] + os.listdir('/sys/class/net/')
            except: return ["ALL"]

    def _build_ui(self):
        # ── Toolbar ──
        toolbar = ctk.CTkFrame(self, fg_color="transparent")
        toolbar.pack(fill="x", pady=10, padx=20)

        ctk.CTkLabel(toolbar, text="Network Protocol Analyzer", text_color="#3b82f6", font=ctk.CTkFont(family="Segoe UI", size=20, weight="bold")).pack(side="left")

        self.iface_var = ctk.StringVar()
        ifaces = self._get_interfaces()
        self.iface_var.set(ifaces[0] if ifaces else "")
        self.iface_combo = ctk.CTkComboBox(toolbar, variable=self.iface_var, values=ifaces, width=200, font=ctk.CTkFont(family="Segoe UI", size=13))
        self.iface_combo.pack(side="left", padx=20)

        ctrl = ctk.CTkFrame(toolbar, fg_color="transparent")
        ctrl.pack(side="right")

        ctk.CTkButton(ctrl, text="📂 Load PCAP", command=self.load_pcap, width=120).pack(side="right", padx=4)
        ctk.CTkButton(ctrl, text="💾 Export PCAP", command=self.export_pcap, width=120).pack(side="right", padx=4)
        ctk.CTkButton(ctrl, text="🗑 Clear", command=self.clear_data, fg_color="#4b5563", hover_color="#374151", width=100).pack(side="right", padx=4)

        self.btn_stop = ctk.CTkButton(ctrl, text="⏹ Stop", command=self.stop_capture, fg_color="#dc2626", hover_color="#b91c1c", width=100)
        self.btn_stop.pack(side="right", padx=4)
        self.btn_stop.configure(state="disabled")

        self.btn_start = ctk.CTkButton(ctrl, text="⏵ Start", command=self.start_capture, fg_color="#10b981", hover_color="#059669", width=100)
        self.btn_start.pack(side="right", padx=4)

        # ── Filter Bar ──
        filter_bar = ctk.CTkFrame(self)
        filter_bar.pack(fill="x", padx=20, pady=(0, 10))

        ctk.CTkLabel(filter_bar, text="Filter (Metadata):").pack(side="left", padx=(10,8), pady=8)
        self.filter_entry = ctk.CTkEntry(filter_bar, width=300, placeholder_text="e.g., port == 443", font=ctk.CTkFont(family="Consolas", size=13))
        self.filter_entry.pack(side="left", padx=4)
        self.filter_entry.bind("<Return>", lambda e: self.apply_filter())

        ctk.CTkLabel(filter_bar, text="Search Payload:").pack(side="left", padx=(20,8))
        self.search_entry = ctk.CTkEntry(filter_bar, width=200, font=ctk.CTkFont(family="Consolas", size=13))
        self.search_entry.pack(side="left", padx=4)
        self.search_entry.bind("<Return>", lambda e: self.apply_filter())

        self.auto_scroll_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(filter_bar, text="Auto-Scroll", variable=self.auto_scroll_var).pack(side="left", padx=16)

        ctk.CTkButton(filter_bar, text="Apply", command=self.apply_filter, width=100).pack(side="left", padx=16)
        ctk.CTkButton(filter_bar, text="Clear Filters", command=self.clear_filter, fg_color="#4b5563", hover_color="#374151", width=120).pack(side="left")

        # ── Main Content Notebook ──
        self.notebook = ctk.CTkTabview(self)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        self.notebook.add("Live Capture")
        self.notebook.add("Dashboard")
        self.notebook.add("Conversations")
        self.notebook.add("Endpoints")
        self.notebook.add("Security Alerts")
        self.notebook.add("Traffic Graph")

        self._build_live_tab(self.notebook.tab("Live Capture"))
        self._build_dashboard_tab(self.notebook.tab("Dashboard"))
        self._build_conv_tab(self.notebook.tab("Conversations"))
        self._build_ep_tab(self.notebook.tab("Endpoints"))
        self._build_sec_tab(self.notebook.tab("Security Alerts"))
        self._build_graph_tab(self.notebook.tab("Traffic Graph"))

        # ── Status Bar ──
        status_bar = ctk.CTkFrame(self, fg_color="#1f1f1f", corner_radius=0)
        status_bar.pack(side="bottom", fill="x")
        self.status_lbl = ctk.CTkLabel(status_bar, text="● Ready", text_color="#94a3b8")
        self.status_lbl.pack(side="left", padx=20, pady=4)
        self.stat_lbl = ctk.CTkLabel(status_bar, text="", text_color="#94a3b8")
        self.stat_lbl.pack(side="right", padx=20, pady=4)

    def _build_live_tab(self, parent):
        paned = tk.PanedWindow(parent, orient="vertical", bg="#2b2b2b", sashrelief="flat", sashwidth=6)
        paned.pack(fill="both", expand=True)

        # Table
        cols = ("No", "Time", "Protocol", "Source", "Sport", "Dest", "Dport", "Length", "Info")
        self.tree = ttk.Treeview(paned, columns=cols, show="headings", selectmode="browse")
        widths = [60, 100, 70, 140, 60, 140, 60, 60, 350]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col, anchor="w")
            self.tree.column(col, width=w, minwidth=50, anchor="w")

        vsb = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_packet_select)

        self.tree.tag_configure("TCP", foreground="#60a5fa", background="#2b2b2b")
        self.tree.tag_configure("UDP", foreground="#c084fc", background="#2b2b2b")
        self.tree.tag_configure("ICMP", foreground="#fcd34d", background="#2b2b2b")
        self.tree.tag_configure("ARP", foreground="#a7f3d0", background="#2b2b2b")
        self.tree.tag_configure("DNS", foreground="#38bdf8", background="#1e3a5f")
        self.tree.tag_configure("HTTP", foreground="#4ade80", background="#1a3f28")
        self.tree.tag_configure("TLS", foreground="#c084fc", background="#2d1b4e")
        self.tree.tag_configure("ALERT", foreground="#f87171", background="#451a1a")

        # Context Menu
        self.ctx_menu = tk.Menu(self, tearoff=0, bg=self.C_CARD, fg=self.C_TEXT, activebackground=self.C_PRIMARY)
        self.ctx_menu.add_command(label="Follow TCP Stream", command=self.follow_tcp_stream)
        if IS_WINDOWS: self.tree.bind("<Button-3>", lambda e: self.ctx_menu.post(e.x_root, e.y_root) if self.tree.selection() else None)
        else: self.tree.bind("<Button-2>", lambda e: self.ctx_menu.post(e.x_root, e.y_root) if self.tree.selection() else None)

        paned.add(self.tree, minsize=200)

        # Details Paned
        det_paned = tk.PanedWindow(paned, orient="horizontal", bg="#2b2b2b", sashrelief="flat", sashwidth=6)
        paned.add(det_paned, minsize=200)

        # Hierarchical Details
        self.det_tree = ttk.Treeview(det_paned, show="tree", selectmode="none")
        det_vsb = ttk.Scrollbar(self.det_tree, orient="vertical", command=self.det_tree.yview)
        self.det_tree.configure(yscrollcommand=det_vsb.set)
        det_vsb.pack(side="right", fill="y")
        det_paned.add(self.det_tree, minsize=300)

        # Hex Dump
        self.hex_text = scrolledtext.ScrolledText(det_paned, bg=self.C_CARD, fg="#a7f3d0", font=self.FONT_MONO, relief="flat", state="disabled")
        det_paned.add(self.hex_text, minsize=300)

    def _build_conv_tab(self, parent):
        cols = ("Address A", "Address B", "Protocol", "Packets", "Bytes", "State")
        self.conv_tree = ttk.Treeview(parent, columns=cols, show="headings")
        for col in cols:
            self.conv_tree.heading(col, text=col, anchor="w")
            self.conv_tree.column(col, width=150, anchor="w")
        self.conv_tree.pack(fill="both", expand=True, pady=10)

    def _build_ep_tab(self, parent):
        cols = ("IP Address", "Hostname", "Location", "Tx Packets", "Rx Packets", "Tx Bytes", "Rx Bytes")
        self.ep_tree = ttk.Treeview(parent, columns=cols, show="headings")
        for col in cols:
            self.ep_tree.heading(col, text=col, anchor="w")
            self.ep_tree.column(col, width=120, anchor="w")
        self.ep_tree.pack(fill="both", expand=True, pady=10)

    def _build_sec_tab(self, parent):
        cols = ("Time", "Severity", "Source", "Message")
        self.sec_tree = ttk.Treeview(parent, columns=cols, show="headings")
        self.sec_tree.heading("Time", text="Time", anchor="w"); self.sec_tree.column("Time", width=120, anchor="w")
        self.sec_tree.heading("Severity", text="Severity", anchor="w"); self.sec_tree.column("Severity", width=100, anchor="w")
        self.sec_tree.heading("Source", text="Source", anchor="w"); self.sec_tree.column("Source", width=150, anchor="w")
        self.sec_tree.heading("Message", text="Message", anchor="w"); self.sec_tree.column("Message", width=600, anchor="w")
        self.sec_tree.tag_configure("HIGH", foreground=self.C_DANGER)
        self.sec_tree.tag_configure("MEDIUM", foreground="#f59e0b")
        self.sec_tree.pack(fill="both", expand=True, pady=10)

    def _build_graph_tab(self, parent):
        self.graph_canvas = tk.Canvas(parent, bg="#1f1f1f", highlightthickness=0)
        self.graph_canvas.pack(fill="both", expand=True, padx=20, pady=20)
        self.graph_canvas.bind("<Configure>", lambda e: self._draw_graph())

    def _draw_graph(self):
        self.graph_canvas.delete("all")
        w = self.graph_canvas.winfo_width()
        h = self.graph_canvas.winfo_height()
        if w < 50 or h < 50: return

        history = list(self.traffic_history)
        if not history: return

        max_val = max(history) if max(history) > 0 else 1000

        for i in range(5):
            y = h - (h * (i / 4.0))
            if i > 0: self.graph_canvas.create_line(0, y, w, y, fill=self.C_HOVER, dash=(4, 4))
            self.graph_canvas.create_text(5, y-10, text=f"{max_val * (i/4.0) / 1024:.1f} KB/s", fill=self.C_MUTED, anchor="w", font=self.FONT_SANS)

        pts = []
        step_x = w / 60.0
        for i, val in enumerate(history):
            pts.extend([i * step_x, h - (val / max_val * h)])

        if len(pts) >= 4:
            self.graph_canvas.create_line(*pts, fill=self.C_PRIMARY, width=2, smooth=True)

    def _build_dashboard_tab(self, parent):
        self.dash_canvas = tk.Canvas(parent, bg="#1f1f1f", highlightthickness=0)
        self.dash_canvas.pack(fill="both", expand=True, padx=20, pady=20)
        self.dash_canvas.bind("<Configure>", lambda e: self._draw_dashboard())

    def _draw_dashboard(self):
        c = self.dash_canvas
        c.delete("all")
        w, h = c.winfo_width(), c.winfo_height()
        if w < 100 or h < 100: return

        # Pie Chart Data
        stats = {k: v for k, v in STATE.stats.items() if k not in ("Total", "Bytes")}
        total_p = sum(stats.values())
        if total_p == 0:
            c.create_text(w/2, h/2, text="No Data Available Yet", fill="#dce4ee", font=self.FONT_SANS)
            return

        # Draw Pie Chart
        colors = ["#3b82f6", "#10b981", "#f59e0b", "#8b5cf6", "#ec4899", "#ef4444", "#14b8a6"]
        start = 0
        
        # Adjust layout parameters to prevent text overlap
        cx, cy = w * 0.25, h * 0.5
        r = min(w * 0.15, h * 0.35) 
        
        c.create_text(cx, cy - r - 20, text="Protocol Distribution", fill="#dce4ee", font=("Segoe UI", 14, "bold"))
        for i, (k, v) in enumerate(stats.items()):
            if v == 0: continue
            extent = (v / total_p) * 360
            color = colors[i % len(colors)]
            c.create_arc(cx-r, cy-r, cx+r, cy+r, start=start, extent=extent, fill=color, outline="#1f1f1f")

            # Legend
            ly = cy - r + (i * 25) + 20
            c.create_rectangle(cx+r+30, ly-5, cx+r+45, ly+10, fill=color, outline=color)
            c.create_text(cx+r+55, ly+2, text=f"{k}: {v} ({v/total_p*100:.1f}%)", fill="#dce4ee", anchor="w", font=self.FONT_SANS)
            start += extent

        # Top Talkers Bar Chart
        bar_x = w * 0.70  # Shifted further right to avoid overlaps
        bar_w = w * 0.20  
        
        c.create_text(bar_x + (bar_w/2), h*0.1, text="Top Talkers (Bytes)", fill="#dce4ee", font=("Segoe UI", 14, "bold"))
        top_eps = sorted(STATE.endpoints.items(), key=lambda x: x[1]['tx_bytes'] + x[1]['rx_bytes'], reverse=True)[:5]
        if not top_eps: return

        max_b = (top_eps[0][1]['tx_bytes'] + top_eps[0][1]['rx_bytes']) or 1
        bar_y_start = h * 0.2

        for i, (ip, ed) in enumerate(top_eps):
            val = ed['tx_bytes'] + ed['rx_bytes']
            bw = (val / max_b) * bar_w
            by = bar_y_start + (i * 55)
            c.create_rectangle(bar_x, by, bar_x + bw, by + 25, fill="#3b82f6", outline="")
            
            ip_label = f"{ip} ({STATE.resolve_geoip(ip).split(',')[0]})"
            c.create_text(bar_x - 10, by + 12, text=ip_label, fill="#dce4ee", anchor="e", font=self.FONT_SANS)
            c.create_text(bar_x + bw + 10, by + 12, text=f"{val/1024:.1f} KB", fill="#dce4ee", anchor="w", font=self.FONT_SANS)

    # ── Actions ──

    def apply_filter(self):
        self.filter_str = self.filter_entry.get().strip()
        search_term = self.search_entry.get().strip().lower()
        if self.filter_str.startswith("e.g.,"): self.filter_str = ""
        self.tree.delete(*self.tree.get_children())
        self.tree_iids.clear()

        # Re-evaluate history
        with STATE.lock:
            pkts = list(STATE.packet_store)

        for pkt in pkts:
            match_meta = FilterEngine.evaluate(pkt, self.filter_str)
            match_search = True
            if search_term:
                match_search = (pkt.raw_data and search_term.encode() in pkt.raw_data.lower()) or (search_term in str(pkt.info).lower())

            if match_meta and match_search:
                self._insert_to_tree(pkt)

    def clear_filter(self):
        self.filter_entry.delete(0, 'end')
        self.search_entry.delete(0, 'end')
        self.apply_filter()

    def start_capture(self):
        if self.is_capturing: return
        iface = self.iface_var.get()
        if not iface: return messagebox.showerror("Error", "Select a network interface.")

        self.is_capturing = True
        self.status_lbl.configure(text="● Capturing...", text_color=self.C_GREEN)
        self.btn_start.configure(state="disabled")
        self.btn_stop.configure(state="normal")

        self.capture_engine = CaptureEngine(iface, self.process_queue)
        self.process_worker = ProcessWorker(self.process_queue, self.ui_queue)
        self.capture_engine.start()
        self.process_worker.start()

    def stop_capture(self):
        if not self.is_capturing: return
        self.is_capturing = False
        if self.capture_engine: self.capture_engine.stop()
        if self.process_worker: self.process_worker.running = False
        self.status_lbl.configure(text="● Stopped", text_color=self.C_DANGER)
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def clear_data(self):
        self.stop_capture()
        with STATE.lock:
            STATE.packet_store.clear()
            STATE.flows.clear()
            STATE.endpoints.clear()
            STATE.alerts.clear()
            STATE.stats = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'Total': 0, 'Bytes': 0}
        self.tree.delete(*self.tree.get_children())
        self.tree_iids.clear()
        self.conv_tree.delete(*self.conv_tree.get_children())
        self.ep_tree.delete(*self.ep_tree.get_children())
        self.sec_tree.delete(*self.sec_tree.get_children())
        self._set_text(self.hex_text, "")
        self.det_tree.delete(*self.det_tree.get_children())

    # ── UI Loops ──

    def _poll_ui_queue(self):
        processed = 0
        last_item = None
        while not self.ui_queue.empty() and processed < 100:
            try:
                pkt = self.ui_queue.get_nowait()
                if isinstance(pkt, Exception):
                    self.stop_capture()
                    msg = "Permission Denied: Run as Root/Administrator." if isinstance(pkt, PermissionError) else str(pkt)
                    messagebox.showerror("Capture Error", msg)
                    break

                match_meta = not self.filter_str or FilterEngine.evaluate(pkt, self.filter_str)
                search_term = self.search_entry.get().strip().lower()
                match_search = True
                if search_term:
                    match_search = (pkt.raw_data and search_term.encode() in pkt.raw_data.lower()) or (search_term in str(pkt.info).lower())

                if match_meta and match_search:
                    last_item = self._insert_to_tree(pkt)
                processed += 1
            except queue.Empty: break

        if last_item and self.auto_scroll_var.get() and not self.tree.selection():
            self.tree.see(last_item)

        self.after(50, self._poll_ui_queue)

    def _insert_to_tree(self, pkt):
        src_res = STATE.resolve_ip(pkt.src_ip)
        dst_res = STATE.resolve_ip(pkt.dst_ip)
        src_disp = src_res if src_res != pkt.src_ip else pkt.src_ip
        dst_disp = dst_res if dst_res != pkt.dst_ip else pkt.dst_ip

        row = (
            pkt.id, pkt.time_str, pkt.proto_name,
            src_disp, getattr(pkt, 'sport', ''),
            dst_disp, getattr(pkt, 'dport', ''),
            pkt.length, pkt.info
        )
        tag = pkt.proto_name if pkt.proto_name in ("TCP", "UDP", "ICMP", "ARP", "DNS") else ""
        if "HTTP" in pkt.app_layer: tag = "HTTP"
        if "TLS" in pkt.app_layer: tag = "TLS"
        if "Cleartext" in pkt.app_layer: tag = "ALERT"

        iid = self.tree.insert("", "end", iid=str(pkt.id), values=row, tags=(tag,))
        self.tree_iids.append(iid)

        # Enforce UI bound
        if len(self.tree_iids) > 2000:
            old_iid = self.tree_iids.popleft()
            if self.tree.exists(old_iid):
                self.tree.delete(old_iid)
        return iid

    def _update_dashboard_loop(self):
        with STATE.lock:
            # Stats Bar
            t, tcp, udp, b = STATE.stats['Total'], STATE.stats.get('TCP',0), STATE.stats.get('UDP',0), STATE.stats['Bytes']
            mb = b / (1024*1024)
            self.stat_lbl.configure(text=f"Total: {t} | TCP: {tcp} | UDP: {udp} | Data: {mb:.2f} MB")

            # Notebook updates based on visible tab to save CPU
            curr_tab = self.notebook.get()

            if curr_tab == "Conversations": # Conversations
                self.conv_tree.delete(*self.conv_tree.get_children())
                for fk, fd in sorted(STATE.flows.items(), key=lambda x: x[1]['bytes'], reverse=True)[:50]:
                    self.conv_tree.insert("", "end", values=(fk[0], fk[1], fk[2], fd['pkts'], fd['bytes'], fd.get('state', '')))

            elif curr_tab == "Endpoints": # Endpoints
                self.ep_tree.delete(*self.ep_tree.get_children())
                for ip, ed in sorted(STATE.endpoints.items(), key=lambda x: x[1]['tx_bytes'] + x[1]['rx_bytes'], reverse=True)[:50]:
                    self.ep_tree.insert("", "end", values=(ip, STATE.resolve_ip(ip), STATE.resolve_geoip(ip), ed['tx_pkts'], ed['rx_pkts'], ed['tx_bytes'], ed['rx_bytes']))

            elif curr_tab == "Security Alerts": # Security
                self.sec_tree.delete(*self.sec_tree.get_children())
                for a in reversed(STATE.alerts):
                    self.sec_tree.insert("", "end", values=(a['time'], a['severity'], a['src'], a['msg']), tags=(a['severity'],))

            elif curr_tab == "Dashboard":
                self._draw_dashboard()

            # Record bandwidth for graph
            current_bytes = STATE.stats['Bytes']
            bps = current_bytes - self.last_total_bytes
            self.traffic_history.append(bps)
            self.last_total_bytes = current_bytes
            if curr_tab == "Traffic Graph":
                self._draw_graph()

        self.after(1000, self._update_dashboard_loop)

    def _on_packet_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        pkt_id = int(sel[0])

        with STATE.lock:
            pkt = next((p for p in reversed(STATE.packet_store) if p.id == pkt_id), None)

        if not pkt: return

        self.det_tree.delete(*self.det_tree.get_children())

        # Frame
        f_id = self.det_tree.insert("", "end", text=f"Frame (Length: {pkt.length} bytes)")
        self.det_tree.insert(f_id, "end", text=f"Arrival Time: {pkt.time_str}")

        # Link Layer
        if pkt.link_layer:
            l_id = self.det_tree.insert("", "end", text="Ethernet II")
            for k, v in pkt.link_layer.items():
                self.det_tree.insert(l_id, "end", text=f"{k}: {v}")

        # Network Layer
        if pkt.network_layer:
            if 'Version' in pkt.network_layer:
                n_label = f"IPv{pkt.network_layer['Version']}"
            else:
                n_label = pkt.proto_name or "Network Layer"
            n_id = self.det_tree.insert("", "end", text=n_label)
            for k, v in pkt.network_layer.items():
                self.det_tree.insert(n_id, "end", text=f"{k}: {v}")

        # Transport Layer
        if pkt.transport_layer:
            t_id = self.det_tree.insert("", "end", text=pkt.proto_name)
            for k, v in pkt.transport_layer.items():
                self.det_tree.insert(t_id, "end", text=f"{k}: {v}")

        # App Layer
        if pkt.app_layer:
            a_id = self.det_tree.insert("", "end", text="Application Data")
            for k, v in pkt.app_layer.items():
                self.det_tree.insert(a_id, "end", text=f"{k}: {v}")

        # Hex
        self._set_text(self.hex_text, hexdump(pkt.raw_data))

    def _set_text(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("end", text)
        widget.config(state="disabled")

    def follow_tcp_stream(self):
        sel = self.tree.selection()
        if not sel: return
        pkt_id = int(sel[0])
        with STATE.lock:
            target_pkt = next((p for p in STATE.packet_store if p.id == pkt_id), None)
        if not target_pkt or target_pkt.proto_name != "TCP": return messagebox.showinfo("Info", "Select a TCP packet to follow.")

        fk = target_pkt.flow_key
        stream_data = []
        with STATE.lock:
            for p in STATE.packet_store:
                if getattr(p, 'flow_key', None) == fk and p.proto_name == "TCP" and p.raw_data:
                    if not p.is_ipv6:
                        # Approximate payload offset: link header (if present) + IP header + 20-byte TCP header.
                        # This assumes no TCP options; streams using options may show a few extra bytes.
                        app_data = p.raw_data[(14 if IS_LINUX else 0) + p.network_layer.get("Header Length", 20) + 20:]
                        if app_data:
                            direction = "CLIENT" if p.src_ip == target_pkt.src_ip else "SERVER"
                            stream_data.append(f"--- {direction} ---\n{app_data.decode('utf-8', errors='replace')}")

        if not stream_data: return messagebox.showinfo("Info", "No payload data found for this stream.")

        top = ctk.CTkToplevel(self)
        top.title(f"TCP Stream: {fk[0]} <-> {fk[1]}")
        top.geometry("800x600")
        txt = scrolledtext.ScrolledText(top, bg="#0f172a", fg="#e2e8f0", font=self.FONT_MONO)
        txt.pack(fill="both", expand=True)
        txt.insert("end", "\n\n".join(stream_data))
        txt.config(state="disabled")

    def export_pcap(self):
        with STATE.lock: pkts = list(STATE.packet_store)
        if not pkts: return messagebox.showinfo("Export", "No packets to export.")

        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP","*.pcap")])
        if not path: return

        link_type = 1 if IS_LINUX else 101
        try:
            with open(path, "wb") as f:
                f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))
                for p in pkts:
                    sec = int(p.ts)
                    usec = int((p.ts - sec) * 1000000)
                    f.write(struct.pack("<IIII", sec, usec, p.length, p.length))
                    f.write(p.raw_data)
            messagebox.showinfo("Export", f"Exported {len(pkts)} packets successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def load_pcap(self):
        if self.is_capturing:
            messagebox.showinfo("Info", "Stop the live capture first.")
            return

        path = filedialog.askopenfilename(filetypes=[("PCAP", "*.pcap")])
        if not path: return
        self.clear_data()

        self.status_lbl.configure(text=f"● Loaded Offline PCAP: {os.path.basename(path)}", text_color=self.C_PRIMARY)
        self.process_worker = ProcessWorker(self.process_queue, self.ui_queue)
        self.process_worker.start()

        threading.Thread(target=self._load_pcap_worker, args=(path,), daemon=True).start()

    def _load_pcap_worker(self, path):
        try:
            with open(path, "rb") as f:
                global_hdr = f.read(24)
                if len(global_hdr) < 24: return
                magic, vmaj, vmin, tz, sf, snaplen, network = struct.unpack("<IHHIIII", global_hdr)
                is_le = True
                if magic == 0xd4c3b2a1:
                    magic, vmaj, vmin, tz, sf, snaplen, network = struct.unpack(">IHHIIII", global_hdr)
                    is_le = False

                # Check link type to handle ethernet offset
                link_type = network
                is_linux_format = IS_LINUX
                if link_type == 1: is_linux_format = True # Ethernet
                elif link_type == 101: is_linux_format = False # Raw IP

                while True:
                    hdr = f.read(16)
                    if len(hdr) < 16: break
                    sec, usec, incl_len, orig_len = struct.unpack("<IIII" if is_le else ">IIII", hdr)
                    raw_data = f.read(incl_len)
                    if not raw_data: break
                    ts = sec + usec / 1000000.0

                    # Trick the parser if we are on windows loading linux pcap or vice versa
                    pkt = PacketParser.parse(raw_data, ts, is_linux_format)
                    if pkt:
                        self.process_queue.put((raw_data, ts))

                    time.sleep(0.001) # Small delay to not overwhelm UI
        except Exception as e:
            print(f"Error loading PCAP: {e}")

    def on_close(self):
        self.stop_capture()
        self.destroy()

if __name__ == "__main__":
    app = NetworkAnalyzerApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()
