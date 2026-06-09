"""
Network Packet Sniffer - Desktop GUI
Cross-platform: Windows & Linux
Requires: Python 3.x (tkinter is built-in)
Run as Administrator/root for raw socket access.
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import socket
import struct
import threading
import datetime
import time
import os
import sys
import csv
import queue
from collections import defaultdict
from typing import Dict, Any, Optional

# ─── Platform detection ──────────────────────────────────────────────────────
IS_WINDOWS = sys.platform.startswith("win")

# ─── Global DNS Resolution Cache ─────────────────────────────────────────────
DNS_CACHE = {}
QUEUED_IPS = set()
DNS_QUEUE = queue.Queue()

def dns_resolver_worker():
    """Background thread to resolve IPs without blocking the sniffer UI."""
    while True:
        ip = DNS_QUEUE.get()
        try:
            name = socket.gethostbyaddr(ip)[0]
            DNS_CACHE[ip] = name
        except Exception:
            DNS_CACHE[ip] = ip # Fallback to IP on failure
        finally:
            DNS_QUEUE.task_done()

threading.Thread(target=dns_resolver_worker, daemon=True).start()

# ─── Protocol constants ──────────────────────────────────────────────────────
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP"}
TCP_FLAGS = {
    0x01: "FIN", 0x02: "SYN", 0x04: "RST",
    0x08: "PSH", 0x10: "ACK", 0x20: "URG"
}
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 465: "SMTPS",
    587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-alt", 8443: "HTTPS-alt"
}

# ─── Helper Functions ────────────────────────────────────────────────────────

def hexdump(src: bytes, length: int = 16) -> str:
    """Generate a Wireshark-style hex/ASCII dump of raw bytes."""
    result = []
    for i in range(0, len(src), length):
        chunk = src[i:i+length]
        hexa = ' '.join([f'{b:02X}' for b in chunk])
        text = ''.join([chr(b) if 32 <= b < 127 else '.' for b in chunk])
        result.append(f'{i:04X}   {hexa:<{length*3}}   {text}')
    return '\n'.join(result)

def inspect_payload(data: bytes, proto_id: int, sport: str, dport: str) -> str:
    """Deep Packet Inspection for basic Application Layer signatures."""
    try:
        if proto_id == 6: # TCP
            if sport == '80' or dport == '80':
                idx = data.find(b'\r\n')
                if idx > 0:
                    line = data[:idx].decode('utf-8', errors='ignore')
                    if any(line.startswith(m) for m in ("GET ", "POST ", "PUT ", "DELETE ", "HTTP/")):
                        return line
            elif sport == '443' or dport == '443':
                if len(data) >= 5 and data[0] == 0x16 and data[1] == 0x03:
                    return "TLS Handshake"
        elif proto_id == 17: # UDP
            if sport == '53' or dport == '53':
                if len(data) >= 12:
                    tx_id = struct.unpack("!H", data[:2])[0]
                    flags = struct.unpack("!H", data[2:4])[0]
                    is_resp = (flags & 0x8000) != 0
                    return f"DNS {'Response' if is_resp else 'Query'} (TX: 0x{tx_id:04x})"
    except Exception:
        pass
    return ""

# ─── Packet parsing ──────────────────────────────────────────────────────────

def parse_ip_header(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 20: return None
    iph = struct.unpack("!BBHHHBBH4s4s", data[:20])
    return {
        "ihl": (iph[0] & 0xF) * 4,
        "ttl": iph[6],
        "proto": iph[7],
        "src": socket.inet_ntoa(iph[8]),
        "dst": socket.inet_ntoa(iph[9])
    }

def parse_tcp_header(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 20: return None
    tcph = struct.unpack("!HHLLBBHHH", data[:20])
    flags = [name for mask, name in TCP_FLAGS.items() if tcph[5] & mask]
    return {
        "sport": tcph[0], "dport": tcph[1],
        "seq": tcph[2], "ack": tcph[3],
        "flags": flags, "window": tcph[6],
        "header_len": (tcph[4] >> 4) * 4
    }

def parse_udp_header(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 8: return None
    udph = struct.unpack("!HHHH", data[:8])
    return {"sport": udph[0], "dport": udph[1], "length": udph[2]}

def parse_icmp_header(data: bytes) -> Optional[Dict[str, Any]]:
    if len(data) < 4: return None
    icmph = struct.unpack("!BBH", data[:4])
    types = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
    return {"type_name": types.get(icmph[0], f"Type {icmph[0]}")}

def port_label(port: int) -> str:
    svc = WELL_KNOWN_PORTS.get(port, "")
    return f"{port} ({svc})" if svc else str(port)

# ─── Sniffer thread ──────────────────────────────────────────────────────────

class SnifferThread(threading.Thread):
    def __init__(self, callback, proto_filter="ALL", ip_filter="", port_filter="", payload_filter=""):
        super().__init__(daemon=True)
        self.callback = callback
        self.proto_filter = proto_filter
        self.ip_filter = ip_filter.strip()
        self.port_filter = port_filter.strip()
        self.payload_filter = payload_filter.strip().lower().encode(errors='ignore')
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def run(self):
        sock = None
        try:
            if IS_WINDOWS:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                sock.bind((socket.gethostbyname(socket.gethostname()), 0))
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            else:
                sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))

            sock.settimeout(1.0)

            while not self._stop_event.is_set():
                try:
                    raw, _ = sock.recvfrom(65535)
                except socket.timeout:
                    continue

                ts = time.time()
                ip_data = raw if IS_WINDOWS else raw[14:]
                ip = parse_ip_header(ip_data)
                if not ip: continue

                proto_name = PROTO_MAP.get(ip["proto"], f"#{ip['proto']}")

                # 1. IP & Protocol Filter Check
                if self.proto_filter != "ALL" and proto_name != self.proto_filter: continue
                if self.ip_filter and (self.ip_filter not in ip["src"] and self.ip_filter not in ip["dst"]): continue
                
                # 2. Payload Search Filter
                if self.payload_filter and self.payload_filter not in raw.lower(): continue

                # Queue DNS resolution async
                for addr in (ip["src"], ip["dst"]):
                    if addr not in DNS_CACHE and addr not in QUEUED_IPS:
                        QUEUED_IPS.add(addr)
                        DNS_QUEUE.put(addr)

                pkt = {
                    "ts": ts,
                    "time": datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S.%f")[:-3],
                    "proto": proto_name, "src": ip["src"], "dst": ip["dst"],
                    "ttl": ip["ttl"], "sport": "-", "dport": "-",
                    "flags": "", "length": len(raw), "info": "", "dpi": "",
                    "raw_data": raw 
                }

                payload = ip_data[ip["ihl"]:]
                sport_str = ""
                dport_str = ""

                if ip["proto"] == 6:   # TCP
                    tcp = parse_tcp_header(payload)
                    if tcp:
                        sport_str, dport_str = str(tcp["sport"]), str(tcp["dport"])
                        pkt.update({
                            "sport": port_label(tcp["sport"]), "dport": port_label(tcp["dport"]),
                            "flags": " ".join(tcp["flags"]),
                            "info": f"Seq={tcp['seq']} Ack={tcp['ack']} Win={tcp['window']}"
                        })
                        app_payload = payload[tcp["header_len"]:]
                        pkt["dpi"] = inspect_payload(app_payload, 6, sport_str, dport_str)
                
                elif ip["proto"] == 17:  # UDP
                    udp = parse_udp_header(payload)
                    if udp:
                        sport_str, dport_str = str(udp["sport"]), str(udp["dport"])
                        pkt.update({
                            "sport": port_label(udp["sport"]), "dport": port_label(udp["dport"]),
                            "info": f"Len={udp['length']}"
                        })
                        app_payload = payload[8:]
                        pkt["dpi"] = inspect_payload(app_payload, 17, sport_str, dport_str)
                
                elif ip["proto"] == 1:   # ICMP
                    icmp = parse_icmp_header(payload)
                    if icmp: pkt["info"] = icmp["type_name"]

                # 3. Port Filter Check
                if self.port_filter and self.port_filter not in (sport_str, dport_str):
                    continue

                if pkt["dpi"]:
                    pkt["info"] = f"[{pkt['dpi']}] {pkt['info']}"

                self.callback(pkt)

        except PermissionError:
            self.callback({"_error": "permission"})
        except OSError as e:
            self.callback({"_error": str(e)})
        finally:
            if sock:
                if IS_WINDOWS:
                    try: sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except Exception: pass
                sock.close()

# ─── Custom UI Widgets ───────────────────────────────────────────────────────

class HoverButton(tk.Label):
    def __init__(self, master, text, bg_color, hover_color, text_color, command, **kwargs):
        super().__init__(master, text=text, bg=bg_color, fg=text_color, cursor="hand2", padx=12, pady=6, **kwargs)
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.command = command
        self.is_disabled = False
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)
        self.bind("<Button-1>", self.on_click)

    def on_enter(self, e):
        if not self.is_disabled: self.config(bg=self.hover_color)

    def on_leave(self, e):
        if not self.is_disabled: self.config(bg=self.bg_color)

    def on_click(self, e):
        if not self.is_disabled and self.command: self.command()

    def set_state(self, state):
        self.is_disabled = (state == "disabled")
        if self.is_disabled:
            self.config(fg="#6b7280", bg="#1f2937", cursor="arrow")
        else:
            self.config(fg="#ffffff", bg=self.bg_color, cursor="hand2")

# ─── GUI Application ─────────────────────────────────────────────────────────

class PacketSnifferApp(tk.Tk):
    MAX_ROWS = 2500  
    PRUNE_COUNT = 500 

    def __init__(self):
        super().__init__()
        self.title("Network Sniffer")
        self.geometry("1200x820")
        self.minsize(1000, 600)
        
        self.C_BG       = "#0f172a" 
        self.C_CARD     = "#1e293b" 
        self.C_HOVER    = "#334155" 
        self.C_PRIMARY  = "#6366f1"  
        self.C_PRIMARY_H= "#4f46e5"
        self.C_DANGER   = "#ef4444" 
        self.C_DANGER_H = "#dc2626"
        self.C_TEXT     = "#f8fafc"
        self.C_MUTED    = "#94a3b8"
        
        self.configure(bg=self.C_BG)

        self.packets = []          
        self.sniffer = None
        self.running = False
        self.pkt_counter = 0

        self.stats = defaultdict(int)   
        self.ip_stats = defaultdict(int)
        self.queue = queue.Queue()

        self._build_styles()
        self._build_ui()
        self._build_context_menu()
        self._poll_queue()
        self._update_graph()

    def _build_styles(self):
        self.MONO     = ("Consolas", 10) if IS_WINDOWS else ("Monospace", 10)
        self.MONO_SM  = ("Consolas", 9)  if IS_WINDOWS else ("Monospace", 9)
        self.SANS     = ("Segoe UI", 10) if IS_WINDOWS else ("Sans", 10)
        
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Treeview", background=self.C_CARD, foreground=self.C_TEXT, fieldbackground=self.C_CARD, rowheight=24, font=self.MONO_SM, borderwidth=0)
        style.map("Treeview", background=[("selected", self.C_PRIMARY)], foreground=[("selected", "#ffffff")])
        style.configure("Treeview.Heading", background="#0f172a", foreground=self.C_MUTED, font=("Segoe UI", 9, "bold") if IS_WINDOWS else ("Sans", 9, "bold"), relief="flat", padding=4)
        style.configure("TNotebook", background=self.C_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=self.C_CARD, foreground=self.C_MUTED, padding=[10, 2], borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", self.C_PRIMARY)], foreground=[("selected", "#ffffff")])
        style.configure("Vertical.TScrollbar", background=self.C_CARD, troughcolor=self.C_BG, arrowcolor=self.C_MUTED, borderwidth=0)

    def _build_ui(self):
        # ── Top toolbar ──
        toolbar = tk.Frame(self, bg=self.C_BG, pady=12, padx=16)
        toolbar.pack(fill="x")

        tk.Label(toolbar, text="🛰  Network Sniffer", bg=self.C_BG, fg=self.C_PRIMARY, font=("Segoe UI", 16, "bold") if IS_WINDOWS else ("Sans", 16, "bold")).pack(side="left")

        ctrl = tk.Frame(toolbar, bg=self.C_BG)
        ctrl.pack(side="right")

        self.btn_export = HoverButton(ctrl, "💾 Export ▾", self.C_CARD, self.C_HOVER, self.C_TEXT, self._show_export_menu, font=self.SANS)
        self.btn_export.pack(side="right", padx=4)
        
        self.export_menu = tk.Menu(self, tearoff=0, bg=self.C_CARD, fg=self.C_TEXT, activebackground=self.C_PRIMARY, activeforeground="#ffffff", relief="flat", bd=1)
        self.export_menu.add_command(label="Export to PCAP (Wireshark)", command=self.export_pcap)
        self.export_menu.add_command(label="Export to CSV Table", command=self.export_csv)

        HoverButton(ctrl, "🗑 Clear", self.C_CARD, self.C_HOVER, self.C_TEXT, self.clear_packets, font=self.SANS).pack(side="right", padx=4)
        self.btn_stop = HoverButton(ctrl, "⏹ Stop", self.C_DANGER, self.C_DANGER_H, "#ffffff", self.stop_capture, font=self.SANS)
        self.btn_stop.pack(side="right", padx=4)
        self.btn_stop.set_state("disabled")
        
        self.btn_start = HoverButton(ctrl, "▶ Start", self.C_PRIMARY, self.C_PRIMARY_H, "#ffffff", self.start_capture, font=self.SANS)
        self.btn_start.pack(side="right", padx=4)

        # ── Filter Bar ──
        filter_bar = tk.Frame(self, bg=self.C_CARD, pady=8, padx=16)
        filter_bar.pack(fill="x")

        tk.Label(filter_bar, text="Target IP:", bg=self.C_CARD, fg=self.C_MUTED, font=self.SANS).pack(side="left", padx=(0,4))
        self.ip_var = tk.StringVar()
        self.ip_entry = tk.Entry(filter_bar, textvariable=self.ip_var, width=14, bg=self.C_BG, fg=self.C_TEXT, insertbackground=self.C_TEXT, relief="flat", font=self.MONO_SM)
        self.ip_entry.pack(side="left", padx=(0,15), ipady=3)

        tk.Label(filter_bar, text="Port:", bg=self.C_CARD, fg=self.C_MUTED, font=self.SANS).pack(side="left", padx=(0,4))
        self.port_var = tk.StringVar()
        self.port_entry = tk.Entry(filter_bar, textvariable=self.port_var, width=6, bg=self.C_BG, fg=self.C_TEXT, insertbackground=self.C_TEXT, relief="flat", font=self.MONO_SM)
        self.port_entry.pack(side="left", padx=(0,15), ipady=3)

        tk.Label(filter_bar, text="Protocol:", bg=self.C_CARD, fg=self.C_MUTED, font=self.SANS).pack(side="left", padx=(0,4))
        self.proto_var = tk.StringVar(value="ALL")
        self.proto_combo = ttk.Combobox(filter_bar, textvariable=self.proto_var, values=["ALL","TCP","UDP","ICMP"], state="readonly", width=6)
        self.proto_combo.pack(side="left", padx=(0,15))

        tk.Label(filter_bar, text="Payload contains:", bg=self.C_CARD, fg=self.C_MUTED, font=self.SANS).pack(side="left", padx=(0,4))
        self.payload_var = tk.StringVar()
        self.payload_entry = tk.Entry(filter_bar, textvariable=self.payload_var, width=20, bg=self.C_BG, fg=self.C_TEXT, insertbackground=self.C_TEXT, relief="flat", font=self.MONO_SM)
        self.payload_entry.pack(side="left", padx=(0,15), ipady=3)

        # ── Main paned area ──
        paned = tk.PanedWindow(self, orient="vertical", bg=self.C_BG, sashrelief="flat", sashwidth=6)
        paned.pack(fill="both", expand=True, padx=16, pady=16)

        table_card = tk.Frame(paned, bg=self.C_CARD, bd=1, relief="flat")
        paned.add(table_card, minsize=250)

        cols = ("#", "Time", "Protocol", "Source", "Sport", "Destination", "Dport", "Flags", "TTL", "Len", "Info")
        self.tree = ttk.Treeview(table_card, columns=cols, show="headings", selectmode="browse")

        widths = [50, 90, 70, 130, 70, 130, 70, 100, 45, 60, 250]
        for col, w in zip(cols, widths):
            self.tree.heading(col, text=col, command=lambda c=col: self._sort_by(c))
            self.tree.column(col, width=w, minwidth=40, anchor="w")

        self.tree.tag_configure("TCP",  foreground="#60a5fa")
        self.tree.tag_configure("UDP",  foreground="#c084fc")
        self.tree.tag_configure("ICMP", foreground="#fcd34d")
        self.tree.tag_configure("OTHER",foreground=self.C_MUTED)
        self.tree.tag_configure("odd", background="#1e293b")
        self.tree.tag_configure("even", background="#1a2235")

        vsb = ttk.Scrollbar(table_card, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.auto_scroll = True
        self.tree.bind("<ButtonPress-1>", lambda e: setattr(self, "auto_scroll", False))

        # ── Bottom Split Pane ──
        bottom_pane = tk.Frame(paned, bg=self.C_BG)
        paned.add(bottom_pane, minsize=240)

        detail_card = tk.Frame(bottom_pane, bg=self.C_CARD)
        detail_card.pack(side="left", fill="both", expand=True, padx=(0, 8))
        
        self.notebook = ttk.Notebook(detail_card)
        self.notebook.pack(fill="both", expand=True, padx=4, pady=4)

        f_parsed = tk.Frame(self.notebook, bg=self.C_CARD)
        self.detail_text = scrolledtext.ScrolledText(f_parsed, bg=self.C_CARD, fg=self.C_TEXT, font=self.MONO, relief="flat", state="disabled")
        self.detail_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.notebook.add(f_parsed, text=" Parsed Details ")

        f_hex = tk.Frame(self.notebook, bg=self.C_CARD)
        self.hex_text = scrolledtext.ScrolledText(f_hex, bg=self.C_CARD, fg="#a7f3d0", font=self.MONO, relief="flat", state="disabled")
        self.hex_text.pack(fill="both", expand=True, padx=8, pady=8)
        self.notebook.add(f_hex, text=" Raw Hex Dump ")

        # Stats & Graph Card
        stats_card = tk.Frame(bottom_pane, bg=self.C_CARD, width=320)
        stats_card.pack(side="right", fill="y")
        stats_card.pack_propagate(False)
        
        tk.Label(stats_card, text="Traffic Analysis", bg=self.C_CARD, fg=self.C_PRIMARY, font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=12, pady=(8,0))
        self.stats_text = tk.Text(stats_card, bg=self.C_CARD, fg=self.C_TEXT, font=self.MONO_SM, relief="flat", state="disabled", height=8)
        self.stats_text.pack(fill="x", padx=12, pady=(4,4))

        tk.Label(stats_card, text="Live Traffic (Pkts/sec)", bg=self.C_CARD, fg=self.C_PRIMARY, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12)
        self.graph_canvas = tk.Canvas(stats_card, bg="#1a2235", height=60, highlightthickness=0)
        self.graph_canvas.pack(fill="both", expand=True, padx=12, pady=(4,12))
        
        self.traffic_history = [0] * 60
        self.last_pkt_count = 0

        # ── Status bar ──
        status_bar = tk.Frame(self, bg="#0b1120", pady=4, padx=16)
        status_bar.pack(side="bottom", fill="x")

        self.status_dot = tk.Label(status_bar, text="●", fg=self.C_MUTED, bg="#0b1120", font=("", 10))
        self.status_dot.pack(side="left")
        self.status_lbl = tk.Label(status_bar, text="  Ready", bg="#0b1120", fg=self.C_MUTED, font=self.MONO_SM)
        self.status_lbl.pack(side="left")
        self.stat_lbl = tk.Label(status_bar, text="Total: 0", bg="#0b1120", fg=self.C_MUTED, font=self.MONO_SM)
        self.stat_lbl.pack(side="right")

    def _show_export_menu(self):
        self.export_menu.post(self.btn_export.winfo_rootx(), self.btn_export.winfo_rooty() + self.btn_export.winfo_height())

    def _set_filters_state(self, state):
        self.ip_entry.config(state=state)
        self.port_entry.config(state=state)
        self.proto_combo.config(state="readonly" if state=="normal" else "disabled")
        self.payload_entry.config(state=state)

    def _build_context_menu(self):
        self.ctx_menu = tk.Menu(self, tearoff=0, bg=self.C_CARD, fg=self.C_TEXT, activebackground=self.C_PRIMARY, activeforeground="#ffffff", relief="flat", bd=1)
        self.ctx_menu.add_command(label="Copy Source IP", command=lambda: self._ctx_action("copy_src"))
        self.ctx_menu.add_command(label="Copy Dest IP", command=lambda: self._ctx_action("copy_dst"))
        self.ctx_menu.add_separator()
        self.ctx_menu.add_command(label="Filter by Source IP", command=lambda: self._ctx_action("filter_src"))
        self.ctx_menu.add_command(label="Filter by Dest IP", command=lambda: self._ctx_action("filter_dst"))
        
        if IS_WINDOWS: self.tree.bind("<Button-3>", self._show_context_menu)
        else:
            self.tree.bind("<Button-2>", self._show_context_menu)
            self.tree.bind("<Button-3>", self._show_context_menu)

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.ctx_menu.post(event.x_root, event.y_root)

    def _ctx_action(self, action):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])["values"]
        src_ip, dst_ip = vals[3], vals[5]

        if action == "copy_src":
            self.clipboard_clear()
            self.clipboard_append(src_ip)
        elif action == "copy_dst":
            self.clipboard_clear()
            self.clipboard_append(dst_ip)
        elif action == "filter_src": self.ip_var.set(src_ip)
        elif action == "filter_dst": self.ip_var.set(dst_ip)

    # ── Live Graph Update ─────────────────────────────────────────────────────

    def _update_graph(self):
        if self.running:
            current_count = self.pkt_counter
            delta = current_count - self.last_pkt_count
            self.last_pkt_count = current_count
            
            self.traffic_history.pop(0)
            self.traffic_history.append(delta)
            
            self.graph_canvas.delete("all")
            w = self.graph_canvas.winfo_width()
            h = self.graph_canvas.winfo_height()
            
            if w > 10 and h > 10:
                max_val = max(max(self.traffic_history), 5)
                points = []
                step = w / max(1, len(self.traffic_history) - 1)
                for i, val in enumerate(self.traffic_history):
                    x = i * step
                    y = h - (val / max_val * h * 0.85) 
                    points.extend([x, y])
                
                poly_points = [0, h] + points + [w, h]
                self.graph_canvas.create_polygon(poly_points, fill="#312e81", outline=self.C_PRIMARY)
                self.graph_canvas.create_text(w-5, 5, text=f"{delta} pkts/s", anchor="ne", fill=self.C_PRIMARY, font=self.MONO_SM)

        self.after(1000, self._update_graph)

    # ── Capture control ───────────────────────────────────────────────────────

    def start_capture(self):
        if self.running: return
        self.queue = queue.Queue() 
        self.running = True
        self.status_dot.config(fg="#10b981") 
        self.status_lbl.config(text="  Capturing traffic...")
        
        self.btn_start.set_state("disabled")
        self.btn_stop.set_state("normal")
        self._set_filters_state("disabled")
        
        self.auto_scroll = True
        self.last_pkt_count = self.pkt_counter
        self.traffic_history = [0] * 60
        self.graph_canvas.delete("all")

        self.sniffer = SnifferThread(
            self.queue.put, 
            self.proto_var.get(), 
            self.ip_var.get(),
            self.port_var.get(),
            self.payload_var.get()
        )
        self.sniffer.start()

    def stop_capture(self):
        if not self.running: return
        self.running = False
        if self.sniffer: self.sniffer.stop()
        
        self.status_dot.config(fg=self.C_MUTED)
        self.status_lbl.config(text="  Stopped")
        self.btn_start.set_state("normal")
        self.btn_stop.set_state("disabled")
        self._set_filters_state("normal")

    def clear_packets(self):
        self.stop_capture()
        self.packets.clear()
        self.stats.clear()
        self.ip_stats.clear()
        self.pkt_counter = 0
        self.tree.delete(*self.tree.get_children())
        self._set_text(self.detail_text, "")
        self._set_text(self.hex_text, "")
        self._update_stats_panel()
        self.stat_lbl.config(text="Total: 0")
        self.traffic_history = [0] * 60
        self.graph_canvas.delete("all")

    # ── Queue polling ─────────────────────────────────────────────────────────

    def _poll_queue(self):
        processed = 0
        last_iid = None
        
        while not self.queue.empty() and processed < 100:
            try:
                pkt = self.queue.get_nowait()
                if "_error" in pkt:
                    self._handle_error(pkt["_error"])
                    continue
                last_iid = self._ingest_packet(pkt)
                processed += 1
            except queue.Empty: break

        if processed > 0:
            self._update_status_counts()
            
            children = self.tree.get_children()
            if len(children) > self.MAX_ROWS:
                self.tree.delete(*children[:self.PRUNE_COUNT])
                del self.packets[:self.PRUNE_COUNT] 

            if self.auto_scroll and last_iid:
                self.tree.see(last_iid)

        self.after(100, self._poll_queue)

    def _handle_error(self, err):
        self.stop_capture()
        msg = ("Permission denied.\n\nRaw socket access requires elevated privileges:\n• Windows: Administrator\n• Linux: sudo / root") if err == "permission" else f"Socket error: {err}"
        messagebox.showerror("Capture Error", msg)

    def _truncate(self, s, length=18):
        return s[:length-3] + "..." if len(s) > length else s

    def _ingest_packet(self, pkt):
        self.pkt_counter += 1
        pkt["_id"] = self.pkt_counter
        self.packets.append(pkt)

        proto = pkt["proto"]
        self.stats[proto] += 1
        self.ip_stats[pkt["src"]] += 1

        stripe_tag = "even" if self.pkt_counter % 2 == 0 else "odd"
        color_tag = proto if proto in ("TCP","UDP","ICMP") else "OTHER"
        
        # Pull resolved names from Cache if ready, else use IP
        src_display = self._truncate(DNS_CACHE.get(pkt["src"], pkt["src"]))
        dst_display = self._truncate(DNS_CACHE.get(pkt["dst"], pkt["dst"]))

        row = (
            self.pkt_counter, pkt["time"], proto,
            src_display, pkt["sport"], dst_display, pkt["dport"],
            pkt["flags"], pkt["ttl"], f"{pkt['length']}", pkt["info"]
        )
        return self.tree.insert("", "end", values=row, tags=(color_tag, stripe_tag))

    def _update_status_counts(self):
        self.stat_lbl.config(text=f"Total: {self.pkt_counter}   TCP: {self.stats.get('TCP',0)}   UDP: {self.stats.get('UDP',0)}   ICMP: {self.stats.get('ICMP',0)}")
        if self.pkt_counter % 10 == 0: self._update_stats_panel()

    # ── Detail Updates ────────────────────────────────────────────────────────

    def _on_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        vals = self.tree.item(sel[0])["values"]
        if not vals: return

        pkt_id = int(vals[0])
        p = next((pkt for pkt in reversed(self.packets) if pkt["_id"] == pkt_id), None)
        if not p: return

        src_res = DNS_CACHE.get(p['src'], '')
        src_str = f"{p['src']} ({src_res})" if src_res and src_res != p['src'] else p['src']
        
        dst_res = DNS_CACHE.get(p['dst'], '')
        dst_str = f"{p['dst']} ({dst_res})" if dst_res and dst_res != p['dst'] else p['dst']

        # 1. Parsed View
        lines = [
            f"FRAME DETAILS (Packet #{p['_id']})",
            f"{'='*40}",
            f"Timestamp    : {p['time']}",
            f"Protocol     : {p['proto']}",
            f"Length       : {p['length']} bytes",
            f"TTL          : {p['ttl']}",
            "",
            f"NETWORK LAYER (IPv4)",
            f"{'-'*40}",
            f"Source IP    : {src_str}",
            f"Dest IP      : {dst_str}",
            "",
            f"TRANSPORT LAYER",
            f"{'-'*40}",
            f"Source Port  : {p['sport']}",
            f"Dest Port    : {p['dport']}"
        ]
        if p["flags"]: lines.append(f"Flags        : {p['flags']}")
        if p["info"]:  lines.append(f"Info         : {p['info']}")
        
        self._set_text(self.detail_text, "\n".join(lines))

        # 2. Hex Dump View
        if "raw_data" in p:
            self._set_text(self.hex_text, hexdump(p["raw_data"]))
        else:
            self._set_text(self.hex_text, "No raw data captured.")

    def _set_text(self, widget, text):
        widget.config(state="normal")
        widget.delete("1.0","end")
        widget.insert("end", text)
        widget.config(state="disabled")

    def _update_stats_panel(self):
        total = self.pkt_counter
        if total == 0:
            self._set_text(self.stats_text, "No packets yet.")
            return

        lines = [f"Total packets : {total}", ""]
        for proto in ("TCP","UDP","ICMP"):
            c = self.stats.get(proto,0)
            pct = int(c/total*100) if total else 0
            bar = "█" * (pct//5)
            lines.append(f"{proto:<5} {c:>6}  {pct:>3}% {bar}")

        lines.extend(["", "Top Talkers (Source):", "-"*25])
        for ip, c in sorted(self.ip_stats.items(), key=lambda x: -x[1])[:5]:
            display = self._truncate(DNS_CACHE.get(ip, ip), 18)
            lines.append(f"{display:<18} {c:>5}")

        self._set_text(self.stats_text, "\n".join(lines))

    def _sort_by(self, col):
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children("")]
        try: data.sort(key=lambda x: int(x[0]))
        except ValueError: data.sort()
        for i, (_, k) in enumerate(data): self.tree.move(k, "", i)

    # ── Exporting Data ────────────────────────────────────────────────────────

    def export_csv(self):
        if not self.packets: return messagebox.showinfo("Export", "No packets to export.")
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV","*.csv")], title="Save CSV")
        if not path: return
        
        export_data = [{k: v for k, v in p.items() if k not in ('raw_data', 'ts', 'dpi')} for p in self.packets]
        fields = ["_id","time","proto","src","sport","dst","dport", "flags","ttl","length","info"]
        
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(export_data)
        messagebox.showinfo("Export", f"Saved {len(self.packets)} packets to:\n{path}")

    def export_pcap(self):
        """Export raw packet history into a Wireshark-compatible PCAP file."""
        if not self.packets: return messagebox.showinfo("Export", "No packets to export.")
        path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP","*.pcap")], title="Save PCAP")
        if not path: return
        
        # Linktype 101 corresponds to Raw IP (Windows behavior), 1 is Ethernet (Linux behavior)
        link_type = 101 if IS_WINDOWS else 1 
        
        try:
            with open(path, "wb") as f:
                # PCAP Global Header: Magic, Major, Minor, Res1, Res2, SnapLen, LinkType
                f.write(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))
                
                for p in self.packets:
                    raw = p.get("raw_data")
                    if raw:
                        ts = p.get("ts", time.time())
                        sec = int(ts)
                        usec = int((ts - sec) * 1000000)
                        length = len(raw)
                        # PCAP Packet Header: TimeSec, TimeMicroSec, InclLen, OrigLen
                        f.write(struct.pack("<IIII", sec, usec, length, length))
                        f.write(raw)
                        
            messagebox.showinfo("Export", f"Successfully exported {len(self.packets)} packets to PCAP.\n\nYou can now open this file in Wireshark.")
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to save PCAP:\n{e}")

    def on_close(self):
        self.stop_capture()
        self.destroy()

if __name__ == "__main__":
    app = PacketSnifferApp()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.mainloop()