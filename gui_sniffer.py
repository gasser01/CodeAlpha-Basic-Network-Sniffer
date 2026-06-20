#!/usr/bin/env python3
# Network sniffer with a GUI - CodeAlpha Task 1
# Live, colour-coded packet view built with Tkinter. Capturing runs on a
# background thread and feeds packets to the window through a queue so the
# interface stays responsive.
#
# Still needs admin/root rights (raw capture) and Npcap on Windows.

import queue
import threading
import datetime
import tkinter as tk
from tkinter import ttk

from scapy.all import sniff, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP

PROTO_NAMES = {1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
               47: "GRE", 50: "ESP", 89: "OSPF"}

# one colour per protocol so the table is easy to scan
PROTO_COLORS = {
    "TCP":  "#1f6f3f",   # green
    "UDP":  "#1c4f8f",   # blue
    "ICMP": "#a4601a",   # orange
    "ARP":  "#6b6b6b",   # grey
    "DNS":  "#6a1b9a",   # purple
    "OTHER": "#444444",
}


def proto_name(num):
    return PROTO_NAMES.get(num, "P-%d" % num)


def clean_payload(data, limit=2000):
    """Build a readable hex + ascii dump of the raw bytes."""
    if not data:
        return ""
    data = data[:limit]
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join("%02x" % b for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append("%-48s  %s" % (hex_part, ascii_part))
    return "\n".join(lines)


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer - CodeAlpha Task 1")
        self.root.geometry("1100x650")
        self.root.configure(bg="#1e1e1e")

        self.pkt_queue = queue.Queue()
        self.stop_event = threading.Event()
        self.sniff_thread = None
        self.count = 0
        self.payloads = {}                     # row id -> payload dump
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}

        self._build_widgets()
        self.root.after(200, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI ----------
    def _build_widgets(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#252526", foreground="#dddddd",
                        fieldbackground="#252526", rowheight=22, font=("Consolas", 9))
        style.configure("Treeview.Heading", background="#333333",
                        foreground="#ffffff", font=("Segoe UI", 9, "bold"))

        # top control bar
        top = tk.Frame(self.root, bg="#1e1e1e")
        top.pack(fill="x", padx=8, pady=6)

        tk.Label(top, text="Interface:", bg="#1e1e1e", fg="#cccccc").pack(side="left")
        self.iface_var = tk.StringVar()
        tk.Entry(top, textvariable=self.iface_var, width=22, bg="#2d2d2d",
                 fg="#ffffff", insertbackground="#ffffff").pack(side="left", padx=(4, 12))

        tk.Label(top, text="Filter (BPF):", bg="#1e1e1e", fg="#cccccc").pack(side="left")
        self.filter_var = tk.StringVar()
        tk.Entry(top, textvariable=self.filter_var, width=24, bg="#2d2d2d",
                 fg="#ffffff", insertbackground="#ffffff").pack(side="left", padx=(4, 12))

        self.start_btn = tk.Button(top, text="▶ Start", command=self.start_capture,
                                   bg="#1f6f3f", fg="white", width=10, relief="flat")
        self.start_btn.pack(side="left", padx=3)
        self.stop_btn = tk.Button(top, text="■ Stop", command=self.stop_capture,
                                  bg="#8a2b2b", fg="white", width=10, relief="flat",
                                  state="disabled")
        self.stop_btn.pack(side="left", padx=3)
        tk.Button(top, text="Clear", command=self.clear, bg="#444444",
                  fg="white", width=8, relief="flat").pack(side="left", padx=3)

        # packet table
        cols = ("no", "time", "proto", "src", "sport", "dst", "dport", "len", "info")
        headers = {"no": "#", "time": "Time", "proto": "Proto", "src": "Source",
                   "sport": "SPort", "dst": "Destination", "dport": "DPort",
                   "len": "Len", "info": "Info"}
        widths = {"no": 55, "time": 90, "proto": 60, "src": 150, "sport": 60,
                  "dst": 150, "dport": 60, "len": 55, "info": 260}

        mid = tk.Frame(self.root, bg="#1e1e1e")
        mid.pack(fill="both", expand=True, padx=8)

        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=headers[c])
            self.tree.column(c, width=widths[c],
                             anchor="center" if c in ("no", "proto", "sport", "dport", "len") else "w")
        vsb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # row colours per protocol
        for proto, color in PROTO_COLORS.items():
            self.tree.tag_configure(proto, foreground=color)
        self.tree.bind("<<TreeviewSelect>>", self._show_payload)

        # bottom: stats + payload viewer
        bottom = tk.Frame(self.root, bg="#1e1e1e")
        bottom.pack(fill="x", padx=8, pady=6)

        self.stats_var = tk.StringVar(value=self._stats_text())
        tk.Label(bottom, textvariable=self.stats_var, bg="#1e1e1e", fg="#dddddd",
                 font=("Consolas", 10), anchor="w").pack(fill="x")

        tk.Label(bottom, text="Payload (hex / ascii):", bg="#1e1e1e",
                 fg="#888888").pack(anchor="w", pady=(4, 0))
        self.payload_box = tk.Text(bottom, height=8, bg="#161616", fg="#9cdcfe",
                                   font=("Consolas", 9), wrap="none")
        self.payload_box.pack(fill="x")

    def _stats_text(self):
        return ("Total: %d    TCP: %d    UDP: %d    ICMP: %d    ARP: %d    Other: %d"
                % (self.count, self.stats["TCP"], self.stats["UDP"],
                   self.stats["ICMP"], self.stats["ARP"], self.stats["OTHER"]))

    # ---------- capture ----------
    def start_capture(self):
        if self.sniff_thread and self.sniff_thread.is_alive():
            return
        self.stop_event.clear()
        iface = self.iface_var.get().strip() or None
        bpf = self.filter_var.get().strip() or None
        self.sniff_thread = threading.Thread(
            target=self._run_sniff, args=(iface, bpf), daemon=True)
        self.sniff_thread.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")

    def stop_capture(self):
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def _run_sniff(self, iface, bpf):
        try:
            sniff(iface=iface, filter=bpf, store=False,
                  prn=lambda p: self.pkt_queue.put(p),
                  stop_filter=lambda p: self.stop_event.is_set())
        except Exception as e:
            self.pkt_queue.put(("__error__", str(e)))

    # ---------- packet -> table ----------
    def _drain_queue(self):
        try:
            while True:
                item = self.pkt_queue.get_nowait()
                if isinstance(item, tuple) and item[0] == "__error__":
                    self.payload_box.delete("1.0", "end")
                    self.payload_box.insert("end", "Capture error: %s\n\n"
                        "Make sure you are running as Administrator and Npcap "
                        "is installed." % item[1])
                    self.stop_capture()
                    continue
                self._add_packet(item)
        except queue.Empty:
            pass
        self.root.after(200, self._drain_queue)

    def _add_packet(self, pkt):
        self.count += 1
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        length = len(pkt)
        proto = "OTHER"
        src = dst = sport = dport = ""
        info = ""
        payload_data = b""

        if ARP in pkt:
            proto = "ARP"
            a = pkt[ARP]
            src, dst = a.psrc, a.pdst
            info = "who-has %s tell %s" % (a.pdst, a.psrc) if a.op == 1 else "%s is-at %s" % (a.psrc, a.hwsrc)

        elif IP in pkt:
            ip = pkt[IP]
            src, dst = ip.src, ip.dst
            proto = proto_name(ip.proto)
            if TCP in pkt:
                t = pkt[TCP]
                sport, dport = t.sport, t.dport
                info = "flags=%s seq=%d" % (t.sprintf("%TCP.flags%"), t.seq)
            elif UDP in pkt:
                u = pkt[UDP]
                sport, dport = u.sport, u.dport
                if sport == 53 or dport == 53:
                    proto = "DNS"
                info = "len=%d" % u.len
            elif ICMP in pkt:
                info = "type=%d code=%d" % (pkt[ICMP].type, pkt[ICMP].code)
            if pkt.haslayer("Raw"):
                payload_data = bytes(pkt["Raw"].load)

        elif Ether in pkt:
            e = pkt[Ether]
            src, dst = e.src, e.dst
            info = "ethertype=0x%04x" % e.type

        # bump stats (group DNS under UDP, unknown under OTHER)
        key = proto if proto in self.stats else ("UDP" if proto == "DNS" else "OTHER")
        self.stats[key] += 1

        tag = proto if proto in PROTO_COLORS else "OTHER"
        row = self.tree.insert("", "end", values=(
            self.count, ts, proto, src, sport, dst, dport, length, info), tags=(tag,))
        self.payloads[row] = clean_payload(payload_data) if payload_data else "(no application payload)"

        # auto-scroll to newest
        self.tree.see(row)
        self.stats_var.set(self._stats_text())

    def _show_payload(self, _event):
        sel = self.tree.selection()
        if not sel:
            return
        dump = self.payloads.get(sel[0], "")
        self.payload_box.delete("1.0", "end")
        self.payload_box.insert("end", dump)

    def clear(self):
        self.tree.delete(*self.tree.get_children())
        self.payloads.clear()
        self.count = 0
        for k in self.stats:
            self.stats[k] = 0
        self.stats_var.set(self._stats_text())
        self.payload_box.delete("1.0", "end")

    def _on_close(self):
        self.stop_event.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    SnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
