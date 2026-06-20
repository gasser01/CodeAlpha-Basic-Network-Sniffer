#!/usr/bin/env python3
# Network sniffer with a GUI - CodeAlpha Task 1
# Live, colour-coded packet view built with Tkinter. Capturing runs on a
# background thread and feeds packets to the window through a queue so the
# interface stays responsive.
#
# Still needs admin/root rights (raw capture) and Npcap on Windows.

import os
import sys
import queue
import datetime
import tkinter as tk
from tkinter import ttk, messagebox

from scapy.all import conf, AsyncSniffer
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP


def is_admin():
    """True if we already have the rights needed to capture packets."""
    if sys.platform == "win32":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # Linux / macOS: raw sockets need root (uid 0)
    return hasattr(os, "geteuid") and os.geteuid() == 0


def relaunch_as_admin():
    """Restart this program with a Windows UAC elevation prompt.

    Returns True if an elevated instance was launched (caller should quit),
    False if elevation failed or was cancelled by the user.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        params = " ".join('"%s"' % a for a in sys.argv)
        # ShellExecuteW with the "runas" verb triggers the UAC dialog
        rc = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1)
        return rc > 32  # >32 means it started successfully
    except Exception:
        return False

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


def _default_iface_name():
    try:
        return getattr(conf.iface, "name", str(conf.iface))
    except Exception:
        return "auto"


def list_interfaces():
    """Return [(label, sniff_name)] of pickable interfaces, default first.

    'label' is what we show in the dropdown (name + IP); 'sniff_name' is what
    gets passed to scapy (None means 'let scapy pick the default').
    """
    out = [("(default)  -  %s" % _default_iface_name(), None)]
    try:
        if sys.platform == "win32":
            from scapy.arch.windows import get_windows_if_list
            # skip the npcap/wfp/qos filter-layer duplicates of each adapter
            skip = ("-WFP", "-Npcap", "-QoS", "-Virtual", "Kernel Debug")
            seen = set()
            for i in get_windows_if_list():
                name = i.get("name", "")
                if not name or name in seen or any(s in name for s in skip):
                    continue
                ip4 = next((x for x in (i.get("ips") or [])
                            if ":" not in x and x), None)
                if not ip4:
                    continue  # skip adapters with no IPv4 (idle/virtual clutter)
                seen.add(name)
                out.append(("%s  (%s)" % (name, ip4), name))
        else:
            from scapy.all import get_if_list
            for name in get_if_list():
                out.append((name, name))
    except Exception:
        pass
    return out


class SnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer - CodeAlpha Task 1")
        self.root.geometry("1100x650")
        self.root.configure(bg="#1e1e1e")

        self.pkt_queue = queue.Queue()
        self.sniffer = None                    # the running AsyncSniffer (or None)
        self.running = False
        self.count = 0
        self.payloads = {}                     # row id -> payload dump
        self.packets = []                      # every captured packet (for live filtering)
        self.display_filter = ""               # live table filter text (lowercased)
        self.stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "OTHER": 0}
        self.MAX_PACKETS = 5000                # cap memory on busy networks

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
        self.iface_map = dict(list_interfaces())          # label -> sniff name
        iface_labels = list(self.iface_map.keys())
        self.iface_var = tk.StringVar(value=iface_labels[0])
        self.iface_combo = ttk.Combobox(top, textvariable=self.iface_var,
                                        values=iface_labels, width=30,
                                        state="readonly")
        self.iface_combo.pack(side="left", padx=(4, 12))

        tk.Label(top, text="Capture (BPF):", bg="#1e1e1e", fg="#cccccc").pack(side="left")
        self.filter_var = tk.StringVar()
        bpf_entry = tk.Entry(top, textvariable=self.filter_var, width=18, bg="#2d2d2d",
                             fg="#ffffff", insertbackground="#ffffff")
        bpf_entry.pack(side="left", padx=(4, 12))
        # press Enter to (re)apply the capture filter to the LIVE capture
        bpf_entry.bind("<Return>", self.apply_capture_filter)

        self.start_btn = tk.Button(top, text="▶ Start", command=self.start_capture,
                                   bg="#1f6f3f", fg="white", width=10, relief="flat")
        self.start_btn.pack(side="left", padx=3)
        self.stop_btn = tk.Button(top, text="■ Stop", command=self.stop_capture,
                                  bg="#8a2b2b", fg="white", width=10, relief="flat",
                                  state="disabled")
        self.stop_btn.pack(side="left", padx=3)
        tk.Button(top, text="Clear", command=self.clear, bg="#444444",
                  fg="white", width=8, relief="flat").pack(side="left", padx=3)

        # show an elevation button only when we are NOT already admin/root
        if not is_admin():
            tk.Button(top, text="🛡 Run as Admin", command=self.elevate,
                      bg="#8a6d1a", fg="white", relief="flat").pack(side="right", padx=3)

        # second row: live display filter (works WITHOUT stopping the capture)
        top2 = tk.Frame(self.root, bg="#1e1e1e")
        top2.pack(fill="x", padx=8, pady=(0, 4))
        tk.Label(top2, text="Display filter:", bg="#1e1e1e",
                 fg="#cccccc").pack(side="left")
        self.disp_var = tk.StringVar()
        disp_entry = tk.Entry(top2, textvariable=self.disp_var, bg="#2d2d2d",
                              fg="#ffd866", insertbackground="#ffffff")
        disp_entry.pack(side="left", fill="x", expand=True, padx=(4, 8))
        self.disp_var.trace_add("write", self._on_display_filter)
        disp_entry.bind("<Return>", lambda e: self._on_display_filter())
        tk.Label(top2, text="press Enter to filter  (e.g.  tcp   443   192.168   dns)",
                 bg="#1e1e1e", fg="#777777").pack(side="left")

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
        base = ("Total: %d    TCP: %d    UDP: %d    ICMP: %d    ARP: %d    Other: %d"
                % (self.count, self.stats["TCP"], self.stats["UDP"],
                   self.stats["ICMP"], self.stats["ARP"], self.stats["OTHER"]))
        if self.display_filter:
            shown = len(self.tree.get_children())
            base += "        [filter \"%s\": showing %d]" % (self.display_filter, shown)
        return base

    # ---------- capture ----------
    def _current_bpf(self):
        return self.filter_var.get().strip() or None

    def _spawn_sniffer(self, iface, bpf):
        """Start a fresh AsyncSniffer; return True on success."""
        try:
            self.sniffer = AsyncSniffer(
                iface=iface, filter=bpf, store=False,
                prn=lambda p: self.pkt_queue.put(p))
            self.sniffer.start()
            return True
        except Exception as e:
            self.pkt_queue.put(("__error__", str(e)))
            return False

    def _kill_sniffer(self):
        if self.sniffer is not None:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None

    def start_capture(self):
        if self.running:
            return
        # We try to capture even if IsUserAnAdmin() is False, because Npcap can
        # be installed to allow non-admin capture. If it really fails, the error
        # handler offers to relaunch as administrator.
        iface = self.iface_map.get(self.iface_var.get())   # None = scapy default
        if self._spawn_sniffer(iface, self._current_bpf()):
            self.running = True
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")

    def stop_capture(self):
        self.running = False
        self._kill_sniffer()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")

    def apply_capture_filter(self, _event=None):
        """Enter pressed in the BPF box: re-apply the filter to the LIVE
        capture without stopping/clearing - the stream keeps running, now
        filtered at capture level."""
        if not self.running:
            return  # not capturing yet; the filter will apply when you Start
        iface = self.iface_map.get(self.iface_var.get())
        self._kill_sniffer()
        self._spawn_sniffer(iface, self._current_bpf())   # table is kept as-is

    # ---------- packet -> table ----------
    def _drain_queue(self):
        try:
            while True:
                item = self.pkt_queue.get_nowait()
                if isinstance(item, tuple) and item[0] == "__error__":
                    self.payload_box.delete("1.0", "end")
                    self.payload_box.insert("end", "Capture error: %s\n\n"
                        "Make sure Npcap is installed and try running as "
                        "Administrator." % item[1])
                    self.stop_capture()
                    # the capture actually failed - now it makes sense to offer UAC
                    if sys.platform == "win32" and not is_admin():
                        self.prompt_for_admin()
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
        iid = str(self.count)
        values = (self.count, ts, proto, src, sport, dst, dport, length, info)
        pkt_row = {
            "iid": iid,
            "values": values,
            "tag": tag,
            # one lowercase string we can substring-search for the live filter
            "search": " ".join(str(v) for v in values).lower(),
        }
        self.packets.append(pkt_row)
        self.payloads[iid] = (clean_payload(payload_data) if payload_data
                              else "(no application payload)")

        # drop the oldest packet if we are over the cap
        if len(self.packets) > self.MAX_PACKETS:
            old = self.packets.pop(0)
            self.payloads.pop(old["iid"], None)
            if self.tree.exists(old["iid"]):
                self.tree.delete(old["iid"])

        # only show it now if it matches the current live filter
        if self._matches(pkt_row):
            self.tree.insert("", "end", iid=iid, values=values, tags=(tag,))
            self.tree.see(iid)
        self.stats_var.set(self._stats_text())

    # ---------- live display filter ----------
    def _matches(self, pkt_row):
        return not self.display_filter or self.display_filter in pkt_row["search"]

    def _on_display_filter(self, *_):
        self.display_filter = self.disp_var.get().strip().lower()
        self._render_table()

    def _render_table(self):
        """Rebuild the visible table from self.packets using the live filter."""
        self.tree.delete(*self.tree.get_children())
        last = None
        for p in self.packets:
            if self._matches(p):
                self.tree.insert("", "end", iid=p["iid"],
                                 values=p["values"], tags=(p["tag"],))
                last = p["iid"]
        if last:
            self.tree.see(last)
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
        self.packets.clear()
        self.count = 0
        for k in self.stats:
            self.stats[k] = 0
        self.stats_var.set(self._stats_text())
        self.payload_box.delete("1.0", "end")

    def elevate(self):
        """Relaunch the app with admin rights (Windows UAC prompt)."""
        if is_admin():
            messagebox.showinfo("Already elevated",
                                "The app is already running as administrator.")
            return
        if sys.platform != "win32":
            messagebox.showinfo(
                "Run as root",
                "On Linux/macOS, close this window and start it with:\n\n"
                "    sudo python3 gui_sniffer.py")
            return
        if relaunch_as_admin():
            # an elevated copy is starting - close this non-elevated one
            self.root.destroy()
        else:
            messagebox.showwarning(
                "Elevation cancelled",
                "Could not start with administrator rights. Packet capture "
                "will not work until you run the app as administrator.")

    def prompt_for_admin(self):
        """On startup, offer to restart elevated if we lack capture rights."""
        if is_admin():
            return
        if sys.platform == "win32":
            msg = ("Capturing packets needs administrator rights.\n\n"
                   "Restart the app as administrator now?")
            if messagebox.askyesno("Administrator required", msg):
                self.elevate()
        else:
            messagebox.showwarning(
                "Root required",
                "Capturing packets needs root. Restart with:\n\n"
                "    sudo python3 gui_sniffer.py")

    def _on_close(self):
        self.running = False
        self._kill_sniffer()
        self.root.destroy()


def main():
    root = tk.Tk()
    SnifferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
