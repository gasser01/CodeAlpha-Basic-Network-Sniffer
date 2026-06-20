#!/usr/bin/env python3
"""
Generates 'Sniffer_Explained.pdf' - a line-by-line illustrated walkthrough of
sniffer.py with syntax-highlighted code screenshots and diagrams.

Run:  python make_explainer_pdf.py
"""

import os
import tempfile

from PIL import Image, ImageDraw, ImageFont
from pygments import highlight
from pygments.lexers import PythonLexer
from pygments.formatters import ImageFormatter
from fpdf import FPDF
from fpdf.enums import XPos, YPos

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "sniffer.py")
OUT = os.path.join(HERE, "Sniffer_Explained.pdf")
TMP = tempfile.mkdtemp(prefix="snif_pdf_")

MONO = r"C:\Windows\Fonts\consola.ttf"
MONO_B = r"C:\Windows\Fonts\consolab.ttf"

# theme colors (RGB)
INK = (33, 37, 41)
MUTED = (110, 117, 125)
ACCENT = (31, 111, 63)      # green
ACCENT2 = (28, 79, 143)     # blue
CARD = (245, 246, 248)
LINE = (210, 214, 220)

with open(SRC, encoding="utf-8") as fh:
    SRC_LINES = fh.read().split("\n")


def code_slice(a, b):
    """1-indexed inclusive line range from sniffer.py."""
    return "\n".join(SRC_LINES[a - 1:b])


# ---------------------------------------------------------------------------
# Each block: title, (first_line, last_line), and a line-by-line explanation.
# ---------------------------------------------------------------------------
BLOCKS = [
    ("1. File header & documentation", (1, 22), [
        "Line 1: the 'shebang' - lets the file run as ./sniffer.py on Linux/macOS.",
        "Lines 2-22: a module docstring. It documents what the tool does, every",
        "   command-line example (USAGE), and a legal/ethics NOTE that capturing",
        "   needs admin rights and permission. Triple quotes = multi-line string.",
    ]),
    ("2. Imports & Windows color fix", (24, 45), [
        "Lines 24-26: standard library - argparse (CLI options), datetime",
        "   (timestamps), sys (platform check / stdout).",
        "Line 28: pull the pieces we need from Scapy: sniff() plus the layer",
        "   classes IP, IPv6, TCP, UDP, ICMP, ARP and Raw (application data).",
        "Lines 31-42: _enable_windows_ansi() switches on ANSI color processing on",
        "   Windows 10+ via a ctypes call to SetConsoleMode; it is a no-op on other",
        "   systems and silently ignores any error.",
        "Line 45: call it once at import so colors work in cmd.exe.",
    ]),
    ("3. The color table (class C)", (48, 58), [
        "Lines 49-58: class C is just a namespace of ANSI escape codes.",
        "   Each string like '\\033[32m' tells the terminal to switch color.",
        "   RESET returns to normal; DIM/BOLD change weight; the rest are colors.",
        "These are used later to paint protocols and fields different colors.",
    ]),
    ("4. Lookup tables & shared state", (61, 75), [
        "Lines 62-67: PROTO_COLOR maps a protocol name to one of the colors so",
        "   TCP is green, UDP blue, ICMP magenta, ARP yellow - easy to scan.",
        "Lines 70-72: PROTO_NAMES maps IP protocol NUMBERS to names for less",
        "   common protocols (GRE=47, ESP=50, OSPF=89, ...) that Scapy may not",
        "   dissect into a friendly object.",
        "Line 75: 'state' is a shared dict holding the running packet count,",
        "   whether color is on, and the open log file (None until used).",
    ]),
    ("5. paint() - apply a color", (78, 82), [
        "Line 78: paint(text, color) returns the text wrapped in color codes.",
        "Lines 80-81: if color is turned off, return the text unchanged.",
        "Line 82: otherwise sandwich it: <color> + text + RESET.",
    ]),
    ("6. format_payload() - readable bytes", (85, 94), [
        "Line 85: takes raw bytes and a max length (default 64).",
        "Line 91: snippet = first max_len bytes only (keep the console tidy).",
        "Line 92: build a string - printable ASCII (32..126) stays, every other",
        "   byte becomes '.' so binary data does not corrupt the terminal.",
        "Line 93: add '...' if we truncated the payload.",
        "Line 94: return the preview plus the true total byte count.",
    ]),
    ("7. emit() - print and log", (97, 110), [
        "Line 102: print the (possibly colored) line to the screen.",
        "Lines 103-110: if a log file is open, write a PLAIN copy to it.",
        "Lines 105-108: strip every ANSI code by replacing each one with '',",
        "   so the log file stays clean and readable.",
        "Lines 109-110: write the line and flush so it is saved immediately.",
    ]),
    ("8. process_packet() - part 1: Layer 3", (113, 139), [
        "Line 113: this function runs once for EVERY captured packet.",
        "Lines 115-116: bump the packet counter and remember this number.",
        "Line 117: record the capture time as HH:MM:SS.",
        "Lines 120-122: if it has an IPv4 layer, read source, destination, TTL",
        "   and the protocol number.",
        "Lines 123-125: same for IPv6 (hop-limit instead of TTL, 'nh' = next header).",
        "Lines 126-135: if it is ARP, print a 'who-has / is-at' line and return",
        "   early (ARP has no IP layer).",
        "Lines 136-139: anything else - print Scapy's own summary and return.",
    ]),
    ("9. process_packet() - part 2: Layer 4 & output", (141, 171), [
        "Lines 142-144: defaults - label is the IP version, no ports yet.",
        "Lines 146-149: TCP -> record ports and the TCP flags (e.g. S, A, PA).",
        "Lines 150-152: UDP -> record ports.",
        "Lines 153-156: ICMP -> record its type and code (e.g. echo request).",
        "Lines 157-159: otherwise, if the protocol number is known, use its name.",
        "Lines 162-163: build 'ip:port' endpoints (or just 'ip' when no ports).",
        "Lines 165-170: color the protocol tag and assemble the final summary",
        "   line: time, number, protocol, source -> destination, and extras.",
        "Line 171: send it to emit() to be printed/logged.",
    ]),
    ("10. process_packet() - part 3: payload", (173, 176), [
        "Line 174: does the packet carry a Raw (application data) layer?",
        "Line 175: if so, build a readable preview with format_payload().",
        "Line 176: print it indented under the packet, dimmed.",
    ]),
    ("11. main() - options, setup & banner", (179, 206), [
        "Lines 180-193: define the command-line options with argparse:",
        "   -i interface, -c count, -f BPF filter, -o output log, --no-color.",
        "Line 193: parse whatever the user typed.",
        "Line 196: only use color if not disabled AND output is a real terminal",
        "   (so redirected/piped output stays clean).",
        "Lines 198-199: open the log file for appending if -o was given.",
        "Lines 201-206: print a header banner showing the chosen settings.",
    ]),
    ("12. main() - capture loop & shutdown", (208, 226), [
        "Lines 209-215: the heart of the program - sniff() listens on the",
        "   interface, applies the BPF filter, and calls process_packet for each",
        "   packet. store=False means packets are printed then discarded (low RAM).",
        "Lines 216-218: if we lack privileges, show a clear message and exit 1.",
        "Lines 219-220: Ctrl+C just stops the loop quietly.",
        "Lines 221-223: always close the log file on the way out.",
        "Lines 225-226: print the total captured and return success (0).",
    ]),
    ("13. Program entry point", (229, 230), [
        "Line 229: this block runs only when the file is executed directly",
        "   (not when imported as a module).",
        "Line 230: call main() and use its return value as the process exit code.",
    ]),
]


# ---------------------------------------------------------------------------
# Render a code block to a PNG that looks like a dark editor screenshot.
# ---------------------------------------------------------------------------
def render_code_png(code, start_line, path):
    fmt = ImageFormatter(
        style="monokai", font_name="Consolas", font_size=26,
        line_numbers=True, line_number_start=start_line,
        line_number_bg="#2b2b2b", line_number_fg="#7a7a7a",
        line_number_separator=False, image_pad=18, line_pad=6,
    )
    png = highlight(code, PythonLexer(), fmt)
    with open(path, "wb") as fh:
        fh.write(png)
    return path


def render_terminal_png(path):
    """Hand-drawn 'terminal screenshot' of real sample output."""
    W = 1600
    pad = 24
    line_h = 34
    font = ImageFont.truetype(MONO, 24)
    fontb = ImageFont.truetype(MONO_B, 24)

    grey = (150, 150, 150)
    white = (230, 230, 230)
    green = (87, 196, 122)
    blue = (90, 150, 235)
    magenta = (200, 120, 210)

    # each line is a list of (text, color, bold)
    lines = [
        [("=" * 60, (90, 160, 200), False)],
        [(" CodeAlpha - Basic Network Sniffer", white, True)],
        [(" interface=default  count=5  filter=none", grey, False)],
        [("=" * 60, (90, 160, 200), False)],
        [(" Press Ctrl+C to stop.", grey, False)],
        [("", white, False)],
        [("[13:14:35] ", grey, False), ("#1   ", white, False),
         ("UDP  ", blue, True), ("160.79.104.10:443 -> 192.168.100.6:57918", white, False),
         ("   ttl=55", grey, False)],
        [("          payload: @Zo.....xn.*D9...Z.2%Q  (155 bytes)", grey, False)],
        [("[13:14:35] ", grey, False), ("#3   ", white, False),
         ("TCP  ", green, True), ("185.199.111.133:443 -> 192.168.100.6:49334", white, False),
         ("   flags=A ttl=56", grey, False)],
        [("[13:14:35] ", grey, False), ("#4   ", white, False),
         ("TCP  ", green, True), ("192.168.100.6:59457 -> 102.132.103.60:443", white, False),
         ("   flags=PA ttl=64", grey, False)],
        [("[13:14:36] ", grey, False), ("#5   ", white, False),
         ("ICMP ", magenta, True), ("8.8.8.8 -> 192.168.100.6", white, False),
         ("   type=0 code=0 ttl=117", grey, False)],
        [("", white, False)],
        [("[+] Done. Captured 5 packet(s).", green, True)],
    ]
    H = pad * 2 + line_h * len(lines) + 40
    img = Image.new("RGB", (W, H), (24, 24, 24))
    d = ImageDraw.Draw(img)
    # title bar with traffic-light dots
    d.rectangle([0, 0, W, 30], fill=(45, 45, 45))
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 22, 9, 26 + i * 22, 21], fill=col)
    y = 44
    for segs in lines:
        x = pad
        for text, color, bold in segs:
            f = fontb if bold else font
            d.text((x, y), text, font=f, fill=color)
            x += d.textlength(text, font=f)
        y += line_h
    img.save(path)
    return path


# ---------------------------------------------------------------------------
# PDF assembly
# ---------------------------------------------------------------------------
class PDF(FPDF):
    def multi_cell(self, *args, **kwargs):
        # always return the cursor to the left margin on the next line
        kwargs.setdefault("new_x", XPos.LMARGIN)
        kwargs.setdefault("new_y", YPos.NEXT)
        return super().multi_cell(*args, **kwargs)

    def header(self):
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "", 8)
        self.set_text_color(*MUTED)
        self.cell(0, 8, "CodeAlpha - Basic Network Sniffer  |  sniffer.py explained",
                  align="L", new_x=XPos.LMARGIN, new_y=YPos.TOP)
        self.cell(0, 8, "Page %d" % self.page_no(), align="R")
        self.ln(10)

    def footer(self):
        self.set_y(-12)
        self.set_font("Helvetica", "", 7)
        self.set_text_color(*MUTED)
        self.cell(0, 8, "Generated for the CodeAlpha Cyber Security internship",
                  align="C")


def heading(pdf, text, size=15, color=INK, top=2):
    pdf.ln(top)
    pdf.set_font("Helvetica", "B", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 8, text)
    pdf.ln(1)


def para(pdf, text, size=10.5, color=INK):
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*color)
    pdf.multi_cell(0, 5.6, text)
    pdf.ln(1)


def bullets(pdf, items, size=9.6):
    pdf.set_font("Helvetica", "", size)
    pdf.set_text_color(*INK)
    for it in items:
        x = pdf.get_x()
        pdf.set_text_color(*ACCENT)
        pdf.cell(5, 5.2, chr(149))   # bullet dot
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5.2, it)
    pdf.ln(1)


def image_fit(pdf, path, max_w=180, max_h=210):
    w_px, h_px = Image.open(path).size
    w_mm = max_w
    h_mm = h_px * (w_mm / w_px)
    if h_mm > max_h:
        h_mm = max_h
        w_mm = w_px * (h_mm / h_px)
    if pdf.get_y() + h_mm > 282:
        pdf.add_page()
    x = pdf.l_margin + (max_w - w_mm) / 2
    pdf.image(path, x=x, y=pdf.get_y(), w=w_mm)
    pdf.set_y(pdf.get_y() + h_mm + 4)


def box(pdf, x, y, w, h, title, lines, fill=CARD, border=LINE, tcol=INK):
    pdf.set_fill_color(*fill)
    pdf.set_draw_color(*border)
    pdf.rect(x, y, w, h, style="DF")
    pdf.set_xy(x, y + 2.5)
    pdf.set_font("Helvetica", "B", 8.5)
    pdf.set_text_color(*tcol)
    pdf.multi_cell(w, 4.2, title, align="C")
    pdf.set_xy(x, y + 14)
    pdf.set_font("Helvetica", "", 7.5)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(w, 3.6, lines, align="C")


def arrow(pdf, x1, y, x2):
    pdf.set_draw_color(*ACCENT)
    pdf.set_line_width(0.5)
    pdf.line(x1, y, x2, y)
    pdf.line(x2, y, x2 - 2.2, y - 1.8)
    pdf.line(x2, y, x2 - 2.2, y + 1.8)


def build():
    pdf = PDF(orientation="P", unit="mm", format="A4")
    pdf.set_auto_page_break(True, margin=15)
    pdf.set_margins(15, 15, 15)

    # ---- cover ----
    pdf.add_page()
    pdf.ln(28)
    pdf.set_fill_color(*ACCENT)
    pdf.rect(15, pdf.get_y(), 180, 2, style="F")
    pdf.ln(8)
    pdf.set_font("Helvetica", "B", 26)
    pdf.set_text_color(*INK)
    pdf.multi_cell(0, 12, "Basic Network Sniffer")
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(*MUTED)
    pdf.multi_cell(0, 8, "A line-by-line explanation of sniffer.py")
    pdf.ln(2)
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*ACCENT2)
    pdf.multi_cell(0, 7, "CodeAlpha - Cyber Security Internship | Task 1")
    pdf.ln(6)
    pdf.set_fill_color(*ACCENT)
    pdf.rect(15, pdf.get_y(), 180, 2, style="F")
    pdf.ln(12)
    para(pdf,
         "This document walks through every part of the Python packet sniffer. "
         "Each section shows a screenshot of the real source code (with line "
         "numbers) followed by a plain-English explanation of what each line "
         "does. It also includes diagrams of how packets travel from the "
         "network card into the program and how a single output line is built.",
         size=11)
    pdf.ln(2)
    para(pdf,
         "Tools used: Python 3, Scapy (packet capture), Npcap (Windows driver). "
         "The sniffer prints source/destination IPs, protocol, ports, TCP flags "
         "and a payload preview for IPv4, IPv6, ARP and more.",
         size=11)

    # ---- diagram: data flow ----
    pdf.add_page()
    heading(pdf, "How the sniffer sees your network")
    para(pdf,
         "Every packet your computer sends or receives passes through the "
         "network card. Npcap lets Scapy read a copy of each packet; Scapy "
         "hands it to our process_packet() function, which decodes the layers "
         "and prints a summary. Nothing is modified - the sniffer only observes.")
    y = pdf.get_y() + 4
    bw, bh, gap = 30, 24, 7
    x = 15
    steps = [
        ("Network", "traffic on\nthe wire"),
        ("NIC +\nNpcap", "captures a\ncopy"),
        ("Scapy\nsniff()", "delivers\npackets"),
        ("process_\npacket()", "decodes\nlayers"),
        ("Console\n+ log", "readable\noutput"),
    ]
    for i, (t, s) in enumerate(steps):
        box(pdf, x, y, bw, bh, t, s, fill=(CARD if i % 2 == 0 else (235, 242, 237)))
        if i < len(steps) - 1:
            arrow(pdf, x + bw, y + bh / 2, x + bw + gap)
        x += bw + gap
    pdf.set_y(y + bh + 10)

    heading(pdf, "How a packet is layered (and where the code reads it)", size=13)
    para(pdf,
         "A network packet is wrapped in layers, like envelopes inside "
         "envelopes. The sniffer peels them from the outside in:")
    rows = [
        ("Layer 2 - Link", "Ethernet / ARP (MAC addresses)", "haslayer(ARP)"),
        ("Layer 3 - Network", "IP / IPv6 (source & dest IP, TTL)", "packet[IP] / packet[IPv6]"),
        ("Layer 4 - Transport", "TCP / UDP / ICMP (ports, flags)", "packet[TCP] / [UDP] / [ICMP]"),
        ("Layer 7 - Application", "the actual data (HTTP, DNS, ...)", "packet[Raw].load"),
    ]
    pdf.ln(1)
    for name, desc, code in rows:
        pdf.set_font("Helvetica", "B", 9.5)
        pdf.set_text_color(*ACCENT2)
        pdf.cell(42, 6, name)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*INK)
        pdf.cell(78, 6, desc)
        pdf.set_font("Courier", "", 9)
        pdf.set_text_color(*MUTED)
        pdf.multi_cell(0, 6, code)

    # ---- diagram: anatomy of an output line + real screenshot ----
    pdf.add_page()
    heading(pdf, "Anatomy of one output line")
    para(pdf, "Here is a real line the sniffer prints, with each part labelled:")
    pdf.ln(1)
    pdf.set_fill_color(24, 24, 24)
    pdf.rect(15, pdf.get_y(), 180, 9, style="F")
    pdf.set_xy(17, pdf.get_y() + 1.6)
    pdf.set_font("Courier", "B", 9.5)
    pdf.set_text_color(120, 230, 150)
    pdf.cell(0, 5, "[13:14:35] #4  TCP  192.168.100.6:59457 -> 102.132.103.60:443  flags=PA ttl=64")
    pdf.set_xy(15, pdf.get_y() + 11)
    labels = [
        ("[13:14:35]", "capture time (HH:MM:SS)"),
        ("#4", "packet number in this session"),
        ("TCP", "protocol (color-coded: TCP green, UDP blue, ICMP magenta)"),
        ("192.168.100.6:59457", "source IP and port (your PC)"),
        ("->", "direction of travel"),
        ("102.132.103.60:443", "destination IP and port (443 = HTTPS)"),
        ("flags=PA", "TCP flags: P=Push data, A=Acknowledge"),
        ("ttl=64", "Time To Live - hop counter before the packet is dropped"),
    ]
    for tok, meaning in labels:
        pdf.set_font("Courier", "B", 9)
        pdf.set_text_color(*ACCENT)
        pdf.cell(46, 5.4, tok)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 5.4, meaning)
    pdf.ln(3)
    heading(pdf, "Real sample run", size=13)
    para(pdf, "Actual captured output (5 packets) from a live test:")
    shot = render_terminal_png(os.path.join(TMP, "terminal.png"))
    image_fit(pdf, shot, max_w=180, max_h=120)

    # ---- code walkthrough ----
    pdf.add_page()
    heading(pdf, "Line-by-line code walkthrough", size=16)
    para(pdf,
         "Each block below is a screenshot of the real sniffer.py (the numbers "
         "on the left are the actual file line numbers) followed by an "
         "explanation of what every line does.")

    for i, (title, (a, b), notes) in enumerate(BLOCKS):
        if i > 0:
            pdf.ln(2)
        heading(pdf, title, size=12.5, color=ACCENT2, top=3)
        png = render_code_png(code_slice(a, b), a, os.path.join(TMP, "b%02d.png" % i))
        image_fit(pdf, png, max_w=180, max_h=150)
        bullets(pdf, notes)

    # ---- how to run ----
    pdf.add_page()
    heading(pdf, "How to run it", size=16)
    para(pdf, "Open an ELEVATED terminal (Run as administrator on Windows, or "
              "use sudo on Linux/macOS). Npcap must be installed on Windows.")
    pdf.ln(1)
    cmds = [
        ("python sniffer.py", "capture on the default interface until Ctrl+C"),
        ("python sniffer.py -c 50", "stop after 50 packets"),
        ('python sniffer.py -f "tcp port 80"', "only capture HTTP traffic"),
        ('python sniffer.py -f "udp port 53"', "only DNS (readable domain names)"),
        ("python sniffer.py -o capture.log", "also save a clean copy to a file"),
        ("python sniffer.py --no-color", "plain text (good for redirecting)"),
    ]
    for cmd, desc in cmds:
        pdf.set_font("Courier", "B", 9.5)
        pdf.set_text_color(*ACCENT)
        pdf.cell(86, 6.4, cmd)
        pdf.set_font("Helvetica", "", 9.5)
        pdf.set_text_color(*INK)
        pdf.multi_cell(0, 6.4, desc)
    pdf.ln(3)
    heading(pdf, "Important - legal & ethical use", size=13, color=(150, 40, 40))
    para(pdf,
         "Only capture traffic on networks you own or are explicitly authorized "
         "to monitor. Packet sniffing on networks without permission is illegal "
         "in most countries. This tool is for learning and authorized testing "
         "only, as part of the CodeAlpha Cyber Security internship.")

    pdf.output(OUT)
    print("Wrote", OUT)


if __name__ == "__main__":
    build()
