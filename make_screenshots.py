#!/usr/bin/env python3
"""
Renders documentation images into docs/:
  docs/gui_sniffer.png  - a faithful screenshot of the Tkinter GUI
  docs/cli_output.png   - a terminal screenshot of the CLI output

Run:  python make_screenshots.py
"""

import os
from PIL import Image, ImageDraw, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
DOCS = os.path.join(HERE, "docs")
os.makedirs(DOCS, exist_ok=True)

SEG = r"C:\Windows\Fonts\segoeui.ttf"
SEGB = r"C:\Windows\Fonts\segoeuib.ttf"
MONO = r"C:\Windows\Fonts\consola.ttf"
MONOB = r"C:\Windows\Fonts\consolab.ttf"


def font(path, size):
    return ImageFont.truetype(path, size)


# protocol -> row text color (matches PROTO_COLORS in gui_sniffer.py)
PROTO_RGB = {
    "TCP": (74, 200, 120),
    "UDP": (90, 150, 235),
    "ICMP": (210, 140, 70),
    "ARP": (160, 160, 160),
    "DNS": (180, 130, 220),
}


def gui_screenshot():
    W, H = 1340, 820
    img = Image.new("RGB", (W, H), (30, 30, 30))
    d = ImageDraw.Draw(img)

    f_ui = font(SEG, 19)
    f_uib = font(SEGB, 19)
    f_mono = font(MONO, 18)
    f_monob = font(MONOB, 18)

    # ---- window title bar ----
    d.rectangle([0, 0, W, 38], fill=(45, 45, 48))
    d.text((14, 8), "Network Sniffer  -  CodeAlpha Task 1", font=f_uib, fill=(235, 235, 235))
    for i, (lab, col) in enumerate([("-", (200, 200, 200)),
                                    ("[]", (200, 200, 200)),
                                    ("x", (220, 90, 90))]):
        d.text((W - 110 + i * 36, 8), lab, font=f_ui, fill=col)

    # ---- control bar ----
    y = 52
    d.text((16, y), "Interface:", font=f_ui, fill=(204, 204, 204))
    d.rounded_rectangle([110, y - 4, 320, y + 26], radius=4, fill=(45, 45, 45))
    d.text((120, y), "Wi-Fi", font=f_mono, fill=(255, 255, 255))

    d.text((340, y), "Filter (BPF):", font=f_ui, fill=(204, 204, 204))
    d.rounded_rectangle([460, y - 4, 700, y + 26], radius=4, fill=(45, 45, 45))
    d.text((470, y), "tcp or udp", font=f_mono, fill=(255, 255, 255))

    def button(x, text, color, w=110):
        d.rounded_rectangle([x, y - 6, x + w, y + 28], radius=5, fill=color)
        tw = d.textlength(text, font=f_uib)
        d.text((x + (w - tw) / 2, y), text, font=f_uib, fill=(255, 255, 255))
        return x + w + 10

    bx = 730
    bx = button(bx, "Start", (31, 111, 63))
    bx = button(bx, "Stop", (138, 43, 43))
    bx = button(bx, "Clear", (68, 68, 68), w=90)

    # ---- table ----
    cols = [("#", 55, "c"), ("Time", 95, "c"), ("Proto", 70, "c"),
            ("Source", 175, "l"), ("SPort", 70, "c"), ("Destination", 175, "l"),
            ("DPort", 70, "c"), ("Len", 60, "c"), ("Info", 380, "l")]
    tx0, ty0 = 14, 98
    tw = sum(c[1] for c in cols)
    # header
    d.rectangle([tx0, ty0, tx0 + tw, ty0 + 30], fill=(51, 51, 51))
    cx = tx0
    for name, w, _ in cols:
        d.text((cx + 8, ty0 + 6), name, font=f_uib, fill=(255, 255, 255))
        cx += w

    rows = [
        ("1", "14:02:11", "TCP", "192.168.1.5", "51544", "142.250.74.78", "443", "66", "flags=PA seq=914233"),
        ("2", "14:02:11", "DNS", "192.168.1.5", "54122", "192.168.1.1", "53", "74", "len=54"),
        ("3", "14:02:11", "TCP", "142.250.74.78", "443", "192.168.1.5", "51544", "1454", "flags=A seq=88210"),
        ("4", "14:02:12", "UDP", "192.168.1.19", "57621", "192.168.1.255", "57621", "108", "len=88"),
        ("5", "14:02:12", "ICMP", "192.168.1.5", "", "8.8.8.8", "", "98", "type=8 code=0"),
        ("6", "14:02:12", "ICMP", "8.8.8.8", "", "192.168.1.5", "", "98", "type=0 code=0"),
        ("7", "14:02:13", "ARP", "192.168.1.7", "", "192.168.1.1", "", "42", "who-has 192.168.1.1 tell .7"),
        ("8", "14:02:13", "TCP", "192.168.1.5", "59457", "104.18.41.41", "443", "583", "flags=PA seq=20194"),
        ("9", "14:02:13", "UDP", "192.168.1.5", "56011", "104.18.41.41", "443", "1250", "len=1230"),
        ("10", "14:02:14", "DNS", "192.168.1.1", "53", "192.168.1.5", "54122", "190", "len=170"),
        ("11", "14:02:14", "TCP", "192.168.1.5", "49334", "185.199.111.133", "443", "66", "flags=A seq=51"),
        ("12", "14:02:15", "ARP", "192.168.1.7", "", "192.168.1.20", "", "42", "who-has 192.168.1.20 tell .7"),
        ("13", "14:02:15", "UDP", "160.79.104.10", "443", "192.168.1.5", "57918", "1294", "len=1274"),
        ("14", "14:02:16", "TCP", "192.168.1.5", "59457", "102.132.103.60", "443", "70", "flags=PA seq=20262"),
    ]
    rh = 30
    ry = ty0 + 31
    sel_index = 7  # the highlighted row
    for i, row in enumerate(rows):
        bg = (9, 71, 113) if i == sel_index else ((37, 37, 38) if i % 2 == 0 else (43, 43, 44))
        d.rectangle([tx0, ry, tx0 + tw, ry + rh], fill=bg)
        color = PROTO_RGB.get(row[2], (200, 200, 200))
        if i == sel_index:
            color = (255, 255, 255)
        cx = tx0
        for (val, (_, w, align)) in zip(row, cols):
            f = f_mono
            tw_txt = d.textlength(val, font=f)
            if align == "c":
                d.text((cx + (w - tw_txt) / 2, ry + 6), val, font=f, fill=color)
            else:
                d.text((cx + 8, ry + 6), val, font=f, fill=color)
            cx += w
        ry += rh

    # ---- stats bar ----
    sy = ry + 12
    d.text((16, sy), "Total: 14    TCP: 6    UDP: 5    ICMP: 1    ARP: 2    Other: 0",
           font=f_mono, fill=(221, 221, 221))

    # ---- payload viewer ----
    py = sy + 36
    d.text((16, py), "Payload (hex / ascii):", font=f_ui, fill=(136, 136, 136))
    box_top = py + 28
    d.rectangle([14, box_top, W - 14, H - 14], fill=(22, 22, 22))
    dump = [
        "0000  47 45 54 20 2f 20 48 54 54 50 2f 31 2e 31 0d 0a   GET / HTTP/1.1..",
        "0010  48 6f 73 74 3a 20 65 78 61 6d 70 6c 65 2e 63 6f   Host: example.co",
        "0020  6d 0d 0a 55 73 65 72 2d 41 67 65 6e 74 3a 20 63   m..User-Agent: c",
        "0030  75 72 6c 2f 38 2e 30 0d 0a 41 63 63 65 70 74 3a   url/8.0..Accept:",
        "0040  20 2a 2f 2a 0d 0a 0d 0a                           *.*....",
    ]
    yy = box_top + 12
    for ln in dump:
        d.text((24, yy), ln, font=f_mono, fill=(156, 220, 254))
        yy += 26

    out = os.path.join(DOCS, "gui_sniffer.png")
    img.save(out)
    print("wrote", out)


def cli_screenshot():
    W = 1500
    pad = 24
    line_h = 32
    f = font(MONO, 22)
    fb = font(MONOB, 22)
    grey = (150, 150, 150)
    white = (230, 230, 230)
    green = (87, 196, 122)
    blue = (90, 150, 235)
    magenta = (200, 120, 210)
    yellow = (220, 200, 90)
    cyan = (90, 160, 200)

    lines = [
        [("=" * 58, cyan, False)],
        [(" CodeAlpha - Basic Network Sniffer", white, True)],
        [(" interface=default  count=0  filter=none", grey, False)],
        [("=" * 58, cyan, False)],
        [(" Press Ctrl+C to stop.", grey, False)],
        [("", white, False)],
        [("[14:02:11] ", grey, False), ("#1   ", white, False), ("TCP  ", green, True),
         ("192.168.1.5:51544 -> 142.250.74.78:443", white, False), ("   flags=PA ttl=64", grey, False)],
        [("          payload: ", grey, False), ("....e...$.....  (66 bytes)", grey, False)],
        [("[14:02:11] ", grey, False), ("#2   ", white, False), ("UDP  ", blue, True),
         ("192.168.1.5:54122 -> 192.168.1.1:53", white, False), ("   ttl=64", grey, False)],
        [("          payload: ", grey, False), ("......google.com....  (54 bytes)", grey, False)],
        [("[14:02:12] ", grey, False), ("#3   ", white, False), ("ICMP ", magenta, True),
         ("192.168.1.5 -> 8.8.8.8", white, False), ("   type=8 code=0 ttl=64", grey, False)],
        [("[14:02:13] ", grey, False), ("#4   ", white, False), ("ARP  ", yellow, True),
         ("192.168.1.7 who-has 192.168.1.1", white, False)],
        [("", white, False)],
        [("[+] Done. Captured 4 packet(s).", green, True)],
    ]
    H = pad * 2 + line_h * len(lines) + 44
    img = Image.new("RGB", (W, H), (24, 24, 24))
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 30], fill=(45, 45, 45))
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 22, 9, 26 + i * 22, 21], fill=col)
    d.text((W / 2 - 120, 4), "Administrator: PowerShell", font=font(SEG, 16), fill=(170, 170, 170))
    y = 44
    for segs in lines:
        x = pad
        for text, color, bold in segs:
            ff = fb if bold else f
            d.text((x, y), text, font=ff, fill=color)
            x += d.textlength(text, font=ff)
        y += line_h
    out = os.path.join(DOCS, "cli_output.png")
    img.save(out)
    print("wrote", out)


if __name__ == "__main__":
    gui_screenshot()
    cli_screenshot()
