#!/usr/bin/env python3
"""
CodeAlpha - Task 1: Basic Network Sniffer
============================================
A packet sniffer built with Scapy. It captures live network traffic and
displays source/destination IPs, protocol, ports, TCP flags, and a preview
of the payload. Supports IPv4 and IPv6 and can optionally log to a file.

------------------------------------------------------------------------------
USAGE
    sudo python3 sniffer.py                         # sniff on default interface
    sudo python3 sniffer.py -i eth0 -c 50           # 50 packets on eth0
    sudo python3 sniffer.py -f "tcp port 80"        # only HTTP traffic (BPF)
    sudo python3 sniffer.py -o capture.log          # also write to a log file
    sudo python3 sniffer.py --no-color              # plain output (for redirects)

NOTE
    Sniffing requires admin privileges (root / sudo on Linux & macOS,
    Administrator + Npcap on Windows). Run ONLY on networks you own or are
    explicitly authorized to monitor. This is an educational tool.
------------------------------------------------------------------------------
"""

import argparse
import datetime
import sys

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, Raw


def _enable_windows_ansi() -> None:
    """On Windows 10+ turn on ANSI escape processing so colors render in the
    console instead of showing raw "<-[32m" codes. No-op on other platforms."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        # enable ENABLE_VIRTUAL_TERMINAL_PROCESSING (0x4) on stdout
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass  # if it fails, --no-color or a modern terminal still works


_enable_windows_ansi()


# --- Optional ANSI colors (auto-disabled with --no-color or when piped) -------
class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"


# Map a transport protocol name to a color for quick visual scanning
PROTO_COLOR = {
    "TCP": C.GREEN,
    "UDP": C.BLUE,
    "ICMP": C.MAGENTA,
    "ARP": C.YELLOW,
}

# IP protocol numbers we want readable names for when it isn't TCP/UDP/ICMP
PROTO_NAMES = {
    2: "IGMP", 47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF", 132: "SCTP",
}

# State shared across packets
state = {"count": 0, "use_color": True, "log": None}


def paint(text: str, color: str) -> str:
    """Wrap text in an ANSI color, unless color output is disabled."""
    if not state["use_color"]:
        return text
    return f"{color}{text}{C.RESET}"


def format_payload(data: bytes, max_len: int = 64) -> str:
    """Turn raw payload bytes into a readable single-line preview.

    Printable ASCII is shown as-is; everything else becomes '.'. Long
    payloads are truncated so the console stays clean.
    """
    snippet = data[:max_len]
    text = "".join(chr(b) if 32 <= b <= 126 else "." for b in snippet)
    suffix = "..." if len(data) > max_len else ""
    return f"{text}{suffix}  ({len(data)} bytes)"


def emit(line: str) -> None:
    """Print a line to the console and (if enabled) append it to the log file.

    The log file always gets the plain, color-free version.
    """
    print(line)
    if state["log"]:
        # Strip ANSI codes for the file by re-rendering without color
        plain = line
        for code in vars(C).values():
            if isinstance(code, str) and code.startswith("\033"):
                plain = plain.replace(code, "")
        state["log"].write(plain + "\n")
        state["log"].flush()


def process_packet(packet) -> None:
    """Callback run for every captured packet: parse layers and print a summary."""
    state["count"] += 1
    n = state["count"]
    ts = datetime.datetime.now().strftime("%H:%M:%S")

    # ---- Layer 3: figure out the IP (or non-IP) addresses --------------------
    if packet.haslayer(IP):
        l3 = packet[IP]
        src, dst, ttl, ver, proto_num = l3.src, l3.dst, l3.ttl, "IPv4", l3.proto
    elif packet.haslayer(IPv6):
        l3 = packet[IPv6]
        src, dst, ttl, ver, proto_num = l3.src, l3.dst, l3.hlim, "IPv6", l3.nh
    elif packet.haslayer(ARP):
        arp = packet[ARP]
        op = "who-has" if arp.op == 1 else "is-at"
        line = (
            f"{paint(f'[{ts}]', C.DIM)} #{n:<4} "
            f"{paint('ARP ', PROTO_COLOR['ARP'])} "
            f"{arp.psrc} {op} {arp.pdst}"
        )
        emit(line)
        return
    else:
        # Anything else we can't classify - show Scapy's own one-line summary
        emit(f"{paint(f'[{ts}]', C.DIM)} #{n:<4} {paint('OTHER', C.DIM)} {packet.summary()}")
        return

    # ---- Layer 4: transport protocol, ports, extra detail --------------------
    proto = ver  # default label if no known transport layer
    sport = dport = None
    extra = f"ttl={ttl}"

    if packet.haslayer(TCP):
        tcp = packet[TCP]
        proto, sport, dport = "TCP", tcp.sport, tcp.dport
        extra = f"flags={tcp.flags} ttl={ttl}"
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        proto, sport, dport = "UDP", udp.sport, udp.dport
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        proto = "ICMP"
        extra = f"type={icmp.type} code={icmp.code} ttl={ttl}"
    elif proto_num in PROTO_NAMES:
        # Known layer-4 protocol with no Scapy dissector loaded here
        proto = PROTO_NAMES[proto_num]

    # Build "ip:port" endpoints (or just "ip" when there are no ports)
    src_ep = f"{src}:{sport}" if sport is not None else src
    dst_ep = f"{dst}:{dport}" if dport is not None else dst

    proto_tag = paint(f"{proto:<5}", PROTO_COLOR.get(proto, C.CYAN))
    line = (
        f"{paint(f'[{ts}]', C.DIM)} #{n:<4} {proto_tag} "
        f"{paint(src_ep, C.BOLD)} {paint('->', C.DIM)} {paint(dst_ep, C.BOLD)}   "
        f"{paint(extra, C.DIM)}"
    )
    emit(line)

    # ---- Payload preview (if the packet carries application data) ------------
    if packet.haslayer(Raw):
        preview = format_payload(bytes(packet[Raw].load))
        emit(f"          {paint('payload:', C.DIM)} {preview}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 - Basic Network Sniffer (Scapy)"
    )
    parser.add_argument("-i", "--iface", default=None,
                        help="network interface to sniff (default: Scapy's default)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="number of packets to capture (0 = run until Ctrl+C)")
    parser.add_argument("-f", "--filter", default=None,
                        help="BPF capture filter, e.g. 'tcp port 80' or 'udp'")
    parser.add_argument("-o", "--output", default=None,
                        help="append captured summaries to this log file")
    parser.add_argument("--no-color", action="store_true",
                        help="disable colored output")
    args = parser.parse_args()

    # Disable color if requested or if output is being piped/redirected
    state["use_color"] = not args.no_color and sys.stdout.isatty()

    if args.output:
        state["log"] = open(args.output, "a", encoding="utf-8")

    print(paint("=" * 70, C.CYAN))
    print(paint(" CodeAlpha - Basic Network Sniffer", C.BOLD))
    print(f" interface={args.iface or 'default'}  "
          f"count={args.count or 'infinite'}  filter={args.filter or 'none'}")
    print(paint("=" * 70, C.CYAN))
    print(paint(" Press Ctrl+C to stop.\n", C.DIM))

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=process_packet,
            count=args.count,
            store=False,  # don't keep packets in memory - print and discard
        )
    except PermissionError:
        print(paint("\n[!] Permission denied. Run with sudo / as Administrator.", C.RED))
        return 1
    except KeyboardInterrupt:
        pass
    finally:
        if state["log"]:
            state["log"].close()

    print(paint(f"\n[+] Done. Captured {state['count']} packet(s).", C.GREEN))
    return 0


if __name__ == "__main__":
    sys.exit(main())
