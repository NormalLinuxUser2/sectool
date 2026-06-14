from __future__ import annotations

from collections import Counter, defaultdict
from typing import List, Optional

from ..core.context import Context
from ..core.errors import ModuleUnavailableError, SectoolError
from ..core.findings import Finding, Severity
from ..core.output import Reporter

NAME = "packets"
HELP = "Capture or read network traffic and flag suspicious patterns (educational)"

try:
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, Raw, rdpcap, sniff

    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False

CLEARTEXT_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 389: "LDAP",
}
CREDENTIAL_KEYWORDS = (
    b"password", b"passwd", b"pwd=", b"user ", b"pass ", b"authorization: basic",
)
PORT_SCAN_THRESHOLD = 15
TCP_SYN = 0x02
TCP_ACK = 0x10


def _protocol_name(packet) -> str:
    if packet.haslayer(DNS):
        return "DNS"
    if packet.haslayer(TCP):
        return "TCP"
    if packet.haslayer(UDP):
        return "UDP"
    if packet.haslayer(ICMP):
        return "ICMP"
    if packet.haslayer(ARP):
        return "ARP"
    if packet.haslayer(IPv6):
        return "IPv6"
    if packet.haslayer(IP):
        return "IP"
    return packet.lastlayer().name


def _endpoints(packet):
    if packet.haslayer(IP):
        return packet[IP].src, packet[IP].dst
    if packet.haslayer(IPv6):
        return packet[IPv6].src, packet[IPv6].dst
    if packet.haslayer(ARP):
        return packet[ARP].psrc, packet[ARP].pdst
    return None, None


def _preview(payload: bytes, limit: int = 80) -> str:
    text = payload.decode("latin-1", errors="replace")
    printable = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in text)
    return printable[:limit]


def _capture(args, logger) -> list:
    if not HAS_SCAPY:
        raise ModuleUnavailableError(
            "the packets module requires scapy (pip install scapy)"
        )
    if args.read:
        try:
            return list(rdpcap(args.read))
        except FileNotFoundError:
            raise SectoolError(f"pcap file not found: {args.read}")
        except (OSError, ValueError) as exc:
            raise SectoolError(f"could not read pcap {args.read}: {exc}")
    logger.info("starting live capture (count=%s timeout=%ss)", args.count, args.timeout)
    try:
        return list(sniff(iface=args.iface, count=args.count, timeout=args.timeout, filter=args.bpf))
    except PermissionError:
        raise SectoolError("live capture requires elevated privileges")
    except (OSError, ValueError) as exc:
        raise SectoolError(f"capture failed: {exc}")


def _print_summary(reporter: Reporter, total: int, protocols: Counter, talkers: Counter) -> None:
    reporter.message(f"Analyzed {total} packets")
    if protocols:
        distribution = ", ".join(f"{name}={count}" for name, count in protocols.most_common())
        reporter.message(f"Protocols: {distribution}")
    top = talkers.most_common(5)
    if top:
        reporter.message("Top talkers:")
        for (src, dst), count in top:
            reporter.message(f"  {src} -> {dst}: {count}")


def analyze(packets: list, reporter: Reporter, logger) -> List[Finding]:
    findings: List[Finding] = []
    protocols: Counter = Counter()
    talkers: Counter = Counter()
    syn_targets: defaultdict = defaultdict(set)
    cleartext: Counter = Counter()
    arp_table: defaultdict = defaultdict(set)
    credential_hits: List[tuple] = []

    for packet in packets:
        protocols[_protocol_name(packet)] += 1
        src, dst = _endpoints(packet)
        if src and dst:
            talkers[(src, dst)] += 1

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = int(tcp.flags)
            dport = int(tcp.dport)
            if flags & TCP_SYN and not flags & TCP_ACK and src:
                syn_targets[src].add((dst, dport))
            if dport in CLEARTEXT_PORTS:
                cleartext[CLEARTEXT_PORTS[dport]] += 1

        if packet.haslayer(ARP) and int(packet[ARP].op) == 2:
            arp_table[packet[ARP].psrc].add(packet[ARP].hwsrc)

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            lowered = payload.lower()
            if any(keyword in lowered for keyword in CREDENTIAL_KEYWORDS):
                credential_hits.append((src, dst, _preview(payload)))

    _print_summary(reporter, len(packets), protocols, talkers)

    for src, targets in syn_targets.items():
        ports = {port for _, port in targets}
        if len(ports) >= PORT_SCAN_THRESHOLD:
            findings.append(Finding(
                Severity.HIGH, "Possible port scan",
                f"{src} sent TCP SYN packets to {len(ports)} distinct ports.",
                recommendation="Investigate the source host; this resembles scanning activity.",
                category="recon",
                evidence=f"{src} -> {len(ports)} ports",
            ))

    for protocol, count in cleartext.items():
        findings.append(Finding(
            Severity.MEDIUM, f"Cleartext protocol observed: {protocol}",
            f"{count} packets used {protocol}, which transmits data without encryption.",
            recommendation="Migrate to an encrypted equivalent (HTTPS, SFTP, IMAPS, etc.).",
            category="cleartext",
        ))

    for ip, macs in arp_table.items():
        if len(macs) > 1:
            findings.append(Finding(
                Severity.HIGH, "Possible ARP spoofing",
                f"IP {ip} is associated with {len(macs)} different MAC addresses.",
                recommendation="Investigate for ARP cache poisoning / man-in-the-middle activity.",
                category="mitm",
                evidence=", ".join(sorted(macs)),
            ))

    for src, dst, preview in credential_hits[:20]:
        findings.append(Finding(
            Severity.HIGH, "Possible cleartext credentials",
            f"Credential-like data was seen from {src} to {dst}.",
            recommendation="Use encrypted protocols and rotate any exposed credentials.",
            category="credentials",
            evidence=preview,
        ))

    if not findings:
        findings.append(Finding(
            Severity.INFO, "No suspicious patterns detected",
            f"Analyzed {len(packets)} packets without matching any heuristic.",
            category="summary",
        ))
    return findings


def configure_parser(parser) -> None:
    parser.add_argument("--read", metavar="PCAP", help="Read packets from a pcap file")
    parser.add_argument("--iface", help="Interface to capture on (live capture)")
    parser.add_argument("--count", type=int, default=200, help="Packets to capture live (default: 200)")
    parser.add_argument("--timeout", type=float, default=15.0, help="Live capture timeout in seconds")
    parser.add_argument("--bpf", help="BPF capture filter, e.g. 'tcp port 80'")


def run(args, context: Context) -> List[Finding]:
    packets = _capture(args, context.logger)
    findings = analyze(packets, context.reporter, context.logger)
    context.reporter.report(findings, title="Packet analysis")
    return findings
