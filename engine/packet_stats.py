"""
engine/packet_stats.py
────────────────────────────────────────────────────────────────────────────────
Statistics and summary generation from a normalised packet list.

Produces the "Week 1 deliverable" output:
  • Total packet count
  • Protocol breakdown (TCP / UDP / ICMP / OTHER)
  • Top source and destination IPs
  • Top destination ports
  • Capture time range and duration
  • Traffic volume over time (for timeline charts later)
"""

from __future__ import annotations

import datetime
from collections import defaultdict, Counter
from typing import Optional

from engine.normaliser import NormalisedPacket, get_protocol_summary, get_ip_summary, get_time_range
from engine.logger import get_logger

log = get_logger(__name__)

# Common well-known ports for labelling
WELL_KNOWN_PORTS = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 8080: "HTTP-alt", 8443: "HTTPS-alt",
}


def generate_stats(packets: list[NormalisedPacket], pcap_meta: dict) -> dict:
    """
    Master stats function. Returns a structured stats dict.

    pcap_meta: output from pcap_loader.load_pcap()
    """
    if not packets:
        return {"error": "No packets to analyse"}

    first_ts, last_ts, duration = get_time_range(packets)

    stats = {
        "file": {
            "name":       pcap_meta.get("filename", "unknown"),
            "path":       pcap_meta.get("path", ""),
            "sha256":     pcap_meta.get("sha256", ""),
            "size_bytes": pcap_meta.get("file_size", 0),
        },
        "capture": {
            "first_packet":       first_ts.isoformat() if first_ts else None,
            "last_packet":        last_ts.isoformat()  if last_ts  else None,
            "duration_seconds":   round(duration, 3),
            "duration_human":     _fmt_duration(duration),
        },
        "totals": {
            "packets":     len(packets),
            "bytes":       sum(p.length for p in packets),
        },
        "protocols":      _protocol_breakdown(packets),
        "top_src_ips":    _top_ips(packets, direction="src", n=10),
        "top_dst_ips":    _top_ips(packets, direction="dst", n=10),
        "top_dst_ports":  _top_ports(packets, n=15),
        "ip_pairs":       _top_ip_pairs(packets, n=10),
        "timeline":       _build_timeline(packets, first_ts, duration),
        "unique_ips":     _unique_ips(packets),
        "unique_ports":   _unique_ports(packets),
    }

    log.info(f"Stats generated: {stats['totals']['packets']:,} pkts, "
             f"{_fmt_bytes(stats['totals']['bytes'])}, "
             f"duration {stats['capture']['duration_human']}")
    return stats


# ── Internal helpers ───────────────────────────────────────────────────────────

def _protocol_breakdown(packets: list[NormalisedPacket]) -> dict:
    counts = Counter(p.protocol for p in packets)
    total  = len(packets)
    return {
        proto: {
            "count":   cnt,
            "percent": round(cnt / total * 100, 1) if total else 0,
            "bytes":   sum(p.length for p in packets if p.protocol == proto),
        }
        for proto, cnt in counts.most_common()
    }


def _top_ips(packets: list[NormalisedPacket], direction: str, n: int) -> list[dict]:
    attr  = "src_ip" if direction == "src" else "dst_ip"
    count = Counter(getattr(p, attr) for p in packets if getattr(p, attr))
    total = len(packets)
    return [
        {
            "ip":      ip,
            "packets": cnt,
            "percent": round(cnt / total * 100, 1),
        }
        for ip, cnt in count.most_common(n)
    ]


def _top_ports(packets: list[NormalisedPacket], n: int) -> list[dict]:
    count = Counter(
        p.dst_port for p in packets
        if p.dst_port is not None and p.protocol in ("TCP", "UDP")
    )
    return [
        {
            "port":    port,
            "service": WELL_KNOWN_PORTS.get(port, "unknown"),
            "count":   cnt,
            "protocol": _guess_protocol(port),
        }
        for port, cnt in count.most_common(n)
    ]


def _top_ip_pairs(packets: list[NormalisedPacket], n: int) -> list[dict]:
    """Most active src→dst IP pairs."""
    count: Counter = Counter()
    bytes_: Counter = Counter()
    for p in packets:
        if p.src_ip and p.dst_ip:
            key = (p.src_ip, p.dst_ip)
            count[key]  += 1
            bytes_[key] += p.length
    return [
        {
            "src": src,
            "dst": dst,
            "packets": cnt,
            "bytes": bytes_[(src, dst)],
        }
        for (src, dst), cnt in count.most_common(n)
    ]


def _build_timeline(
    packets: list[NormalisedPacket],
    first_ts: Optional[datetime.datetime],
    duration: float,
    buckets: int = 60,
) -> list[dict]:
    """
    Splits the capture into `buckets` time slots and counts packets per slot.
    Returns list of {time, packets, bytes} suitable for Chart.js.
    """
    if not first_ts or duration <= 0:
        return []

    bucket_size = max(duration / buckets, 1.0)
    timeline: list[dict] = [
        {
            "time":    (first_ts + datetime.timedelta(seconds=i * bucket_size)).isoformat(),
            "packets": 0,
            "bytes":   0,
        }
        for i in range(buckets)
    ]

    for pkt in packets:
        if not pkt.timestamp:
            continue
        offset = (pkt.timestamp - first_ts).total_seconds()
        idx    = min(int(offset / bucket_size), buckets - 1)
        timeline[idx]["packets"] += 1
        timeline[idx]["bytes"]   += pkt.length

    return timeline


def _unique_ips(packets: list[NormalisedPacket]) -> dict:
    src = {p.src_ip for p in packets if p.src_ip}
    dst = {p.dst_ip for p in packets if p.dst_ip}
    return {
        "src_count":  len(src),
        "dst_count":  len(dst),
        "total_unique": len(src | dst),
        "internal":   sorted(ip for ip in (src | dst) if _is_private(ip)),
        "external":   sorted(ip for ip in (src | dst) if not _is_private(ip)),
    }


def _unique_ports(packets: list[NormalisedPacket]) -> dict:
    ports = {p.dst_port for p in packets if p.dst_port is not None}
    return {
        "count": len(ports),
        "well_known": sorted(p for p in ports if p in WELL_KNOWN_PORTS),
        "ephemeral":  len([p for p in ports if p > 1024]),
    }


def _is_private(ip: str) -> bool:
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        if parts[0] == 127: return True
        return False
    except Exception:
        return False


def _guess_protocol(port: int) -> str:
    tcp_ports = {21, 22, 23, 25, 80, 110, 143, 443, 445, 3389, 8080, 8443}
    udp_ports = {53, 67, 68, 161, 162, 123}
    if port in tcp_ports: return "TCP"
    if port in udp_ports: return "UDP"
    return "TCP/UDP"


def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024: return f"{b:.1f} {unit}"
        b //= 1024
    return f"{b:.1f} TB"


def _fmt_duration(seconds: float) -> str:
    if seconds < 60:   return f"{seconds:.1f}s"
    if seconds < 3600: return f"{seconds/60:.1f}m"
    return f"{seconds/3600:.1f}h"
