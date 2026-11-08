"""
engine/normaliser.py
────────────────────────────────────────────────────────────────────────────────
Packet normalisation module.

Takes raw Scapy packets from pcap_loader and produces a clean, ordered,
deduplicated packet list ready for session reconstruction.

Responsibilities:
  • Sort all packets by timestamp (handles out-of-order captures)
  • IP defragmentation (reassemble fragmented IP datagrams)
  • TCP duplicate removal (same seq number = duplicate)
  • Normalise timestamps to UTC datetime objects
  • Extract basic metadata per packet into a flat NormalisedPacket dict
"""

from __future__ import annotations

import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import rdpcap

from engine.logger import get_logger

log = get_logger(__name__)


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class NormalisedPacket:
    index:      int
    timestamp:  datetime.datetime
    src_ip:     Optional[str]
    dst_ip:     Optional[str]
    src_port:   Optional[int]
    dst_port:   Optional[int]
    protocol:   str                   # TCP | UDP | ICMP | OTHER
    length:     int
    payload:    bytes = field(repr=False, default=b"")
    flags:      str   = ""            # TCP flags e.g. "S", "SA", "PA", "F"
    raw_pkt:    object = field(repr=False, default=None)
    is_retransmit: bool = False       # TCP retransmission — kept but marked

    @property
    def five_tuple(self) -> tuple:
        """Canonical flow key — always smaller IP first for bidirectionality."""
        a = (self.src_ip, self.src_port)
        b = (self.dst_ip, self.dst_port)
        low, high = (a, b) if (self.src_ip or "") <= (self.dst_ip or "") else (b, a)
        return (low[0], low[1], high[0], high[1], self.protocol)


# ── Public API ─────────────────────────────────────────────────────────────────

def normalise(packets: list) -> list[NormalisedPacket]:
    """
    Full normalisation pipeline.
    Input:  raw Scapy packet list from pcap_loader
    Output: sorted, deduplicated list of NormalisedPacket
    """
    log.info(f"Normalising {len(packets):,} raw packets...")

    # Step 1 — sort by timestamp
    packets = _sort_by_time(packets)

    # Step 2 — IP defragmentation
    packets = _defragment_ip(packets)

    # Step 3 — convert to NormalisedPacket
    normalised = [_to_norm(i, pkt) for i, pkt in enumerate(packets)]

    # Step 4 — remove TCP duplicates
    normalised = _dedup_tcp(normalised)

    log.info(f"Normalised → {len(normalised):,} packets")
    return normalised


def get_protocol_summary(packets: list[NormalisedPacket]) -> dict:
    """
    Returns a dict of protocol → packet count.
    e.g. {"TCP": 1200, "UDP": 340, "ICMP": 12, "OTHER": 5}
    """
    counts: dict[str, int] = defaultdict(int)
    for pkt in packets:
        counts[pkt.protocol] += 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def get_ip_summary(packets: list[NormalisedPacket]) -> dict:
    """
    Returns top IPs by packet count: {ip: count}
    Useful for quick triage — high-count IPs are worth investigating.
    """
    counts: dict[str, int] = defaultdict(int)
    for pkt in packets:
        if pkt.src_ip:
            counts[pkt.src_ip] += 1
        if pkt.dst_ip:
            counts[pkt.dst_ip] += 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def get_time_range(packets: list[NormalisedPacket]) -> tuple:
    """Returns (first_timestamp, last_timestamp, duration_seconds)."""
    if not packets:
        return (None, None, 0)
    times = [p.timestamp for p in packets if p.timestamp]
    if not times:
        return (None, None, 0)
    first, last = min(times), max(times)
    duration = (last - first).total_seconds()
    return (first, last, duration)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _sort_by_time(packets: list) -> list:
    try:
        return sorted(packets, key=lambda p: float(p.time))
    except Exception:
        return packets   # if timestamps are broken, keep original order


def _defragment_ip(packets: list) -> list:
    """
    Reassemble fragmented IP packets.
    Scapy doesn't have a built-in defrag, so we do it manually:
    group fragments by (src, dst, ip_id), reassemble when MF=0.
    """
    frags: dict[tuple, list] = defaultdict(list)
    complete: list = []

    for pkt in packets:
        if pkt.haslayer(IP):
            ip = pkt[IP]
            if ip.flags == 1 or ip.frag > 0:   # More Fragments or non-zero offset
                key = (ip.src, ip.dst, ip.id)
                frags[key].append(pkt)
                # Check if we have the last fragment (MF=0, offset>0)
                if ip.flags == 0 and ip.frag > 0:
                    # Try to reassemble
                    try:
                        sorted_frags = sorted(frags[key], key=lambda p: p[IP].frag)
                        reassembled = _reassemble_fragments(sorted_frags)
                        if reassembled:
                            complete.append(reassembled)
                    except Exception:
                        complete.extend(frags[key])   # keep raw on failure
                    del frags[key]
            else:
                complete.append(pkt)
        else:
            complete.append(pkt)

    # Flush any incomplete fragment groups
    for remaining in frags.values():
        complete.extend(remaining)

    reassembled_count = len(packets) - len(complete)
    if reassembled_count > 0:
        log.info(f"Defragmented {reassembled_count} IP fragments")

    return complete


def _reassemble_fragments(frags: list) -> object:
    """Concatenate IP fragment payloads in frag-offset order."""
    try:
        base = frags[0].copy()
        payload = b""
        for frag in sorted(frags, key=lambda p: p[IP].frag):
            if frag.haslayer(Raw):
                payload += bytes(frag[Raw])
            elif frag.haslayer(IP):
                ip_layer = frag[IP]
                payload += bytes(ip_layer.payload)
        base[IP].flags = 0
        base[IP].frag  = 0
        base[IP].payload = Raw(payload)
        return base
    except Exception:
        return None


def _dedup_tcp(packets: list[NormalisedPacket]) -> list[NormalisedPacket]:
    """
    Mark TCP retransmissions instead of removing them.
    Retransmission rate per flow is an anomaly signal (Issue #6 fix).
    A high retransmit rate can indicate:
      - Network congestion (normal)
      - Slow C2 polling over lossy channel (suspicious)
      - IDS evasion via overlapping segments (malicious)
    """
    from scapy.layers.inet import TCP as ScapyTCP
    seen: set[tuple] = set()
    retransmits = 0

    for pkt in packets:
        if pkt.protocol == "TCP" and pkt.raw_pkt and pkt.raw_pkt.haslayer(ScapyTCP):
            seq = pkt.raw_pkt[ScapyTCP].seq
            key = (pkt.five_tuple, seq)
            if key in seen:
                pkt.is_retransmit = True
                retransmits += 1
            else:
                seen.add(key)

    if retransmits:
        log.info(f"Marked {retransmits} TCP retransmission(s) (kept, not removed)")
    return packets  # return ALL packets, retransmits marked


def _to_norm(index: int, pkt) -> NormalisedPacket:
    """Convert a raw Scapy packet to NormalisedPacket."""
    src_ip  = dst_ip  = None
    src_port = dst_port = None
    protocol = "OTHER"
    flags    = ""
    payload  = b""

    try:
        ts = datetime.datetime.utcfromtimestamp(float(pkt.time))
    except Exception:
        ts = datetime.datetime.utcnow()

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst

        if pkt.haslayer(TCP):
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            flags    = _tcp_flags(pkt[TCP].flags)
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])

        elif pkt.haslayer(UDP):
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw])

        elif pkt.haslayer(ICMP):
            protocol = "ICMP"

    length = len(pkt)

    return NormalisedPacket(
        index    = index,
        timestamp = ts,
        src_ip   = src_ip,
        dst_ip   = dst_ip,
        src_port = src_port,
        dst_port = dst_port,
        protocol = protocol,
        length   = length,
        payload  = payload,
        flags    = flags,
        raw_pkt  = pkt,
    )


def _tcp_flags(flags_int) -> str:
    """Convert Scapy TCP flags integer to readable string like 'SYN', 'ACK', 'PSH+ACK'."""
    flag_map = {
        0x01: "FIN",
        0x02: "SYN",
        0x04: "RST",
        0x08: "PSH",
        0x10: "ACK",
        0x20: "URG",
    }
    try:
        val = int(flags_int)
        parts = [name for bit, name in flag_map.items() if val & bit]
        return "+".join(parts) if parts else str(flags_int)
    except Exception:
        return str(flags_int)
