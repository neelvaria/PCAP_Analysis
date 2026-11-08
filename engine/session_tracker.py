"""
engine/session_tracker.py
────────────────────────────────────────────────────────────────────────────────
Session reconstruction core — Week 2.

Responsibilities:
  1. Extract 5-tuple flows from NormalisedPackets
  2. Group packets by bidirectional flow key
  3. Reassemble TCP byte streams in sequence-number order
  4. Detect and reconstruct HTTP request/response pairs from TCP payloads
  5. Return a list of Flow objects ready for DB insertion

A "flow" here means all packets sharing the same
  (src_ip, dst_ip, src_port, dst_port, protocol) 5-tuple,
  normalised so the lower IP is always "src" for bidirectionality.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

from engine.normaliser import NormalisedPacket
from engine.logger import get_logger

log = get_logger(__name__)

# Well-known service names for dst ports
SERVICE_MAP = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 80: "HTTP",
    110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3389: "RDP", 4444: "Meterpreter", 8080: "HTTP-alt",
    8443: "HTTPS-alt", 9001: "Tor",
}


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class HttpSession:
    method:        Optional[str] = None
    host:          Optional[str] = None
    uri:           Optional[str] = None
    user_agent:    Optional[str] = None
    status_code:   Optional[int] = None
    content_type:  Optional[str] = None
    body_size:     int = 0
    request_time:  Optional[str] = None
    full_request:  str = ""
    full_response: str = ""


@dataclass
class Flow:
    src_ip:       Optional[str]
    dst_ip:       Optional[str]
    src_port:     Optional[int]
    dst_port:     Optional[int]
    protocol:     str
    service:      str = ""

    # Aggregates
    packet_count: int = 0
    byte_count:   int = 0
    first_seen:   Optional[str] = None
    last_seen:    Optional[str] = None
    duration_sec: float = 0.0
    flags_seen:   set = field(default_factory=set)

    # Reconstructed application data
    payload_bytes:   bytes = field(repr=False, default=b"")
    payload_preview: str = ""
    http_sessions:   list[HttpSession] = field(default_factory=list)

    # Retransmission tracking (anomaly signal)
    retransmit_count: int   = 0
    retransmit_rate:  float = 0.0   # fraction of packets that are retransmits

    # All raw NormalisedPackets belonging to this flow
    packets: list[NormalisedPacket] = field(repr=False, default_factory=list)

    @property
    def five_tuple(self) -> str:
        return (f"{self.src_ip}:{self.src_port} → "
                f"{self.dst_ip}:{self.dst_port} [{self.protocol}]")


# ── Public API ─────────────────────────────────────────────────────────────────

def reconstruct_sessions(packets: list[NormalisedPacket]) -> list[Flow]:
    """
    Full session reconstruction pipeline.

    Input:  normalised packet list (from normaliser.normalise())
    Output: list of Flow objects, sorted by byte_count descending
    """
    log.info(f"Reconstructing sessions from {len(packets):,} packets...")

    # Step 1 — group packets into bidirectional flows
    flow_map = _group_into_flows(packets)

    # Step 2 — for each flow, reassemble TCP stream + parse HTTP
    flows = []
    for key, flow in flow_map.items():
        _finalise_flow(flow)
        flows.append(flow)

    flows.sort(key=lambda f: f.byte_count, reverse=True)

    tcp_flows   = sum(1 for f in flows if f.protocol == "TCP")
    udp_flows   = sum(1 for f in flows if f.protocol == "UDP")
    http_flows  = sum(1 for f in flows if f.http_sessions)
    total_bytes = sum(f.byte_count for f in flows)

    log.info(f"Reconstructed {len(flows):,} flows "
             f"(TCP:{tcp_flows} UDP:{udp_flows}) | "
             f"HTTP sessions: {http_flows} | "
             f"Total bytes: {_fmt_bytes(total_bytes)}")

    return flows


# ── Internal ───────────────────────────────────────────────────────────────────

def _group_into_flows(packets: list[NormalisedPacket]) -> dict:
    """
    Group packets by canonical bidirectional 5-tuple.
    For each unique flow key, create or update a Flow object.
    """
    flow_map: dict[tuple, Flow] = {}

    for pkt in packets:
        if not pkt.src_ip or not pkt.dst_ip:
            continue

        key = _flow_key(pkt)

        if key not in flow_map:
            # Determine canonical src/dst — initiator is the one that sent SYN
            # or, for UDP, the first packet's direction
            src_ip, src_port, dst_ip, dst_port = _canonical_direction(pkt, key)
            service = SERVICE_MAP.get(dst_port or 0,
                      SERVICE_MAP.get(src_port or 0, ""))

            flow_map[key] = Flow(
                src_ip   = src_ip,
                dst_ip   = dst_ip,
                src_port = src_port,
                dst_port = dst_port,
                protocol = pkt.protocol,
                service  = service,
                first_seen = pkt.timestamp.isoformat() if pkt.timestamp else None,
            )

        flow = flow_map[key]
        flow.packets.append(pkt)
        flow.packet_count += 1
        flow.byte_count   += pkt.length
        flow.last_seen = pkt.timestamp.isoformat() if pkt.timestamp else None
        if pkt.flags:
            flow.flags_seen.add(pkt.flags)
        if getattr(pkt, "is_retransmit", False):
            flow.retransmit_count += 1

    return flow_map


def _finalise_flow(flow: Flow):
    """Reassemble TCP stream + parse HTTP + set duration + payload preview."""
    # Retransmission rate
    if flow.packet_count > 0:
        flow.retransmit_rate = round(flow.retransmit_count / flow.packet_count, 4)

    # Duration
    if flow.first_seen and flow.last_seen:
        from datetime import datetime
        try:
            t1 = datetime.fromisoformat(flow.first_seen)
            t2 = datetime.fromisoformat(flow.last_seen)
            flow.duration_sec = round((t2 - t1).total_seconds(), 3)
        except Exception:
            pass

    # TCP stream reassembly
    if flow.protocol == "TCP" and flow.packets:
        flow.payload_bytes = _reassemble_tcp(flow.packets)

        # HTTP parse
        if flow.dst_port in (80, 8080, 8000) or flow.src_port in (80, 8080, 8000):
            flow.http_sessions = _parse_http(flow.payload_bytes,
                                             flow.first_seen)

    # UDP payload concat
    elif flow.protocol == "UDP":
        for pkt in flow.packets:
            if pkt.payload:
                flow.payload_bytes += pkt.payload

    # Preview (first 200 printable bytes)
    if flow.payload_bytes:
        preview = flow.payload_bytes[:200]
        flow.payload_preview = preview.decode("latin-1", errors="replace").strip()

    # Serialise flags set to string
    flow.flags_seen = " | ".join(sorted(flow.flags_seen))


def _reassemble_tcp(packets: list[NormalisedPacket]) -> bytes:
    """
    Reassemble TCP payload bytes in sequence-number order.

    Strategy:
      - Collect (seq, payload) tuples for packets with Raw payload
      - Sort by seq number
      - Concatenate, skipping overlaps
    """
    segments: list[tuple[int, bytes]] = []

    for pkt in packets:
        if not pkt.payload or not pkt.raw_pkt:
            continue
        try:
            if pkt.raw_pkt.haslayer(TCP) and pkt.raw_pkt.haslayer(Raw):
                seq = pkt.raw_pkt[TCP].seq
                data = bytes(pkt.raw_pkt[Raw])
                if data:
                    segments.append((seq, data))
        except Exception:
            continue

    if not segments:
        return b""

    segments.sort(key=lambda x: x[0])

    # Concatenate with overlap detection
    result = b""
    last_seq_end = 0
    for seq, data in segments:
        if not result:
            result = data
            last_seq_end = seq + len(data)
        elif seq >= last_seq_end:
            result += data
            last_seq_end = seq + len(data)
        elif seq + len(data) > last_seq_end:
            # partial overlap — append only the new part
            overlap = last_seq_end - seq
            result += data[overlap:]
            last_seq_end = seq + len(data)
        # else: full duplicate — skip

    return result


def _parse_http(payload: bytes, flow_start: str = None) -> list[HttpSession]:
    """
    Parse HTTP/1.x request(s) and response(s) from a reassembled TCP stream.
    Returns a list of HttpSession objects.
    """
    sessions = []
    if not payload:
        return sessions

    text = payload.decode("latin-1", errors="replace")

    # Split on HTTP request methods to find each transaction
    request_pattern = re.compile(
        r'((?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+\S+\s+HTTP/\d\.\d)',
        re.IGNORECASE
    )
    splits = list(request_pattern.finditer(text))

    if not splits:
        return sessions

    for i, match in enumerate(splits):
        start = match.start()
        end   = splits[i+1].start() if i+1 < len(splits) else len(text)
        chunk = text[start:end]

        session = HttpSession(request_time=flow_start)
        lines   = chunk.split("\r\n")

        # Parse request line
        req_line = lines[0] if lines else ""
        parts = req_line.split(" ", 2)
        if len(parts) >= 2:
            session.method = parts[0]
            session.uri    = parts[1]

        # Parse request headers
        in_headers = True
        req_end    = 0
        for j, line in enumerate(lines[1:], 1):
            if not line:
                in_headers = False
                req_end = j
                break
            if in_headers:
                if line.lower().startswith("host:"):
                    session.host = line.split(":", 1)[1].strip()
                elif line.lower().startswith("user-agent:"):
                    session.user_agent = line.split(":", 1)[1].strip()

        session.full_request = "\r\n".join(lines[:req_end+1])[:2000]

        # Parse response (look for HTTP/1.x status)
        resp_match = re.search(r'HTTP/\d\.\d\s+(\d{3})', chunk)
        if resp_match:
            session.status_code = int(resp_match.group(1))
            resp_start = resp_match.start()
            resp_text  = chunk[resp_start:]
            resp_lines = resp_text.split("\r\n")

            for line in resp_lines[1:]:
                if not line:
                    break
                if line.lower().startswith("content-type:"):
                    session.content_type = line.split(":", 1)[1].strip()

            session.full_response = resp_text[:2000]

            # Body size estimate
            body_match = re.search(r'content-length:\s*(\d+)', resp_text, re.IGNORECASE)
            if body_match:
                session.body_size = int(body_match.group(1))

        sessions.append(session)

    return sessions


def _flow_key(pkt: NormalisedPacket) -> tuple:
    """
    Canonical bidirectional flow key — always (lower_ip, its_port, higher_ip, its_port, proto).
    This ensures A→B and B→A map to the same flow.
    """
    a = (pkt.src_ip or "", pkt.src_port or 0)
    b = (pkt.dst_ip or "", pkt.dst_port or 0)
    lo, hi = (a, b) if a[0] <= b[0] else (b, a)
    return (lo[0], lo[1], hi[0], hi[1], pkt.protocol)


def _canonical_direction(pkt: NormalisedPacket, key: tuple):
    """
    For TCP: the SYN sender is the client (src).
    For UDP/others: keep the first packet's direction.
    """
    if pkt.protocol == "TCP" and pkt.flags and "SYN" in pkt.flags and "ACK" not in pkt.flags:
        return pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port
    # Default: keep as-is from the first packet
    return pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port


def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024: return f"{b:.1f} {unit}"
        b //= 1024
    return f"{b:.1f} TB"
