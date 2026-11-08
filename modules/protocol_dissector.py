"""
modules/protocol_dissector.py
────────────────────────────────────────────────────────────────────────────────
Protocol dissector module — Week 3.

Dissects reconstructed flows at the application layer:
  • HTTP  — full header/body parsing, method, host, URI, status, user-agent
  • DNS   — query name, record type, response IP(s), TTL
  • FTP   — command/response pairs, filenames, credentials
  • SMTP  — envelope (FROM/TO), subject line detection
  • Generic — printable payload preview for unknown protocols

Input:  list of Flow objects (from session_tracker)
Output: list of DissectedFlow objects with structured app-layer data
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from engine.session_tracker import Flow
from engine.logger import get_logger

log = get_logger(__name__)


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class DnsRecord:
    query:       str
    record_type: str      # A, AAAA, MX, TXT, CNAME …
    answers:     list[str] = field(default_factory=list)
    is_response: bool = False

@dataclass
class FtpSession:
    commands:    list[str] = field(default_factory=list)
    user:        Optional[str] = None
    password:    Optional[str] = None
    filenames:   list[str] = field(default_factory=list)
    data_size:   int = 0

@dataclass
class SmtpSession:
    mail_from:   Optional[str] = None
    rcpt_to:     list[str] = field(default_factory=list)
    subject:     Optional[str] = None
    body_preview: str = ""

@dataclass
class DissectedFlow:
    flow:         Flow

    # Protocol tag
    protocol_tag: str = "UNKNOWN"   # HTTP | DNS | FTP | SMTP | TLS | GENERIC

    # Parsed application data (only one will be populated per flow)
    http_requests:  list[dict] = field(default_factory=list)
    dns_records:    list[DnsRecord] = field(default_factory=list)
    ftp_session:    Optional[FtpSession] = None
    smtp_session:   Optional[SmtpSession] = None

    # Generic payload info
    payload_text:   str = ""
    is_plaintext:   bool = False
    is_encrypted:   bool = False

    # Flags for threat detection modules
    has_credentials: bool = False
    has_file_transfer: bool = False


# ── Public API ─────────────────────────────────────────────────────────────────

def dissect_flows(flows: list[Flow]) -> list[DissectedFlow]:
    """
    Dissect all flows. Returns list of DissectedFlow objects.
    Non-interesting flows (no payload, or pure ACK streams) are still included
    with protocol_tag='GENERIC' so the DB has a complete picture.
    """
    results = []
    http_count = dns_count = ftp_count = smtp_count = tls_count = 0

    for flow in flows:
        d = _dissect_one(flow)
        results.append(d)
        if d.protocol_tag == "HTTP":  http_count  += 1
        elif d.protocol_tag == "DNS": dns_count   += 1
        elif d.protocol_tag == "FTP": ftp_count   += 1
        elif d.protocol_tag == "SMTP":smtp_count  += 1
        elif d.protocol_tag == "TLS": tls_count   += 1

    log.info(
        f"Dissected {len(results)} flows — "
        f"HTTP:{http_count} DNS:{dns_count} FTP:{ftp_count} "
        f"SMTP:{smtp_count} TLS:{tls_count}"
    )
    return results


# ── Dispatcher ─────────────────────────────────────────────────────────────────

def _dissect_one(flow: Flow) -> DissectedFlow:
    d = DissectedFlow(flow=flow)

    # Classify by port first (fast path), then by payload signature
    dst = flow.dst_port or 0
    src = flow.src_port or 0
    port = dst if dst < src else src   # lower port = likely server

    if port in (80, 8080, 8000, 8888) or dst in (80, 8080, 8000, 8888):
        _dissect_http(d)
    elif port == 443 or dst == 443:
        _dissect_tls(d)
    elif port == 53 or dst == 53:
        _dissect_dns(d)
    elif port in (20, 21) or dst in (20, 21):
        _dissect_ftp(d)
    elif port == 25 or dst == 25:
        _dissect_smtp(d)
    elif flow.payload_bytes:
        _dissect_generic(d)
    else:
        d.protocol_tag = "GENERIC"

    return d


# ── Protocol dissectors ────────────────────────────────────────────────────────

def _dissect_http(d: DissectedFlow):
    d.protocol_tag = "HTTP"
    payload = d.flow.payload_bytes
    if not payload:
        return

    text = payload.decode("latin-1", errors="replace")
    d.is_plaintext = True

    # Parse all request/response pairs
    req_pattern = re.compile(
        r'((?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\s+\S+\s+HTTP/\d\.\d)',
        re.IGNORECASE
    )

    splits = list(req_pattern.finditer(text))
    for i, match in enumerate(splits):
        start = match.start()
        end   = splits[i + 1].start() if i + 1 < len(splits) else len(text)
        chunk = text[start:end]

        req = _parse_http_request(chunk)
        if req:
            d.http_requests.append(req)

    # Fallback: check for response-only flow (server side)
    if not d.http_requests:
        resp = _parse_http_response_only(text)
        if resp:
            d.http_requests.append(resp)


def _parse_http_request(chunk: str) -> Optional[dict]:
    lines  = chunk.split("\r\n") or chunk.split("\n")
    if not lines:
        return None

    req_line = lines[0]
    parts    = req_line.split(" ", 2)
    if len(parts) < 2:
        return None

    req = {
        "method":       parts[0],
        "uri":          parts[1],
        "http_version": parts[2] if len(parts) > 2 else "",
        "host":         None,
        "user_agent":   None,
        "content_type": None,
        "cookies":      None,
        "auth":         None,
        "body":         "",
        "status_code":  None,
        "response_content_type": None,
        "response_body_size":    0,
    }

    in_req_headers = True
    body_start_idx = None

    for j, line in enumerate(lines[1:], 1):
        if not line and in_req_headers:
            in_req_headers = False
            body_start_idx = j + 1
            continue
        if in_req_headers:
            low = line.lower()
            if low.startswith("host:"):
                req["host"] = line.split(":", 1)[1].strip()
            elif low.startswith("user-agent:"):
                req["user_agent"] = line.split(":", 1)[1].strip()
            elif low.startswith("content-type:"):
                req["content_type"] = line.split(":", 1)[1].strip()
            elif low.startswith("cookie:"):
                req["cookies"] = line.split(":", 1)[1].strip()[:200]
            elif low.startswith("authorization:"):
                req["auth"] = line.split(":", 1)[1].strip()

    # Response embedded in same chunk
    resp_match = re.search(r'HTTP/\d\.\d\s+(\d{3})', chunk)
    if resp_match:
        req["status_code"] = int(resp_match.group(1))
        resp_text = chunk[resp_match.start():]
        ct_match  = re.search(r'content-type:\s*([^\r\n]+)', resp_text, re.IGNORECASE)
        if ct_match:
            req["response_content_type"] = ct_match.group(1).strip()
        cl_match  = re.search(r'content-length:\s*(\d+)', resp_text, re.IGNORECASE)
        if cl_match:
            req["response_body_size"] = int(cl_match.group(1))

    return req


def _parse_http_response_only(text: str) -> Optional[dict]:
    m = re.search(r'HTTP/\d\.\d\s+(\d{3})', text)
    if not m:
        return None
    resp = {
        "method": "RESPONSE",
        "uri": "",
        "status_code": int(m.group(1)),
        "response_content_type": None,
        "response_body_size": 0,
    }
    ct = re.search(r'content-type:\s*([^\r\n]+)', text, re.IGNORECASE)
    if ct:
        resp["response_content_type"] = ct.group(1).strip()
    return resp


def _dissect_tls(d: DissectedFlow):
    d.protocol_tag  = "TLS"
    d.is_encrypted  = True
    d.is_plaintext  = False

    # Try to extract SNI from ClientHello (plaintext in TLS handshake)
    payload = d.flow.payload_bytes
    if payload and len(payload) > 5:
        sni = _extract_tls_sni(payload)
        if sni:
            d.payload_text = f"SNI: {sni}"


def _extract_tls_sni(data: bytes) -> Optional[str]:
    """
    Parse SNI (Server Name Indication) from a TLS ClientHello.
    The SNI is sent in plaintext even in TLS 1.3.
    """
    try:
        if data[0] != 0x16:           # not a TLS handshake record
            return None
        if data[5] != 0x01:           # not a ClientHello
            return None
        # Skip: record header (5) + handshake header (4) + version (2)
        #        + random (32) + session_id_len (1)
        pos = 5 + 4 + 2 + 32
        if pos >= len(data):
            return None
        session_id_len = data[pos]; pos += 1 + session_id_len
        if pos + 2 >= len(data):
            return None
        cipher_suites_len = int.from_bytes(data[pos:pos+2], "big"); pos += 2 + cipher_suites_len
        if pos >= len(data):
            return None
        comp_len = data[pos]; pos += 1 + comp_len
        if pos + 2 >= len(data):
            return None
        extensions_len = int.from_bytes(data[pos:pos+2], "big"); pos += 2
        end = pos + extensions_len

        while pos + 4 < end:
            ext_type = int.from_bytes(data[pos:pos+2], "big"); pos += 2
            ext_len  = int.from_bytes(data[pos:pos+2], "big"); pos += 2
            if ext_type == 0:    # SNI extension
                # list_len(2) + type(1) + name_len(2) + name
                name_len = int.from_bytes(data[pos+3:pos+5], "big")
                return data[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
            pos += ext_len
    except Exception:
        pass
    return None


def _dissect_dns(d: DissectedFlow):
    d.protocol_tag = "DNS"
    d.is_plaintext = True

    # Parse DNS from raw UDP payloads
    for pkt in d.flow.packets:
        if not pkt.payload:
            continue
        record = _parse_dns_payload(pkt.payload)
        if record:
            d.dns_records.append(record)


def _parse_dns_payload(payload: bytes) -> Optional[DnsRecord]:
    """
    Minimal DNS packet parser (no external libs, pure Python).
    Handles standard A/AAAA/CNAME/MX/TXT queries and responses.
    """
    try:
        if len(payload) < 12:
            return None

        flags      = int.from_bytes(payload[2:4], "big")
        is_response = bool(flags & 0x8000)
        qd_count   = int.from_bytes(payload[4:6],  "big")

        if qd_count == 0:
            return None

        # Parse question section — skip the 12-byte header
        pos   = 12
        qname = _parse_dns_name(payload, pos)
        if not qname:
            return None

        # Skip past the name (null-terminated labels)
        while pos < len(payload) and payload[pos] != 0:
            if payload[pos] & 0xC0 == 0xC0:   # compression pointer
                pos += 2
                break
            pos += payload[pos] + 1
        else:
            pos += 1   # skip null terminator

        if pos + 4 > len(payload):
            return None

        qtype = int.from_bytes(payload[pos:pos+2], "big")
        type_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX",
                    16: "TXT", 6: "SOA", 2: "NS", 255: "ANY"}
        record_type = type_map.get(qtype, f"TYPE{qtype}")

        record = DnsRecord(
            query       = qname,
            record_type = record_type,
            is_response = is_response,
        )

        # Parse answer section if this is a response
        if is_response:
            an_count = int.from_bytes(payload[6:8], "big")
            pos += 4   # skip qtype + qclass
            for _ in range(min(an_count, 5)):
                answer = _parse_dns_answer(payload, pos)
                if answer:
                    record.answers.append(answer)
                    pos += _dns_rr_len(payload, pos)
                else:
                    break

        return record

    except Exception:
        return None


def _parse_dns_name(data: bytes, pos: int) -> Optional[str]:
    """Decode a DNS compressed/uncompressed name starting at pos."""
    try:
        labels = []
        visited = set()
        while pos < len(data):
            if pos in visited:
                break
            visited.add(pos)
            length = data[pos]
            if length == 0:
                break
            if length & 0xC0 == 0xC0:   # compression pointer
                ptr = ((length & 0x3F) << 8) | data[pos + 1]
                result = _parse_dns_name(data, ptr)
                if result:
                    labels.append(result)
                break
            pos += 1
            labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
            pos += length
        return ".".join(labels) if labels else None
    except Exception:
        return None


def _parse_dns_answer(data: bytes, pos: int) -> Optional[str]:
    """Parse one DNS resource record answer, return value as string."""
    try:
        # Skip name
        while pos < len(data):
            length = data[pos]
            if length == 0: pos += 1; break
            if length & 0xC0 == 0xC0: pos += 2; break
            pos += length + 1

        if pos + 10 > len(data):
            return None
        rtype  = int.from_bytes(data[pos:pos+2],   "big")
        rdlen  = int.from_bytes(data[pos+8:pos+10], "big")
        rdata  = data[pos+10:pos+10+rdlen]

        if rtype == 1 and rdlen == 4:    # A record
            return ".".join(str(b) for b in rdata)
        if rtype == 28 and rdlen == 16:  # AAAA record
            parts = [f"{int.from_bytes(rdata[i:i+2],'big'):x}" for i in range(0,16,2)]
            return ":".join(parts)
        if rtype == 5:                   # CNAME
            return _parse_dns_name(data, pos + 10) or ""
        if rtype == 16:                  # TXT
            return rdata[1:].decode("latin-1", errors="replace")[:100]
        return f"TYPE{rtype}:{rdata.hex()[:20]}"
    except Exception:
        return None


def _dns_rr_len(data: bytes, pos: int) -> int:
    """Return total byte length of a DNS resource record at pos."""
    try:
        start = pos
        while pos < len(data):
            l = data[pos]
            if l == 0: pos += 1; break
            if l & 0xC0 == 0xC0: pos += 2; break
            pos += l + 1
        if pos + 10 > len(data):
            return len(data) - start
        rdlen = int.from_bytes(data[pos+8:pos+10], "big")
        return (pos + 10 + rdlen) - start
    except Exception:
        return 4


def _dissect_ftp(d: DissectedFlow):
    d.protocol_tag = "FTP"
    d.is_plaintext = True

    payload = d.flow.payload_bytes
    if not payload:
        return

    text    = payload.decode("latin-1", errors="replace")
    session = FtpSession()

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        upper = line.upper()
        session.commands.append(line[:200])

        if upper.startswith("USER "):
            session.user     = line[5:].strip()
            d.has_credentials = True
        elif upper.startswith("PASS "):
            session.password  = line[5:].strip()
            d.has_credentials = True
        elif upper.startswith("RETR ") or upper.startswith("STOR "):
            fname = line[5:].strip()
            if fname:
                session.filenames.append(fname)
                d.has_file_transfer = True

    d.ftp_session = session


def _dissect_smtp(d: DissectedFlow):
    d.protocol_tag = "SMTP"
    d.is_plaintext = True

    payload = d.flow.payload_bytes
    if not payload:
        return

    text    = payload.decode("latin-1", errors="replace")
    session = SmtpSession()

    for line in text.splitlines():
        line = line.strip()
        upper = line.upper()
        if upper.startswith("MAIL FROM:"):
            session.mail_from = line[10:].strip()
        elif upper.startswith("RCPT TO:"):
            session.rcpt_to.append(line[8:].strip())
        elif line.lower().startswith("subject:"):
            session.subject = line[8:].strip()

    body_idx = text.find("\r\n\r\n")
    if body_idx != -1:
        session.body_preview = text[body_idx+4:body_idx+300]

    d.smtp_session = session


def _dissect_generic(d: DissectedFlow):
    d.protocol_tag = "GENERIC"
    payload = d.flow.payload_bytes
    if not payload:
        return

    # TLS heuristic: starts with 0x16 (TLS record) or 0x15/0x17
    if len(payload) > 5 and payload[0] in (0x15, 0x16, 0x17):
        d.protocol_tag = "TLS"
        d.is_encrypted = True
        sni = _extract_tls_sni(payload)
        if sni:
            d.payload_text = f"SNI: {sni}"
        return

    # Check printability
    printable = sum(1 for b in payload[:512] if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / min(len(payload), 512)
    d.is_plaintext = ratio > 0.75

    if d.is_plaintext:
        d.payload_text = payload[:300].decode("latin-1", errors="replace").strip()
    else:
        d.payload_text = f"Binary payload ({len(payload)} bytes) - hex: {payload[:16].hex()}"
