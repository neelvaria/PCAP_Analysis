"""
modules/beacon_detector.py  —  SOC-grade beacon detection (calibrated v2.1)

Architecture fix: Real C2 tools open a NEW TCP connection per callback with a
fresh ephemeral source port. Per-flow interval analysis therefore misses them.
The correct approach (used by RITA, FireEye, Corelight) is HOST-PAIR analysis:
group all connections sharing the same (src_ip, dst_ip, dst_port) and analyse
the inter-CONNECTION timestamps — not inter-packet timestamps within one flow.

Calibration basis (public threat intelligence reports):
  - Cobalt Strike: 60s default, ≤5% jitter   (Mandiant ATT&CK eval 2023)
  - QakBot:        240s, ~15% jitter           (Secureworks CTU-2022-0409)
  - Emotet:        60s, up to 30% jitter       (abuse.ch tracker)
  - TrickBot:      10–30s fast beacon          (CISA AA20-302A)
  - AsyncRAT:      3s configurable             (MITRE S0622)
  - Dridex:        120s tight                  (Proofpoint TA542 profile)

False positive sources (suppressed):
  - NTP (port 123, 1024s): benign_periodic_ports whitelist
  - Chrome update (port 443, ~1800s): cloud CDN risk_modifier=0.3
  - DHCP (67/68), mDNS (5353): zero risk_modifier
  - Windows telemetry (443, 3600s): long interval → low base score
"""

from __future__ import annotations

import math
import statistics
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from engine.session_tracker import Flow
from engine.logger import get_logger
from modules.traffic_classifier import (classify_ip, is_benign_periodic_flow,
                                         flow_risk_modifier)
from modules.attack_signatures import check_signatures, get_highest_severity
from config import (BEACON_MIN_PACKETS, SEVERITY_CRITICAL_THRESHOLD,
                    SEVERITY_HIGH_THRESHOLD, SEVERITY_MEDIUM_THRESHOLD,
                    BEACON_INTERVAL_CV_STRONG, BEACON_INTERVAL_CV_WEAK)

log = get_logger(__name__)

KNOWN_MALICIOUS_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike default",
    "6734f37431670b3ab4292b8f60f29984": "Cobalt Strike malleable",
    "b386946a5a44d1ddcc843bc75336dfce": "Metasploit Meterpreter",
    "04f423239b3967ef0e1a81e28a59fca2": "Dridex banking trojan",
    "d0ec4b50a944b182f058f98b2d54f3a0": "TrickBot/BazarLoader",
    "a0e9f5d64349fb13191bc781f81f42e1": "AsyncRAT",
    "c35b9b3b72deebc5d6fa81ddc4282ebb": "NjRAT",
    "3b5074b1b5d032e5620f69f9159a5791": "Emotet",
    "c8b7dce09e745d84e2e8be01e86f68ee": "QakBot",
    "51c64c77e60f3980eea90869b68c58a8": "Generic C2 beacon",
}

# Minimum number of CONNECTIONS (not packets) to a host-pair to analyse
BEACON_MIN_CONNECTIONS = 4

# CV thresholds — sourced from config.py so analysts can tune without code changes.
# CV_STRONG (default 0.3):  strong beacon signal (CS, TrickBot, Dridex)
# CV_WEAK   (default 0.8):  jittered/moderate beacon (QakBot, Emotet)
# Wider than previous CV_STRICT=0.10/CV_MODERATE=0.35:
# the old values were too tight — caught only clock-like beacons and missed
# QakBot/Emotet which intentionally add jitter to evade strict CV checks.
CV_STRICT    = BEACON_INTERVAL_CV_STRONG   # alias used in scoring rules
CV_MODERATE  = BEACON_INTERVAL_CV_WEAK

# Interval bounds (seconds) — calibrated from threat reports
# Below MIN_INTERVAL: ping flood, not C2 (reduces FP on noisy traffic)
# Above MAX_INTERVAL: too slow for automated alert; single session analysis
MIN_BEACON_INTERVAL = 1.5      # below this is noise/flood
MAX_BEACON_INTERVAL = 3600.0   # above this is too slow to be reliable beacon


@dataclass
class BeaconFinding:
    flow_id:           str
    src_ip:            str
    dst_ip:            str
    dst_port:          Optional[int]
    protocol:          str
    src_classification: str = "PUBLIC"
    dst_classification: str = "PUBLIC"

    # Connection-level interval analysis (host-pair)
    connection_count:  int   = 0
    interval_mean:     float = 0.0
    interval_stddev:   float = 0.0
    interval_cv:       float = 0.0
    interval_jitter_pct: float = 0.0
    interval_sample:   list  = field(default_factory=list)

    # Packet-level analysis (within flow)
    packet_count:      int   = 0
    duration_sec:      float = 0.0
    size_stddev:       float = 0.0
    size_mean:         float = 0.0
    payload_entropy:   float = 0.0
    retransmit_rate:   float = 0.0

    # JA3
    ja3_hash:          Optional[str] = None
    ja3_match:         Optional[str] = None
    signature_hits:    list = field(default_factory=list)

    # Explainability
    rules_triggered:   list = field(default_factory=list)
    evidence:          list = field(default_factory=list)
    reasons:           list = field(default_factory=list)
    confidence:        float = 0.0

    threat_score:      int   = 0
    severity:          str   = "LOW"
    risk_modifier:     float = 1.0


# ── Public API ─────────────────────────────────────────────────────────────────

def detect_beacons(flows: list[Flow]) -> list[BeaconFinding]:
    """
    Two-pass beacon detection:
    Pass 1 — Host-pair aggregation: group all flows by (src_ip, dst_ip, dst_port).
             Analyse inter-connection timing. This catches C2 tools that open a
             new TCP session per callback (Cobalt Strike, Meterpreter, most RATs).
    Pass 2 — Single-flow analysis: for persistent connections (Netcat, bind shells)
             analyse intra-flow packet timing. Also runs signature checks.
    """
    findings: list[BeaconFinding] = []
    seen_pairs: set[tuple] = set()

    # ── Pass 1: Host-pair (connection-level) analysis ─────────────────────────
    host_pair_findings = _host_pair_analysis(flows)
    for f in host_pair_findings:
        key = (f.src_ip, f.dst_ip, f.dst_port)
        seen_pairs.add(key)
        findings.append(f)

    # ── Pass 2: Per-flow analysis (persistent connections + signatures) ────────
    for flow in flows:
        if is_benign_periodic_flow(flow.src_port, flow.dst_port, flow.dst_ip):
            continue
        dst_cls = classify_ip(flow.dst_ip or "0.0.0.0")
        if dst_cls.category in ("MULTICAST", "BROADCAST", "LOOPBACK", "LINK_LOCAL"):
            continue

        finding = _analyse_single_flow(flow, dst_cls)
        if finding and finding.threat_score > 0:
            # Only add if host-pair analysis didn't already cover this
            key = (finding.src_ip, finding.dst_ip, finding.dst_port)
            if key in seen_pairs:
                # Merge signature hits into existing host-pair finding
                existing = next(f for f in findings
                                if (f.src_ip, f.dst_ip, f.dst_port) == key)
                if finding.signature_hits:
                    existing.signature_hits.extend(finding.signature_hits)
                    existing.reasons.extend(finding.reasons)
                    existing.threat_score = min(
                        existing.threat_score + len(finding.signature_hits) * 10, 100)
                    _set_severity(existing)
            else:
                findings.append(finding)

    findings.sort(key=lambda f: f.threat_score, reverse=True)
    _log_summary(findings)
    return findings


# ── Pass 1: Host-pair (connection-level) beacon analysis ──────────────────────

def _host_pair_analysis(flows: list[Flow]) -> list[BeaconFinding]:
    """
    Group flows by (src_ip, dst_ip, dst_port) and analyse
    the inter-CONNECTION first-packet timestamps.

    This is the correct algorithm for detecting C2 beacons that open
    a new TCP connection per check-in (the vast majority of C2 frameworks).
    """
    # Group: (src_ip, dst_ip, dst_port) → list of first_packet_timestamps
    groups: dict[tuple, list] = defaultdict(list)
    flow_by_pair: dict[tuple, list[Flow]] = defaultdict(list)

    for flow in flows:
        src = flow.src_ip or ""
        dst = flow.dst_ip or ""
        dpt = flow.dst_port

        if not src or not dst or not dpt:
            continue
        if is_benign_periodic_flow(flow.src_port, dpt, dst):
            continue
        dst_cls = classify_ip(dst)
        if dst_cls.category in ("MULTICAST", "BROADCAST", "LOOPBACK", "LINK_LOCAL"):
            continue

        # Get first packet timestamp of this flow
        ts_list = []
        for pkt in flow.packets:
            if pkt.timestamp:
                ts_list.append(pkt.timestamp.timestamp())
        if ts_list:
            key = (src, dst, dpt)
            groups[key].append(min(ts_list))
            flow_by_pair[key].append(flow)

    findings = []
    for (src, dst, dpt), timestamps in groups.items():
        if len(timestamps) < BEACON_MIN_CONNECTIONS:
            continue  # not enough connections to make a statistical judgement

        timestamps.sort()
        f = _score_connection_series(src, dst, dpt, timestamps, flow_by_pair[(src, dst, dpt)])
        if f and f.threat_score > 0:
            findings.append(f)

    return findings


def _score_connection_series(src: str, dst: str, dpt: int,
                               timestamps: list[float],
                               flows: list[Flow]) -> Optional[BeaconFinding]:
    """Score a series of connection timestamps for beacon regularity."""
    dst_cls  = classify_ip(dst)
    risk_mod = flow_risk_modifier(src, dst)

    intervals = [b - a for a, b in zip(timestamps, timestamps[1:])
                 if MIN_BEACON_INTERVAL <= b - a <= MAX_BEACON_INTERVAL]

    if len(intervals) < BEACON_MIN_CONNECTIONS - 1:
        return None

    mean   = statistics.mean(intervals)
    stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    cv     = stddev / mean if mean > 0 else 0.0

    # Jitter tolerance: % of intervals within ±25% of mean
    # (wider than before — calibrated against QakBot/Emotet real data)
    within_jitter = sum(1 for iv in intervals if abs(iv - mean) / mean <= 0.25)
    jitter_pct    = within_jitter / len(intervals)

    # Representative flow for metadata
    rep_flow = max(flows, key=lambda f: f.packet_count)

    f = BeaconFinding(
        flow_id            = f"{src} → {dst}:{dpt} [HOSTPAIR]",
        src_ip             = src,
        dst_ip             = dst,
        dst_port           = dpt,
        protocol           = rep_flow.protocol,
        src_classification = classify_ip(src).category,
        dst_classification = dst_cls.category,
        connection_count   = len(timestamps),
        interval_mean      = round(mean, 3),
        interval_stddev    = round(stddev, 3),
        interval_cv        = round(cv, 4),
        interval_jitter_pct= jitter_pct,
        interval_sample    = [round(iv, 1) for iv in intervals[:8]],
        packet_count       = sum(fl.packet_count for fl in flows),
        risk_modifier      = risk_mod,
    )

    raw_score = 0

    # Rule: Tight CV (Cobalt Strike, TrickBot, Dridex profile)
    if cv < CV_STRICT and mean < 300:
        raw_score += 50
        f.rules_triggered.append("RULE:CV_STRICT")
        f.reasons.append(
            f"Tight beacon: {len(timestamps)} connections, mean={mean:.1f}s "
            f"CV={cv:.4f} (CS/TrickBot/Dridex profile)"
        )
        f.evidence.append(f"Inter-connection intervals: {f.interval_sample}")

    # Rule: Moderate CV with high jitter% (QakBot, Emotet profile)
    elif cv < CV_MODERATE and jitter_pct >= 0.65 and mean < MAX_BEACON_INTERVAL:
        raw_score += 35
        f.rules_triggered.append("RULE:CV_JITTERED")
        f.reasons.append(
            f"Jittered beacon: {len(timestamps)} connections, mean={mean:.1f}s "
            f"CV={cv:.3f} jitter_within_25%={jitter_pct:.0%} (QakBot/Emotet profile)"
        )

    # Rule: Fast repeat connections to suspicious port
    if dpt in {4444, 4445, 1337, 31337, 8888, 6666, 6667, 447, 6606}:
        raw_score += 40
        f.rules_triggered.append("RULE:SUSPICIOUS_PORT_REPEATED")
        f.reasons.append(
            f"Repeated connections to known C2 port {dpt} "
            f"({len(timestamps)} connections)"
        )

    # Rule: Many connections to same external IP (fan-in pattern)
    if len(timestamps) >= 8 and not _is_private(dst):
        raw_score += 15
        f.rules_triggered.append("RULE:HIGH_CONNECTION_COUNT")
        f.reasons.append(
            f"High external connection count: {len(timestamps)} connections "
            f"to {dst}:{dpt}"
        )

    # Apply risk modifier
    if risk_mod < 1.0 and raw_score > 0:
        adjusted = int(raw_score * risk_mod)
        f.reasons.append(
            f"Score adjusted: ×{risk_mod:.1f} ({dst_cls.category}: "
            f"{dst_cls.description or dst_cls.category})"
        )
        raw_score = adjusted

    f.threat_score = min(raw_score, 100)
    _set_severity(f)
    f.confidence = min(len(f.rules_triggered) / 3.0, 1.0)

    return f if f.threat_score > 0 else None


# ── Pass 2: Single-flow analysis (persistent connections + signatures) ─────────

def _analyse_single_flow(flow: Flow, dst_cls) -> Optional[BeaconFinding]:
    """Analyse a single persistent flow for beaconing + run all signatures."""
    if not flow.packets or len(flow.packets) < 2:
        return None

    src_cls  = classify_ip(flow.src_ip or "0.0.0.0")
    risk_mod = flow_risk_modifier(flow.src_ip, flow.dst_ip)

    f = BeaconFinding(
        flow_id            = flow.five_tuple,
        src_ip             = flow.src_ip or "",
        dst_ip             = flow.dst_ip or "",
        dst_port           = flow.dst_port,
        protocol           = flow.protocol,
        src_classification = src_cls.category,
        dst_classification = dst_cls.category,
        packet_count       = flow.packet_count,
        duration_sec       = flow.duration_sec,
        risk_modifier      = risk_mod,
    )

    raw_score = 0

    # ── Signature detection (highest priority) ────────────────────────────────
    sig_result = check_signatures(flow)
    if sig_result.triggered:
        sig_score = min(sig_result.total_score, 60)
        raw_score += sig_score
        f.signature_hits = [s.id for s in sig_result.signatures]
        f.rules_triggered.extend([f"RULE:{s.id}" for s in sig_result.signatures])
        f.reasons.extend(sig_result.reasons)
        f.evidence.append(
            f"Signature matches: {', '.join(s.name for s in sig_result.signatures)}"
        )
        if get_highest_severity(sig_result) == "CRITICAL":
            raw_score = max(raw_score, SEVERITY_CRITICAL_THRESHOLD + 5)

    # ── Intra-flow interval analysis (persistent connections only) ────────────
    timestamps = sorted(
        pkt.timestamp.timestamp()
        for pkt in flow.packets if pkt.timestamp
    )
    if len(timestamps) >= BEACON_MIN_PACKETS:
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:])
                     if b - a > MIN_BEACON_INTERVAL]
        if len(intervals) >= BEACON_MIN_PACKETS - 1:
            mean   = statistics.mean(intervals)
            stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
            cv     = stddev / mean if mean > 0 else 0.0

            f.interval_mean   = round(mean,   4)
            f.interval_stddev = round(stddev, 4)
            f.interval_cv     = round(cv,     4)

            within_jitter = sum(1 for iv in intervals if abs(iv - mean) / mean <= 0.25)
            f.interval_jitter_pct = within_jitter / len(intervals)

            if cv < CV_STRICT and mean < 300:
                raw_score += 40
                f.rules_triggered.append("RULE:INTRA_FLOW_REGULAR")
                f.reasons.append(
                    f"Regular intra-flow intervals: mean={mean:.1f}s CV={cv:.3f}"
                )
            elif cv < CV_MODERATE and f.interval_jitter_pct >= 0.65:
                raw_score += 20
                f.rules_triggered.append("RULE:INTRA_FLOW_JITTERED")
                f.reasons.append(
                    f"Jittered intra-flow: mean={mean:.1f}s CV={cv:.3f} "
                    f"jitter%={f.interval_jitter_pct:.0%}"
                )

    # ── Packet size consistency ────────────────────────────────────────────────
    sizes = [pkt.length for pkt in flow.packets if pkt.length > 0]
    if len(sizes) >= 4:
        size_mean   = statistics.mean(sizes)
        size_stddev = statistics.stdev(sizes) if len(sizes) > 1 else 0.0
        size_cv     = size_stddev / size_mean if size_mean > 0 else 0.0
        f.size_mean   = round(size_mean,   2)
        f.size_stddev = round(size_stddev, 2)
        if size_cv < 0.10 and flow.packet_count >= 5:
            raw_score += 15
            f.rules_triggered.append("RULE:FIXED_SIZE")
            f.reasons.append(
                f"Fixed packet sizes: mean={size_mean:.0f}B stddev={size_stddev:.1f}B"
            )

    # ── Payload entropy — context-aware (fix: suppress on legitimate TLS) ──────
    # High entropy on port 443 with proper TLS = HTTPS, not C2.
    # Only flag if: non-standard port OR port 443 without SNI (raw encrypt).
    if flow.payload_bytes and len(flow.payload_bytes) > 32:
        entropy = _shannon_entropy(flow.payload_bytes[:512])
        f.payload_entropy = round(entropy, 3)
        if entropy > 7.0:
            # Check if this looks like legitimate TLS
            is_standard_tls_port = flow.dst_port in (443, 8443, 465, 993, 995)
            has_tls_sni = bool(getattr(flow, "tls_sni", None))
            # Suppress entropy signal if standard TLS port + SNI present
            # (standard browser/app HTTPS — not anomalous)
            if is_standard_tls_port and has_tls_sni:
                # Still record entropy but do NOT add to score
                f.reasons.append(
                    f"Note: high entropy ({entropy:.2f} bits/byte) suppressed — "
                    f"standard TLS on port {flow.dst_port} with SNI={flow.tls_sni}"
                )
            else:
                raw_score += 10
                f.rules_triggered.append("RULE:HIGH_ENTROPY")
                context = (f"port {flow.dst_port} (standard TLS port, no SNI)"
                           if is_standard_tls_port
                           else f"non-standard port {flow.dst_port}")
                f.reasons.append(
                    f"High payload entropy ({entropy:.2f} bits/byte) on {context} — "
                    f"possible encrypted C2 or non-standard tunnel"
                )

    # ── JA3 fingerprint ────────────────────────────────────────────────────────
    if flow.protocol == "TCP" and flow.payload_bytes:
        ja3 = _compute_ja3(flow.payload_bytes)
        if ja3:
            f.ja3_hash = ja3
            if ja3 in KNOWN_MALICIOUS_JA3:
                f.ja3_match = KNOWN_MALICIOUS_JA3[ja3]
                raw_score += 50
                f.rules_triggered.append("RULE:JA3_MALICIOUS")
                f.reasons.append(f"Known malicious JA3: {ja3[:16]}… ({f.ja3_match})")
                f.evidence.append(f"JA3: {ja3}")

    # ── Long low-bandwidth flow ────────────────────────────────────────────────
    if (flow.duration_sec > 60 and flow.byte_count > 0 and
            flow.byte_count / flow.duration_sec < 512):
        raw_score += 20
        f.rules_triggered.append("RULE:LOW_BW_LONG_LIVED")
        bps = flow.byte_count / flow.duration_sec
        f.reasons.append(
            f"Low-BW long-lived: {flow.duration_sec:.0f}s @ {bps:.0f}B/s"
        )

    # ── Apply risk modifier ────────────────────────────────────────────────────
    if risk_mod < 1.0 and raw_score > 0:
        raw_score = int(raw_score * risk_mod)
        if raw_score > 0:
            f.reasons.append(
                f"Score ×{risk_mod:.1f} ({dst_cls.category})"
            )

    f.threat_score = min(raw_score, 100)
    _set_severity(f)
    f.confidence = min(len(f.rules_triggered) / 5.0, 1.0)

    return f if f.threat_score > 0 else None


# ── Helpers ────────────────────────────────────────────────────────────────────

def _set_severity(f: BeaconFinding):
    if f.threat_score >= SEVERITY_CRITICAL_THRESHOLD:
        f.severity = "CRITICAL"
    elif f.threat_score >= SEVERITY_HIGH_THRESHOLD:
        f.severity = "HIGH"
    elif f.threat_score >= SEVERITY_MEDIUM_THRESHOLD:
        f.severity = "MEDIUM"
    else:
        f.severity = "LOW"


def _shannon_entropy(data: bytes) -> float:
    if not data: return 0.0
    from collections import Counter
    counts = Counter(data)
    total  = len(data)
    return -sum((c/total) * math.log2(c/total) for c in counts.values())


def _compute_ja3(payload: bytes):
    try:
        if len(payload) < 10 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        pos = 5 + 4
        if pos + 2 > len(payload): return None
        tls_version = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        pos += 32
        if pos >= len(payload): return None
        session_len = payload[pos]; pos += 1 + session_len
        if pos + 2 > len(payload): return None
        cs_len = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        ciphers = []
        for i in range(0, cs_len, 2):
            if pos + i + 2 > len(payload): break
            cs = int.from_bytes(payload[pos+i:pos+i+2], "big")
            if cs not in (0x0000, 0x00FF): ciphers.append(cs)
        pos += cs_len
        if pos >= len(payload): return None
        comp_len = payload[pos]; pos += 1 + comp_len
        if pos + 2 > len(payload):
            return hashlib.md5(
                f"{tls_version},{'-'.join(map(str,ciphers))},,,".encode()
            ).hexdigest()
        ext_total = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
        end_ext = pos + ext_total
        ext_types, curves, point_fmts = [], [], []
        while pos + 4 <= end_ext:
            ext_type = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
            ext_len  = int.from_bytes(payload[pos:pos+2], "big"); pos += 2
            ext_data = payload[pos:pos+ext_len]; pos += ext_len
            if ext_type == 0x000A:
                cl = int.from_bytes(ext_data[0:2], "big")
                for j in range(2, 2+cl, 2):
                    if j+2 <= len(ext_data):
                        curves.append(int.from_bytes(ext_data[j:j+2], "big"))
            elif ext_type == 0x000B:
                if len(ext_data) >= 2:
                    point_fmts = list(ext_data[1:1+ext_data[0]])
            elif ext_type not in (0x0000,):
                ext_types.append(ext_type)
        ja3_str = (f"{tls_version},"
                   f"{'-'.join(map(str,ciphers))},"
                   f"{'-'.join(map(str,ext_types))},"
                   f"{'-'.join(map(str,curves))},"
                   f"{'-'.join(map(str,point_fmts))}")
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return None


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def _log_summary(findings):
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high     = sum(1 for f in findings if f.severity == "HIGH")
    medium   = sum(1 for f in findings if f.severity == "MEDIUM")
    log.info(f"Beacon detection: {len(findings)} findings — "
             f"CRITICAL:{critical} HIGH:{high} MEDIUM:{medium}")
