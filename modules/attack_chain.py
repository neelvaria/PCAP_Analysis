"""
modules/attack_chain.py
────────────────────────────────────────────────────────────────────────────────
Attack chain correlation engine — SOC upgrade.

Groups flows by source IP and builds per-host timelines.
Detects multi-stage attack patterns:
  Recon → Initial Access → Lateral Movement → C2 → Exfiltration

Key insight: individual flows look normal; correlating them across time
reveals the attack narrative.
"""

from __future__ import annotations

import datetime
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from engine.session_tracker import Flow
from engine.logger import get_logger

log = get_logger(__name__)

# ── MITRE phase definitions ────────────────────────────────────────────────────
PHASES = {
    "RECON":           ("TA0043", "Reconnaissance"),
    "INITIAL_ACCESS":  ("TA0001", "Initial Access"),
    "EXECUTION":       ("TA0002", "Execution"),
    "LATERAL":         ("TA0008", "Lateral Movement"),
    "C2":              ("TA0011", "Command and Control"),
    "EXFILTRATION":    ("TA0010", "Exfiltration"),
    "UNKNOWN":         ("",       "Unknown"),
}

# Port-to-phase heuristics
_RECON_PORTS      = {21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443,
                     135, 139, 1433, 3306, 5432, 6379, 27017}
_LATERAL_PORTS    = {445, 135, 139, 3389, 5985, 5986, 22, 1433}
_C2_PORTS         = {4444, 4445, 1337, 31337, 8888, 6666, 6667, 9001,
                     9030, 9050, 2222, 5555}
_EXFIL_SIGNALS    = {21, 25, 80, 443, 8080}   # FTP, email, HTTP(S) large uploads


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class TimelineEvent:
    timestamp:   str
    phase:       str
    tactic_id:   str
    tactic_name: str
    src_ip:      str
    dst_ip:      str
    dst_port:    Optional[int]
    protocol:    str
    description: str
    score:       int
    flow_ref:    Optional[object] = field(repr=False, default=None)


@dataclass
class HostProfile:
    ip:             str
    first_seen:     Optional[str]
    last_seen:      Optional[str]
    total_flows:    int = 0
    total_bytes:    int = 0
    phases_seen:    set = field(default_factory=set)
    timeline:       list[TimelineEvent] = field(default_factory=list)
    threat_score:   int = 0
    severity:       str = "LOW"
    is_pivot:       bool = False   # host seen as both src and dst
    unique_dst_ips: set = field(default_factory=set)
    unique_dst_ports: set = field(default_factory=set)


@dataclass
class AttackChain:
    """Represents a correlated multi-stage attack from a single source IP."""
    src_ip:         str
    start_time:     Optional[str]
    end_time:       Optional[str]
    duration_sec:   float
    phases:         list[str]           # ordered list of detected phases
    events:         list[TimelineEvent]
    threat_score:   int
    severity:       str
    narrative:      str                 # human-readable attack summary
    mitre_tactics:  list[str]


@dataclass
class CorrelationReport:
    host_profiles:  dict[str, HostProfile]
    attack_chains:  list[AttackChain]
    pivot_hosts:    list[str]
    total_hosts:    int
    high_risk_hosts: list[str]


# ── Public API ─────────────────────────────────────────────────────────────────

def correlate_flows(flows: list[Flow],
                    beacon_findings: list = None,
                    dns_findings: list = None) -> CorrelationReport:
    """
    Build per-host attack timelines and detect multi-stage attack chains.

    Args:
        flows:           All reconstructed flows
        beacon_findings: Optional beacon detector results
        dns_findings:    Optional DNS analyser findings
    """
    beacon_src_ips = set()
    if beacon_findings:
        beacon_src_ips = {b.src_ip for b in beacon_findings}

    dns_src_ips = set()
    if dns_findings:
        dns_src_ips = {f.src_ip for f in dns_findings}

    # Build per-source-IP profiles
    profiles: dict[str, HostProfile] = {}
    dst_ips_all: set[str] = set()

    for flow in flows:
        src = flow.src_ip or "unknown"
        dst = flow.dst_ip or "unknown"
        if src not in profiles:
            profiles[src] = HostProfile(ip=src, first_seen=flow.first_seen,
                                         last_seen=flow.last_seen)
        p = profiles[src]
        p.total_flows  += 1
        p.total_bytes  += flow.byte_count
        p.last_seen     = flow.last_seen
        p.unique_dst_ips.add(dst)
        if flow.dst_port:
            p.unique_dst_ports.add(flow.dst_port)
        dst_ips_all.add(dst)

        # Classify flow phase
        phase, event = _classify_flow_phase(flow)
        if event:
            p.timeline.append(event)
            p.phases_seen.add(phase)

    # Mark pivot hosts (appear as both src and dst)
    for ip, profile in profiles.items():
        if ip in dst_ips_all:
            profile.is_pivot = True

    # Enrich profiles with external findings
    for ip, profile in profiles.items():
        if ip in beacon_src_ips:
            profile.phases_seen.add("C2")
            profile.threat_score += 40
        if ip in dns_src_ips:
            profile.phases_seen.add("EXFILTRATION")
            profile.threat_score += 25

    # Score and detect attack chains
    attack_chains: list[AttackChain] = []
    for ip, profile in profiles.items():
        _score_host_profile(profile)
        chain = _detect_attack_chain(profile)
        if chain:
            attack_chains.append(chain)

    attack_chains.sort(key=lambda c: c.threat_score, reverse=True)

    pivot_hosts    = [ip for ip, p in profiles.items() if p.is_pivot]
    high_risk      = [ip for ip, p in profiles.items() if p.threat_score >= 60]

    log.info(
        f"Correlation: {len(profiles)} hosts, {len(attack_chains)} chains, "
        f"{len(pivot_hosts)} pivots, {len(high_risk)} high-risk"
    )

    return CorrelationReport(
        host_profiles   = profiles,
        attack_chains   = attack_chains,
        pivot_hosts     = pivot_hosts,
        total_hosts     = len(profiles),
        high_risk_hosts = high_risk,
    )


# ── Internal helpers ───────────────────────────────────────────────────────────

def _classify_flow_phase(flow: Flow) -> tuple[str, Optional[TimelineEvent]]:
    """Classify a flow into an attack phase and build an event."""
    dst_port = flow.dst_port or 0
    phase    = "UNKNOWN"
    desc     = ""
    score    = 0

    # C2 ports — highest priority
    if dst_port in _C2_PORTS:
        phase = "C2"
        desc  = f"C2 connection to {flow.dst_ip}:{dst_port}"
        score = 50

    # Lateral movement
    elif dst_port in _LATERAL_PORTS and _is_private(flow.dst_ip or ""):
        phase = "LATERAL"
        desc  = f"Lateral movement attempt to {flow.dst_ip}:{dst_port}"
        score = 35

    # Port scan pattern (many unique ports, low bytes per flow)
    elif (flow.packet_count <= 3 and flow.byte_count < 200
          and dst_port in _RECON_PORTS):
        phase = "RECON"
        desc  = f"Recon probe to {flow.dst_ip}:{dst_port}"
        score = 15

    # Large outbound transfer to external IP — exfil signal
    elif (flow.byte_count > 500_000
          and not _is_private(flow.dst_ip or "")
          and dst_port in _EXFIL_SIGNALS):
        phase = "EXFILTRATION"
        desc  = (f"Large outbound transfer: {flow.byte_count//1024}KB "
                 f"to {flow.dst_ip}:{dst_port}")
        score = 40

    # Standard external connection — possible initial access
    elif (not _is_private(flow.dst_ip or "")
          and flow.protocol == "TCP"
          and dst_port in (80, 443, 8080, 8443)):
        phase = "INITIAL_ACCESS"
        desc  = f"External HTTP(S) to {flow.dst_ip}:{dst_port}"
        score = 5

    if phase == "UNKNOWN" or score == 0:
        return "UNKNOWN", None

    tactic_id, tactic_name = PHASES.get(phase, ("", "Unknown"))
    ts = flow.first_seen or datetime.datetime.utcnow().isoformat()

    event = TimelineEvent(
        timestamp   = ts,
        phase       = phase,
        tactic_id   = tactic_id,
        tactic_name = tactic_name,
        src_ip      = flow.src_ip or "?",
        dst_ip      = flow.dst_ip or "?",
        dst_port    = flow.dst_port,
        protocol    = flow.protocol,
        description = desc,
        score       = score,
        flow_ref    = flow,
    )
    return phase, event


def _score_host_profile(profile: HostProfile):
    """Compute threat score for a host based on phases and behavior."""
    score = 0

    # Phase presence scoring
    phase_scores = {
        "C2": 50, "EXFILTRATION": 40, "LATERAL": 35,
        "EXECUTION": 30, "INITIAL_ACCESS": 10, "RECON": 5,
    }
    for phase in profile.phases_seen:
        score += phase_scores.get(phase, 0)

    # Port scan: many unique ports to same destination
    if len(profile.unique_dst_ports) > 15:
        score += 20

    # Fan-out: connecting to many different external IPs
    external_dsts = [ip for ip in profile.unique_dst_ips
                     if not _is_private(ip) and ip != "255.255.255.255"]
    if len(external_dsts) > 10:
        score += 15

    # Pivot host (used as both attacker and victim)
    if profile.is_pivot:
        score += 20

    profile.threat_score = min(score + profile.threat_score, 100)
    if profile.threat_score >= 80:
        profile.severity = "CRITICAL"
    elif profile.threat_score >= 60:
        profile.severity = "HIGH"
    elif profile.threat_score >= 40:
        profile.severity = "MEDIUM"
    else:
        profile.severity = "LOW"


def _detect_attack_chain(profile: HostProfile) -> Optional[AttackChain]:
    """Build an AttackChain if the host shows multi-phase behavior."""
    phases = profile.phases_seen

    # Need at least 2 phases to call it a chain
    meaningful = phases - {"UNKNOWN", "INITIAL_ACCESS"}
    if len(meaningful) < 1 and profile.threat_score < 40:
        return None

    # Sort events chronologically
    events = sorted(profile.timeline, key=lambda e: e.timestamp)
    if not events:
        return None

    # Build narrative
    ordered_phases = []
    for phase in ["RECON", "INITIAL_ACCESS", "EXECUTION",
                  "LATERAL", "C2", "EXFILTRATION"]:
        if phase in phases:
            ordered_phases.append(phase)

    narrative = _build_narrative(profile.ip, ordered_phases,
                                  profile.unique_dst_ips, profile.threat_score)

    tactics = [PHASES[p][0] for p in ordered_phases if p in PHASES and PHASES[p][0]]

    # Duration
    duration = 0.0
    if events:
        try:
            t0 = datetime.datetime.fromisoformat(events[0].timestamp)
            t1 = datetime.datetime.fromisoformat(events[-1].timestamp)
            duration = (t1 - t0).total_seconds()
        except Exception:
            pass

    return AttackChain(
        src_ip       = profile.ip,
        start_time   = events[0].timestamp  if events else None,
        end_time     = events[-1].timestamp if events else None,
        duration_sec = duration,
        phases       = ordered_phases,
        events       = events,
        threat_score = profile.threat_score,
        severity     = profile.severity,
        narrative    = narrative,
        mitre_tactics= tactics,
    )


def _build_narrative(src_ip: str, phases: list[str],
                     dst_ips: set, score: int) -> str:
    """Generate a plain-English attack narrative for an analyst."""
    if not phases:
        return f"Host {src_ip} showed suspicious activity (score={score})"

    parts = []
    if "RECON" in phases:
        parts.append(f"Host {src_ip} performed reconnaissance (port scanning)")
    if "INITIAL_ACCESS" in phases:
        parts.append("established external connections")
    if "EXECUTION" in phases:
        parts.append("executed remote commands")
    if "LATERAL" in phases:
        internal = [ip for ip in dst_ips if _is_private(ip)]
        parts.append(f"moved laterally to {len(internal)} internal host(s)")
    if "C2" in phases:
        parts.append("established C2 beaconing channel")
    if "EXFILTRATION" in phases:
        parts.append("exfiltrated data to external endpoint")

    return ". Then ".join(parts).capitalize() + f". Threat score: {score}/100."


def _is_private(ip: str) -> bool:
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def format_chain_report(report: CorrelationReport) -> str:
    """Plain-text summary for CLI output."""
    lines = [
        "Attack Chain Correlation Report",
        f"  Hosts analysed : {report.total_hosts}",
        f"  Attack chains  : {len(report.attack_chains)}",
        f"  Pivot hosts    : {len(report.pivot_hosts)}",
        f"  High-risk hosts: {len(report.high_risk_hosts)}",
        "",
    ]
    for chain in report.attack_chains[:5]:
        lines.append(f"  [{chain.severity}] {chain.src_ip}  score={chain.threat_score}")
        lines.append(f"    Phases: {' → '.join(chain.phases)}")
        lines.append(f"    {chain.narrative}")
        lines.append("")
    return "\n".join(lines)
