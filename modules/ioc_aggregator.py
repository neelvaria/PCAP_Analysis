"""
modules/ioc_aggregator.py
────────────────────────────────────────────────────────────────────────────────
IOC (Indicator of Compromise) Aggregator — Week 4.

Collects findings from all Week 4 detection modules and produces:
  • Unified IOC list (IPs, domains, hashes, JA3 fingerprints)
  • Composite threat score per indicator
  • MITRE ATT&CK tactic/technique mapping
  • CSV + JSON export
"""

from __future__ import annotations

import csv
import json
import io
from dataclasses import dataclass, field
from typing import Optional

from modules.beacon_detector import BeaconFinding
from modules.traffic_classifier import classify_ip, CATEGORIES
from modules.dns_analyser    import DnsFinding, DnsStats
from modules.file_extractor  import ExtractedFile
from engine.logger           import get_logger

log = get_logger(__name__)


# ── MITRE ATT&CK quick-lookup ──────────────────────────────────────────────────
# Maps detection type to (Tactic, Technique ID, Technique Name)
MITRE_MAP = {
    "beacon":           ("C2",           "T1071.001", "Application Layer Protocol: Web Protocols"),
    "beacon_port":      ("C2",           "T1571",     "Non-Standard Port"),
    "beacon_ja3":       ("C2",           "T1071.001", "Application Layer Protocol: Web Protocols"),
    "dns_tunnelling":   ("Exfiltration", "T1048.003", "Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol"),
    "dns_dga":          ("C2",           "T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
    "ftp_creds":        ("Credential Access", "T1552.001", "Unsecured Credentials: Credentials In Files"),
    "file_malware":     ("Execution",    "T1059",     "Command and Scripting Interpreter"),
    "large_upload":     ("Exfiltration", "T1041",     "Exfiltration Over C2 Channel"),
}


# ── Data model ─────────────────────────────────────────────────────────────────

@dataclass
class IOC:
    ioc_type:     str          # IP | DOMAIN | HASH_MD5 | HASH_SHA256 | JA3 | PORT
    value:        str
    threat_score: int          # 0–100
    severity:     str          # LOW | MEDIUM | HIGH | CRITICAL
    sources:      list[str]    # which modules flagged this
    reasons:      list[str]
    mitre_tactic:     str = ""
    mitre_technique:  str = ""
    mitre_name:       str = ""
    first_seen:   str = ""
    context:      str = ""     # e.g. "src: 192.168.1.5 → dst: 45.33.32.156:4444"


@dataclass
class IOCReport:
    iocs:               list[IOC]
    total_score:        int = 0
    critical_count:     int = 0
    high_count:         int = 0
    medium_count:       int = 0
    low_count:          int = 0
    attack_surface:     list[str] = field(default_factory=list)
    beacon_clusters:    list[dict] = field(default_factory=list)


# ── Public API ─────────────────────────────────────────────────────────────────

def aggregate_iocs(
    beacon_findings:  list[BeaconFinding],
    dns_stats:        DnsStats,
    extracted_files:  list[ExtractedFile],
) -> IOCReport:
    """
    Aggregate all findings into a unified IOC list.
    Deduplicates on (ioc_type, value), merging scores and sources.
    """
    ioc_map: dict[tuple, IOC] = {}

    # ── From beacon detector ───────────────────────────────────────────────────
    for b in beacon_findings:
        # External IP indicator — suppressed for cloud/CDN unless score is very high.
        # Rationale: Google/Cloudflare/AWS IPs connecting with regular intervals
        # are almost always CDN polling or cloud API calls, not C2.
        # Promotion threshold: cloud IPs need score>=70 (HIGH); unknown public >= 40.
        if b.dst_ip and not _is_private(b.dst_ip):
            dst_cls   = classify_ip(b.dst_ip)
            risk_mod  = dst_cls.risk_modifier
            # Minimum score to promote to IOC based on IP category
            if dst_cls.category == "CLOUD_CDN":
                min_score = 85   # CDN IPs almost never C2 — needs near-CRITICAL score
            elif dst_cls.category in ("CLOUD_AWS","CLOUD_AZURE","CLOUD_GCP"):
                min_score = 70   # cloud infra may host attacker VMs — higher bar
            else:
                min_score = 40   # unknown public IP — standard threshold

            if b.threat_score >= min_score:
                adjusted_score = min(int(b.threat_score * risk_mod), 100)
                _upsert(ioc_map, IOC(
                    ioc_type     = "IP",
                    value        = b.dst_ip,
                    threat_score = adjusted_score,
                    severity     = _score_to_severity(adjusted_score),
                    sources      = ["beacon_detector"],
                    reasons      = b.reasons + (
                        [f"IP category: {dst_cls.category} "
                         f"({dst_cls.cloud_provider or 'unknown'}) — "
                         f"score adjusted ×{risk_mod:.1f}"]
                        if risk_mod < 1.0 else []
                    ),
                    context      = f"{b.src_ip} → {b.dst_ip}:{b.dst_port}",
                    **_mitre("beacon"),
                ))
            else:
                log.debug(
                    f"IOC suppressed: {b.dst_ip} ({dst_cls.category}) "
                    f"score={b.threat_score} < min_score={min_score}"
                )

        # Suspicious port
        if b.dst_port and b.threat_score >= 30:
            _upsert(ioc_map, IOC(
                ioc_type     = "PORT",
                value        = str(b.dst_port),
                threat_score = min(b.threat_score, 60),
                severity     = _score_to_severity(min(b.threat_score, 60)),
                sources      = ["beacon_detector"],
                reasons      = [r for r in b.reasons if "port" in r.lower()],
                context      = f"dst_port={b.dst_port} proto={b.protocol}",
                **_mitre("beacon_port"),
            ))

        # JA3 fingerprint
        if b.ja3_hash:
            _upsert(ioc_map, IOC(
                ioc_type     = "JA3",
                value        = b.ja3_hash,
                threat_score = 80 if b.ja3_match else 30,
                severity     = "CRITICAL" if b.ja3_match else "MEDIUM",
                sources      = ["beacon_detector"],
                reasons      = [f"JA3: {b.ja3_hash}" +
                                 (f" = {b.ja3_match}" if b.ja3_match else "")],
                context      = f"{b.src_ip} → {b.dst_ip}",
                **_mitre("beacon_ja3"),
            ))

    # ── From DNS analyser ──────────────────────────────────────────────────────
    for f in dns_stats.findings:
        mitre_key = "dns_tunnelling" if f.is_tunnelling else "dns_dga"
        _upsert(ioc_map, IOC(
            ioc_type     = "DOMAIN",
            value        = f.domain,
            threat_score = f.threat_score,
            severity     = f.severity,
            sources      = ["dns_analyser"],
            reasons      = f.reasons,
            context      = f"src={f.src_ip} queries={f.query_count}",
            **_mitre(mitre_key),
        ))

    # ── From file extractor ────────────────────────────────────────────────────
    for ef in extracted_files:
        if ef.vt_verdict in ("MALICIOUS", "SUSPICIOUS"):
            score = 90 if ef.vt_verdict == "MALICIOUS" else 60

            _upsert(ioc_map, IOC(
                ioc_type     = "HASH_SHA256",
                value        = ef.sha256,
                threat_score = score,
                severity     = "CRITICAL" if score >= 80 else "HIGH",
                sources      = ["file_extractor", "virustotal"],
                reasons      = [
                    f"VirusTotal: {ef.vt_malicious}/{ef.vt_total} engines "
                    f"detect as {ef.vt_verdict}",
                    f"File: {ef.filename} ({ef.file_type})",
                ],
                context      = ef.source_flow,
                **_mitre("file_malware"),
            ))
            _upsert(ioc_map, IOC(
                ioc_type     = "HASH_MD5",
                value        = ef.md5,
                threat_score = score,
                severity     = "CRITICAL" if score >= 80 else "HIGH",
                sources      = ["file_extractor"],
                reasons      = [f"MD5 of malicious file: {ef.filename}"],
                context      = ef.source_flow,
                **_mitre("file_malware"),
            ))

    iocs = sorted(ioc_map.values(), key=lambda x: -x.threat_score)

    # ── Flow clustering — group similar beacons into patterns ─────────────────
    # Groups beacon findings by (dst_port, protocol) to detect fan-out:
    # e.g. "Cobalt Strike beacon pattern: 12 connections to 4 destinations on 443/TCP"
    cluster_summary = _cluster_beacons(beacon_findings)

    report = IOCReport(iocs=iocs)
    report.beacon_clusters = cluster_summary
    report.critical_count = sum(1 for i in iocs if i.severity == "CRITICAL")
    report.high_count     = sum(1 for i in iocs if i.severity == "HIGH")
    report.medium_count   = sum(1 for i in iocs if i.severity == "MEDIUM")
    report.low_count      = sum(1 for i in iocs if i.severity == "LOW")
    report.total_score    = sum(i.threat_score for i in iocs[:10]) // max(len(iocs[:10]), 1)
    report.attack_surface = list({i.mitre_tactic for i in iocs if i.mitre_tactic})

    log.info(
        f"IOC report: {len(iocs)} indicators — "
        f"CRITICAL:{report.critical_count} HIGH:{report.high_count} "
        f"MEDIUM:{report.medium_count} Tactics:{report.attack_surface}"
    )
    return report


def export_csv(report: IOCReport) -> str:
    """Return IOC list as CSV string."""
    buf = io.StringIO()
    w   = csv.writer(buf)
    w.writerow(["Type","Value","Score","Severity","Tactic","Technique","Sources","Context","Reasons"])
    for ioc in report.iocs:
        w.writerow([
            ioc.ioc_type,
            ioc.value,
            ioc.threat_score,
            ioc.severity,
            ioc.mitre_tactic,
            f"{ioc.mitre_technique} {ioc.mitre_name}",
            "|".join(ioc.sources),
            ioc.context,
            " | ".join(ioc.reasons[:2]),
        ])
    return buf.getvalue()


def export_json(report: IOCReport) -> str:
    """Return IOC list as JSON string."""
    def serialise(ioc: IOC) -> dict:
        return {
            "type":      ioc.ioc_type,
            "value":     ioc.value,
            "score":     ioc.threat_score,
            "severity":  ioc.severity,
            "mitre":     {"tactic": ioc.mitre_tactic,
                          "technique": ioc.mitre_technique,
                          "name": ioc.mitre_name},
            "sources":   ioc.sources,
            "context":   ioc.context,
            "reasons":   ioc.reasons,
        }
    return json.dumps(
        {"summary": {
            "total_iocs": len(report.iocs),
            "critical":   report.critical_count,
            "high":       report.high_count,
            "medium":     report.medium_count,
            "tactics":    report.attack_surface,
         },
         "iocs": [serialise(i) for i in report.iocs]},
        indent=2
    )


# ── Helpers ────────────────────────────────────────────────────────────────────

def _cluster_beacons(beacon_findings: list) -> list[dict]:
    """
    Group beacon findings by (dst_port, protocol) to expose fan-out C2 patterns.
    Returns summary dicts like:
      {'pattern': 'TCP:4444', 'connections': 30, 'unique_dsts': 1,
       'max_score': 100, 'severity': 'CRITICAL',
       'summary': '30 connections to 1 destination on TCP:4444'}
    """
    from collections import defaultdict
    groups: dict[str, list] = defaultdict(list)
    for b in beacon_findings:
        key = f"{b.protocol}:{b.dst_port}"
        groups[key].append(b)

    clusters = []
    for pattern, beacons in groups.items():
        unique_dsts = len({b.dst_ip for b in beacons})
        total_conns = sum(b.connection_count for b in beacons)
        max_score   = max(b.threat_score for b in beacons)
        severity    = beacons[0].severity
        clusters.append({
            "pattern":     pattern,
            "connections": total_conns,
            "unique_dsts": unique_dsts,
            "max_score":   max_score,
            "severity":    severity,
            "summary":     (
                f"{total_conns} connection(s) to {unique_dsts} destination(s) "                f"on {pattern}"
            ),
        })

    return sorted(clusters, key=lambda c: -c["max_score"])


def _upsert(ioc_map: dict, new: IOC):
    """Insert or merge an IOC (higher score wins, sources are unioned)."""
    key = (new.ioc_type, new.value)
    if key in ioc_map:
        existing = ioc_map[key]
        if new.threat_score > existing.threat_score:
            existing.threat_score = new.threat_score
            existing.severity     = new.severity
        existing.sources = list(set(existing.sources + new.sources))
        existing.reasons = list(set(existing.reasons + new.reasons))
    else:
        ioc_map[key] = new


def _mitre(key: str) -> dict:
    tactic, technique, name = MITRE_MAP.get(key, ("", "", ""))
    return {"mitre_tactic": tactic,
            "mitre_technique": technique,
            "mitre_name": name}


def _score_to_severity(score: int) -> str:
    if score >= 80: return "CRITICAL"
    if score >= 60: return "HIGH"
    if score >= 40: return "MEDIUM"
    return "LOW"


def _is_private(ip: str) -> bool:
    try:
        p = list(map(int, ip.split(".")))
        return (p[0] == 10 or
                (p[0] == 172 and 16 <= p[1] <= 31) or
                (p[0] == 192 and p[1] == 168) or
                p[0] == 127)
    except Exception:
        return False
