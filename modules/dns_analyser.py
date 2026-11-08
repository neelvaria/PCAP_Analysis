"""
modules/dns_analyser.py
────────────────────────────────────────────────────────────────────────────────
DNS Analysis & Exfiltration Detection Module — Week 4.

Detection techniques:
  1. Shannon entropy of subdomain labels — high entropy = base64/hex-encoded data
  2. Subdomain length analysis           — long subdomains = tunnelling
  3. Query rate analysis                 — too many queries/sec = DGA or tunnelling
  4. NXDOMAIN storm detection            — many failed lookups = DGA malware
  5. DNS tunnelling pattern              — TXT/NULL record types + oversized queries
  6. Domain Generation Algorithm (DGA)  — random-looking domain names
  7. Known malicious TLD patterns        — .xyz/.tk/.pw/.cc commonly used in attacks
  8. Rare query types                    — MX/TXT/NULL from workstation = suspicious

Each finding gets a threat score (0–100) and severity label.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Optional

from modules.protocol_dissector import DissectedFlow, DnsRecord
from engine.logger import get_logger

log = get_logger(__name__)

# ── Constants — sourced from config.py so analysts can tune without code edits ─
import config as _cfg

# Entropy threshold — legit subdomains rarely exceed 4.0 bits/char
# (raised from 3.5 — base64-encoded legitimate service tokens often hit 3.5–4.0)
DNS_ENTROPY_THRESHOLD     = _cfg.DNS_ENTROPY_THRESHOLD
# Labels longer than this are suspicious
DNS_LONG_LABEL_CHARS      = 40
# Subdomains longer than this are very suspicious (lowered from 52 to 50)
DNS_LONG_SUBDOMAIN_CHARS  = _cfg.DNS_LONG_SUBDOMAIN_CHARS
# Queries/minute above this is anomalous (raised from 20 — resolvers cache aggressively)
DNS_QUERY_RATE_THRESHOLD  = _cfg.DNS_HIGH_QUERY_RATE / 60.0  # convert to per-second
# NXDOMAIN count above this suggests DGA
DNS_NXDOMAIN_THRESHOLD    = 10
# Suspicious TLDs
SUSPICIOUS_TLDS = {".xyz", ".tk", ".pw", ".cc", ".top", ".gq", ".ml", ".ga",
                   ".cf", ".bit", ".onion", ".biz", ".info"}

# Legitimate high-volume domains (allowlist to reduce noise)
LEGIT_DOMAINS = {
    "google.com", "googleapis.com", "gstatic.com", "google-analytics.com",
    "microsoft.com", "windows.com", "office.com", "azure.com",
    "cloudflare.com", "akamai.com", "amazonaws.com", "cloudfront.net",
    "facebook.com", "fbcdn.net", "instagram.com", "twitter.com",
    "apple.com", "icloud.com", "akadns.net", "edgesuite.net",
}


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class DnsFinding:
    domain:          str
    src_ip:          str
    query_count:     int
    record_types:    list[str]

    # Detection results
    entropy:         float = 0.0
    max_label_len:   int   = 0
    subdomain_len:   int   = 0
    query_rate:      float = 0.0    # queries/minute

    # Flags
    is_tunnelling:   bool = False
    is_dga:          bool = False
    is_exfiltration: bool = False
    has_unusual_type: bool = False

    reasons:         list[str] = field(default_factory=list)
    threat_score:    int   = 0
    severity:        str   = "LOW"
    sample_queries:  list[str] = field(default_factory=list)


@dataclass
class DnsStats:
    """Aggregate DNS statistics across all flows."""
    total_queries:   int = 0
    unique_domains:  int = 0
    nxdomain_count:  int = 0
    top_queried:     list[tuple] = field(default_factory=list)
    findings:        list[DnsFinding] = field(default_factory=list)
    tunnelling_flows: int = 0
    dga_flows:       int = 0


# ── Public API ─────────────────────────────────────────────────────────────────

def analyse_dns(dissected_flows: list[DissectedFlow]) -> DnsStats:
    """
    Analyse all DNS flows for exfiltration, tunnelling, and DGA patterns.
    Returns a DnsStats object with aggregated stats and individual findings.
    """
    stats = DnsStats()

    # Collect all DNS records keyed by (src_ip, base_domain)
    # so we can measure per-source query rates
    by_domain: dict[str, list[DnsRecord]] = defaultdict(list)
    src_map:   dict[str, str]             = {}   # domain → src_ip

    for d in dissected_flows:
        if d.protocol_tag != "DNS" or not d.dns_records:
            continue
        src_ip = d.flow.src_ip or "unknown"
        for rec in d.dns_records:
            if not rec.query:
                continue
            stats.total_queries += 1
            base = _base_domain(rec.query)
            by_domain[base].append(rec)
            src_map[base] = src_ip

    stats.unique_domains = len(by_domain)
    stats.top_queried    = sorted(
        [(d, len(recs)) for d, recs in by_domain.items()],
        key=lambda x: -x[1]
    )[:15]

    # Analyse each domain group
    for base_domain, records in by_domain.items():
        if base_domain in LEGIT_DOMAINS:
            continue
        finding = _analyse_domain(base_domain, records, src_map.get(base_domain, "?"))
        if finding and finding.threat_score > 0:
            stats.findings.append(finding)
            if finding.is_tunnelling:
                stats.tunnelling_flows += 1
            if finding.is_dga:
                stats.dga_flows += 1

    stats.findings.sort(key=lambda f: f.threat_score, reverse=True)

    log.info(
        f"DNS analysis: {stats.total_queries} queries, "
        f"{stats.unique_domains} domains, "
        f"{len(stats.findings)} suspicious — "
        f"tunnelling:{stats.tunnelling_flows} DGA:{stats.dga_flows}"
    )
    return stats


# ── Per-domain analysis ────────────────────────────────────────────────────────

def _analyse_domain(domain: str, records: list[DnsRecord],
                    src_ip: str) -> Optional[DnsFinding]:
    score   = 0
    reasons = []

    query_names = [r.query for r in records if r.query]
    all_labels  = [_get_subdomain(q, domain) for q in query_names]
    all_labels  = [l for l in all_labels if l]

    rec_types = list({r.record_type for r in records})
    query_count = len(records)

    finding = DnsFinding(
        domain       = domain,
        src_ip       = src_ip,
        query_count  = query_count,
        record_types = rec_types,
        sample_queries = query_names[:5],
    )

    # ── 1. Shannon entropy of subdomain labels ─────────────────────────────────
    if all_labels:
        all_label_text = "".join(all_labels)
        entropy = _shannon_entropy(all_label_text)
        finding.entropy = round(entropy, 3)

        if entropy > DNS_ENTROPY_THRESHOLD + 0.5:
            score += 40
            reasons.append(
                f"Very high subdomain entropy: {entropy:.2f} bits/char "
                f"(base64/hex encoded data — tunnelling indicator)"
            )
            finding.is_tunnelling   = True
            finding.is_exfiltration = True
        elif entropy > DNS_ENTROPY_THRESHOLD:
            score += 20
            reasons.append(
                f"High subdomain entropy: {entropy:.2f} bits/char "
                f"(possible encoded payload)"
            )

    # ── 2. Subdomain length analysis ───────────────────────────────────────────
    if all_labels:
        max_label = max(len(l) for l in all_labels)
        finding.max_label_len = max_label

        full_subdomains = [q.replace("." + domain, "") for q in query_names]
        max_subdomain = max((len(s) for s in full_subdomains), default=0)
        finding.subdomain_len = max_subdomain

        if max_label > DNS_LONG_LABEL_CHARS:
            score += 35
            reasons.append(
                f"Very long subdomain label: {max_label} chars "
                f"(threshold: {DNS_LONG_LABEL_CHARS}) — DNS tunnelling"
            )
            finding.is_tunnelling = True
        elif max_subdomain > DNS_LONG_SUBDOMAIN_CHARS:
            score += 25
            reasons.append(
                f"Long subdomain total: {max_subdomain} chars — possible exfiltration"
            )

    # ── 3. Query rate anomaly ─────────────────────────────────────────────────
    # (simplified: query_count relative to expected)
    if query_count > 30:
        rate_score = min(25, int(query_count / 10))
        score += rate_score
        reasons.append(
            f"High query volume: {query_count} queries to {domain}"
        )
        finding.query_rate = float(query_count)

    # ── 4. Unusual record types ────────────────────────────────────────────────
    tunnel_types = {"TXT", "NULL", "ANY", "TYPE65"}
    found_tunnel_types = set(rec_types) & tunnel_types
    if found_tunnel_types:
        score += 30
        reasons.append(
            f"Tunnelling record types: {found_tunnel_types} "
            f"(used by dnscat2, iodine, dns2tcp)"
        )
        finding.is_tunnelling    = True
        finding.has_unusual_type = True

    # ── 5. DGA detection — n-gram consonant cluster analysis ──────────────────
    dga_score = _dga_score(domain)
    finding.is_dga = dga_score > 0.75
    if dga_score > 0.85:
        score += 40
        reasons.append(
            f"Very likely DGA domain: '{domain}' "
            f"(random character distribution, score={dga_score:.2f})"
        )
    elif dga_score > 0.75:
        score += 20
        reasons.append(
            f"Possible DGA domain: '{domain}' (score={dga_score:.2f})"
        )

    # ── 6. Suspicious TLD ─────────────────────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 15
            reasons.append(f"Suspicious TLD: {tld} (commonly used in malware)")
            break

    # ── 7. Numeric/hex-heavy domain ───────────────────────────────────────────
    sld = domain.split(".")[0] if "." in domain else domain
    hex_ratio = sum(1 for c in sld if c in "0123456789abcdef") / max(len(sld), 1)
    if hex_ratio > 0.7 and len(sld) > 8:
        score += 15
        reasons.append(
            f"Hex-heavy domain name: '{sld}' "
            f"({hex_ratio:.0%} hex chars — possible C2 DGA)"
        )

    finding.threat_score = min(score, 100)
    finding.reasons      = reasons

    # Severity
    if finding.threat_score >= 80:
        finding.severity = "CRITICAL"
    elif finding.threat_score >= 60:
        finding.severity = "HIGH"
    elif finding.threat_score >= 40:
        finding.severity = "MEDIUM"
    else:
        finding.severity = "LOW"

    return finding if score > 0 else None


# ── Helper functions ───────────────────────────────────────────────────────────

def _shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    counts  = Counter(text.lower())
    total   = len(text)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    return entropy


def _base_domain(fqdn: str) -> str:
    """
    Extract the registrable domain (second-level + TLD).
    e.g. "abc.def.evil.com" → "evil.com"
    """
    fqdn = fqdn.rstrip(".")
    parts = fqdn.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


def _get_subdomain(fqdn: str, base: str) -> str:
    """Extract just the subdomain part from an FQDN."""
    fqdn = fqdn.rstrip(".")
    if fqdn.endswith("." + base):
        return fqdn[:-(len(base) + 1)]
    if fqdn == base:
        return ""
    return fqdn


def _dga_score(domain: str) -> float:
    """
    Score a domain name for DGA-like randomness.
    Returns 0.0 (very legitimate) to 1.0 (very DGA-like).

    Heuristics:
      - High consonant cluster density
      - No real English n-grams
      - High ratio of unique characters
      - Long SLD (>= 10 chars without dashes)
    """
    sld = domain.split(".")[0] if "." in domain else domain
    sld = sld.lower()
    if len(sld) < 6:
        return 0.0

    # Common English bigrams in legitimate domain names
    COMMON_BIGRAMS = {
        "er","re","in","on","an","en","ti","es","or","at","de","al",
        "te","co","it","ic","is","le","am","ut","se","ar","nt","th",
        "he","to","nd","st","io","ng","ce","ly","ou","ma","ed","si",
        "ne","ra","ri","ro","ac","me","wo","em","fe","li","mi","sh",
        "oo","of","go","so","do","lo","no","po","fo","bo","mo","wo",
        "ss","ll","tt","ff","pp","mm","ck","ff","wn","ld","lf","lt",
        "ft","ct","pt","xt","fl","bl","cl","gl","pl","sl","cr","gr",
        "pr","tr","br","dr","fr","wr","sp","sc","sk","sw","sm","sn",
        "gh","ph","wh","ch","ow","aw","ew","ow","ai","ay","ea","ee",
        "oa","ui","ue","ie","oi","ey","gy","fy","ny","ry","ty","vy",
        "of","og","ol","om","op","ot","ov","ow","os","ob","oc","od",
    }

    bigrams = [sld[i:i+2] for i in range(len(sld)-1)]
    if not bigrams:
        return 0.0

    legit_bigram_ratio = (
        sum(1 for bg in bigrams if bg in COMMON_BIGRAMS) / len(bigrams)
    )

    # High unique char ratio
    unique_ratio = len(set(sld)) / len(sld)

    # Consonant cluster: 3+ consecutive consonants is suspicious
    vowels = set("aeiou")
    max_consonant_run = 0
    run = 0
    for c in sld:
        if c.isalpha() and c not in vowels:
            run += 1
            max_consonant_run = max(max_consonant_run, run)
        else:
            run = 0

    consonant_penalty = min(max_consonant_run / 5.0, 1.0)

    # Combine signals
    score = (
        (1 - legit_bigram_ratio) * 0.5  +   # fewer real bigrams = more suspicious
        (unique_ratio - 0.3) * 0.3       +   # more unique chars = more suspicious
        consonant_penalty * 0.2              # consonant clusters
    )
    return max(0.0, min(score, 1.0))


def format_dns_report(stats: DnsStats) -> str:
    """Return a plain-text summary of DNS findings."""
    lines = [
        f"DNS Analysis Report",
        f"  Total queries   : {stats.total_queries}",
        f"  Unique domains  : {stats.unique_domains}",
        f"  Suspicious      : {len(stats.findings)}",
        f"  Tunnelling flows: {stats.tunnelling_flows}",
        f"  DGA domains     : {stats.dga_flows}",
        "",
    ]
    for f in stats.findings[:10]:
        lines.append(
            f"  [{f.severity:8s}] {f.domain:<40s} score={f.threat_score}"
        )
        for r in f.reasons:
            lines.append(f"    → {r}")
    return "\n".join(lines)
