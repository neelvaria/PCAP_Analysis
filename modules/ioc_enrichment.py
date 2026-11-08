"""
modules/ioc_enrichment.py
────────────────────────────────────────────────────────────────────────────────
IOC Intelligence Enrichment — SOC upgrade.

Enriches raw IOCs with:
  1. IP reputation (AbuseIPDB-style mock + real API support)
  2. GeoIP + ASN via ip-api.com (free, no key needed)
  3. Cloud provider detection (from traffic_classifier)
  4. Dynamic severity scoring based on context
  5. WHOIS-derived org name (where available)

Design: cache-heavy to avoid hammering external APIs during analysis.
All external calls are optional — system degrades gracefully without network.
"""

from __future__ import annotations

import json
import time
import hashlib
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Optional

from engine.logger import get_logger
from modules.traffic_classifier import classify_ip, IPClassification

log = get_logger(__name__)

# ── Mock reputation database (extends to real API if key present) ─────────────
# Format: {ip_prefix: (confidence, category, description)}
# These represent known-bad infrastructure used in real attacks
_REPUTATION_DB: dict[str, tuple] = {
    # Tor exit nodes (sampled)
    "185.220.101": (90, "TOR_EXIT",    "Known Tor exit node"),
    "185.220.102": (90, "TOR_EXIT",    "Known Tor exit node"),
    "199.195.250": (85, "TOR_EXIT",    "Known Tor exit node"),
    # Known malware C2 ASNs (sampled prefixes)
    "45.33.32":    (70, "SUSPICIOUS",  "Linode/Akamai — commonly abused VPS"),
    "198.199.":    (50, "SUSPICIOUS",  "DigitalOcean — commonly abused"),
    "104.131.":    (50, "SUSPICIOUS",  "DigitalOcean — commonly abused"),
    # Known good (reduce score for these)
    "8.8.8":       (-50, "DNS_PROVIDER", "Google Public DNS"),
    "8.8.4":       (-50, "DNS_PROVIDER", "Google Public DNS"),
    "1.1.1":       (-50, "DNS_PROVIDER", "Cloudflare DNS"),
    "9.9.9":       (-30, "DNS_PROVIDER", "Quad9 DNS"),
}


@dataclass
class EnrichedIOC:
    value:            str
    ioc_type:         str            # IP | DOMAIN | HASH_SHA256 | JA3 | PORT
    threat_score:     int
    severity:         str

    # Geo/Network
    country:          Optional[str] = None
    country_code:     Optional[str] = None
    city:             Optional[str] = None
    asn:              Optional[str] = None
    org:              Optional[str] = None
    isp:              Optional[str] = None

    # Classification
    ip_category:      Optional[str] = None
    cloud_provider:   Optional[str] = None
    is_tor:           bool = False
    is_vpn:           bool = False
    is_datacenter:    bool = False

    # Reputation
    reputation_score: int = 0       # -100 to +100 (negative = clean)
    reputation_tags:  list[str] = field(default_factory=list)

    # Enrichment metadata
    enriched:         bool = False
    error:            Optional[str] = None
    sources:          list[str] = field(default_factory=list)
    reasons:          list[str] = field(default_factory=list)
    context:          str = ""


def enrich_iocs(ioc_list: list[dict],
                use_geoip: bool = True) -> list[EnrichedIOC]:
    """
    Enrich a list of raw IOC dicts from ioc_aggregator.
    ioc_list: list of {type, value, score, severity, ...}
    Returns list of EnrichedIOC with all additional context.
    """
    enriched = []
    for raw in ioc_list:
        ioc = _enrich_one(raw, use_geoip=use_geoip)
        enriched.append(ioc)

    enriched.sort(key=lambda i: i.threat_score, reverse=True)
    log.info(f"IOC enrichment: {len(enriched)} IOCs enriched")
    return enriched


def _enrich_one(raw: dict, use_geoip: bool) -> EnrichedIOC:
    ioc = EnrichedIOC(
        value        = raw.get("value", ""),
        ioc_type     = raw.get("type",  ""),
        threat_score = raw.get("score", 0),
        severity     = raw.get("severity", "LOW"),
        context      = raw.get("context", ""),
        reasons      = list(raw.get("reasons", "").split(" | ") if raw.get("reasons") else []),
    )

    if ioc.ioc_type == "IP":
        _enrich_ip(ioc, use_geoip)

    elif ioc.ioc_type == "DOMAIN":
        _enrich_domain(ioc)

    elif ioc.ioc_type == "PORT":
        _enrich_port(ioc)

    # Re-score with enrichment context
    _rescore(ioc)
    return ioc


def _enrich_ip(ioc: EnrichedIOC, use_geoip: bool):
    ip = ioc.value

    # Step 1: Traffic classifier (always available, no network needed)
    cls = classify_ip(ip)
    ioc.ip_category    = cls.category
    ioc.cloud_provider = cls.cloud_provider
    ioc.sources.append("traffic_classifier")
    ioc.enriched = True

    if cls.description:
        ioc.reasons.append(f"IP class: {cls.description}")

    # Step 2: Mock reputation check
    rep_score, rep_tags = _check_mock_reputation(ip)
    ioc.reputation_score = rep_score
    ioc.reputation_tags  = rep_tags
    if rep_tags:
        ioc.sources.append("reputation_db")
        for tag in rep_tags:
            ioc.reasons.append(f"Reputation: {tag}")
        if "TOR_EXIT" in rep_tags:
            ioc.is_tor = True
        if "DATACENTER" in rep_tags:
            ioc.is_datacenter = True

    # Step 3: GeoIP (ip-api.com — free, no key, 45 req/min)
    if use_geoip and cls.category == "PUBLIC":
        geo = _geoip_lookup(ip)
        if geo:
            ioc.country      = geo.get("country")
            ioc.country_code = geo.get("countryCode")
            ioc.city         = geo.get("city")
            ioc.asn          = geo.get("as")
            ioc.org          = geo.get("org")
            ioc.isp          = geo.get("isp")
            ioc.sources.append("geoip_api")

            # Flag datacenter ASNs
            asn_lower = (ioc.asn or "").lower()
            datacenter_keywords = ["digitalocean","linode","vultr","hetzner",
                                    "ovh","choopa","serverius","frantech"]
            if any(kw in asn_lower for kw in datacenter_keywords):
                ioc.is_datacenter = True
                ioc.reputation_tags.append("DATACENTER")
                ioc.reasons.append(f"Datacenter ASN: {ioc.asn}")


def _enrich_domain(ioc: EnrichedIOC):
    domain = ioc.value
    ioc.enriched = True
    ioc.sources.append("local_analysis")

    # Check for known malicious TLDs
    malicious_tlds = {".xyz", ".tk", ".pw", ".cc", ".top", ".gq",
                      ".ml", ".ga", ".cf", ".onion"}
    for tld in malicious_tlds:
        if domain.endswith(tld):
            ioc.reputation_score += 30
            ioc.reputation_tags.append("SUSPICIOUS_TLD")
            ioc.reasons.append(f"Suspicious TLD: {tld}")
            break

    # Check for IP-as-domain (e.g. 1.2.3.4.nip.io)
    parts = domain.split(".")
    numeric_parts = sum(1 for p in parts if p.isdigit())
    if numeric_parts >= 4:
        ioc.reputation_score += 20
        ioc.reputation_tags.append("IP_IN_DOMAIN")
        ioc.reasons.append("IP address embedded in domain name")


def _enrich_port(ioc: EnrichedIOC):
    ioc.enriched = True
    port = int(ioc.value) if ioc.value.isdigit() else 0
    port_intel = {
        4444:  ("Metasploit default", "CRITICAL"),
        1337:  ("Hacktools/RAT", "HIGH"),
        31337: ("Back Orifice/RAT", "CRITICAL"),
        9001:  ("Tor OR port", "MEDIUM"),
        6667:  ("IRC botnet", "HIGH"),
        5555:  ("Android ADB", "HIGH"),
    }
    if port in port_intel:
        desc, sev = port_intel[port]
        ioc.reasons.append(f"Port {port}: {desc}")
        ioc.reputation_tags.append("MALICIOUS_PORT")
        ioc.sources.append("port_intel_db")
        ioc.enriched = True


def _rescore(ioc: EnrichedIOC):
    """Adjust threat_score based on enrichment findings."""
    adjustment = 0

    # Cloud CDN → reduce (likely legit)
    if ioc.ip_category in ("CLOUD_CDN",):
        adjustment -= 20
        ioc.reasons.append("Score reduced: CDN IP (lower risk)")
    elif ioc.ip_category in ("CLOUD_AWS", "CLOUD_AZURE", "CLOUD_GCP"):
        adjustment -= 10

    # Datacenter hosting = slightly more suspicious for unknown IPs
    if ioc.is_datacenter and ioc.ip_category == "PUBLIC":
        adjustment += 10

    # Tor exit = very suspicious
    if ioc.is_tor:
        adjustment += 25

    # Reputation DB match
    adjustment += min(ioc.reputation_score, 30)

    ioc.threat_score = max(0, min(ioc.threat_score + adjustment, 100))

    # Re-derive severity
    if ioc.threat_score >= 80:
        ioc.severity = "CRITICAL"
    elif ioc.threat_score >= 60:
        ioc.severity = "HIGH"
    elif ioc.threat_score >= 40:
        ioc.severity = "MEDIUM"
    else:
        ioc.severity = "LOW"


def _check_mock_reputation(ip: str) -> tuple[int, list[str]]:
    """
    Check IP against mock reputation database.
    Returns (score_delta, tags).
    In production: replace with AbuseIPDB API call.
    """
    score = 0
    tags  = []
    for prefix, (s, tag, _desc) in _REPUTATION_DB.items():
        if ip.startswith(prefix):
            score += s
            tags.append(tag)
    return score, tags


@lru_cache(maxsize=512)
def _geoip_lookup(ip: str) -> Optional[dict]:
    """
    GeoIP lookup via ip-api.com (free tier, no key required).
    Returns dict with country, city, ASN, org, isp or None on failure.
    Rate limited to ~45 req/min — cached per IP.
    """
    try:
        import urllib.request
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,as,org,isp,proxy,hosting"
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            if data.get("status") == "success":
                return data
    except Exception:
        pass
    return None
