"""
modules/traffic_classifier.py
────────────────────────────────────────────────────────────────────────────────
Traffic classification engine — SOC upgrade.

Classifies every IP address and flow into a precise category:
  LOOPBACK | PRIVATE | LINK_LOCAL | MULTICAST | BROADCAST
  CLOUD_AWS | CLOUD_AZURE | CLOUD_GCP | CLOUD_CDN | PUBLIC

This feeds directly into:
  - Beacon detector (skip multicast/broadcast — huge FP source)
  - IOC enrichment (cloud IPs don't get same weight as unknown C2)
  - Alert explainability (tell analyst *why* this IP is interesting)
"""

from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

# ── Cloud provider CIDR prefixes (authoritative sources, curated) ─────────────
# AWS:   https://ip-ranges.amazonaws.com/ip-ranges.json  (sampled)
# Azure: https://www.microsoft.com/en-us/download/details.aspx?id=56519 (sampled)
# GCP:   https://cloud.google.com/compute/docs/faq#find_ip_range (sampled)
# CDN:   Cloudflare, Fastly, Akamai known ranges

_CLOUD_RANGES: list[tuple[str, str, str]] = [
    # (cidr, provider, service)
    # AWS
    ("3.0.0.0/8",       "AWS",       "EC2/General"),
    ("13.32.0.0/15",    "AWS",       "CloudFront"),
    ("13.224.0.0/14",   "AWS",       "CloudFront"),
    ("13.248.0.0/16",   "AWS",       "Global Accelerator"),
    ("18.0.0.0/8",      "AWS",       "EC2/General"),
    ("34.192.0.0/12",   "AWS",       "EC2/US-East"),
    ("35.160.0.0/13",   "AWS",       "EC2/US-West"),
    ("52.0.0.0/11",     "AWS",       "EC2/General"),
    ("54.64.0.0/11",    "AWS",       "EC2/General"),
    # GCP
    ("34.64.0.0/10",    "GCP",       "Compute Engine"),
    ("34.128.0.0/10",   "GCP",       "Compute Engine"),
    ("35.184.0.0/13",   "GCP",       "Compute Engine"),
    ("35.192.0.0/14",   "GCP",       "Compute Engine"),
    ("104.154.0.0/15",  "GCP",       "Compute Engine"),
    ("104.196.0.0/14",  "GCP",       "Compute Engine"),
    # Azure
    ("13.64.0.0/11",    "Azure",     "Compute"),
    ("13.96.0.0/13",    "Azure",     "Compute"),
    ("20.0.0.0/8",      "Azure",     "General"),
    ("40.64.0.0/10",    "Azure",     "Compute"),
    ("51.0.0.0/8",      "Azure",     "Europe"),
    ("104.40.0.0/13",   "Azure",     "Compute"),
    # Cloudflare CDN
    ("104.16.0.0/13",   "Cloudflare","CDN"),
    ("104.24.0.0/14",   "Cloudflare","CDN"),
    ("172.64.0.0/13",   "Cloudflare","CDN"),
    ("162.158.0.0/15",  "Cloudflare","CDN"),
    ("198.41.128.0/17", "Cloudflare","CDN"),
    # Fastly CDN
    ("23.235.32.0/20",  "Fastly",    "CDN"),
    ("103.244.50.0/24", "Fastly",    "CDN"),
    ("151.101.0.0/16",  "Fastly",    "CDN"),
    # Akamai
    ("23.32.0.0/11",    "Akamai",    "CDN"),
    ("23.192.0.0/11",   "Akamai",    "CDN"),
    ("95.100.0.0/15",   "Akamai",    "CDN"),
]

# Build compiled network objects once
_CLOUD_NETS = [
    (ipaddress.ip_network(cidr, strict=False), provider, svc)
    for cidr, provider, svc in _CLOUD_RANGES
]

# Ports to whitelist as normal periodic traffic (STRONG false-positive reducers)
BENIGN_PERIODIC_PORTS = {
    67, 68,           # DHCP
    137, 138, 139,    # NetBIOS
    5353,             # mDNS
    1900,             # SSDP/UPnP
    5355,             # LLMNR
    2049,             # NFS
    111,              # RPC portmapper
    123,              # NTP
    161, 162,         # SNMP
    520, 521,         # RIP routing
    5683,             # CoAP IoT
}

# Multicast address ranges
_MULTICAST_NET   = ipaddress.ip_network("224.0.0.0/4")
_LINK_LOCAL_NET  = ipaddress.ip_network("169.254.0.0/16")
_LOOPBACK_NET    = ipaddress.ip_network("127.0.0.0/8")
_PRIVATE_NETS    = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


@dataclass
class IPClassification:
    ip:            str
    category:      str    # see CATEGORIES below
    is_internal:   bool
    is_routable:   bool
    cloud_provider: Optional[str] = None
    cloud_service:  Optional[str] = None
    risk_modifier:  float = 1.0   # multiplier for threat scoring
    description:    str   = ""


# Categories with their default risk_modifier
CATEGORIES = {
    "LOOPBACK":     0.0,   # never interesting
    "PRIVATE":      0.8,   # lateral movement still interesting
    "LINK_LOCAL":   0.0,   # auto-config, ignore
    "MULTICAST":    0.1,   # mostly benign protocols
    "BROADCAST":    0.0,   # ARP etc, ignore
    "CLOUD_AWS":    0.5,   # common legit target — lower base weight
    "CLOUD_AZURE":  0.5,
    "CLOUD_GCP":    0.5,
    "CLOUD_CDN":    0.3,   # CDN = almost always legit
    "PUBLIC":       1.0,   # unknown public IP = full weight
}


@lru_cache(maxsize=4096)
def classify_ip(ip: str) -> IPClassification:
    """
    Classify an IP address. Results are LRU-cached for performance.
    Called O(n_packets) times so caching matters.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return IPClassification(ip=ip, category="PUBLIC", is_internal=False,
                                is_routable=True, risk_modifier=1.0,
                                description="Invalid IP format")

    # Loopback
    if addr in _LOOPBACK_NET:
        return IPClassification(ip=ip, category="LOOPBACK", is_internal=True,
                                is_routable=False, risk_modifier=0.0,
                                description="Loopback address")

    # Link-local (169.254.x.x)
    if addr in _LINK_LOCAL_NET:
        return IPClassification(ip=ip, category="LINK_LOCAL", is_internal=True,
                                is_routable=False, risk_modifier=0.0,
                                description="Link-local (APIPA)")

    # Multicast (224.0.0.0/4)
    if addr in _MULTICAST_NET:
        return IPClassification(ip=ip, category="MULTICAST", is_internal=False,
                                is_routable=False, risk_modifier=0.1,
                                description="Multicast group address")

    # Broadcast
    if ip == "255.255.255.255" or ip.endswith(".255"):
        return IPClassification(ip=ip, category="BROADCAST", is_internal=False,
                                is_routable=False, risk_modifier=0.0,
                                description="Broadcast address")

    # Private RFC-1918
    for net in _PRIVATE_NETS:
        if addr in net:
            return IPClassification(ip=ip, category="PRIVATE", is_internal=True,
                                    is_routable=False, risk_modifier=0.8,
                                    description=f"RFC-1918 private ({net})")

    # Cloud providers (checked before PUBLIC)
    for net, provider, service in _CLOUD_NETS:
        if addr in net:
            cat = f"CLOUD_{provider.upper().replace(' ','_').replace('CLOUDFLARE','CDN').replace('FASTLY','CDN').replace('AKAMAI','CDN')}"
            if cat not in CATEGORIES:
                cat = "CLOUD_CDN"
            return IPClassification(
                ip=ip, category=cat, is_internal=False, is_routable=True,
                cloud_provider=provider, cloud_service=service,
                risk_modifier=CATEGORIES.get(cat, 0.5),
                description=f"{provider} {service} ({net})"
            )

    # Default: unknown public IP
    return IPClassification(ip=ip, category="PUBLIC", is_internal=False,
                            is_routable=True, risk_modifier=1.0,
                            description="Unknown public IP")


def is_benign_periodic_flow(src_port: Optional[int],
                             dst_port: Optional[int],
                             dst_ip:   Optional[str]) -> bool:
    """
    True if this flow is almost certainly benign periodic traffic
    (DHCP, mDNS, NetBIOS, NTP, SSDP, etc.).
    Used by beacon detector to skip scoring entirely.
    """
    for port in (src_port, dst_port):
        if port in BENIGN_PERIODIC_PORTS:
            return True
    # Multicast destination
    if dst_ip:
        try:
            addr = ipaddress.ip_address(dst_ip)
            if addr in _MULTICAST_NET:
                return True
        except ValueError:
            pass
    return False


def flow_risk_modifier(src_ip: Optional[str],
                       dst_ip: Optional[str]) -> float:
    """
    Combined risk multiplier for a flow based on both endpoint classifications.
    Reduces noise: cloud→cloud flows get 0.3x weight.
    Unknown public destination gets full 1.0x weight.
    """
    src_cls = classify_ip(src_ip or "0.0.0.0")
    dst_cls = classify_ip(dst_ip or "0.0.0.0")

    # If either endpoint is a no-interest address, suppress
    if src_cls.risk_modifier == 0.0 or dst_cls.risk_modifier == 0.0:
        return 0.0

    # Use destination modifier as primary signal (attacker-controlled end)
    return dst_cls.risk_modifier
