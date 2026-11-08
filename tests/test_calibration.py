"""
tests/test_calibration.py
────────────────────────────────────────────────────────────────────────────────
Ground-truth calibration test suite.

Validates beacon detection and DNS analysis against synthetic PCAPs whose
timing parameters are sourced from published threat intelligence reports:

  Beacon scenarios (C2 timing):
    Cobalt Strike default : 60s,  <5%  jitter (Mandiant ATT&CK eval 2023)
    Metasploit Meterpreter: 3s,   <2%  jitter (MITRE S0357)
    QakBot                : 240s, ~15% jitter (Secureworks CTU-2022-0409)
    Emotet                : 60s,  ~30% jitter (abuse.ch botnet tracker)
    TrickBot              : 15s,  <8%  jitter (CISA advisory AA20-302A)
    AsyncRAT              : 3s,   <1%  jitter (MITRE S0622)

  Legitimate traffic (must NOT be flagged HIGH or CRITICAL):
    NTP client            : 1024s, low natural variance
    Browser update check  : 1800s, exponential variance

  DNS scenarios:
    iodine DNS tunnel     : 55-char base64 subdomains, high entropy
    Short DNS labels      : 30-char subdomains, moderate entropy

Usage:
    python tests/test_calibration.py
"""

from __future__ import annotations

import os, sys, random, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2   import Ether
from scapy.packet      import Raw
from scapy.utils       import wrpcap

from engine.pcap_loader         import load_pcap
from engine.normaliser          import normalise
from engine.session_tracker     import reconstruct_sessions
from modules.beacon_detector    import detect_beacons
from modules.dns_analyser       import analyse_dns
from modules.protocol_dissector import dissect_flows
from engine.logger              import get_logger

log   = get_logger("test_calibration")
PASS  = "\033[32m[PASS]\033[0m"
FAIL  = "\033[31m[FAIL]\033[0m"
WARN  = "\033[33m[WARN]\033[0m"

# Severity ordering for comparisons
SEV = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ── PCAP builders ──────────────────────────────────────────────────────────────

def _beacon_pcap(path: str, src: str, dst: str, dport: int,
                  interval: float, jitter_pct: float, n: int,
                  base_time: float = 1700000000.0, payload_size: int = 64):
    """
    Generate a PCAP where malware opens a fresh TCP connection every `interval`
    seconds — the standard pattern for C2 frameworks (Cobalt Strike, Meterpreter,
    QakBot, Emotet, TrickBot, AsyncRAT etc.).
    """
    random.seed(42)
    pkts = []
    t = base_time
    for i in range(n):
        jitter = random.uniform(-jitter_pct * interval, jitter_pct * interval)
        t += interval + jitter
        sport = random.randint(49152, 65535)
        # Outbound connection
        p = Ether()/IP(src=src, dst=dst)/\
            TCP(sport=sport, dport=dport, flags="PA", seq=1000 + i * 100)/\
            Raw(bytes(random.randint(0, 255) for _ in range(payload_size)))
        p.time = t
        pkts.append(p)
        # Response (bidirectional)
        r = Ether()/IP(src=dst, dst=src)/\
            TCP(sport=dport, dport=sport, flags="PA", seq=2000 + i * 50)/\
            Raw(bytes(random.randint(0, 255) for _ in range(32)))
        r.time = t + 0.1
        pkts.append(r)
    wrpcap(path, pkts)
    return len(pkts)


def _legit_pcap(path: str, src: str, dst: str, dport: int,
                 interval: float, n: int, base_time: float = 1700000000.0):
    """
    Legitimate periodic traffic with natural exponential inter-arrival —
    NTP polling, browser update checks, telemetry.
    """
    random.seed(7)
    pkts = []
    t = base_time
    for i in range(n):
        t += random.expovariate(1.0 / interval)  # exponential, not uniform
        p = Ether()/IP(src=src, dst=dst)/\
            UDP(sport=random.randint(1024, 65535), dport=dport)/\
            Raw(b"\x00" * 48)
        p.time = t
        pkts.append(p)
    wrpcap(path, pkts)
    return len(pkts)


def _dns_tunnel_pcap(path: str, src: str, label_len: int,
                      n: int, base_time: float = 1700000000.0):
    """
    DNS tunnelling PCAP with base64-like high-entropy subdomains (iodine/dnscat2 pattern).
    """
    random.seed(13)
    CHARS = "abcdefghijklmnopqrstuvwxyz0123456789"
    pkts  = []
    for i in range(n):
        sub  = "".join(random.choice(CHARS) for _ in range(label_len))
        body = (bytes([len(sub)]) + sub.encode() +
                b"\x04evil\x03com\x00\x00\x10\x00\x01")
        pay  = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + body
        p = Ether()/IP(src=src, dst="8.8.8.8")/\
            UDP(sport=random.randint(1024, 65535), dport=53)/Raw(pay)
        p.time = base_time + i * random.uniform(0.5, 2.0)
        pkts.append(p)
    wrpcap(path, pkts)
    return len(pkts)


# ── Test runner ────────────────────────────────────────────────────────────────

def run_calibration():
    print("\n" + "=" * 70)
    print("  CALIBRATION TEST SUITE — Ground-truth beacon & DNS detection")
    print("=" * 70 + "\n")

    passed = failed = 0
    scenarios = []

    with tempfile.TemporaryDirectory() as td:

        def pcap(name: str) -> str:
            return os.path.join(td, name)

        # ── Build all PCAPs ────────────────────────────────────────────────────
        _beacon_pcap(pcap("cs.pcap"),        "192.168.1.10","185.220.101.5", 443, 60, 0.05, 20)
        _beacon_pcap(pcap("meterp.pcap"),    "192.168.1.11","45.33.32.156", 4444, 3, 0.02, 30)
        _beacon_pcap(pcap("qakbot.pcap"),    "192.168.1.12","91.194.74.100",8080,240, 0.15, 15)
        _beacon_pcap(pcap("emotet.pcap"),    "192.168.1.13","77.75.79.33",  443,  60, 0.30, 18)
        _beacon_pcap(pcap("trickbot.pcap"),  "192.168.1.14","194.165.16.72",447,  15, 0.08, 25)
        _beacon_pcap(pcap("asyncrat.pcap"),  "192.168.1.15","23.19.58.114", 6606,  3, 0.01, 35)
        _legit_pcap( pcap("ntp.pcap"),       "192.168.1.20","129.6.15.28",  123, 1024, 10)
        _legit_pcap( pcap("chrome.pcap"),    "192.168.1.21","142.250.80.4", 443, 1800,  8)
        _dns_tunnel_pcap(pcap("dns55.pcap"), "192.168.1.30", 55, 20)
        _dns_tunnel_pcap(pcap("dns30.pcap"), "192.168.1.30", 30, 15)

        # ── Define scenarios ───────────────────────────────────────────────────
        # (file, description, expected_min_severity, expected_max_severity, type)
        # type: "beacon" or "dns"
        scenarios_def = [
            ("cs.pcap",       "Cobalt Strike 60s <5% jitter",   "HIGH",   "CRITICAL", "beacon"),
            ("meterp.pcap",   "Meterpreter 3s port 4444",       "CRITICAL","CRITICAL","beacon"),
            ("qakbot.pcap",   "QakBot 240s 15% jitter",         "HIGH",   "CRITICAL", "beacon"),
            ("emotet.pcap",   "Emotet 60s 30% jitter",          "MEDIUM", "CRITICAL", "beacon"),
            ("trickbot.pcap", "TrickBot 15s port 447",          "CRITICAL","CRITICAL","beacon"),
            ("asyncrat.pcap", "AsyncRAT 3s port 6606",          "CRITICAL","CRITICAL","beacon"),
            ("ntp.pcap",      "Legit NTP 1024s (no alert)",     "NONE",   "LOW",      "beacon"),
            ("chrome.pcap",   "Legit Chrome 1800s (no alert)",  "NONE",   "LOW",      "beacon"),
            ("dns55.pcap",    "DNS tunnel 55-char iodine",      "HIGH",   "CRITICAL", "dns"),
            ("dns30.pcap",    "DNS tunnel 30-char labels",      "MEDIUM", "CRITICAL", "dns"),
        ]

        for fname, desc, exp_min, exp_max, kind in scenarios_def:
            path    = pcap(fname)
            meta    = load_pcap(path)
            packets = normalise(meta["packets"])
            flows   = reconstruct_sessions(packets)

            if kind == "dns":
                dns_stats = analyse_dns(dissect_flows(flows))
                if dns_stats.findings:
                    f         = dns_stats.findings[0]
                    got_sev   = f.severity
                    got_score = f.threat_score
                    detail    = f"entropy={f.entropy:.2f} label={f.max_label_len}"
                else:
                    got_sev = "NONE"; got_score = 0; detail = "no finding"
            else:
                beacons = detect_beacons(flows)
                if beacons:
                    b         = beacons[0]
                    got_sev   = b.severity
                    got_score = b.threat_score
                    detail    = (f"conn={b.connection_count} "
                                 f"cv={b.interval_cv:.3f} "
                                 f"mean={b.interval_mean:.1f}s")
                else:
                    got_sev = "NONE"; got_score = 0; detail = "no finding"

            got_n = SEV.get(got_sev, 0)
            min_n = SEV.get(exp_min, 0)
            max_n = SEV.get(exp_max, 4)
            ok    = min_n <= got_n <= max_n

            icon = PASS if ok else FAIL
            print(f"  {icon} {desc:<42} "
                  f"exp=[{exp_min}–{exp_max}]  got={got_sev}({got_score})  {detail}")

            if ok: passed += 1
            else:  failed += 1

    # ── DGA model calibration ──────────────────────────────────────────────────
    print()
    print("  DGA Model Calibration")
    print("  " + "─" * 60)

    from modules.dns_analyser import _dga_score

    dga_cases = [
        # (domain, expected_label)  — label: "MALICIOUS" score>0.65, "LEGIT" score<=0.65
        ("ejkpcjhgapnfkber.com",  "MALICIOUS"),  # Conficker C DGA (published)
        ("lkjjqwlbnzfxhtkm.net",  "MALICIOUS"),  # Conficker C DGA
        ("xqkzvbnmwrtplfgj.tk",   "MALICIOUS"),  # Random consonant DGA
        ("bnmwqrtzxcvplfgj.ru",   "MALICIOUS"),  # Random consonant DGA
        ("hgjklzxcvbnmqwer.xyz",  "MALICIOUS"),  # Random consonant DGA
        ("google.com",            "LEGIT"),
        ("microsoft.com",         "LEGIT"),
        ("amazon.com",            "LEGIT"),
        ("cloudflare.com",        "LEGIT"),
        ("netflix.com",           "LEGIT"),
        ("wikipedia.org",         "LEGIT"),
        ("github.com",            "LEGIT"),
        ("nfsu.ac.in",            "LEGIT"),
        ("apple.com",             "LEGIT"),
        ("stackoverflow.com",     "LEGIT"),
    ]

    dga_threshold = 0.65
    for domain, expected in dga_cases:
        score = _dga_score(domain)
        got   = "MALICIOUS" if score > dga_threshold else "LEGIT"
        ok    = got == expected
        icon  = PASS if ok else FAIL
        print(f"  {icon} {domain:<40} score={score:.3f}  expected={expected}")
        if ok: passed += 1
        else:  failed += 1

    print()
    total = passed + failed
    pct   = 100 * passed // total if total else 0
    print(f"  {'='*60}")
    print(f"  Results: {passed}/{total} passed ({pct}%)  —  "
          f"{failed} failure(s)")
    print(f"  {'='*60}\n")
    return failed == 0


if __name__ == "__main__":
    import sys
    sys.exit(0 if run_calibration() else 1)
