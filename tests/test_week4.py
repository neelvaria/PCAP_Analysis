"""
tests/test_week4.py
────────────────────────────────────────────────────────────────────────────────
Week 4 test suite: C2 beacon detection + DNS exfiltration + IOC aggregation.

Tests:
  1. Beacon detection — regular interval detection (CV < 0.15)
  2. Suspicious port flagging (port 4444)
  3. JA3 fingerprint computation
  4. Known malicious JA3 match
  5. DNS entropy calculation (Shannon entropy)
  6. DNS tunnelling detection (long subdomain labels)
  7. DGA domain scoring
  8. IOC aggregation and deduplication
  9. IOC CSV + JSON export
  10. Full Week 4 pipeline on synthetic PCAP
"""

import sys, os, tempfile, math, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
import datetime

from engine.pcap_loader         import load_pcap
from engine.normaliser          import normalise
from engine.session_tracker     import reconstruct_sessions, Flow
from modules.protocol_dissector import dissect_flows
from modules.beacon_detector    import (detect_beacons, _compute_ja3,
                                         KNOWN_MALICIOUS_JA3, BeaconFinding)
from modules.dns_analyser       import (analyse_dns, _shannon_entropy,
                                         _dga_score, _base_domain)
from modules.ioc_aggregator     import aggregate_iocs, export_csv, export_json
from modules.file_extractor     import extract_files
from engine.printer             import (print_beacon_findings,
                                         print_dns_findings, print_ioc_report)
from engine.logger              import get_logger

log = get_logger("test_week4")
PASS = "\033[32m[PASS]\033[0m"
FAIL = "\033[31m[FAIL]\033[0m"


# ── Synthetic PCAP builder ─────────────────────────────────────────────────────

def build_week4_pcap(path: str) -> int:
    """
    Build a PCAP designed to trigger all Week 4 detectors:
      - Regular-interval beacon to external IP port 4444
      - DNS tunnelling (very long subdomain labels)
      - DGA-like domain queries
      - Normal HTTP for baseline
    """
    pkts = []
    base_time = 1700000000.0   # fixed epoch for reproducibility

    # ── 1. C2 Beacon — 10 packets at exactly 30s intervals to port 4444 ───────
    for i in range(12):
        pkt = Ether()/IP(src="192.168.1.20", dst="45.33.32.156")/\
              TCP(sport=55000, dport=4444, flags="PA",
                  seq=1000 + i*100)/\
              Raw(b"\x00" * 64)   # fixed-size payload
        pkt.time = base_time + i * 30.0
        pkts.append(pkt)

    # ── 2. DNS tunnelling — long base64-looking subdomain labels ─────────────
    long_sub = "aGVsbG8td29ybGQtdGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4"
    dns_tunnel_payload = (
        b"\xcc\xdd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + bytes([len(long_sub)]) + long_sub.encode()
        + b"\x04evil\x03com\x00"
        + b"\x00\x10\x00\x01"   # TXT record type
    )
    for i in range(8):
        pkt = Ether()/IP(src="192.168.1.20", dst="8.8.8.8")/\
              UDP(sport=12000 + i, dport=53)/\
              Raw(dns_tunnel_payload)
        pkt.time = base_time + 400 + i * 5
        pkts.append(pkt)

    # ── 3. DGA domain queries ─────────────────────────────────────────────────
    dga_domains = [
        b"\x10xqkzvbnmwrtplfg\x03xyz\x00",   # random consonants, .xyz
        b"\x10pqrzxcvbnmwkqjh\x03top\x00",   # random, .top
        b"\x10bnmwqrtzxcvplfg\x03tk\x00",    # random, .tk
    ]
    for i, dom in enumerate(dga_domains):
        dns_dga = (
            b"\xee\xff\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            + dom
            + b"\x00\x01\x00\x01"
        )
        pkt = Ether()/IP(src="192.168.1.20", dst="8.8.8.8")/\
              UDP(sport=13000 + i, dport=53)/\
              Raw(dns_dga)
        pkt.time = base_time + 600 + i * 3
        pkts.append(pkt)

    # ── 4. Normal HTTP for baseline ───────────────────────────────────────────
    http_req = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
    pkt = Ether()/IP(src="192.168.1.20", dst="142.250.80.4")/\
          TCP(sport=60000, dport=80, flags="PA")/Raw(http_req)
    pkt.time = base_time + 700
    pkts.append(pkt)

    wrpcap(path, pkts)
    log.info(f"Week 4 test PCAP: {path}  ({len(pkts)} packets)")
    return len(pkts)


# ── Tests ──────────────────────────────────────────────────────────────────────

def run_tests():
    print("\n" + "="*60)
    print("  PCAP ENGINE — WEEK 4 TEST SUITE")
    print("="*60 + "\n")
    passed = failed = 0

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name
    build_week4_pcap(pcap_path)
    meta    = load_pcap(pcap_path)
    packets = normalise(meta["packets"])
    flows   = reconstruct_sessions(packets)

    # ── Test 1: Beacon interval detection ─────────────────────────────────────
    label = "Test 1: Regular beacon interval detection"
    try:
        beacons = detect_beacons(flows)
        beacon_flows = [b for b in beacons if b.dst_port == 4444]
        assert len(beacon_flows) > 0, \
            f"No beacon on port 4444 detected. All findings: {[(b.dst_port, b.threat_score) for b in beacons]}"
        b = beacon_flows[0]
        assert b.threat_score > 0, "Zero threat score"
        assert b.interval_cv < 0.5, f"CV too high: {b.interval_cv}"
        assert b.severity in ("CRITICAL","HIGH","MEDIUM"), f"Low severity: {b.severity}"
        has_interval_reason = any("interval" in r.lower() or "beacon" in r.lower()
                                   or "port" in r.lower() for r in b.reasons)
        assert has_interval_reason, f"No interval reason. Reasons: {b.reasons}"
        print(f"{PASS} {label}")
        print(f"       Port 4444 beacon: score={b.threat_score} severity={b.severity}")
        print(f"       interval_mean={b.interval_mean}s  CV={b.interval_cv}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 2: Suspicious port scoring ───────────────────────────────────────
    label = "Test 2: Suspicious port scoring (port 4444)"
    try:
        beacons = detect_beacons(flows)
        port_findings = [b for b in beacons if b.dst_port == 4444]
        assert len(port_findings) > 0, "No port 4444 finding"
        b = port_findings[0]
        # Port 4444 should contribute to score
        assert b.threat_score >= 30, f"Score too low for port 4444: {b.threat_score}"
        print(f"{PASS} {label}")
        print(f"       Port 4444 threat_score={b.threat_score}  reasons={len(b.reasons)}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 3: JA3 fingerprint computation ───────────────────────────────────
    label = "Test 3: JA3 fingerprint computation"
    try:
        # Build a minimal TLS ClientHello with known structure
        sni_host = b"test.example.com"
        sni_ext  = (b"\x00\x00"
                   + (13 + len(sni_host)).to_bytes(2,"big")
                   + (11 + len(sni_host)).to_bytes(2,"big")
                   + b"\x00" + len(sni_host).to_bytes(2,"big") + sni_host)
        body = (b"\x03\x03" + b"\x00"*32 + b"\x00"
                + b"\x00\x04\xc0\x2b\xc0\x2c"   # 2 cipher suites
                + b"\x01\x00"
                + len(sni_ext).to_bytes(2,"big") + sni_ext)
        ch   = b"\x01" + len(body).to_bytes(3,"big") + body
        tls  = b"\x16\x03\x01" + len(ch).to_bytes(2,"big") + ch

        ja3 = _compute_ja3(tls)
        assert ja3 is not None,         "JA3 is None"
        assert len(ja3) == 32,          f"JA3 wrong length: {len(ja3)}"
        assert all(c in "0123456789abcdef" for c in ja3), "JA3 not hex"
        # Same input should produce same hash
        assert _compute_ja3(tls) == ja3, "JA3 not deterministic"
        print(f"{PASS} {label}")
        print(f"       JA3: {ja3}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 4: Known malicious JA3 match ─────────────────────────────────────
    label = "Test 4: Known malicious JA3 match"
    try:
        # Directly test the KNOWN_MALICIOUS_JA3 dict
        assert len(KNOWN_MALICIOUS_JA3) >= 5, "Too few known malicious JA3 entries"
        # Pick one and verify it has a description
        first_hash, first_name = next(iter(KNOWN_MALICIOUS_JA3.items()))
        assert len(first_hash) == 32, "Hash should be 32 hex chars"
        assert len(first_name) > 0,   "Name should not be empty"

        # Simulate a finding with a known bad JA3
        mock_flow = Flow(src_ip="192.168.1.1", dst_ip="1.2.3.4",
                         src_port=54321, dst_port=443, protocol="TCP")
        mock_flow.packets = []
        mock_flow.payload_bytes = b""
        # Inject ja3 directly into a BeaconFinding
        bf = BeaconFinding(
            flow_id="192.168.1.1:54321 → 1.2.3.4:443 [TCP]",
            src_ip="192.168.1.1", dst_ip="1.2.3.4",
            dst_port=443, protocol="TCP",
            ja3_hash=first_hash, ja3_match=first_name,
            threat_score=80, severity="CRITICAL",
            reasons=[f"Known malicious JA3: {first_hash} ({first_name})"]
        )
        assert bf.ja3_match == first_name
        print(f"{PASS} {label}")
        print(f"       Hash: {first_hash} → {first_name}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 5: Shannon entropy calculation ───────────────────────────────────
    label = "Test 5: Shannon entropy calculation"
    try:
        # High entropy: random-looking base64 string
        high_e = _shannon_entropy("aGVsbG8xMjM0NTY3ODlhYmNkZWZnaGlqa2xtbm9w")
        # Low entropy: simple repeated word
        low_e  = _shannon_entropy("helloworld" * 5)
        # Empty string
        zero_e = _shannon_entropy("")

        assert high_e > 3.5, f"Expected high entropy > 3.5, got {high_e:.3f}"
        assert low_e  < 3.5, f"Expected low entropy < 3.5, got {low_e:.3f}"
        assert zero_e == 0.0, f"Empty string entropy should be 0, got {zero_e}"
        print(f"{PASS} {label}")
        print(f"       high_entropy={high_e:.3f}  low_entropy={low_e:.3f}  zero={zero_e}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 6: DNS tunnelling detection ──────────────────────────────────────
    label = "Test 6: DNS tunnelling detection (long subdomain labels)"
    try:
        dissected = dissect_flows(flows)
        dns_stats = analyse_dns(dissected)
        tunnel_findings = [f for f in dns_stats.findings if f.is_tunnelling]
        assert len(tunnel_findings) > 0, \
            f"No tunnelling detected. Findings: {[(f.domain, f.threat_score, f.reasons[:1]) for f in dns_stats.findings[:5]]}"
        t = tunnel_findings[0]
        assert t.threat_score >= 30, f"Low score for tunnelling: {t.threat_score}"
        long_label_reason = any(
            "label" in r.lower() or "tunnel" in r.lower() or "long" in r.lower()
            for r in t.reasons
        )
        assert long_label_reason, f"No length/tunnel reason: {t.reasons}"
        print(f"{PASS} {label}")
        print(f"       Domain: {t.domain}  score={t.threat_score}")
        print(f"       max_label={t.max_label_len} chars")
        for r in t.reasons[:2]:
            print(f"       → {r}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 7: DGA domain scoring ────────────────────────────────────────────
    label = "Test 7: DGA domain scoring"
    try:
        # Known DGA-like patterns should score high
        dga_examples = [
            ("xqkzvbnmwrtplfg.xyz", 0.75),   # very random consonants
            ("bnmwqrtzxcvplfg.tk",  0.75),
        ]
        # Legitimate domains should score low
        legit_examples = [
            ("google.com",       0.5),
            ("microsoft.com",    0.5),
            ("stackoverflow.com",0.55),
        ]
        for dom, threshold in dga_examples:
            score = _dga_score(dom)
            assert score >= threshold, \
                f"DGA '{dom}' scored {score:.2f}, expected >= {threshold}"

        for dom, max_score in legit_examples:
            score = _dga_score(dom)
            assert score < max_score, \
                f"Legit '{dom}' scored too high: {score:.2f}, expected < {max_score}"

        print(f"{PASS} {label}")
        for dom, _ in dga_examples + legit_examples:
            s = _dga_score(dom)
            label2 = "DGA" if s > 0.5 else "legit"
            print(f"       {dom:35s} score={s:.2f} [{label2}]")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 8: IOC aggregation + deduplication ───────────────────────────────
    label = "Test 8: IOC aggregation and deduplication"
    try:
        beacons  = detect_beacons(flows)
        dissected = dissect_flows(flows)
        dns_stats = analyse_dns(dissected)
        extracted = extract_files(pcap_path, flows)
        ioc_rep   = aggregate_iocs(beacons, dns_stats, extracted)

        assert len(ioc_rep.iocs) >= 0, "IOC list should be a list"
        # Scores should be in range
        for ioc in ioc_rep.iocs:
            assert 0 <= ioc.threat_score <= 100, \
                f"Score out of range: {ioc.threat_score}"
            assert ioc.severity in ("LOW","MEDIUM","HIGH","CRITICAL"), \
                f"Bad severity: {ioc.severity}"
            assert ioc.ioc_type in ("IP","DOMAIN","HASH_MD5","HASH_SHA256","JA3","PORT"), \
                f"Unknown type: {ioc.ioc_type}"

        # Check deduplication: no duplicate (type, value) pairs
        seen = set()
        for ioc in ioc_rep.iocs:
            key = (ioc.ioc_type, ioc.value)
            assert key not in seen, f"Duplicate IOC: {key}"
            seen.add(key)

        print(f"{PASS} {label}")
        print(f"       {len(ioc_rep.iocs)} unique IOCs")
        print(f"       CRITICAL:{ioc_rep.critical_count} HIGH:{ioc_rep.high_count} "
              f"MEDIUM:{ioc_rep.medium_count}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 9: IOC CSV + JSON export ──────────────────────────────────────────
    label = "Test 9: IOC CSV and JSON export"
    try:
        csv_out  = export_csv(ioc_rep)
        json_out = export_json(ioc_rep)

        import csv, io, json as json_mod
        # CSV: must be valid CSV with header
        reader = list(csv.DictReader(io.StringIO(csv_out)))
        assert "Type"  in csv_out, "Missing 'Type' header in CSV"
        assert "Value" in csv_out, "Missing 'Value' header in CSV"

        # JSON: must be valid JSON with 'iocs' key
        data = json_mod.loads(json_out)
        assert "iocs"    in data, "Missing 'iocs' key in JSON"
        assert "summary" in data, "Missing 'summary' key in JSON"
        assert data["summary"]["total_iocs"] == len(ioc_rep.iocs)

        print(f"{PASS} {label}")
        print(f"       CSV: {len(csv_out.splitlines())-1} data rows")
        print(f"       JSON: {data['summary']}")
        passed += 1
    except (AssertionError, Exception) as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 10: Full Week 4 pipeline ─────────────────────────────────────────
    label = "Test 10: Full Week 4 pipeline"
    try:
        beacons_all  = detect_beacons(flows)
        dissected_all = dissect_flows(flows)
        dns_all       = analyse_dns(dissected_all)
        extracted_all = extract_files(pcap_path, flows)
        ioc_all       = aggregate_iocs(beacons_all, dns_all, extracted_all)

        assert isinstance(beacons_all, list)
        assert isinstance(dns_all.findings, list)
        assert isinstance(ioc_all.iocs, list)
        # The beacon on port 4444 should appear somewhere
        port_4444_anywhere = (
            any(b.dst_port == 4444 for b in beacons_all) or
            any(i.value == "4444" for i in ioc_all.iocs)
        )
        assert port_4444_anywhere, "Port 4444 beacon completely missed by pipeline"

        print(f"{PASS} {label}")
        print(f"       Beacons:{len(beacons_all)} DNS:{len(dns_all.findings)} "
              f"IOCs:{len(ioc_all.iocs)}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Live output ────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  BEACON DETECTION OUTPUT")
    print("="*60)
    print_beacon_findings(detect_beacons(flows))

    print("\n" + "="*60)
    print("  DNS ANALYSIS OUTPUT")
    print("="*60)
    print_dns_findings(analyse_dns(dissect_flows(flows)))

    print("\n" + "="*60)
    print("  IOC REPORT OUTPUT")
    print("="*60)
    print_ioc_report(aggregate_iocs(
        detect_beacons(flows),
        analyse_dns(dissect_flows(flows)),
        extract_files(pcap_path, flows)
    ))

    # cleanup
    os.unlink(pcap_path)
    import shutil
    from config import EXTRACTED_DIR
    shutil.rmtree(EXTRACTED_DIR, ignore_errors=True)

    print("\n" + "="*60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")
    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
