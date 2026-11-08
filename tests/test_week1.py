"""
tests/test_week1.py
────────────────────────────────────────────────────────────────────────────────
Week 1 test suite.
  1. Generates a synthetic PCAP with known traffic patterns
  2. Runs the full Week 1 pipeline
  3. Validates all outputs

Run with:  python tests/test_week1.py
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from scapy.volatile import RandShort
try:
    from scapy.layers.dns import DNS, DNSQR
except Exception:
    DNS = DNSQR = None
from engine.pcap_loader  import load_pcap
from engine.normaliser   import normalise, get_protocol_summary
from engine.packet_stats import generate_stats
from engine.printer      import print_full_report
from engine.logger       import get_logger

log = get_logger("test_week1")


# ── Synthetic PCAP builder ─────────────────────────────────────────────────────

def build_test_pcap(path: str):
    """
    Build a realistic synthetic PCAP with:
      - HTTP GET request + response
      - DNS queries (normal + suspicious long subdomain)
      - ICMP ping
      - TCP SYN scan (common attacker recon)
      - Large data transfer (possible exfiltration)
    """
    pkts = []

    # ── HTTP session (client 192.168.1.100 → server 93.184.216.34:80) ────────
    pkts += [
        Ether() / IP(src="192.168.1.100", dst="93.184.216.34") /
        TCP(sport=49201, dport=80, flags="S", seq=1000),

        Ether() / IP(src="93.184.216.34", dst="192.168.1.100") /
        TCP(sport=80, dport=49201, flags="SA", seq=2000, ack=1001),

        Ether() / IP(src="192.168.1.100", dst="93.184.216.34") /
        TCP(sport=49201, dport=80, flags="A", seq=1001, ack=2001),

        Ether() / IP(src="192.168.1.100", dst="93.184.216.34") /
        TCP(sport=49201, dport=80, flags="PA", seq=1001, ack=2001) /
        Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"),

        Ether() / IP(src="93.184.216.34", dst="192.168.1.100") /
        TCP(sport=80, dport=49201, flags="PA", seq=2001, ack=1082) /
        Raw(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Hello</html>"),

        Ether() / IP(src="192.168.1.100", dst="93.184.216.34") /
        TCP(sport=49201, dport=80, flags="FA", seq=1082, ack=2065),
    ]

    # ── HTTPS session (port 443) ───────────────────────────────────────────────
    for i in range(8):
        pkts.append(
            Ether() / IP(src="192.168.1.100", dst="8.8.4.4") /
            TCP(sport=50000+i, dport=443, flags="PA") /
            Raw(b"\x16\x03\x01" + b"\x00" * 50)   # fake TLS record
        )

    # ── Normal DNS queries ─────────────────────────────────────────────────────
    for domain in [b"google.com.", b"microsoft.com.", b"github.com."]:
        pkts.append(
            Ether() / IP(src="192.168.1.100", dst="8.8.8.8") /
            UDP(sport=12345, dport=53) /
            DNS(rd=1, qd=DNSQR(qname=domain))
        )

    # ── Suspicious long subdomain (DNS tunnelling indicator) ──────────────────
    long_sub = b"aGVsbG8td29ybGQtdGhpcy1pcy1hLXZlcnktbG9uZy1zdWJkb21haW4.evil.com."
    pkts.append(
        Ether() / IP(src="192.168.1.100", dst="8.8.8.8") /
        UDP(sport=12399, dport=53) /
        DNS(rd=1, qd=DNSQR(qname=long_sub))
    )

    # ── ICMP ping ─────────────────────────────────────────────────────────────
    for dst in ["8.8.8.8", "1.1.1.1"]:
        pkts.append(Ether() / IP(src="192.168.1.100", dst=dst) / ICMP())
        pkts.append(Ether() / IP(src=dst, dst="192.168.1.100") / ICMP(type=0))

    # ── TCP SYN scan (attacker recon pattern) ─────────────────────────────────
    for port in [22, 23, 80, 443, 445, 3389, 8080]:
        pkts.append(
            Ether() / IP(src="10.0.0.5", dst="192.168.1.100") /
            TCP(sport=int(RandShort()), dport=port, flags="S")
        )

    # ── Large data upload (possible exfiltration) ─────────────────────────────
    large_payload = b"X" * 60000
    for chunk_start in range(0, len(large_payload), 1460):
        chunk = large_payload[chunk_start:chunk_start+1460]
        pkts.append(
            Ether() / IP(src="192.168.1.100", dst="45.33.32.156") /
            TCP(sport=54321, dport=4444, flags="PA") /
            Raw(chunk)
        )

    wrpcap(path, pkts)
    log.info(f"Test PCAP written: {path}  ({len(pkts)} packets)")
    return len(pkts)


# ── Test runner ────────────────────────────────────────────────────────────────

def run_tests():
    print("\n" + "="*60)
    print("  PCAP ENGINE — WEEK 1 TEST SUITE")
    print("="*60 + "\n")

    passed = 0
    failed = 0

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name

    total_built = build_test_pcap(pcap_path)

    # ── Test 1: PCAP loading ───────────────────────────────────────────────────
    print("Test 1: PCAP loader")
    meta = load_pcap(pcap_path)
    assert meta["error"] is None,         f"Load error: {meta['error']}"
    assert meta["sha256"] is not None,    "SHA-256 missing"
    assert meta["packet_count"] > 0,      "No packets loaded"
    assert len(meta["sha256"]) == 64,     "SHA-256 wrong length"
    print(f"  [PASS] Loaded {meta['packet_count']} packets, SHA-256: {meta['sha256'][:16]}...")
    passed += 1

    # ── Test 2: Normalisation ─────────────────────────────────────────────────
    print("Test 2: Normaliser")
    packets = normalise(meta["packets"])
    assert len(packets) > 0,              "No packets after normalisation"
    proto_summary = get_protocol_summary(packets)
    assert "TCP" in proto_summary,        "No TCP packets found"
    assert "UDP" in proto_summary,        "No UDP packets found"
    assert "ICMP" in proto_summary,       "No ICMP packets found"
    assert all(p.timestamp is not None for p in packets), "Missing timestamps"
    print(f"  [PASS] {len(packets)} normalised | Protocols: {proto_summary}")
    passed += 1

    # ── Test 3: Stats generation ───────────────────────────────────────────────
    print("Test 3: Stats generation")
    stats = generate_stats(packets, meta)
    assert "totals"    in stats,          "Missing totals"
    assert "protocols" in stats,          "Missing protocols"
    assert "top_src_ips" in stats,        "Missing top_src_ips"
    assert "top_dst_ports" in stats,      "Missing top_dst_ports"
    assert "timeline"  in stats,          "Missing timeline"
    assert stats["totals"]["packets"] == len(packets), "Packet count mismatch"
    assert stats["totals"]["bytes"]   > 0,             "Zero bytes"
    assert stats["capture"]["duration_seconds"] >= 0,  "Negative duration"
    print(f"  [PASS] Stats: {stats['totals']['packets']} pkts, "
          f"{stats['totals']['bytes']} bytes, "
          f"{len(stats['protocols'])} protocols")
    passed += 1

    # ── Test 4: IP detection ───────────────────────────────────────────────────
    print("Test 4: IP & port extraction")
    src_ips = {e["ip"] for e in stats["top_src_ips"]}
    assert "192.168.1.100" in src_ips,    "Expected internal IP not found"
    port_list = [p["port"] for p in stats["top_dst_ports"]]
    assert 80  in port_list or 443 in port_list or 53 in port_list, \
        "Expected well-known ports not detected"
    print(f"  [PASS] Detected IPs: {sorted(src_ips)[:3]}... Ports: {port_list[:5]}")
    passed += 1

    # ── Test 5: Timeline ──────────────────────────────────────────────────────
    print("Test 5: Timeline generation")
    tl = stats["timeline"]
    assert len(tl) > 0,                   "Empty timeline"
    assert all("time" in b for b in tl),  "Timeline missing time field"
    assert sum(b["packets"] for b in tl) == stats["totals"]["packets"], \
        "Timeline packet count != total"
    print(f"  [PASS] Timeline: {len(tl)} buckets, "
          f"total packets: {sum(b['packets'] for b in tl)}")
    passed += 1

    # ── Full print ─────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  FULL REPORT OUTPUT")
    print("="*60)
    print_full_report(stats)

    # ── Summary ────────────────────────────────────────────────────────────────
    print("="*60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")

    # cleanup
    import os as _os
    _os.unlink(pcap_path)

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
