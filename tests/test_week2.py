"""
tests/test_week2.py
────────────────────────────────────────────────────────────────────────────────
Week 2 test suite: session reconstruction + SQLite storage.

Tests:
  1. Flow grouping — correct 5-tuple extraction
  2. TCP stream reassembly — payloads joined in seq order
  3. HTTP session parsing — method, host, URI, status code
  4. Database schema creation
  5. Flow persistence — insert + query
  6. HTTP session persistence
  7. Full end-to-end pipeline (load → normalise → reconstruct → store → query)
"""

import sys, os, tempfile, sqlite3
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from engine.pcap_loader     import load_pcap
from engine.normaliser      import normalise
from engine.session_tracker import reconstruct_sessions, Flow
from engine.database        import init_db, insert_pcap_file, insert_flow, get_stats
from engine.flow_store      import store_flows
from engine.printer         import print_sessions, print_http_sessions
from engine.logger          import get_logger

log = get_logger("test_week2")

PASS = "\033[32m[PASS]\033[0m"
FAIL = "\033[31m[FAIL]\033[0m"


# ── Synthetic PCAP builder ─────────────────────────────────────────────────────

def build_week2_pcap(path: str) -> int:
    """
    Build a PCAP with:
      - Full HTTP TCP session (3-way handshake + GET + 200 response)
      - HTTPS session (port 443)
      - DNS UDP queries
      - ICMP pings
      - Large data transfer (TCP, non-HTTP port 4444)
      - TCP SYN scan
    """
    pkts = []
    seq_c, seq_s = 1000, 5000   # client/server seq numbers

    # ── HTTP session: client 192.168.1.10 → server 93.184.216.34:80 ──────────
    # 3-way handshake
    pkts += [
        Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/
        TCP(sport=50100, dport=80, flags="S",  seq=seq_c),

        Ether()/IP(src="93.184.216.34", dst="192.168.1.10")/
        TCP(sport=80, dport=50100, flags="SA", seq=seq_s, ack=seq_c+1),

        Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/
        TCP(sport=50100, dport=80, flags="A",  seq=seq_c+1, ack=seq_s+1),
    ]

    http_req = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0 (Windows NT 10.0)\r\n"
        b"Accept: text/html\r\n\r\n"
    )
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Content-Length: 13\r\n\r\n"
        b"Hello, World!"
    )

    pkts += [
        Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/
        TCP(sport=50100, dport=80, flags="PA", seq=seq_c+1, ack=seq_s+1)/
        Raw(http_req),

        Ether()/IP(src="93.184.216.34", dst="192.168.1.10")/
        TCP(sport=80, dport=50100, flags="PA", seq=seq_s+1, ack=seq_c+1+len(http_req))/
        Raw(http_resp),

        Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/
        TCP(sport=50100, dport=80, flags="FA", seq=seq_c+1+len(http_req),
            ack=seq_s+1+len(http_resp)),
    ]

    # Second HTTP GET on same session
    http_req2  = b"GET /page2.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    http_resp2 = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"
    pkts += [
        Ether()/IP(src="192.168.1.10", dst="93.184.216.34")/
        TCP(sport=50101, dport=80, flags="PA", seq=2000, ack=6000)/Raw(http_req2),
        Ether()/IP(src="93.184.216.34", dst="192.168.1.10")/
        TCP(sport=80, dport=50101, flags="PA", seq=6000, ack=2000+len(http_req2))/
        Raw(http_resp2),
    ]

    # ── HTTPS session ──────────────────────────────────────────────────────────
    for i in range(6):
        pkts.append(
            Ether()/IP(src="192.168.1.10", dst="8.8.4.4")/
            TCP(sport=50200+i, dport=443, flags="PA")/
            Raw(b"\x16\x03\x03" + b"\x00"*40)
        )

    # ── DNS UDP ────────────────────────────────────────────────────────────────
    for domain in [b"google.com", b"amazon.com", b"github.com"]:
        pkts.append(
            Ether()/IP(src="192.168.1.10", dst="8.8.8.8")/
            UDP(sport=12000, dport=53)/Raw(domain)
        )

    # ── ICMP ping ──────────────────────────────────────────────────────────────
    pkts += [
        Ether()/IP(src="192.168.1.10", dst="1.1.1.1")/ICMP(),
        Ether()/IP(src="1.1.1.1",      dst="192.168.1.10")/ICMP(type=0),
    ]

    # ── Large data transfer (port 4444 — Meterpreter indicator) ───────────────
    large = b"A" * 50000
    for offset in range(0, len(large), 1460):
        chunk = large[offset:offset+1460]
        pkts.append(
            Ether()/IP(src="192.168.1.10", dst="45.33.32.156")/
            TCP(sport=54321, dport=4444, flags="PA", seq=3000+offset)/
            Raw(chunk)
        )

    # ── TCP SYN scan ──────────────────────────────────────────────────────────
    for port in [21, 22, 23, 25, 3389]:
        pkts.append(
            Ether()/IP(src="10.0.0.99", dst="192.168.1.10")/
            TCP(sport=65000, dport=port, flags="S")
        )

    wrpcap(path, pkts)
    log.info(f"Week 2 test PCAP: {path}  ({len(pkts)} packets)")
    return len(pkts)


# ── Tests ──────────────────────────────────────────────────────────────────────

def run_tests():
    print("\n" + "="*60)
    print("  PCAP ENGINE — WEEK 2 TEST SUITE")
    print("="*60 + "\n")

    passed = failed = 0

    # ── Build test PCAP ────────────────────────────────────────────────────────
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name
    with tempfile.NamedTemporaryFile(suffix=".db",   delete=False) as f:
        db_path   = f.name

    build_week2_pcap(pcap_path)
    meta    = load_pcap(pcap_path)
    packets = normalise(meta["packets"])

    # ── Test 1: Flow grouping ──────────────────────────────────────────────────
    label = "Test 1: Flow grouping (5-tuple extraction)"
    try:
        flows = reconstruct_sessions(packets)
        assert len(flows) > 0, "No flows reconstructed"
        protos = {f.protocol for f in flows}
        assert "TCP" in protos, "No TCP flows"
        assert "UDP" in protos, "No UDP flows"
        # Check port 80 flow exists
        http_flows = [f for f in flows if f.dst_port == 80 or f.src_port == 80]
        assert len(http_flows) > 0, "No port-80 flow found"
        # Check large data flow exists
        large_flows = [f for f in flows if f.byte_count > 40_000]
        assert len(large_flows) > 0, "Large transfer flow missing"
        print(f"{PASS} {label}")
        print(f"       {len(flows)} flows | Protocols: {protos}")
        print(f"       Largest flow: {large_flows[0].five_tuple} "
              f"({large_flows[0].byte_count:,} bytes)")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 2: TCP stream reassembly ──────────────────────────────────────────
    label = "Test 2: TCP stream reassembly"
    try:
        http80 = next((f for f in flows
                       if (f.dst_port == 80 or f.src_port == 80)
                       and f.payload_bytes), None)
        assert http80 is not None, "No HTTP flow with payload"
        assert len(http80.payload_bytes) > 50, "Payload too small"
        payload_str = http80.payload_bytes.decode("latin-1", errors="replace")
        assert "HTTP" in payload_str, "HTTP not found in reassembled stream"
        print(f"{PASS} {label}")
        print(f"       Reassembled {len(http80.payload_bytes)} bytes, "
              f"preview: {repr(payload_str[:60])}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 3: HTTP session parsing ───────────────────────────────────────────
    label = "Test 3: HTTP session parsing"
    try:
        all_http = [f for f in flows if f.http_sessions]
        assert len(all_http) > 0, "No HTTP sessions parsed"
        session = all_http[0].http_sessions[0]
        assert session.method in ("GET","POST","PUT","DELETE","HEAD"), \
            f"Bad method: {session.method}"
        assert session.host is not None, "Missing Host header"
        assert session.uri  is not None, "Missing URI"
        assert session.status_code in (200, 404, 301, 302, 500, None), \
            f"Unexpected status: {session.status_code}"
        print(f"{PASS} {label}")
        print(f"       {session.method} {session.host}{session.uri} "
              f"→ HTTP {session.status_code}")
        print(f"       User-Agent: {session.user_agent}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 4: Database schema ────────────────────────────────────────────────
    label = "Test 4: Database schema creation"
    try:
        conn = init_db(db_path)
        tables = {row[0] for row in
                  conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        for t in ("pcap_files", "flows", "packets", "http_sessions"):
            assert t in tables, f"Missing table: {t}"
        print(f"{PASS} {label}")
        print(f"       Tables: {sorted(tables)}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 5: Flow persistence ───────────────────────────────────────────────
    label = "Test 5: Flow persistence (insert + query)"
    try:
        from engine.packet_stats import generate_stats
        stats   = generate_stats(packets, meta)
        pcap_id = insert_pcap_file(conn, meta, stats)
        assert pcap_id > 0, "Bad pcap_id"

        stored = store_flows(conn, flows, pcap_id)
        assert stored == len(flows), f"stored {stored} != {len(flows)}"

        db_flows = conn.execute(
            "SELECT COUNT(*) FROM flows WHERE pcap_id=?", (pcap_id,)
        ).fetchone()[0]
        assert db_flows == len(flows), f"DB flows {db_flows} != {len(flows)}"

        db_pkts = conn.execute(
            "SELECT COUNT(*) FROM packets WHERE pcap_id=?", (pcap_id,)
        ).fetchone()[0]
        assert db_pkts > 0, "No packets stored"

        print(f"{PASS} {label}")
        print(f"       Stored {db_flows} flows, {db_pkts} packets")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 6: HTTP session persistence ──────────────────────────────────────
    label = "Test 6: HTTP session persistence"
    try:
        db_http = conn.execute(
            "SELECT COUNT(*) FROM http_sessions WHERE pcap_id=?", (pcap_id,)
        ).fetchone()[0]
        assert db_http > 0, "No HTTP sessions in DB"

        row = conn.execute(
            "SELECT method, host, uri, status_code FROM http_sessions LIMIT 1"
        ).fetchone()
        assert row["method"] is not None, "NULL method in DB"
        assert row["host"]   is not None, "NULL host in DB"
        print(f"{PASS} {label}")
        print(f"       {db_http} HTTP sessions stored")
        print(f"       Sample: {row['method']} {row['host']}{row['uri']} → {row['status_code']}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 7: DB stats query ─────────────────────────────────────────────────
    label = "Test 7: Database stats summary"
    try:
        summary = get_stats(conn)
        assert summary["flows"]   > 0, "Zero flows in stats"
        assert summary["packets"] > 0, "Zero packets in stats"
        assert summary["total_bytes"] > 0, "Zero bytes in stats"
        print(f"{PASS} {label}")
        print(f"       {summary}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    conn.close()

    # ── Print session + HTTP tables ────────────────────────────────────────────
    print("\n" + "="*60)
    print("  SESSION TABLE OUTPUT (top 15 flows)")
    print("="*60)
    print_sessions(flows[:15])

    print("\n" + "="*60)
    print("  HTTP SESSIONS OUTPUT")
    print("="*60)
    http_flows = [f for f in flows if f.http_sessions]
    print_http_sessions(http_flows)

    # ── Cleanup ────────────────────────────────────────────────────────────────
    os.unlink(pcap_path)
    os.unlink(db_path)

    print("\n" + "="*60)
    print(f"  Results: {passed} passed, {failed} failed")
    print("="*60 + "\n")

    return failed == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
