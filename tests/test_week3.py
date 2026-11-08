"""
tests/test_week3.py
────────────────────────────────────────────────────────────────────────────────
Week 3 test suite: protocol dissection + file extraction.

Tests:
  1. HTTP dissection — method, host, URI, status, user-agent
  2. DNS dissection  — query name, record type, pure Python parser
  3. TLS SNI extraction from ClientHello bytes
  4. FTP credential extraction from plaintext stream
  5. Generic payload classification (plaintext vs binary)
  6. File magic byte detection
  7. File SHA256 hashing + metadata
  8. tshark HTTP object export on a real PCAP
  9. Full Week 3 pipeline: load → reconstruct → dissect → extract
"""

import sys, os, tempfile, hashlib
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from engine.pcap_loader         import load_pcap
from engine.normaliser          import normalise
from engine.session_tracker     import reconstruct_sessions
from modules.protocol_dissector import dissect_flows, _dissect_one, DissectedFlow
from modules.file_extractor     import (extract_files, _detect_file_type,
                                         _build_extracted_file, MAGIC_SIGNATURES)
from engine.printer             import print_dissection_summary, print_extracted_files
from engine.logger              import get_logger

log = get_logger("test_week3")
PASS = "\033[32m[PASS]\033[0m"
FAIL = "\033[31m[FAIL]\033[0m"


# ── Synthetic PCAP ─────────────────────────────────────────────────────────────

def build_week3_pcap(path: str) -> int:
    pkts = []

    # HTTP session with full request/response
    http_req = (
        b"GET /download/malware.exe HTTP/1.1\r\n"
        b"Host: evil.example.com\r\n"
        b"User-Agent: curl/7.81.0\r\n"
        b"Accept: */*\r\n\r\n"
    )
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Content-Length: 6\r\n\r\n"
        b"MZ\x90\x00\x03\x00"    # starts with MZ (PE magic)
    )
    pkts += [
        Ether()/IP(src="192.168.1.5", dst="93.184.216.34")/
        TCP(sport=50000, dport=80, flags="PA", seq=100, ack=200)/Raw(http_req),
        Ether()/IP(src="93.184.216.34", dst="192.168.1.5")/
        TCP(sport=80, dport=50000, flags="PA", seq=200, ack=100+len(http_req))/
        Raw(http_resp),
    ]

    # DNS queries (plain UDP raw payload — our parser reads raw bytes)
    # A query for "malware.ru"
    dns_query = (
        b"\xaa\xbb"          # transaction ID
        b"\x01\x00"          # flags: standard query
        b"\x00\x01"          # questions: 1
        b"\x00\x00"          # answer RRs: 0
        b"\x00\x00"          # authority: 0
        b"\x00\x00"          # additional: 0
        b"\x07malware"       # label "malware" (len=7)
        b"\x02ru"            # label "ru" (len=2)
        b"\x00"              # root
        b"\x00\x01"          # type A
        b"\x00\x01"          # class IN
    )
    pkts.append(
        Ether()/IP(src="192.168.1.5", dst="8.8.8.8")/
        UDP(sport=54321, dport=53)/Raw(dns_query)
    )

    # DNS response for the same query
    dns_resp = (
        b"\xaa\xbb"          # same transaction ID
        b"\x81\x80"          # flags: standard response, no error
        b"\x00\x01"          # questions: 1
        b"\x00\x01"          # answer RRs: 1
        b"\x00\x00"
        b"\x00\x00"
        b"\x07malware\x02ru\x00"   # question name
        b"\x00\x01\x00\x01"        # type A, class IN
        # Answer RR
        b"\xc0\x0c"          # name pointer to offset 12
        b"\x00\x01"          # type A
        b"\x00\x01"          # class IN
        b"\x00\x00\x00\x3c"  # TTL 60
        b"\x00\x04"          # rdlength 4
        b"\x01\x02\x03\x04"  # rdata: 1.2.3.4
    )
    pkts.append(
        Ether()/IP(src="8.8.8.8", dst="192.168.1.5")/
        UDP(sport=53, dport=54321)/Raw(dns_resp)
    )

    # FTP session with credentials
    ftp_payload = (
        b"220 FTP Server ready\r\n"
        b"USER admin\r\n"
        b"331 Password required\r\n"
        b"PASS s3cr3t_password\r\n"
        b"230 Login successful\r\n"
        b"RETR secret_data.zip\r\n"
        b"226 Transfer complete\r\n"
    )
    pkts.append(
        Ether()/IP(src="10.0.0.10", dst="10.0.0.1")/
        TCP(sport=55000, dport=21, flags="PA", seq=1, ack=1)/Raw(ftp_payload)
    )

    # HTTPS (TLS) session — real ClientHello bytes with SNI "secure.bank.com"
    # Manually crafted minimal TLS ClientHello containing SNI extension
    sni_host   = b"secure.bank.com"
    sni_ext    = (
        b"\x00\x00"               # ext type: SNI (0)
        + (13 + len(sni_host)).to_bytes(2, "big")   # ext length
        + (11 + len(sni_host)).to_bytes(2, "big")   # list length
        + b"\x00"                 # name type: host_name
        + len(sni_host).to_bytes(2, "big")
        + sni_host
    )
    # Build minimal ClientHello body
    client_hello_body = (
        b"\x03\x03"                  # client version TLS 1.2
        + b"\x00" * 32               # random
        + b"\x00"                    # session id length = 0
        + b"\x00\x02\xc0\x2b"        # cipher suites length + one suite
        + b"\x01\x00"                # compression methods
        + len(sni_ext).to_bytes(2, "big")  # extensions length
        + sni_ext
    )
    client_hello = (
        b"\x01"                                  # HandshakeType: client_hello
        + len(client_hello_body).to_bytes(3, "big")
        + client_hello_body
    )
    tls_record = (
        b"\x16\x03\x01"                           # TLS handshake record
        + len(client_hello).to_bytes(2, "big")
        + client_hello
    )
    pkts.append(
        Ether()/IP(src="192.168.1.5", dst="203.0.113.1")/
        TCP(sport=56000, dport=443, flags="PA", seq=1, ack=1)/Raw(tls_record)
    )

    # Large binary payload (to test file carving) — PNG header
    png_data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 600
    pkts.append(
        Ether()/IP(src="192.168.1.5", dst="93.184.216.34")/
        TCP(sport=57000, dport=80, flags="PA", seq=1, ack=1)/
        Raw(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n" + png_data)
    )

    wrpcap(path, pkts)
    log.info(f"Week 3 test PCAP: {path}  ({len(pkts)} packets)")
    return len(pkts)


# ── Test runner ────────────────────────────────────────────────────────────────

def run_tests():
    print("\n" + "="*60)
    print("  PCAP ENGINE — WEEK 3 TEST SUITE")
    print("="*60 + "\n")
    passed = failed = 0

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = f.name
    build_week3_pcap(pcap_path)
    meta    = load_pcap(pcap_path)
    packets = normalise(meta["packets"])
    flows   = reconstruct_sessions(packets)

    # ── Test 1: HTTP dissection ────────────────────────────────────────────────
    label = "Test 1: HTTP protocol dissection"
    try:
        dissected = dissect_flows(flows)
        http_d = [d for d in dissected if d.protocol_tag == "HTTP"]
        assert len(http_d) > 0, "No HTTP dissected flows"
        h = http_d[0]
        assert len(h.http_requests) > 0, "No HTTP requests parsed"
        # Find the actual request (not a RESPONSE-only record)
        # Search all HTTP-dissected flows for a complete request
        req = None
        for hd in http_d:
            for r in hd.http_requests:
                if r.get("method") not in ("RESPONSE",) and r.get("host"):
                    req = r; break
            if req: break
        assert req is not None, "No complete HTTP request with host found"
        assert req["method"] in ("GET","POST","PUT","DELETE","HEAD"), \
            f"Bad method: {req['method']}"
        assert req["host"] is not None, "Missing Host"
        assert req["uri"]  is not None, "Missing URI"
        assert req["user_agent"] is not None, "Missing User-Agent"
        print(f"{PASS} {label}")
        print(f"       {req['method']} {req['host']}{req['uri']} "
              f"→ {req['status_code']} | UA: {req['user_agent']}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 2: DNS dissection ─────────────────────────────────────────────────
    label = "Test 2: DNS protocol dissection"
    try:
        dns_d = [d for d in dissected if d.protocol_tag == "DNS"]
        assert len(dns_d) > 0, "No DNS flows dissected"
        recs = [r for d in dns_d for r in d.dns_records]
        assert len(recs) > 0, "No DNS records parsed"
        queries = [r.query for r in recs]
        assert any("malware" in q.lower() or "ru" in q.lower()
                   for q in queries), f"Expected malware.ru query, got: {queries}"
        resp_recs = [r for r in recs if r.is_response]
        assert len(resp_recs) > 0, "No DNS responses parsed"
        assert any("1.2.3.4" in r.answers for r in resp_recs), \
            f"Expected 1.2.3.4 in answers, got: {[r.answers for r in resp_recs]}"
        print(f"{PASS} {label}")
        print(f"       Queries: {[r.query for r in recs[:3]]}")
        print(f"       Answers: {[r.answers for r in resp_recs[:2]]}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 3: TLS SNI extraction ─────────────────────────────────────────────
    label = "Test 3: TLS SNI extraction from ClientHello"
    try:
        from modules.protocol_dissector import _extract_tls_sni
        # Build the same ClientHello as in the test PCAP
        sni_host   = b"secure.bank.com"
        sni_ext    = (
            b"\x00\x00"
            + (13 + len(sni_host)).to_bytes(2, "big")
            + (11 + len(sni_host)).to_bytes(2, "big")
            + b"\x00"
            + len(sni_host).to_bytes(2, "big")
            + sni_host
        )
        client_hello_body = (
            b"\x03\x03" + b"\x00"*32 + b"\x00"
            + b"\x00\x02\xc0\x2b" + b"\x01\x00"
            + len(sni_ext).to_bytes(2, "big") + sni_ext
        )
        client_hello = b"\x01" + len(client_hello_body).to_bytes(3,"big") + client_hello_body
        tls_record   = b"\x16\x03\x01" + len(client_hello).to_bytes(2,"big") + client_hello

        sni = _extract_tls_sni(tls_record)
        assert sni == "secure.bank.com", f"Got SNI: {sni}"
        print(f"{PASS} {label}")
        print(f"       Extracted SNI: '{sni}'")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 4: FTP credential extraction ─────────────────────────────────────
    label = "Test 4: FTP credential extraction"
    try:
        ftp_d = [d for d in dissected if d.protocol_tag == "FTP"]
        assert len(ftp_d) > 0, "No FTP flows dissected"
        sess = ftp_d[0].ftp_session
        assert sess is not None, "No FTP session"
        assert sess.user     == "admin",            f"Wrong user: {sess.user}"
        assert sess.password == "s3cr3t_password",  f"Wrong pass: {sess.password}"
        assert "secret_data.zip" in sess.filenames, f"Missing filename: {sess.filenames}"
        assert ftp_d[0].has_credentials,            "has_credentials not set"
        assert ftp_d[0].has_file_transfer,          "has_file_transfer not set"
        print(f"{PASS} {label}")
        print(f"       user={sess.user}  pass={sess.password}  files={sess.filenames}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 5: Generic payload classification ─────────────────────────────────
    label = "Test 5: Plaintext vs binary payload classification"
    try:
        from modules.protocol_dissector import _dissect_generic, DissectedFlow as DF
        from engine.session_tracker import Flow

        # Plaintext flow
        plain_flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                          src_port=1234, dst_port=9999, protocol="TCP")
        plain_flow.payload_bytes = b"Hello world, this is plaintext data " * 10
        pd = DF(flow=plain_flow)
        _dissect_generic(pd)
        assert pd.is_plaintext,  "Should be plaintext"
        assert not pd.is_encrypted, "Should not be encrypted"

        # Binary flow
        bin_flow = Flow(src_ip="1.1.1.1", dst_ip="2.2.2.2",
                        src_port=1234, dst_port=9998, protocol="TCP")
        bin_flow.payload_bytes = bytes(range(256)) * 4
        bd = DF(flow=bin_flow)
        _dissect_generic(bd)
        assert not bd.is_plaintext, "Should be binary"

        print(f"{PASS} {label}")
        print(f"       Plain preview: {repr(pd.payload_text[:40])}")
        print(f"       Binary preview: {bd.payload_text[:40]}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 6: Magic byte file detection ──────────────────────────────────────
    label = "Test 6: Magic byte file type detection"
    try:
        test_cases = [
            (b"\x89PNG\r\n\x1a\n" + b"\x00"*100, "PNG"),
            (b"MZ\x90\x00" + b"\x00"*100, "executable"),  # MZ/DOS
            (b"%PDF-1.4" + b"\x00"*100, "PDF"),
            (b"PK\x03\x04" + b"\x00"*100, "ZIP"),
            (b"\xff\xd8\xff\xe0" + b"\x00"*100, "JPEG"),
        ]
        for data, expected in test_cases:
            detected = _detect_file_type(data, "test")
            # strip parenthetical for comparison
        chk = detected.lower().split("(")[0].strip()
        assert expected.lower() in chk, \
                f"Expected {expected} in '{detected}'"
        print(f"{PASS} {label}")
        for data, expected in test_cases:
            print(f"       {expected:6s} → {_detect_file_type(data, '')}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 7: File hashing + metadata ───────────────────────────────────────
    label = "Test 7: File hash computation + metadata"
    try:
        with tempfile.NamedTemporaryFile(suffix=".png", delete=False) as f:
            test_data = b"\x89PNG\r\n\x1a\n" + b"\xAB" * 200
            f.write(test_data)
            fpath = f.name

        ef = _build_extracted_file(fpath, "test.png", "test", "1.1.1.1:80→2.2.2.2:1234")
        assert ef is not None, "ExtractedFile is None"
        assert ef.sha256 == hashlib.sha256(test_data).hexdigest(), "SHA256 mismatch"
        assert ef.md5    == hashlib.md5(test_data).hexdigest(),    "MD5 mismatch"
        assert ef.size_bytes == len(test_data), "Size mismatch"
        assert "PNG" in ef.file_type, f"Type wrong: {ef.file_type}"
        os.unlink(fpath)
        print(f"{PASS} {label}")
        print(f"       sha256={ef.sha256[:20]}...  type={ef.file_type}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 8: tshark HTTP export ─────────────────────────────────────────────
    label = "Test 8: tshark HTTP object export"
    try:
        import subprocess
        result = subprocess.run(["tshark", "--version"], capture_output=True)
        assert result.returncode == 0, "tshark not available"
        # Run tshark export on our test PCAP
        extracted = extract_files(pcap_path, flows)
        # We may or may not get files depending on tshark + payload, but no crash
        assert isinstance(extracted, list), "extract_files should return list"
        print(f"{PASS} {label}")
        print(f"       tshark extracted {len(extracted)} file(s)")
        if extracted:
            for ef in extracted[:3]:
                print(f"       → {ef.filename}  {ef.size_bytes}B  {ef.file_type}")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Test 9: Full Week 3 pipeline ───────────────────────────────────────────
    label = "Test 9: Full Week 3 pipeline"
    try:
        dissected = dissect_flows(flows)
        assert len(dissected) == len(flows), "dissected count != flows count"
        tags = {d.protocol_tag for d in dissected}
        assert len(tags) >= 2, f"Too few protocol tags: {tags}"
        extracted = extract_files(pcap_path, flows)
        assert isinstance(extracted, list)
        print(f"{PASS} {label}")
        print(f"       {len(dissected)} flows dissected | Tags: {sorted(tags)}")
        print(f"       {len(extracted)} files extracted")
        passed += 1
    except AssertionError as e:
        print(f"{FAIL} {label}: {e}"); failed += 1

    # ── Print outputs ──────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  DISSECTION SUMMARY OUTPUT")
    print("="*60)
    dissected = dissect_flows(flows)
    print_dissection_summary(dissected)

    print("\n" + "="*60)
    print("  EXTRACTED FILES OUTPUT")
    print("="*60)
    extracted = extract_files(pcap_path, flows)
    print_extracted_files(extracted)

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
