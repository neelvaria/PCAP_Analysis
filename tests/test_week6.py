import time
"""tests/test_week6.py — Week 6 PDF Report Generator Tests"""
import sys, os, io, tempfile, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap
from engine.pcap_loader import load_pcap
from engine.normaliser import normalise
from engine.packet_stats import generate_stats
from engine.session_tracker import reconstruct_sessions
from modules.protocol_dissector import dissect_flows
from modules.file_extractor import extract_files
from modules.beacon_detector import detect_beacons
from modules.dns_analyser import analyse_dns
from modules.ioc_aggregator import aggregate_iocs
from reports.pdf_generator import generate_report
from engine.logger import get_logger
log = get_logger("test_week6")
PASS = "\033[32m[PASS]\033[0m"; FAIL = "\033[31m[FAIL]\033[0m"


def build_pcap(path):
    pkts = []; base = 1700000000.0
    for i in range(12):
        p = Ether()/IP(src="192.168.1.5",dst="45.33.32.1")/TCP(sport=55000,dport=4444,flags="PA",seq=100+i*100)/Raw(b"\x00"*64)
        p.time = base + i*30.0; pkts.append(p)
    http_req = b"GET /evil.exe HTTP/1.1\r\nHost: evil.com\r\nUser-Agent: TestAgent\r\n\r\n"
    http_resp= b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nMZ\x90\x00"
    pkts.append(Ether()/IP(src="192.168.1.5",dst="1.2.3.4")/TCP(sport=50000,dport=80,flags="PA",seq=1,ack=1)/Raw(http_req))
    pkts.append(Ether()/IP(src="1.2.3.4",dst="192.168.1.5")/TCP(sport=80,dport=50000,flags="PA",seq=1,ack=len(http_req)+1)/Raw(http_resp))
    wrpcap(path, pkts)


def run_pipeline(pcap_path):
    meta=load_pcap(pcap_path); pkts=normalise(meta["packets"])
    stats=generate_stats(pkts,meta); flows=reconstruct_sessions(pkts)
    dis=dissect_flows(flows); ext=extract_files(pcap_path,flows)
    bea=detect_beacons(flows); dns=analyse_dns(dis); ioc=aggregate_iocs(bea,dns,ext)
    return {"meta":meta,"stats":stats,"flows":flows,"beacons":bea,"dns_stats":dns,
            "ioc_report":ioc,"extracted_files":ext,
            "case_info":{"case_number":"CASE-2025-TEST","analyst_name":"Test Analyst","organisation":"NFSU"}}


def run_tests():
    print("\n"+"="*60+"\n  PCAP ENGINE — WEEK 6 TEST SUITE\n"+"="*60+"\n")
    passed=failed=0

    with tempfile.NamedTemporaryFile(suffix=".pcap",delete=False) as f: pcap_path=f.name
    with tempfile.TemporaryDirectory() as rdir:
        build_pcap(pcap_path)
        data=run_pipeline(pcap_path)

        def chk(label, ok, detail=""):
            nonlocal passed, failed
            if ok: print(f"{PASS} {label}"); passed+=1
            else:  print(f"{FAIL} {label}: {detail}"); failed+=1

        # T1: PDF created
        pdf=None
        try:
            pdf=generate_report(data,output_dir=rdir)
            sz=os.path.getsize(pdf)
            chk("Test 1: PDF created and sized", sz>8000, f"size={sz}")
            print(f"       {os.path.basename(pdf)}  {sz:,}B")
        except Exception as e: chk("Test 1: PDF created", False, str(e))

        # T2: Valid PDF header
        try:
            with open(pdf,"rb") as f: hdr=f.read(8)
            chk("Test 2: Valid PDF header", hdr.startswith(b"%PDF"), f"header={hdr}")
            print(f"       Header: {hdr[:8]}")
        except Exception as e: chk("Test 2: Valid PDF header",False,str(e))

        # T3: PDF has EOF marker
        try:
            with open(pdf,"rb") as f: content=f.read()
            ok=b"%%EOF" in content or b"%EOF" in content
            chk("Test 3: PDF EOF marker present", ok, "missing %%EOF")
            print(f"       Content: {len(content):,} bytes")
        except Exception as e: chk("Test 3: PDF EOF",False,str(e))

        # T4: Minimal data (no findings)
        try:
            min_data={"meta":{"filename":"min.pcap","sha256":"a"*64,"file_size":0,"path":"/tmp/x"},
                      "stats":{"totals":{"packets":1,"bytes":1},"capture":{"first_packet":None,"last_packet":None,"duration_human":"0s","duration_seconds":0},"protocols":{},"top_src_ips":[],"top_dst_ports":[],"unique_ips":{"total_unique":0,"internal":[],"external":[]}},
                      "flows":[],"beacons":[],"dns_stats":None,"ioc_report":None,"extracted_files":[],
                      "case_info":{"case_number":"MIN-001","analyst_name":"Analyst","organisation":"Org"}}
            mp=generate_report(min_data,output_dir=rdir)
            chk("Test 4: Minimal data PDF", os.path.getsize(mp)>3000)
            print(f"       Minimal: {os.path.getsize(mp):,}B")
        except Exception as e: chk("Test 4: Minimal data",False,str(e))

        # T5: Case info in data
        chk("Test 5: Case info in report data",
            data["case_info"]["case_number"]=="CASE-2025-TEST" and
            data["case_info"]["analyst_name"]=="Test Analyst")
        print(f"       case={data['case_info']['case_number']} analyst={data['case_info']['analyst_name']}")

        # T6: Beacons present
        try:
            b=data["beacons"]
            chk("Test 6: Beacons in report data", len(b)>0 and b[0].threat_score>0)
            print(f"       {len(b)} beacon(s), score={b[0].threat_score}")
        except Exception as e: chk("Test 6",False,str(e))

        # T7: IOC report
        try:
            ioc=data["ioc_report"]
            chk("Test 7: IOC report in data", ioc is not None and len(ioc.iocs)>0)
            print(f"       {len(ioc.iocs)} IOC(s) CRIT:{ioc.critical_count}")
        except Exception as e: chk("Test 7",False,str(e))

        # T8: Unique filenames
        try:
            p1=generate_report(data,output_dir=rdir); time.sleep(1.1)
            p2=generate_report(data,output_dir=rdir)
            chk("Test 8: Unique PDF filenames per run", p1!=p2)
            print(f"       {os.path.basename(p1)}  ≠  {os.path.basename(p2)}")
        except Exception as e: chk("Test 8",False,str(e))

        # T9: Flask PDF endpoint
        try:
            from web.app import create_app
            from engine.case_manager import list_cases
            app=create_app(); client=app.test_client()
            with app.app_context():
                with open(pcap_path,"rb") as f:
                    pcap_bytes = f.read()
                r=client.post("/upload",
                    data={"pcap":(io.BytesIO(pcap_bytes),"t6.pcap","application/octet-stream"),
                          "case_number":f"TEST6-PDF-{int(time.time())}"},
                    content_type="multipart/form-data",follow_redirects=False)
                # Extract analysis_id from redirect URL /analysis/<uuid>
                location = r.headers.get("Location","")
                aid = location.strip("/").split("/")[-1]
                rp = client.get(f"/export/report.pdf?analysis_id={aid}")
                chk("Test 9: Flask /export/report.pdf",
                    rp.status_code==200 and "pdf" in rp.content_type and len(rp.data)>5000,
                    f"status={rp.status_code} len={len(rp.data)}")
                print(f"       {rp.status_code}  {rp.content_type}  {len(rp.data):,}B")
        except Exception as e: chk("Test 9",False,str(e))

        # T10: Output naming
        try:
            pdfs=[f for f in os.listdir(rdir) if f.endswith(".pdf")]
            chk("Test 10: All PDFs have correct naming",
                len(pdfs)>=2 and all(f.startswith("forensic_report_") for f in pdfs))
            print(f"       {len(pdfs)} PDFs in output dir")
            for fn in pdfs: print(f"       {fn}  {os.path.getsize(os.path.join(rdir,fn)):,}B")
        except Exception as e: chk("Test 10",False,str(e))

    os.unlink(pcap_path)
    print(f"\n{'='*60}\n  Results: {passed} passed, {failed} failed\n{'='*60}\n")
    return failed==0


if __name__=="__main__":
    sys.exit(0 if run_tests() else 1)
