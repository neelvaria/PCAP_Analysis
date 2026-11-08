"""
engine/printer.py
────────────────────────────────────────────────────────────────────────────────
Console output formatter for the PCAP engine.
Prints beautiful coloured tables to the terminal using tabulate + colorama.
"""

from tabulate import tabulate
from colorama import Fore, Style, init

init(autoreset=True)


def print_banner():
    banner = r"""
  ____   ____    _    ____     _____
 |  _ \ / ___|  / \  |  _ \   | ____|_ __   __ _(_)_ __   ___
 | |_) | |     / _ \ | |_) |  |  _| | '_ \ / _` | | '_ \ / _ \
 |  __/| |___ / ___ \|  __/   | |___| | | | (_| | | | | |  __/
 |_|    \____/_/   \_\_|       |_____|_| |_|\__, |_|_| |_|\___|
                                            |___/
  PCAP Session Reconstruction Engine  v1.0  — Week 1
"""
    print(Fore.CYAN + banner + Style.RESET_ALL)


def print_file_info(stats: dict):
    f = stats["file"]
    c = stats["capture"]
    t = stats["totals"]

    print(Fore.CYAN + "\n─── File Info ────────────────────────────────────────────────" + Style.RESET_ALL)
    rows = [
        ["Filename",   f["name"]],
        ["SHA-256",    f["sha256"][:32] + "..."],
        ["File size",  _fmt_bytes(f["size_bytes"])],
        ["First pkt",  c["first_packet"] or "N/A"],
        ["Last pkt",   c["last_packet"]  or "N/A"],
        ["Duration",   c["duration_human"]],
        ["Packets",    f"{t['packets']:,}"],
        ["Total bytes",_fmt_bytes(t["bytes"])],
    ]
    print(tabulate(rows, tablefmt="simple"))


def print_protocol_breakdown(stats: dict):
    print(Fore.CYAN + "\n─── Protocol Breakdown ───────────────────────────────────────" + Style.RESET_ALL)
    protos = stats["protocols"]
    rows = []
    for proto, data in protos.items():
        bar = _bar(data["percent"], 20)
        rows.append([
            proto,
            f"{data['count']:,}",
            f"{data['percent']}%",
            _fmt_bytes(data["bytes"]),
            bar,
        ])
    print(tabulate(rows, headers=["Protocol", "Packets", "%", "Bytes", ""], tablefmt="simple"))


def print_top_ips(stats: dict):
    print(Fore.CYAN + "\n─── Top Source IPs ───────────────────────────────────────────" + Style.RESET_ALL)
    rows = [
        [i+1, e["ip"], f"{e['packets']:,}", f"{e['percent']}%",
         Fore.YELLOW + "internal" + Style.RESET_ALL if _is_private(e["ip"]) else Fore.RED + "external" + Style.RESET_ALL]
        for i, e in enumerate(stats["top_src_ips"][:10])
    ]
    print(tabulate(rows, headers=["#", "IP", "Pkts", "%", "Type"], tablefmt="simple"))

    print(Fore.CYAN + "\n─── Top Destination IPs ──────────────────────────────────────" + Style.RESET_ALL)
    rows = [
        [i+1, e["ip"], f"{e['packets']:,}", f"{e['percent']}%",
         Fore.YELLOW + "internal" + Style.RESET_ALL if _is_private(e["ip"]) else Fore.RED + "external" + Style.RESET_ALL]
        for i, e in enumerate(stats["top_dst_ips"][:10])
    ]
    print(tabulate(rows, headers=["#", "IP", "Pkts", "%", "Type"], tablefmt="simple"))


def print_top_ports(stats: dict):
    print(Fore.CYAN + "\n─── Top Destination Ports ────────────────────────────────────" + Style.RESET_ALL)
    rows = [
        [p["port"], p["service"], p["count"], p["protocol"]]
        for p in stats["top_dst_ports"]
    ]
    print(tabulate(rows, headers=["Port", "Service", "Count", "Proto"], tablefmt="simple"))


def print_ip_pairs(stats: dict):
    print(Fore.CYAN + "\n─── Top IP Conversation Pairs ────────────────────────────────" + Style.RESET_ALL)
    rows = [
        [e["src"], "→", e["dst"], f"{e['packets']:,}", _fmt_bytes(e["bytes"])]
        for e in stats["ip_pairs"]
    ]
    print(tabulate(rows, headers=["Source", "", "Destination", "Packets", "Bytes"], tablefmt="simple"))


def print_unique_summary(stats: dict):
    u = stats["unique_ips"]
    p = stats["unique_ports"]
    print(Fore.CYAN + "\n─── Unique Entity Summary ────────────────────────────────────" + Style.RESET_ALL)
    rows = [
        ["Unique IPs total",     u["total_unique"]],
        ["Internal IPs",         u["src_count"]],
        ["External IPs",         len(u["external"])],
        ["Unique dst ports",     p["count"]],
        ["Well-known ports",     len(p["well_known"])],
        ["Ephemeral ports",      p["ephemeral"]],
    ]
    print(tabulate(rows, tablefmt="simple"))


def print_full_report(stats: dict):
    print_banner()
    print_file_info(stats)
    print_protocol_breakdown(stats)
    print_top_ips(stats)
    print_top_ports(stats)
    print_ip_pairs(stats)
    print_unique_summary(stats)
    print()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _bar(percent: float, width: int = 20) -> str:
    filled = int(round(percent / 100 * width))
    return Fore.GREEN + "█" * filled + Fore.WHITE + "░" * (width - filled) + Style.RESET_ALL


def _fmt_bytes(b: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if b < 1024: return f"{b:.1f} {unit}"
        b //= 1024
    return f"{b:.1f} TB"


def _is_private(ip: str) -> bool:
    try:
        parts = list(map(int, ip.split(".")))
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
        if parts[0] == 192 and parts[1] == 168: return True
        if parts[0] == 127: return True
        return False
    except Exception:
        return False


def print_sessions(flows):
    """Print session table — Week 2 output."""
    from colorama import Fore, Style
    print(Fore.CYAN + "\n─── Reconstructed Sessions ───────────────────────────────────" + Style.RESET_ALL)
    rows = []
    for i, f in enumerate(flows[:30], 1):
        svc   = f" [{f.service}]" if f.service else ""
        proto = f.protocol
        rows.append([
            i,
            f"{f.src_ip}:{f.src_port}",
            "→",
            f"{f.dst_ip}:{f.dst_port}{svc}",
            proto,
            f"{f.packet_count:,}",
            _fmt_bytes(f.byte_count),
            f"{f.duration_sec:.2f}s",
            ("HTTP" if f.http_sessions else ""),
        ])
    from tabulate import tabulate
    print(tabulate(rows,
        headers=["#","Source","","Destination","Proto","Pkts","Bytes","Dur","Layer7"],
        tablefmt="simple"))
    if len(flows) > 30:
        print(f"  … and {len(flows)-30} more flows")


def print_http_sessions(http_flows):
    """Print HTTP request/response pairs extracted from TCP streams."""
    from colorama import Fore, Style
    from tabulate import tabulate
    print(Fore.CYAN + "\n─── HTTP Sessions ────────────────────────────────────────────" + Style.RESET_ALL)
    rows = []
    for flow in http_flows:
        for h in flow.http_sessions:
            host = h.host or f"{flow.dst_ip}"
            rows.append([
                h.method or "?",
                host,
                (h.uri or "")[:50],
                h.status_code or "?",
                h.content_type or "",
                _fmt_bytes(h.body_size),
                (h.user_agent or "")[:30],
            ])
    if rows:
        print(tabulate(rows,
            headers=["Method","Host","URI","Status","Content-Type","Body","User-Agent"],
            tablefmt="simple"))
    else:
        print("  No HTTP sessions found")


def print_dissection_summary(dissected):
    """Print protocol dissection summary — Week 3."""
    from colorama import Fore, Style
    from tabulate import tabulate
    from collections import Counter

    tag_counts = Counter(d.protocol_tag for d in dissected)
    print(Fore.CYAN + "\n─── Protocol Dissection Summary ─────────────────────────────" + Style.RESET_ALL)
    rows = [[tag, cnt] for tag, cnt in tag_counts.most_common()]
    print(tabulate(rows, headers=["Protocol", "Flows"], tablefmt="simple"))

    # DNS queries
    dns_flows = [d for d in dissected if d.protocol_tag == "DNS" and d.dns_records]
    if dns_flows:
        print(Fore.CYAN + "\n─── DNS Queries ──────────────────────────────────────────────" + Style.RESET_ALL)
        rows = []
        for d in dns_flows:
            for rec in d.dns_records[:3]:
                rows.append([
                    rec.query[:50],
                    rec.record_type,
                    ", ".join(rec.answers[:3])[:40] if rec.answers else "",
                    "response" if rec.is_response else "query",
                ])
        print(tabulate(rows[:20], headers=["Query","Type","Answer","Dir"], tablefmt="simple"))

    # TLS SNI
    tls_flows = [d for d in dissected if d.protocol_tag == "TLS" and d.payload_text]
    if tls_flows:
        print(Fore.CYAN + "\n─── TLS SNI (Server Names) ───────────────────────────────────" + Style.RESET_ALL)
        for d in tls_flows[:10]:
            print(f"  {d.payload_text}  ({d.flow.src_ip} → {d.flow.dst_ip})")

    # FTP / credential exposures
    cred_flows = [d for d in dissected if d.has_credentials]
    if cred_flows:
        print(Fore.RED + "\n─── [!] Plaintext Credentials Detected ──────────────────────" + Style.RESET_ALL)
        for d in cred_flows:
            if d.ftp_session:
                print(f"  FTP  user={d.ftp_session.user}  pass={d.ftp_session.password}  "
                      f"({d.flow.src_ip} → {d.flow.dst_ip}:{d.flow.dst_port})")


def print_extracted_files(files):
    """Print extracted file table — Week 3."""
    from colorama import Fore, Style
    from tabulate import tabulate

    print(Fore.CYAN + "\n─── Extracted Files ──────────────────────────────────────────" + Style.RESET_ALL)
    if not files:
        print("  No files extracted")
        return

    rows = []
    for ef in files:
        verdict = ef.vt_verdict
        vt_color = ""
        if "MALICIOUS" in verdict:
            vt_color = Fore.RED
        elif "SUSPICIOUS" in verdict:
            vt_color = Fore.YELLOW
        elif verdict == "CLEAN":
            vt_color = Fore.GREEN

        rows.append([
            ef.filename[:30],
            _fmt_bytes(ef.size_bytes),
            ef.file_type[:30],
            ef.extract_method,
            ef.sha256[:16] + "...",
            vt_color + verdict + Style.RESET_ALL,
        ])

    print(tabulate(rows,
        headers=["Filename","Size","Type","Method","SHA256","VT Verdict"],
        tablefmt="simple"))


def print_beacon_findings(findings):
    """Print C2 beacon detection results — Week 4."""
    from colorama import Fore, Style
    from tabulate import tabulate
    if not findings:
        print(Fore.GREEN + "\n[+] No beacon patterns detected" + Style.RESET_ALL)
        return
    print(Fore.RED + f"\n─── C2 Beacon Detection ({len(findings)} suspicious flows) ───────────" + Style.RESET_ALL)
    rows = []
    for f in findings:
        sev_color = {
            "CRITICAL": Fore.RED, "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW, "LOW": Fore.WHITE
        }.get(f.severity, "")
        rows.append([
            sev_color + f.severity + Style.RESET_ALL,
            f.threat_score,
            f"{f.src_ip}",
            f"{f.dst_ip}:{f.dst_port or '?'}",
            f.protocol,
            f"{f.interval_mean:.1f}s" if f.interval_mean else "-",
            f"{f.interval_cv:.2f}" if f.interval_cv else "-",
            f.packet_count,
        ])
    print(tabulate(rows,
        headers=["Severity","Score","Source","Destination","Proto",
                 "Interval","CV","Pkts"],
        tablefmt="simple"))
    for f in findings:
        if f.reasons:
            print(f"\n  {f.flow_id}")
            for r in f.reasons:
                print(f"    → {r}")


def print_dns_findings(dns_stats):
    """Print DNS analysis results — Week 4."""
    from colorama import Fore, Style
    from tabulate import tabulate
    print(Fore.CYAN + "\n─── DNS Analysis ─────────────────────────────────────────────" + Style.RESET_ALL)
    print(f"  Queries: {dns_stats.total_queries}  |  "
          f"Domains: {dns_stats.unique_domains}  |  "
          f"Suspicious: {len(dns_stats.findings)}  |  "
          f"Tunnelling: {dns_stats.tunnelling_flows}  |  "
          f"DGA: {dns_stats.dga_flows}")
    if dns_stats.findings:
        print(Fore.YELLOW + "\n  Suspicious domains:" + Style.RESET_ALL)
        rows = []
        for f in dns_stats.findings[:15]:
            sev_color = Fore.RED if f.severity in ("CRITICAL","HIGH") else Fore.YELLOW
            rows.append([
                sev_color + f.severity + Style.RESET_ALL,
                f.threat_score,
                f.domain[:40],
                f.query_count,
                f"{f.entropy:.2f}",
                f.max_label_len,
                "YES" if f.is_tunnelling else "",
                "YES" if f.is_dga       else "",
            ])
        print(tabulate(rows,
            headers=["Severity","Score","Domain","Queries","Entropy",
                     "MaxLabel","Tunnel","DGA"],
            tablefmt="simple"))


def print_ioc_report(report):
    """Print unified IOC report — Week 4."""
    from colorama import Fore, Style
    from tabulate import tabulate
    print(Fore.CYAN + "\n─── IOC Report ───────────────────────────────────────────────" + Style.RESET_ALL)
    print(f"  Total: {len(report.iocs)}  |  "
          f"CRITICAL: {Fore.RED}{report.critical_count}{Style.RESET_ALL}  |  "
          f"HIGH: {Fore.RED}{report.high_count}{Style.RESET_ALL}  |  "
          f"MEDIUM: {Fore.YELLOW}{report.medium_count}{Style.RESET_ALL}  |  "
          f"Tactics: {', '.join(report.attack_surface)}")
    if not report.iocs:
        return
    rows = []
    for ioc in report.iocs[:20]:
        sev_color = {
            "CRITICAL": Fore.RED, "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW, "LOW": Fore.WHITE
        }.get(ioc.severity, "")
        rows.append([
            sev_color + ioc.severity + Style.RESET_ALL,
            ioc.threat_score,
            ioc.ioc_type,
            ioc.value[:45],
            ioc.mitre_technique or "-",
            ioc.context[:35],
        ])
    print(tabulate(rows,
        headers=["Severity","Score","Type","Value","MITRE","Context"],
        tablefmt="simple"))
