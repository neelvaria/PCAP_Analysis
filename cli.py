"""
cli.py  —  PCAP Engine  |  SOC Investigation CLI  v2.1

Changes in v2.1:
  - Case isolation: every case gets its own output folder
        cases/<CASE_NUMBER>_<aid8>/
            case_meta.json
            <pcap_filename>         ← original PCAP (chain-of-custody)
            iocs.csv
            iocs.json
            summary.json
            report.pdf              ← generated on --pdf
  - PDF saved INSIDE the case folder (not global reports/)
  - --open-folder  opens the case folder in file manager after analysis
  - Isolation note printed when a duplicate hash is found

Usage (interactive):
    python cli.py

Usage (scripted):
    python cli.py -f capture.pcap -c CASE-2025-001 --all
    python cli.py -f capture.pcap -c CASE-2025-001 --beacons --iocs --pdf --json
"""

from __future__ import annotations

import os, sys, json, argparse, datetime, shutil
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine.case_manager  import (create_case, find_by_hash,
                                   sha256_file, list_cases,
                                   case_dir, init_case_folder)
from engine.pipeline      import run_analysis
from modules.ioc_aggregator import export_csv, export_json
from engine.logger        import get_logger
from config               import CASES_DIR

log = get_logger("cli")

try:
    from colorama import Fore, Style, init as _init; _init(autoreset=True)
    RED=Fore.RED; YELLOW=Fore.YELLOW; GREEN=Fore.GREEN
    CYAN=Fore.CYAN; WHITE=Fore.WHITE; BOLD=Style.BRIGHT; RESET=Style.RESET_ALL
except ImportError:
    RED=YELLOW=GREEN=CYAN=WHITE=BOLD=RESET=""

SEV_COL = {"CRITICAL": RED+BOLD, "HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PCAP Engine — SOC Investigation CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py                                          # interactive
  python cli.py -f sample.pcap -c IR-001 --all
  python cli.py -f sample.pcap -c IR-001 --beacons --iocs --pdf --json
  python cli.py --list-cases                            # show all cases + folders
""")
    parser.add_argument("-f", "--pcap",       help="PCAP file path")
    parser.add_argument("-c", "--case",       help="Case number")
    parser.add_argument("--analyst",          default="SOC Analyst")
    parser.add_argument("--org",              default="Digital Forensics Lab")
    parser.add_argument("--sessions",         action="store_true")
    parser.add_argument("--beacons",          action="store_true")
    parser.add_argument("--dns",              action="store_true")
    parser.add_argument("--iocs",             action="store_true")
    parser.add_argument("--chains",           action="store_true")
    parser.add_argument("--json",             action="store_true",
                        help="Save IOC CSV + JSON + summary.json to case folder")
    parser.add_argument("--pdf",              action="store_true",
                        help="Generate PDF report in case folder")
    parser.add_argument("--all",              action="store_true",
                        help="Enable all output flags")
    parser.add_argument("--list-cases",       action="store_true",
                        help="List all cases with folder paths and exit")
    parser.add_argument("--open-folder",      action="store_true",
                        help="Open case folder in file manager after analysis")
    args = parser.parse_args()

    if args.all:
        args.sessions = args.beacons = args.dns = args.iocs = args.chains = True

    _banner()

    # ── List cases mode ────────────────────────────────────────────────────────
    if args.list_cases:
        _list_all_cases()
        return

    # ── Input collection ───────────────────────────────────────────────────────
    pcap_path   = _get_pcap(args.pcap)
    case_number = _get_case(args.case)

    # ── Duplicate detection ────────────────────────────────────────────────────
    file_hash = sha256_file(pcap_path)
    existing  = find_by_hash(file_hash)
    if existing:
        folder = case_dir(existing)
        _warn(f"File already analysed under case '{existing.case_number}' "
              f"(id: {existing.analysis_id[:8]}…)")
        _info(f"Case folder: {folder}")
        if input("  Use existing results? [Y/n]: ").strip().lower() != "n":
            _print_report(existing, args)
            if args.json:   _save_exports(existing)
            if args.pdf:    _gen_pdf(existing, args)
            if args.open_folder: _open_folder(existing)
            return

    # ── New case ───────────────────────────────────────────────────────────────
    case = create_case(case_number, Path(pcap_path).name, file_hash)
    folder = case_dir(case)
    _info(f"New case: {case_number!r}  id={case.analysis_id}")
    _info(f"Case folder: {folder}")

    # ── Run pipeline ───────────────────────────────────────────────────────────
    _section("RUNNING ANALYSIS PIPELINE")
    _run_pipeline(pcap_path, case)

    # ── Report ─────────────────────────────────────────────────────────────────
    _print_report(case, args)

    # ── Exports ────────────────────────────────────────────────────────────────
    # Always write exports to case folder (iocs.csv / iocs.json / summary.json)
    # flush_case_folder() already runs inside run_analysis via flush_case(),
    # so these are already written. --json just prints confirmation.
    if args.json:
        _save_exports(case)

    if args.pdf:
        _gen_pdf(case, args)

    # ── Print folder summary ───────────────────────────────────────────────────
    _print_folder_summary(case)

    if args.open_folder:
        _open_folder(case)


# ── Pipeline ───────────────────────────────────────────────────────────────────

def _run_pipeline(pcap_path: str, case) -> None:
    """Delegates to unified engine.pipeline.run_analysis()."""
    _info(f"Loading: {pcap_path}")
    run_analysis(pcap_path, case)
    _ok(f"Complete: {len(case.flows)} flows | {len(case.beacons)} beacons | "
        f"{case.ioc_count} IOCs | {case.chain_count} chains")


# ── Case folder utilities ──────────────────────────────────────────────────────

def _save_exports(case):
    """Print confirmation of files already written to case folder by flush_case_folder()."""
    _section("CASE FOLDER EXPORTS")
    folder = case_dir(case)
    files = {
        "iocs.csv":     "IOC export (CSV)",
        "iocs.json":    "IOC export (JSON)",
        "summary.json": "Analysis summary",
        "case_meta.json":"Case metadata",
    }
    for fname, desc in files.items():
        fpath = folder / fname
        if fpath.exists():
            size = fpath.stat().st_size
            _ok(f"{desc}: {fpath}  ({size:,}B)")
        else:
            _warn(f"{desc} not found: {fpath}")


def _gen_pdf(case, args):
    """Generate PDF report and save it INSIDE the case folder."""
    _section("GENERATING PDF REPORT")
    try:
        from reports.pdf_generator import generate_report

        folder = case_dir(case)
        folder.mkdir(parents=True, exist_ok=True)

        data = {
            "meta":  {"filename":   case.file_name,
                      "sha256":     case.file_hash,
                      "file_size":  0,
                      "path":       str(folder / case.file_name)},
            "stats":           case.stats_raw,
            "flows":           case.flows or [],
            "beacons":         case.beacons or [],
            "dns_stats":       case.dns_stats,
            "ioc_report":      case.ioc_report,
            "extracted_files": case.extracted_files or [],
            "case_info": {
                "case_number":  case.case_number,
                "analyst_name": args.analyst,
                "organisation": args.org,
            },
        }
        # Generate into the case folder directly
        pdf_path = generate_report(data, output_dir=str(folder))

        # Also symlink/copy to global reports/ for backward compat
        try:
            import config
            global_reports = Path(config.REPORTS_DIR)
            global_reports.mkdir(parents=True, exist_ok=True)
            global_copy = global_reports / Path(pdf_path).name
            if not global_copy.exists():
                shutil.copy2(pdf_path, global_copy)
        except Exception:
            pass

        _ok(f"PDF saved: {pdf_path}")
        print(f"\n  {CYAN}Open with:{RESET}")
        print(f"    {WHITE}xdg-open \"{pdf_path}\"{RESET}   (Linux)")
        print(f"    {WHITE}open \"{pdf_path}\"{RESET}        (macOS)")
        print(f"    {WHITE}start \"{pdf_path}\"{RESET}       (Windows)")

    except Exception as e:
        _err(f"PDF failed: {e}")
        import traceback; traceback.print_exc()


def _print_folder_summary(case):
    """Print a summary of everything written to the case folder."""
    _section("CASE FOLDER SUMMARY")
    folder = case_dir(case)
    _info(f"Location: {folder}")
    print()
    if folder.exists():
        for item in sorted(folder.iterdir()):
            size = item.stat().st_size
            icon = {
                ".json": "📄",
                ".csv":  "📊",
                ".pdf":  "📋",
                ".pcap": "🔍",
                ".pcapng": "🔍",
                ".cap":  "🔍",
            }.get(item.suffix.lower(), "📁")
            print(f"  {icon}  {item.name:<35} {size:>10,} B")
    else:
        _warn("Case folder not found (pipeline may not have run yet)")


def _list_all_cases():
    """Print all cases with folder paths."""
    _section("ALL INVESTIGATION CASES")
    cases = list_cases()
    if not cases:
        print("  No cases found.")
        return
    print(f"  {'Case Number':<30} {'Threat':<10} {'IOCs':<6} {'Folder exists':<15} Path")
    print("  " + "─"*90)
    for c in cases:
        folder  = case_dir(c)
        exists  = "✓ Yes" if folder.exists() else "✗ No"
        tl_col  = SEV_COL.get(c.threat_level, "")
        print(f"  {c.case_number:<30} {tl_col}{c.threat_level:<10}{RESET} "
              f"{c.ioc_count:<6} {exists:<15} {folder}")


def _open_folder(case):
    """Attempt to open the case folder in the system file manager."""
    folder = case_dir(case)
    if not folder.exists():
        _warn(f"Folder does not exist: {folder}")
        return
    import subprocess, platform
    try:
        system = platform.system()
        if system == "Windows":
            os.startfile(str(folder))
        elif system == "Darwin":
            subprocess.Popen(["open", str(folder)])
        else:
            subprocess.Popen(["xdg-open", str(folder)])
        _ok(f"Opened: {folder}")
    except Exception as e:
        _warn(f"Could not open folder automatically: {e}")
        _info(f"Open manually: {folder}")


# ── Report sections ────────────────────────────────────────────────────────────

def _print_report(case, args):
    _case_info(case)
    _exec_summary(case)
    _network_overview(case)
    if args.sessions: _sessions(case)
    if args.beacons:  _beacons(case)
    if args.dns:      _dns(case)
    if args.iocs:     _iocs(case)
    if args.chains:   _chains(case)
    _conclusion(case)


def _case_info(case):
    _section("CASE INFORMATION")
    folder = case_dir(case)
    _kv([
        ("Case Number",  case.case_number),
        ("Analysis ID",  case.analysis_id),
        ("File",         case.file_name),
        ("SHA-256",      case.file_hash[:32] + "…"),
        ("Started",      case.created_at[:19]),
        ("Report Time",  datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")),
        ("Case Folder",  str(folder)),
    ])


def _exec_summary(case):
    _section("EXECUTIVE SUMMARY")
    stats     = case.stats_raw or {}
    totals    = stats.get("totals", {})
    beacons   = case.beacons or []
    ioc_rep   = case.ioc_report
    dns       = case.dns_stats
    extracted = case.extracted_files or []

    crit = sum(1 for b in beacons if b.severity == "CRITICAL")
    high = sum(1 for b in beacons if b.severity == "HIGH")
    mal  = sum(1 for f in extracted if "MALICIOUS" in (f.vt_verdict or ""))
    nioc = len(ioc_rep.iocs) if ioc_rep else 0

    lvl = ("CRITICAL" if crit or mal else
           "HIGH"     if high or (dns and dns.tunnelling_flows) else
           "MEDIUM"   if nioc else "LOW")

    print(f"  Overall Threat Level: {SEV_COL.get(lvl,'')}{lvl}{RESET}\n")
    _kv([
        ("Total Packets",  f"{totals.get('packets',0):,}"),
        ("Total Bytes",    _fb(totals.get('bytes',0))),
        ("Total Flows",    str(len(case.flows or []))),
        ("Beacon Alerts",  f"{len(beacons)} ({crit} CRITICAL, {high} HIGH)"),
        ("IOCs Found",     str(nioc)),
        ("Suspicious DNS", str(len(dns.findings) if dns else 0)),
        ("Malicious Files",str(mal)),
        ("Attack Chains",  str(len(case.attack_chains or []))),
    ])
    print()
    print(f"  {WHITE}{BOLD}Key Findings:{RESET}")
    findings = []
    if beacons:
        findings.append(f"{len(beacons)} C2 beacon flow(s) — {crit} CRITICAL, {high} HIGH")
    if dns and dns.findings:
        findings.append(f"{len(dns.findings)} suspicious DNS domain(s) — "
                        f"{dns.tunnelling_flows} tunnelling, {dns.dga_flows} DGA")
    if extracted:
        findings.append(f"{len(extracted)} file(s) extracted"
                        + (f" — {mal} MALICIOUS" if mal else ""))
    if ioc_rep and ioc_rep.attack_surface:
        findings.append(f"MITRE tactics: {', '.join(ioc_rep.attack_surface)}")
    if not findings:
        findings.append("No significant threats detected")
    for f in findings:
        print(f"  • {f}")


def _network_overview(case):
    _section("NETWORK OVERVIEW")
    stats = case.stats_raw or {}
    cap   = stats.get("capture", {})
    uniq  = stats.get("unique_ips", {})
    _kv([
        ("First Packet", cap.get("first_packet","N/A")),
        ("Last Packet",  cap.get("last_packet", "N/A")),
        ("Duration",     cap.get("duration_human","N/A")),
        ("Unique IPs",   str(uniq.get("total_unique",0))),
        ("Internal IPs", str(len(uniq.get("internal",[])))),
        ("External IPs", str(len(uniq.get("external",[])))),
    ])
    protos = stats.get("protocols", {})
    if protos:
        print()
        print(f"  {WHITE}{BOLD}Protocol Distribution:{RESET}")
        _tbl(["Protocol","Packets","Bytes","Share"],
             [[p, f"{d['count']:,}", _fb(d['bytes']), f"{d['percent']}%"]
              for p,d in protos.items()])
    src_ips = stats.get("top_src_ips", [])[:8]
    if src_ips:
        print()
        print(f"  {WHITE}{BOLD}Top Source IPs:{RESET}")
        _tbl(["IP","Packets","Share"],
             [[e["ip"], f"{e['packets']:,}", f"{e['percent']}%"] for e in src_ips])


def _sessions(case):
    _section("SESSION ANALYSIS")
    flows = case.flows or []
    if not flows:
        print("  No flows."); return
    print(f"  {len(flows)} flows total — top 20 by byte volume:\n")
    _tbl(["Source","Destination","Proto","Pkts","Bytes","Dur","Score"],
         [[f"{getattr(f,'src_ip','?')}:{getattr(f,'src_port','?')}",
           f"{getattr(f,'dst_ip','?')}:{getattr(f,'dst_port','?')}",
           getattr(f,"protocol","?"), str(getattr(f,"packet_count",0)),
           _fb(getattr(f,"byte_count",0)), f"{getattr(f,'duration_sec',0):.1f}s",
           str(getattr(f,"threat_score",0) or 0)] for f in flows[:20]])


def _beacons(case):
    _section("THREAT DETECTION — C2 BEACONS & REVERSE SHELLS")
    beacons = case.beacons or []
    if not beacons:
        print(f"  {GREEN}No beaconing patterns detected.{RESET}"); return
    for b in beacons:
        col = SEV_COL.get(b.severity,"")
        print(f"\n  {col}[{b.severity}]{RESET}  Score:{b.threat_score}/100  "
              f"Confidence:{round(getattr(b,'confidence',0)*100)}%")
        print(f"  Flow: {CYAN}{b.src_ip} → {b.dst_ip}:{b.dst_port or '?'}"
              f" [{b.protocol}]{RESET}")
        print(f"  Interval mean={b.interval_mean:.1f}s  CV={b.interval_cv:.3f}"
              f"  Entropy={getattr(b,'payload_entropy',0):.2f}")
        if b.ja3_match:
            print(f"  {RED}JA3:{RESET} {b.ja3_match} ({b.ja3_hash})")
        rules = getattr(b,"rules_triggered",[])
        if rules:
            print(f"  Rules: {', '.join(rules)}")
        for r in b.reasons:
            print(f"  → {r}")


def _dns(case):
    _section("DNS ANALYSIS")
    dns = case.dns_stats
    if not dns:
        print("  No DNS data."); return
    _kv([("Total Queries", str(dns.total_queries)),
         ("Unique Domains", str(dns.unique_domains)),
         ("Suspicious", str(len(dns.findings))),
         ("Tunnelling", str(dns.tunnelling_flows)),
         ("DGA Domains", str(dns.dga_flows))])
    if dns.top_queried:
        print()
        print(f"  {WHITE}{BOLD}Top Domains:{RESET}")
        _tbl(["Domain","Queries"],[[d,str(c)] for d,c in dns.top_queried[:10]])
    if dns.findings:
        print()
        print(f"  {WHITE}{BOLD}Suspicious Domains:{RESET}")
        for f in dns.findings:
            col = SEV_COL.get(f.severity,"")
            print(f"\n  {col}[{f.severity}]{RESET}  {CYAN}{f.domain}{RESET}  "
                  f"score={f.threat_score}  entropy={f.entropy:.2f}")
            flags = (["TUNNEL"] if f.is_tunnelling else []) + (["DGA"] if f.is_dga else [])
            if flags: print(f"  Flags: {', '.join(flags)}")
            for r in f.reasons: print(f"  → {r}")


def _iocs(case):
    _section("IOC EXTRACTION")
    ioc_rep = case.ioc_report
    if not ioc_rep or not ioc_rep.iocs:
        print("  No IOCs."); return
    print(f"  {len(ioc_rep.iocs)} IOC(s)  "
          f"CRIT:{ioc_rep.critical_count}  HIGH:{ioc_rep.high_count}  "
          f"MED:{ioc_rep.medium_count}\n")
    _tbl(["Severity","Score","Type","Value","Tactic","Technique"],
         [[f"{SEV_COL.get(i.severity,'')}{i.severity}{RESET}",
           str(i.threat_score), i.ioc_type,
           i.value[:42], getattr(i,"mitre_tactic","—"),
           getattr(i,"mitre_technique","—")]
          for i in ioc_rep.iocs[:25]])
    if len(ioc_rep.iocs) > 25:
        print(f"\n  … +{len(ioc_rep.iocs)-25} more. Use --json to see all in case folder.")


def _chains(case):
    _section("ATTACK CHAIN CORRELATION")
    chains = case.attack_chains or []
    if not chains:
        print(f"  {GREEN}No multi-stage chains detected.{RESET}"); return
    for c in chains:
        col = SEV_COL.get(c.severity,"")
        print(f"\n  {col}[{c.severity}]{RESET}  {CYAN}{c.src_ip}{RESET}  "
              f"score={c.threat_score}/100")
        print(f"  Phases:  {' → '.join(c.phases) or 'N/A'}")
        print(f"  MITRE:   {', '.join(c.mitre_tactics) or 'N/A'}")
        print(f"  {c.narrative}")


def _conclusion(case):
    _section("CONCLUSION")
    beacons  = case.beacons or []
    ioc_rep  = case.ioc_report
    dns      = case.dns_stats
    extracted= case.extracted_files or []
    crit = sum(1 for b in beacons if b.severity == "CRITICAL")
    mal  = sum(1 for f in extracted if "MALICIOUS" in (f.vt_verdict or ""))

    if crit or mal:
        print(f"  {RED}CRITICAL COMPROMISE INDICATORS DETECTED{RESET}")
        print("  1. Isolate affected hosts immediately")
        print("  2. Preserve memory dumps")
        print("  3. Escalate to IR team")
        print("  4. Block flagged IPs at firewall")
    elif beacons or (dns and dns.tunnelling_flows):
        print(f"  {YELLOW}HIGH — Suspicious activity detected{RESET}")
        print("  1. Investigate flagged source IPs")
        print("  2. Review DNS queries from affected hosts")
        print("  3. Monitor for continued beaconing")
    elif ioc_rep and ioc_rep.iocs:
        print(f"  {YELLOW}MEDIUM — Suspicious indicators{RESET}")
        print("  1. Cross-reference IOCs with threat intel")
        print("  2. Perform targeted endpoint investigation")
    else:
        print(f"  {GREEN}LOW — No significant threats detected{RESET}")
        print("  Continue standard monitoring.")

    print(f"\n  Case {case.case_number} | ID {case.analysis_id[:16]}…")


# ── Input helpers ──────────────────────────────────────────────────────────────

def _get_pcap(arg):
    if arg:
        p = Path(arg)
        if not p.exists(): _err(f"Not found: {arg}"); sys.exit(1)
        if p.suffix.lower() not in (".pcap",".pcapng",".cap"):
            _err(f"Unsupported format: {p.suffix}"); sys.exit(1)
        return str(p)
    while True:
        raw = input(f"\n  {CYAN}Enter PCAP file path:{RESET} ").strip()
        if not raw: _warn("Path required."); continue
        p = Path(raw)
        if not p.exists(): _warn(f"Not found: {raw}"); continue
        if p.suffix.lower() not in (".pcap",".pcapng",".cap"):
            _warn("Only .pcap/.pcapng/.cap supported."); continue
        return str(p)


def _get_case(arg):
    if arg:
        c = arg.strip()
        if not c: _err("Case number empty"); sys.exit(1)
        return c
    while True:
        raw = input(f"  {CYAN}Enter Case Number:{RESET} ").strip()
        if raw: return raw
        _warn("Case number required.")


# ── Formatting ─────────────────────────────────────────────────────────────────

def _banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║        PCAP SESSION RECONSTRUCTION ENGINE  v2.1          ║
║        SOC-Grade Digital Forensics Investigation         ║
╚══════════════════════════════════════════════════════════╝{RESET}""")

def _section(t):
    print(f"\n{CYAN}{'─'*60}\n  [{t}]\n{'─'*60}{RESET}")

def _kv(rows):
    for k,v in rows: print(f"  {WHITE}{k:<22}{RESET} {v}")

def _tbl(headers, rows):
    if not rows: print("  (no data)"); return
    cols   = len(headers)
    widths = [max(len(str(h)), max((len(str(r[i] if i<len(r) else ""))
              for r in rows), default=0)) for i,h in enumerate(headers)]
    hdr = "  "+"  ".join(str(h).ljust(widths[i]) for i,h in enumerate(headers))
    sep = "  "+"  ".join("─"*widths[i] for i in range(cols))
    print(f"{WHITE}{hdr}{RESET}\n{sep}")
    for row in rows:
        print("  "+"  ".join(str(row[i] if i<len(row) else "").ljust(widths[i])
                              for i in range(cols)))

def _info(m): print(f"  {GREEN}[INFO]{RESET}    {m}")
def _warn(m): print(f"  {YELLOW}[WARNING]{RESET} {m}")
def _err(m):  print(f"  {RED}[ERROR]{RESET}   {m}")
def _ok(m):   print(f"  {GREEN}[OK]{RESET}      {m}")
def _fb(b):
    b=int(b or 0)
    for u in ("B","KB","MB","GB"):
        if b<1024: return f"{b:.1f} {u}"
        b//=1024
    return f"{b:.1f} TB"


if __name__ == "__main__":
    main()
