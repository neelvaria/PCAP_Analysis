"""
main.py  —  PCAP Engine  |  Non-interactive batch entry point  (v2.1)

Usage:
    python main.py <pcap_path> [flags]
    python main.py "capture.pcap" --sessions --beacons --dns --iocs
    python main.py "capture.pcap" --all --pdf
    python main.py "capture.pcap" --all --pdf -c CASE-2025-001   # skip prompt

Behaviour:
  1. Validates PCAP path
  2. Prompts for Case Number (or uses -c / --case flag to skip prompt)
  3. Checks for duplicate PCAP hash — offers to reuse existing results
  4. Creates isolated CLI case folder under  cases/cli/<CASE>_<uuid8>/
  5. Runs full analysis pipeline
  6. Prints requested report sections
  7. Writes IOC CSV, JSON, summary.json to case folder (always)
  8. Generates PDF into case folder (with --pdf)

All output files land in:  cases/cli/<CASE_NUMBER>_<analysis_id[:8]>/
"""

import sys, json, argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine.pcap_loader      import load_pcap
from engine.normaliser       import normalise
from engine.packet_stats     import generate_stats
from engine.session_tracker  import reconstruct_sessions
from engine.database         import init_db, insert_pcap_file, get_stats
from engine.flow_store       import store_flows
from engine.printer          import (print_full_report, print_sessions,
                                      print_http_sessions,
                                      print_dissection_summary,
                                      print_extracted_files,
                                      print_beacon_findings,
                                      print_dns_findings,
                                      print_ioc_report)
from modules.protocol_dissector import dissect_flows
from modules.file_extractor     import extract_files
from modules.beacon_detector    import detect_beacons
from modules.dns_analyser       import analyse_dns
from modules.ioc_aggregator     import aggregate_iocs, export_csv, export_json
from modules.attack_chain       import correlate_flows, format_chain_report
from engine.case_manager        import (create_case, find_by_hash, sha256_file,
                                         case_dir, init_case_folder,
                                         flush_case_folder)
from engine.pipeline            import run_analysis
from engine.logger              import get_logger
from config                     import DB_PATH

log = get_logger("main")

try:
    from colorama import Fore, Style, init as _cinit; _cinit(autoreset=True)
    GREEN=Fore.GREEN; YELLOW=Fore.YELLOW; RED=Fore.RED
    CYAN=Fore.CYAN; WHITE=Fore.WHITE; BOLD=Style.BRIGHT; RESET=Style.RESET_ALL
except ImportError:
    GREEN=YELLOW=RED=CYAN=WHITE=BOLD=RESET=""


# ── Main entry ─────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="PCAP Engine — SOC-grade forensics (main.py)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py capture.pcap --sessions --beacons --dns --iocs
  python main.py capture.pcap --all --pdf
  python main.py capture.pcap --all --pdf -c IR-2025-001
""")
    p.add_argument("path",               help="Path to .pcap / .pcapng / .cap file")
    p.add_argument("-c", "--case",        help="Case number (skip interactive prompt)")
    p.add_argument("--analyst",          default="SOC Analyst")
    p.add_argument("--org",              default="Digital Forensics Lab")
    p.add_argument("--sessions",         action="store_true", help="Print flow table")
    p.add_argument("--http",             action="store_true", help="Print HTTP sessions")
    p.add_argument("--dissect",          action="store_true", help="Print protocol dissection")
    p.add_argument("--files",            action="store_true", help="Print extracted files")
    p.add_argument("--beacons",          action="store_true", help="Print C2 beacon findings")
    p.add_argument("--dns",              action="store_true", help="Print DNS analysis")
    p.add_argument("--iocs",             action="store_true", help="Print IOC report")
    p.add_argument("--chains",           action="store_true", help="Print attack chain report")
    p.add_argument("--pdf",              action="store_true", help="Generate PDF in case folder")
    p.add_argument("--json",             action="store_true", help="Show case folder file list")
    p.add_argument("--all",              action="store_true", help="Enable all output flags")
    args = p.parse_args()

    if args.all:
        args.sessions = args.http = args.dissect = args.files = True
        args.beacons  = args.dns  = args.iocs    = args.chains = True

    _banner()

    # ── Validate PCAP path ─────────────────────────────────────────────────────
    pcap_path = Path(args.path)
    if not pcap_path.exists():
        _err(f"File not found: {args.path}"); sys.exit(1)
    if pcap_path.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
        _err(f"Unsupported format: {pcap_path.suffix}"); sys.exit(1)

    _info(f"PCAP: {pcap_path}")

    # ── Case number — prompt if not given via -c ───────────────────────────────
    case_number = args.case.strip() if args.case else None
    if not case_number:
        print()
        while True:
            raw = input(f"  {CYAN}Enter Case Number:{RESET} ").strip()
            if raw:
                case_number = raw
                break
            print(f"  {YELLOW}Case number cannot be empty.{RESET}")

    # ── Duplicate PCAP detection ───────────────────────────────────────────────
    file_hash = sha256_file(str(pcap_path))
    existing  = find_by_hash(file_hash)
    if existing:
        folder = case_dir(existing)
        _warn(f"PCAP already analysed under case '{existing.case_number}' "
              f"(id: {existing.analysis_id[:8]}…)")
        _info(f"Existing case folder: {folder}")
        choice = input("  Use existing results? [Y/n]: ").strip().lower()
        if choice != "n":
            _print_existing(existing, args)
            if args.pdf:  _gen_pdf(existing, args)
            if args.json: _show_folder(existing)
            return

    # ── Create isolated CLI case ───────────────────────────────────────────────
    case = create_case(case_number, pcap_path.name, file_hash, source="cli")
    folder = case_dir(case)
    _info(f"New case: {case_number!r}  id={case.analysis_id}")
    _ok  (f"Case folder: {folder}")

    # ── Run unified pipeline ───────────────────────────────────────────────────
    _section("RUNNING ANALYSIS PIPELINE")
    _info(f"Loading {pcap_path.name}…")
    run_analysis(str(pcap_path), case)
    _ok(f"Pipeline complete: {len(case.flows)} flows | "
        f"{case.beacon_count} beacons | {case.ioc_count} IOCs | "
        f"{case.chain_count} chains")

    # ── Print requested sections ───────────────────────────────────────────────
    _section("ANALYSIS RESULTS")
    print_full_report(case.stats_raw)

    if args.sessions: print_sessions(case.flows or [])
    if args.http:
        print_http_sessions([f for f in (case.flows or []) if f.http_sessions])
    if args.dissect:  print_dissection_summary(case.dissected or [])
    if args.files:    print_extracted_files(case.extracted_files or [])
    if args.beacons:  print_beacon_findings(case.beacons or [])
    if args.dns:      print_dns_findings(case.dns_stats)
    if args.iocs:     print_ioc_report(case.ioc_report)
    if args.chains:
        print(format_chain_report(
            _make_corr(case.attack_chains, case.host_profiles)))

    # ── PDF into case folder ───────────────────────────────────────────────────
    if args.pdf:
        _gen_pdf(case, args)

    # ── Always show case folder summary ───────────────────────────────────────
    _show_folder(case)


# ── PDF generation ─────────────────────────────────────────────────────────────

def _gen_pdf(case, args):
    _section("GENERATING PDF REPORT")
    try:
        from reports.pdf_generator import generate_report
        folder = case_dir(case)
        folder.mkdir(parents=True, exist_ok=True)

        report_data = {
            "meta": {
                "filename":  case.file_name,
                "sha256":    case.file_hash,
                "file_size": 0,
                "path":      str(folder / case.file_name),
            },
            "stats":           case.stats_raw,
            "flows":           case.flows or [],
            "beacons":         case.beacons or [],
            "dns_stats":       case.dns_stats,
            "ioc_report":      case.ioc_report,
            "extracted_files": case.extracted_files or [],
            "case_info": {
                "case_number":  case.case_number,
                "analyst_name": getattr(args, "analyst", "SOC Analyst"),
                "organisation": getattr(args, "org", "Digital Forensics Lab"),
            },
        }
        pdf_path = generate_report(report_data, output_dir=str(folder))
        _ok(f"PDF saved: {pdf_path}")
        print(f"\n  {CYAN}Open with:{RESET}")
        print(f"    {WHITE}xdg-open \"{pdf_path}\"{RESET}    (Linux)")
        print(f"    {WHITE}open \"{pdf_path}\"{RESET}         (macOS)")
        print(f"    {WHITE}start \"\"{pdf_path}\"\"{RESET}    (Windows)")
    except Exception as e:
        _err(f"PDF generation failed: {e}")
        import traceback; traceback.print_exc()


# ── Show case folder contents ──────────────────────────────────────────────────

def _show_folder(case):
    _section("CASE FOLDER")
    folder = case_dir(case)
    _info(f"Location: {folder}")
    print()
    if folder.exists():
        icons = {".json":"📄",".csv":"📊",".pdf":"📋",
                 ".pcap":"🔍",".pcapng":"🔍",".cap":"🔍"}
        for item in sorted(folder.iterdir()):
            size = item.stat().st_size
            icon = icons.get(item.suffix.lower(), "📁")
            print(f"  {icon}  {item.name:<40} {size:>10,} B")
    else:
        _warn("Folder not found")


# ── Print results from existing case ─────────────────────────────────────────

def _print_existing(case, args):
    if args.sessions: print_sessions(case.flows or [])
    if args.beacons:  print_beacon_findings(case.beacons or [])
    if args.dns:      print_dns_findings(case.dns_stats)
    if args.iocs:     print_ioc_report(case.ioc_report)


# ── Tiny correlation shim (attack_chain.correlate_flows returns a dataclass) ──

def _make_corr(chains, profiles):
    """Minimal shim so format_chain_report() still works."""
    from dataclasses import dataclass
    @dataclass
    class _Corr:
        attack_chains: list
        host_profiles: dict
        high_risk_hosts: list = None
        pivot_hosts: list = None
    return _Corr(attack_chains=chains or [],
                 host_profiles=profiles or {})


# ── Formatting helpers ─────────────────────────────────────────────────────────

def _banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════╗
║        PCAP SESSION RECONSTRUCTION ENGINE  v2.1          ║
║        main.py — Batch CLI (case-isolated)               ║
╚══════════════════════════════════════════════════════════╝{RESET}""")

def _section(t): print(f"\n{CYAN}{'─'*60}\n  [{t}]\n{'─'*60}{RESET}")
def _info(m):    print(f"  {GREEN}[INFO]{RESET}    {m}")
def _warn(m):    print(f"  {YELLOW}[WARNING]{RESET} {m}")
def _err(m):     print(f"  {RED}[ERROR]{RESET}   {m}")
def _ok(m):      print(f"  {GREEN}[OK]{RESET}      {m}")


if __name__ == "__main__":
    main()
