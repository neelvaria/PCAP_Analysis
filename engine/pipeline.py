"""
engine/pipeline.py  —  Unified analysis pipeline

Single entry point used by BOTH cli.py and web/app.py.
Eliminates the CLI/Web duplication and guarantees identical behavior.

Usage:
    from engine.pipeline import run_analysis
    case = run_analysis(pcap_path, case)   # mutates case in-place
"""

from __future__ import annotations

import os
from pathlib import Path
import sqlite3
from engine.pcap_loader         import load_pcap
from engine.normaliser          import normalise
from engine.packet_stats        import generate_stats
from engine.session_tracker     import reconstruct_sessions
from engine.database            import init_db, insert_pcap_file
from engine.flow_store          import store_flows
from engine.case_manager        import CaseState, flush_case
from modules.protocol_dissector import dissect_flows
from modules.file_extractor     import extract_files
from modules.beacon_detector    import detect_beacons
from modules.dns_analyser       import analyse_dns
from modules.ioc_aggregator     import aggregate_iocs
from modules.attack_chain       import correlate_flows
from engine.logger              import get_logger
from config                     import DB_PATH

log = get_logger("pipeline")



def _write_flow_threat_scores(conn, beacons, flows):
    """
    Back-fill threat_score on the flows DB rows from beacon findings.
    Called once after detect_beacons() so the score is durable in SQLite.
    Matches on (src_ip, dst_ip, dst_port) — same key used by host-pair analysis.
    """
    if not beacons or not flows:
        return
    # Build lookup: (src_ip, dst_ip, dst_port) → max score
    score_map: dict[tuple, int] = {}
    for b in beacons:
        key = (b.src_ip, b.dst_ip, b.dst_port)
        score_map[key] = max(score_map.get(key, 0), b.threat_score)

    if not score_map:
        return

    # Update flow rows — batch with executemany
    updates = []
    for flow in flows:
        key = (flow.src_ip or "", flow.dst_ip or "", flow.dst_port)
        score = score_map.get(key, 0)
        if score > 0:
            updates.append((score, flow.src_ip, flow.dst_ip, flow.dst_port))

    if updates:
        conn.executemany(
            "UPDATE flows SET threat_score=? WHERE src_ip=? AND dst_ip=? AND dst_port=?",
            updates
        )
        conn.commit()


def run_analysis(pcap_path: str, case: CaseState,
                 conn: sqlite3.Connection = None) -> CaseState:
    """
    Run the full analysis pipeline for a PCAP file.

    - Mutates `case` in-place with all results.
    - Writes flows/packets/HTTP sessions to the shared SQLite DB.
    - Calls flush_case() to persist case metadata + severity + IOCs to DB.
    - Returns the mutated case object.

    Args:
        pcap_path:  Absolute path to the .pcap / .pcapng file.
        case:       CaseState created by case_manager.create_case().
        conn:       Optional open DB connection (caller-managed).
                    If None, a fresh connection is opened and closed here.
    """
    own_conn = conn is None
    if own_conn:
        conn = init_db(DB_PATH)

    log.info(f"[INFO] Pipeline start | case={case.case_number} | {pcap_path}")

    try:
        # ── 1. Ingest ──────────────────────────────────────────────────────────
        meta = load_pcap(pcap_path)
        if meta["error"]:
            raise ValueError(f"PCAP load failed: {meta['error']}")

        # ── 2. Normalise ───────────────────────────────────────────────────────
        packets = normalise(meta["packets"])
        if not packets:
            raise ValueError("No packets after normalisation")

        # ── 3. Stats ───────────────────────────────────────────────────────────
        stats = generate_stats(packets, meta)

        # ── 4. Reconstruct sessions ────────────────────────────────────────────
        flows = reconstruct_sessions(packets)

        # ── 5. Persist to DB (flows isolated under pcap_id) ───────────────────
        pcap_db_id = insert_pcap_file(conn, meta, stats)
        store_flows(conn, flows, pcap_db_id)
        case.pcap_db_id = pcap_db_id

        # Copy original PCAP into case folder for chain-of-custody
        try:
            import shutil
            from engine.case_manager import case_dir
            dest = case_dir(case) / case.file_name
            if not dest.exists():
                shutil.copy2(pcap_path, dest)
                log.info(f"[INFO] PCAP copied to case folder: {dest}")
        except Exception as e:
            log.warning(f"Could not copy PCAP to case folder: {e}")

        # ── 6. Protocol dissection ─────────────────────────────────────────────
        dissected = dissect_flows(flows)

        # ── 7. File extraction + VirusTotal ───────────────────────────────────
        extracted = extract_files(pcap_path, flows)

        # ── 8. Beacon detection ────────────────────────────────────────────────
        beacons = detect_beacons(flows)

        # ── 9. DNS analysis ────────────────────────────────────────────────────
        dns_stats = analyse_dns(dissected)

        # ── 10. IOC aggregation ────────────────────────────────────────────────
        ioc_report = aggregate_iocs(beacons, dns_stats, extracted)

        # ── 11. Attack chain correlation ───────────────────────────────────────
        correlation = correlate_flows(
            flows, beacons,
            dns_stats.findings if dns_stats else []
        )

        # ── 12. Store results in case ──────────────────────────────────────────
        # Write beacon threat scores back to flows table so graph/sessions
        # show meaningful threat_score after restart without in-memory state.
        _write_flow_threat_scores(conn, beacons, flows)

        case.flows           = flows
        case.dissected       = dissected
        case.extracted_files = extracted
        case.beacons         = beacons
        case.dns_stats       = dns_stats
        case.ioc_report      = ioc_report
        case.attack_chains   = correlation.attack_chains
        case.host_profiles   = correlation.host_profiles
        case.timeline        = stats.get("timeline", [])
        case.stats_raw       = stats
        case.status          = "complete"

        # ── 13. Persist metadata + severity + IOCs to DB ──────────────────────
        flush_case(case)

        log.info(
            f"[INFO] Pipeline complete | case={case.case_number} "
            f"pid={pcap_db_id} flows={len(flows)} "
            f"beacons={len(beacons)} "
            f"iocs={len(ioc_report.iocs) if ioc_report else 0}"
        )

    finally:
        if own_conn and conn:
            conn.close()

    return case
