"""
web/app.py  —  PCAP Engine Flask Dashboard  (v2.3 — persistent + isolated)

Fixes applied:
  A. Cases are now persisted to DB — survive server restarts
  B. View button exists on every historical row via analysis_id linkage
  C. All queries strictly filtered by case analysis_id / pcap_db_id
  D. CLI and Web both call engine.pipeline.run_analysis() — no duplication
  E. Severity breakdown reads from DB — works after restart, no in-memory dep
  F. Input validation centralised in _validate()
  G. Sessions page enforces case isolation — returns [] without analysis_id
"""

import os, sys, json, tempfile, re
from pathlib import Path

from flask import (Flask, render_template, request, redirect, url_for,
                   jsonify, send_file, flash, g, make_response, abort)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from engine.database    import init_db, get_stats
from engine.case_manager import (create_case, get_case, find_by_hash,
                                  find_by_case_number, list_cases, sha256_file,
                                  get_severity_from_db, get_iocs_from_db,
                                  case_dir)
from engine.pipeline    import run_analysis
from modules.ioc_aggregator import export_csv, export_json
from reports.pdf_generator  import generate_report
from engine.logger      import get_logger
from config             import DB_PATH, EXTRACTED_DIR, REPORTS_DIR

log = get_logger("web")

# ── Input validation ───────────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

def _valid_uuid(val: str) -> bool:
    return bool(val and _UUID_RE.match(val.strip().lower()))

def _safe_int(val, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default

def _require_case(analysis_id: str):
    """Return case or abort 404 — used in routes that need a valid case."""
    if not _valid_uuid(analysis_id):
        abort(400, "Invalid analysis_id")
    case = get_case(analysis_id)
    if not case:
        abort(404, "Case not found — it may have been run in a previous session. "
                   "Re-upload the PCAP to regenerate in-memory results.")
    return case


# ── App factory ────────────────────────────────────────────────────────────────

def create_app() -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.secret_key = os.urandom(24)
    app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
    app.config["UPLOAD_FOLDER"]      = tempfile.mkdtemp(prefix="pcap_uploads_")
    os.makedirs(EXTRACTED_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR,   exist_ok=True)

    def get_db():
        if "db" not in g:
            g.db = init_db(DB_PATH)
        return g.db

    @app.teardown_appcontext
    def close_db(e=None):
        db = g.pop("db", None)
        if db: db.close()

    # ══════════════════════════════════════════════════════════════════════════
    # PAGE ROUTES
    # ══════════════════════════════════════════════════════════════════════════

    @app.route("/")
    def index():
        db    = get_db()
        stats = get_stats(db)

        # FIX B+A: Load cases from DB (persistent) and merge with in-memory
        # list_cases() already loads from DB on startup, so this is always fresh
        cases = list_cases()[:15]

        # FIX B: Historical table now has analysis_id — enables View button
        pcaps = db.execute("""
            SELECT p.*, c.analysis_id, c.case_number, c.threat_level,
                   c.beacon_count, c.ioc_count
            FROM   pcap_files p
            LEFT JOIN cases c ON c.pcap_db_id = p.id
            ORDER BY p.analysed_at DESC LIMIT 15
        """).fetchall()

        return render_template("index.html",
                               stats=stats,
                               cases=cases,
                               pcaps=[dict(p) for p in pcaps])

    # ── Upload ─────────────────────────────────────────────────────────────────
    @app.route("/upload", methods=["GET", "POST"])
    def upload():
        if request.method == "GET":
            return render_template("upload.html")

        f           = request.files.get("pcap")
        case_number = request.form.get("case_number", "").strip()

        # Validation
        if not f or not f.filename:
            flash("No file selected", "error")
            return redirect(url_for("upload"))
        if not case_number:
            flash("Case number is required", "error")
            return redirect(url_for("upload"))
        if not f.filename.lower().endswith((".pcap", ".pcapng", ".cap")):
            flash("Only .pcap / .pcapng / .cap files accepted", "error")
            return redirect(url_for("upload"))

        # FIX F: validate case number isn't already in use
        existing_case_num = find_by_case_number(case_number)
        if existing_case_num:
            flash(f"Case number '{case_number}' already exists. "
                  f"Use a unique case number.", "error")
            return redirect(url_for("upload"))

        save_path = os.path.join(app.config["UPLOAD_FOLDER"], f.filename)
        f.save(save_path)

        # Duplicate PCAP detection
        file_hash = sha256_file(save_path)
        existing  = find_by_hash(file_hash)
        if existing:
            flash(f"This file was already analysed under case "
                  f"'{existing.case_number}'. Showing existing results.", "info")
            log.warning(f"[WARNING] Duplicate file: {f.filename} → {existing.case_number}")
            return redirect(url_for("analysis", analysis_id=existing.analysis_id))

        case = create_case(case_number, f.filename, file_hash, source="web")

        try:
            run_analysis(save_path, case, get_db())
            flash(f"Analysis complete — {case_number}", "success")
            return redirect(url_for("analysis", analysis_id=case.analysis_id))
        except Exception as exc:
            log.error(f"[ERROR] Pipeline: {exc}")
            flash(f"Analysis failed: {exc}", "error")
            return redirect(url_for("upload"))

    # ── Per-case analysis overview ─────────────────────────────────────────────
    @app.route("/analysis/<analysis_id>")
    def analysis(analysis_id: str):
        if not _valid_uuid(analysis_id):
            flash("Invalid analysis ID", "error")
            return redirect(url_for("index"))

        # FIX A: load from DB if not in memory (after restart)
        case = get_case(analysis_id)
        if not case:
            flash("Case loaded from DB (in-memory results unavailable — "
                  "re-upload to regenerate detections).", "info")
            # Build a thin shell from DB row
            db  = get_db()
            row = db.execute(
                "SELECT * FROM cases WHERE analysis_id=?", (analysis_id,)
            ).fetchone()
            if not row:
                flash("Case not found", "error")
                return redirect(url_for("index"))
            from engine.case_manager import CaseState
            case = CaseState(
                analysis_id=row["analysis_id"],
                case_number=row["case_number"],
                file_name=row["file_name"],
                file_hash=row["file_hash"],
                pcap_db_id=row["pcap_db_id"],
                created_at=row["created_at"],
                status=row["status"] or "complete",
            )

        db         = get_db()
        pid        = case.pcap_db_id
        pcap_row   = db.execute("SELECT * FROM pcap_files WHERE id=?", (pid,)).fetchone() if pid else None
        flow_count = db.execute("SELECT COUNT(*) FROM flows WHERE pcap_id=?", (pid,)).fetchone()[0] if pid else 0
        http_count = db.execute("SELECT COUNT(*) FROM http_sessions WHERE pcap_id=?", (pid,)).fetchone()[0] if pid else 0

        # Severity from DB (persistent, works after restart)
        sev = get_severity_from_db(analysis_id)

        return render_template("analysis.html",
                               case=case,
                               pcap=dict(pcap_row) if pcap_row else {},
                               flow_count=flow_count,
                               http_count=http_count,
                               beacon_count=case.beacon_count,
                               ioc_count=case.ioc_count,
                               chain_count=case.chain_count,
                               severity=sev,
                               analysis_id=analysis_id)

    # ── Sessions — FIX C/D: strictly isolated, returns empty without valid ID ──
    @app.route("/sessions")
    def sessions():
        analysis_id = request.args.get("analysis_id", "").strip()
        proto       = request.args.get("proto", "").strip().upper()
        min_bytes   = _safe_int(request.args.get("min_bytes"), 0)
        search      = request.args.get("search", "").strip()

        if not _valid_uuid(analysis_id):
            # FIX C: no analysis_id = empty table, not global dump
            return render_template("sessions.html", flows=[], proto=proto,
                                   min_bytes=min_bytes, search=search,
                                   analysis_id="", no_case=True)

        case = get_case(analysis_id)
        pid  = case.pcap_db_id if case else None

        if pid is None:
            # Try DB fallback
            db  = get_db()
            row = db.execute("SELECT pcap_db_id FROM cases WHERE analysis_id=?",
                             (analysis_id,)).fetchone()
            pid = row["pcap_db_id"] if row else None

        if pid is None:
            return render_template("sessions.html", flows=[], proto=proto,
                                   min_bytes=min_bytes, search=search,
                                   analysis_id=analysis_id, no_case=False)

        db     = get_db()
        params = [min_bytes, pid]
        q = """SELECT src_ip, dst_ip, src_port, dst_port, protocol,
                      service, packet_count, byte_count, duration_sec,
                      threat_score, first_seen, flags_seen, payload_preview
               FROM flows
               WHERE byte_count >= ? AND pcap_id = ?"""

        if proto:
            q += " AND protocol = ?"; params.append(proto)
        if search:
            q += """ AND (src_ip LIKE ? OR dst_ip LIKE ?
                    OR CAST(src_port AS TEXT)=? OR CAST(dst_port AS TEXT)=?
                    OR service LIKE ?)"""
            like = f"%{search}%"
            params += [like, like, search, search, like]
        q += " ORDER BY byte_count DESC LIMIT 200"

        flows = db.execute(q, params).fetchall()
        return render_template("sessions.html",
                               flows=[dict(f) for f in flows],
                               proto=proto, min_bytes=min_bytes,
                               search=search, analysis_id=analysis_id,
                               no_case=False)

    # ── IOCs — reads from DB if in-memory unavailable ─────────────────────────
    @app.route("/iocs")
    def iocs():
        analysis_id = request.args.get("analysis_id", "").strip()
        ioc_list    = []

        case = get_case(analysis_id) if _valid_uuid(analysis_id) else None

        if case and case.ioc_report and hasattr(case.ioc_report, "iocs"):
            # In-memory path (full pipeline ran this session)
            ioc_list = [
                {"type": i.ioc_type, "value": i.value, "score": i.threat_score,
                 "severity": i.severity,
                 "tactic":    getattr(i, "mitre_tactic", ""),
                 "technique": getattr(i, "mitre_technique", ""),
                 "sources":   ", ".join(i.sources),
                 "context":   i.context,
                 "reasons":   " | ".join(i.reasons[:2])}
                for i in case.ioc_report.iocs
            ]
        elif _valid_uuid(analysis_id):
            # DB fallback — works after restart
            ioc_list = get_iocs_from_db(analysis_id)

        return render_template("iocs.html", iocs=ioc_list, analysis_id=analysis_id)

    @app.route("/beacons")
    def beacons_page():
        analysis_id = request.args.get("analysis_id", "").strip()
        case        = get_case(analysis_id) if _valid_uuid(analysis_id) else None
        beacons     = []
        if case:
            beacons = [{
                "severity":        b.severity,
                "score":           b.threat_score,
                "confidence":      round(getattr(b, "confidence", 0) * 100),
                "src_ip":          b.src_ip,
                "dst_ip":          b.dst_ip,
                "dst_port":        b.dst_port,
                "protocol":        b.protocol,
                "src_class":       getattr(b, "src_classification", "PUBLIC"),
                "dst_class":       getattr(b, "dst_classification", "PUBLIC"),
                "interval_mean":   round(b.interval_mean, 2),
                "interval_cv":     round(b.interval_cv, 3),
                "payload_entropy": round(getattr(b, "payload_entropy", 0), 2),
                "packet_count":    b.packet_count,
                "ja3":             b.ja3_hash or "",
                "ja3_match":       b.ja3_match or "",
                "rules_triggered": getattr(b, "rules_triggered", []),
                "reasons":         b.reasons,
            } for b in case.beacons]
        return render_template("beacons.html", beacons=beacons,
                               analysis_id=analysis_id)

    @app.route("/dns")
    def dns_page():
        analysis_id = request.args.get("analysis_id", "").strip()
        case        = get_case(analysis_id) if _valid_uuid(analysis_id) else None
        dns_stats   = case.dns_stats if case else None
        findings, top_queried, dns_summary = [], [], {}
        if dns_stats:
            dns_summary = {
                "total_queries":  dns_stats.total_queries,
                "unique_domains": dns_stats.unique_domains,
                "suspicious":     len(dns_stats.findings),
                "tunnelling":     dns_stats.tunnelling_flows,
                "dga":            dns_stats.dga_flows,
            }
            findings = [{
                "severity": f.severity, "score": f.threat_score,
                "domain": f.domain, "src_ip": f.src_ip,
                "queries": f.query_count, "entropy": round(f.entropy, 3),
                "max_label": f.max_label_len, "is_tunnel": f.is_tunnelling,
                "is_dga": f.is_dga, "reasons": f.reasons,
                "samples": f.sample_queries[:3],
            } for f in dns_stats.findings]
            top_queried = dns_stats.top_queried[:15]
        return render_template("dns.html", findings=findings,
                               top_queried=top_queried, dns_summary=dns_summary,
                               analysis_id=analysis_id)

    @app.route("/files")
    def files_page():
        analysis_id = request.args.get("analysis_id", "").strip()
        case        = get_case(analysis_id) if _valid_uuid(analysis_id) else None
        files = [{
            "filename": ef.filename, "size": ef.size_bytes, "type": ef.file_type,
            "method": ef.extract_method, "sha256": ef.sha256, "md5": ef.md5,
            "verdict": ef.vt_verdict, "malicious": ef.vt_malicious,
            "total": ef.vt_total, "vt_link": ef.vt_link, "source": ef.source_flow,
        } for ef in (case.extracted_files if case else [])]
        return render_template("files.html", files=files, analysis_id=analysis_id)

    @app.route("/chains")
    def chains_page():
        analysis_id = request.args.get("analysis_id", "").strip()
        case        = get_case(analysis_id) if _valid_uuid(analysis_id) else None
        chains = [{
            "src_ip": c.src_ip, "severity": c.severity, "score": c.threat_score,
            "phases": c.phases, "start_time": c.start_time, "end_time": c.end_time,
            "duration": round(c.duration_sec, 1), "narrative": c.narrative,
            "mitre": c.mitre_tactics, "event_count": len(c.events),
        } for c in (case.attack_chains if case else [])]
        return render_template("chains.html", chains=chains, analysis_id=analysis_id)

    @app.route("/timeline")
    def timeline():
        analysis_id = request.args.get("analysis_id", "").strip()
        return render_template("timeline.html", analysis_id=analysis_id)

    # ══════════════════════════════════════════════════════════════════════════
    # JSON API — all return valid JSON, never crash
    # ══════════════════════════════════════════════════════════════════════════

    @app.route("/api/stats")
    def api_stats():
        return jsonify(get_stats(get_db()))

    @app.route("/api/flows")
    def api_flows():
        # FIX C: require analysis_id — never return global dump
        analysis_id = request.args.get("analysis_id", "").strip()
        if not _valid_uuid(analysis_id):
            return jsonify([])
        case = get_case(analysis_id)
        pid  = case.pcap_db_id if case else None
        if pid is None:
            db  = get_db()
            row = db.execute("SELECT pcap_db_id FROM cases WHERE analysis_id=?",
                             (analysis_id,)).fetchone()
            pid = row["pcap_db_id"] if row else None
        if pid is None:
            return jsonify([])
        limit = min(_safe_int(request.args.get("limit"), 100), 500)
        db    = get_db()
        rows  = db.execute("""
            SELECT src_ip, dst_ip, src_port, dst_port, protocol, service,
                   packet_count, byte_count, duration_sec, threat_score,
                   first_seen, last_seen, flags_seen, payload_preview
            FROM flows WHERE pcap_id=?
            ORDER BY byte_count DESC LIMIT ?
        """, (pid, limit)).fetchall()
        return jsonify([dict(r) for r in rows])

    @app.route("/api/timeline")
    def api_timeline():
        analysis_id = request.args.get("analysis_id", "").strip()
        if not _valid_uuid(analysis_id):
            return jsonify([])
        case = get_case(analysis_id)
        # In-memory path (current session)
        if case and case.timeline:
            return jsonify([
                {"time": str(b.get("time","")), "packets": int(b.get("packets",0)),
                 "bytes": int(b.get("bytes",0))}
                for b in case.timeline if isinstance(b, dict)
            ])
        # DB fallback — works after restart
        from engine.case_manager import get_timeline_from_db
        return jsonify(get_timeline_from_db(analysis_id))

    @app.route("/api/iocs")
    def api_iocs():
        analysis_id = request.args.get("analysis_id", "").strip()
        if not _valid_uuid(analysis_id):
            return jsonify([])
        case = get_case(analysis_id)
        if case and case.ioc_report and hasattr(case.ioc_report, "iocs"):
            return jsonify([{
                "type": i.ioc_type, "value": i.value, "score": i.threat_score,
                "severity": i.severity, "tactic": getattr(i,"mitre_tactic",""),
                "technique": getattr(i,"mitre_technique",""), "context": i.context,
            } for i in case.ioc_report.iocs])
        # DB fallback
        return jsonify(get_iocs_from_db(analysis_id))

    @app.route("/api/graph")
    def api_graph():
        analysis_id = request.args.get("analysis_id", "").strip()
        if not _valid_uuid(analysis_id):
            return jsonify({"nodes": [], "edges": []})
        case = get_case(analysis_id)
        pid  = case.pcap_db_id if case else None
        if pid is None:
            db  = get_db()
            row = db.execute("SELECT pcap_db_id FROM cases WHERE analysis_id=?",
                             (analysis_id,)).fetchone()
            pid = row["pcap_db_id"] if row else None
        if pid is None:
            return jsonify({"nodes": [], "edges": []})
        db   = get_db()
        # Aggregate edges: group by (src_ip, dst_ip, protocol) for cleaner graph
        rows = db.execute("""
            SELECT src_ip, dst_ip, protocol,
                   SUM(byte_count)   AS total_bytes,
                   SUM(packet_count) AS total_pkts,
                   MAX(threat_score) AS max_threat,
                   GROUP_CONCAT(DISTINCT service) AS services,
                   COUNT(*)          AS flow_count
            FROM flows WHERE pcap_id=?
            GROUP BY src_ip, dst_ip, protocol
            ORDER BY total_bytes DESC LIMIT 200
        """, (pid,)).fetchall()
        nodes: dict[str, dict] = {}
        edges = []
        from modules.traffic_classifier import classify_ip
        for r in rows:
            src = r["src_ip"] or "?"
            dst = r["dst_ip"] or "?"
            for ip, role in ((src, "src"), (dst, "dst")):
                if ip not in nodes:
                    cls = classify_ip(ip)
                    nodes[ip] = {
                        "id":       ip,
                        "private":  cls.is_internal,
                        "category": cls.category,
                        "threat":   0,
                        "cloud_provider": cls.cloud_provider or "",
                    }
            # Accumulate max threat on destination node
            nodes[dst]["threat"] = max(nodes[dst]["threat"], r["max_threat"] or 0)
            # Also propagate to source if it's an internal host with high-threat flows
            if nodes[src]["private"] and (r["max_threat"] or 0) >= 60:
                nodes[src]["threat"] = max(nodes[src]["threat"], (r["max_threat"] or 0) // 2)

            total_bytes = r["total_bytes"] or 0
            edges.append({
                "source":     src,
                "target":     dst,
                "proto":      r["protocol"],
                "bytes":      total_bytes,
                "weight":     max(1, int(total_bytes ** 0.4)),  # log-scale for D3 edge width
                "packets":    r["total_pkts"] or 0,
                "flows":      r["flow_count"] or 1,
                "service":    (r["services"] or "").split(",")[0],
                "threat":     r["max_threat"] or 0,
            })
        return jsonify({"nodes": list(nodes.values()), "edges": edges})

    @app.route("/api/protocol_breakdown")
    def api_protocol_breakdown():
        analysis_id = request.args.get("analysis_id", "").strip()
        db  = get_db()
        if _valid_uuid(analysis_id):
            case = get_case(analysis_id)
            pid  = case.pcap_db_id if case else None
            if pid is None:
                row = db.execute("SELECT pcap_db_id FROM cases WHERE analysis_id=?",
                                 (analysis_id,)).fetchone()
                pid = row["pcap_db_id"] if row else None
            if pid:
                rows = db.execute("""
                    SELECT protocol, COUNT(*) as cnt, SUM(byte_count) as bytes
                    FROM flows WHERE pcap_id=?
                    GROUP BY protocol ORDER BY cnt DESC
                """, (pid,)).fetchall()
                return jsonify([dict(r) for r in rows])
        # Global aggregate for dashboard overview
        rows = db.execute("""
            SELECT protocol, COUNT(*) as cnt, SUM(byte_count) as bytes
            FROM flows GROUP BY protocol ORDER BY cnt DESC
        """).fetchall()
        return jsonify([dict(r) for r in rows])

    # FIX E: severity reads from DB — works after restart
    @app.route("/api/severity_breakdown")
    def api_severity_breakdown():
        analysis_id = request.args.get("analysis_id", "").strip()

        # Per-case breakdown (priority)
        if _valid_uuid(analysis_id):
            case = get_case(analysis_id)
            if case and case.ioc_report and hasattr(case.ioc_report, "iocs"):
                counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
                for i in case.ioc_report.iocs:
                    if i.severity in counts:
                        counts[i.severity] += 1
                return jsonify(counts)
            # DB fallback — works after restart
            return jsonify(get_severity_from_db(analysis_id))

        # Global aggregate for dashboard (no case selected)
        try:
            db    = get_db()
            rows  = db.execute("""
                SELECT severity, SUM(count) as total
                FROM case_severity GROUP BY severity
            """).fetchall()
            counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for r in rows:
                if r["severity"] in counts:
                    counts[r["severity"]] = r["total"] or 0
            return jsonify(counts)
        except Exception:
            return jsonify({"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})

    @app.route("/api/attack_chains")
    def api_attack_chains():
        analysis_id = request.args.get("analysis_id", "").strip()
        case        = get_case(analysis_id) if _valid_uuid(analysis_id) else None
        if not case:
            return jsonify([])
        return jsonify([{
            "src_ip": c.src_ip, "severity": c.severity, "score": c.threat_score,
            "phases": c.phases, "narrative": c.narrative,
            "mitre": c.mitre_tactics, "start": c.start_time, "end": c.end_time,
        } for c in case.attack_chains])

    # ══════════════════════════════════════════════════════════════════════════
    # EXPORTS
    # ══════════════════════════════════════════════════════════════════════════

    @app.route("/export/iocs.csv")
    def export_iocs_csv():
        analysis_id = request.args.get("analysis_id", "").strip()
        case        = get_case(analysis_id) if _valid_uuid(analysis_id) else None
        if not case or not case.ioc_report:
            return make_response("No IOC data", 404)
        # Write to case folder for persistence
        folder = case_dir(case)
        folder.mkdir(parents=True, exist_ok=True)
        csv_content = export_csv(case.ioc_report)
        try:
            (folder / "iocs.csv").write_text(csv_content)
        except Exception:
            pass
        resp = make_response(csv_content)
        resp.headers["Content-Type"]        = "text/csv; charset=utf-8"
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="iocs_{case.case_number}.csv"')
        return resp

    @app.route("/export/iocs.json")
    def export_iocs_json():
        analysis_id = request.args.get("analysis_id", "").strip()
        case        = get_case(analysis_id) if _valid_uuid(analysis_id) else None
        if not case or not case.ioc_report:
            return make_response("No IOC data", 404)
        # Write to case folder for persistence
        folder = case_dir(case)
        folder.mkdir(parents=True, exist_ok=True)
        json_content = export_json(case.ioc_report)
        try:
            (folder / "iocs.json").write_text(json_content)
        except Exception:
            pass
        resp = make_response(json_content)
        resp.headers["Content-Type"]        = "application/json; charset=utf-8"
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="iocs_{case.case_number}.json"')
        return resp

    @app.route("/export/report.pdf")
    def export_pdf():
        analysis_id = request.args.get("analysis_id", "").strip()
        if not _valid_uuid(analysis_id):
            return make_response("analysis_id required", 400)

        case = get_case(analysis_id)
        if not case:
            db  = get_db()
            row = db.execute("SELECT * FROM cases WHERE analysis_id=?",
                             (analysis_id,)).fetchone()
            if not row:
                return make_response("Case not found", 404)
            flash("In-memory results unavailable — re-upload PCAP for fresh PDF", "info")
            return redirect(url_for("analysis", analysis_id=analysis_id))

        # Use case folder as output dir (web cases go to cases/web/<case>/)
        folder = case_dir(case)
        folder.mkdir(parents=True, exist_ok=True)

        # Check if PDF already exists in case folder (from previous export)
        existing_pdfs = list(folder.glob("forensic_report_*.pdf"))
        if not existing_pdfs:
            # Generate fresh
            db       = get_db()
            pcap_row = db.execute("SELECT * FROM pcap_files WHERE id=?",
                                   (case.pcap_db_id,)).fetchone() if case.pcap_db_id else None
            report_data = {
                "meta": dict(pcap_row) if pcap_row else {
                    "filename": case.file_name, "sha256": case.file_hash,
                    "file_size": 0, "path": str(folder / case.file_name)},
                "stats":           case.stats_raw,
                "flows":           case.flows,
                "beacons":         case.beacons,
                "dns_stats":       case.dns_stats,
                "ioc_report":      case.ioc_report,
                "extracted_files": case.extracted_files,
                "case_info": {
                    "analyst_name": request.args.get("analyst", "SOC Analyst"),
                    "case_number":  case.case_number,
                    "organisation": request.args.get("org", "Digital Forensics Lab"),
                },
            }
            try:
                pdf_path = generate_report(report_data, output_dir=str(folder))
            except Exception as exc:
                log.error(f"[ERROR] PDF: {exc}")
                return make_response(f"PDF failed: {exc}", 500)
        else:
            pdf_path = str(sorted(existing_pdfs)[-1])  # most recent

        return send_file(os.path.abspath(pdf_path), mimetype="application/pdf",
                         as_attachment=True,
                         download_name=f"report_{case.case_number}.pdf",
                         max_age=0)

    return app


if __name__ == "__main__":
    app = create_app()
    print("\n  PCAP Engine  —  http://127.0.0.1:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
