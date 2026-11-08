"""
engine/case_manager.py  —  Persistent case management (v2)

Cases are stored in BOTH the SQLite DB (persistent across restarts) AND
in an in-memory cache (for fast access to runtime analysis objects like
Flow instances, IOC objects, etc. that cannot be serialised to DB).

On startup: DB cases are loaded → registry populated with metadata.
After upload: analysis objects stored in memory cache, metadata in DB.
After restart: DB gives back all case metadata; analysis objects gone
  (re-upload triggers re-analysis; DB flow/IOC data still queryable).
"""
from __future__ import annotations

import uuid, datetime, hashlib, json, sqlite3, logging
from dataclasses import dataclass, field
from typing import Optional
from config import DB_PATH, CASES_DIR
from engine.database import init_db

log = logging.getLogger("case_manager")

# ── In-memory runtime cache (analysis objects, not serialisable) ───────────────
_cache: dict[str, "CaseState"] = {}
_hash_index: dict[str, str]    = {}   # file_hash → analysis_id


@dataclass
class CaseState:
    """Holds all analysis outputs for one investigation."""
    analysis_id:   str
    case_number:   str
    file_name:     str
    file_hash:     str
    created_at:    str
    pcap_db_id:    Optional[int] = None
    status:        str = "complete"
    source:        str = "cli"   # 'cli' or 'web' — determines subfolder

    # Runtime objects (in-memory only, lost on restart)
    flows:           list = field(default_factory=list)
    dissected:       list = field(default_factory=list)
    extracted_files: list = field(default_factory=list)
    beacons:         list = field(default_factory=list)
    dns_stats:       object = None
    ioc_report:      object = None
    attack_chains:   list = field(default_factory=list)
    host_profiles:   dict = field(default_factory=dict)
    timeline:        list = field(default_factory=list)
    stats_raw:       dict = field(default_factory=dict)

    @property
    def beacon_count(self)  -> int: return len(self.beacons)
    @property
    def ioc_count(self)     -> int:
        return len(self.ioc_report.iocs) if self.ioc_report else 0
    @property
    def chain_count(self)   -> int: return len(self.attack_chains)
    @property
    def threat_level(self)  -> str:
        if not self.ioc_report: return "LOW"
        c = self.ioc_report.critical_count
        h = self.ioc_report.high_count
        m = self.ioc_report.medium_count
        if c: return "CRITICAL"
        if h: return "HIGH"
        if m: return "MEDIUM"
        return "LOW"


# ── DB helpers ─────────────────────────────────────────────────────────────────

def _get_conn() -> sqlite3.Connection:
    conn = init_db(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _persist_case(case: CaseState, conn: Optional[sqlite3.Connection] = None):
    """Write or update case metadata row in DB."""
    own = conn is None
    if own: conn = _get_conn()
    conn.execute("""
        INSERT INTO cases
            (analysis_id, case_number, file_name, file_hash, pcap_db_id,
             created_at, status, beacon_count, ioc_count, chain_count,
             threat_level, source)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(analysis_id) DO UPDATE SET
            status=excluded.status,
            beacon_count=excluded.beacon_count,
            ioc_count=excluded.ioc_count,
            chain_count=excluded.chain_count,
            threat_level=excluded.threat_level,
            pcap_db_id=excluded.pcap_db_id,
            source=excluded.source
    """, (case.analysis_id, case.case_number, case.file_name, case.file_hash,
          case.pcap_db_id, case.created_at, case.status,
          case.beacon_count, case.ioc_count, case.chain_count,
          case.threat_level, case.source))
    conn.commit()
    if own: conn.close()


def _persist_severity(case: CaseState, conn: Optional[sqlite3.Connection] = None):
    """Write severity breakdown to DB so dashboard works after restart."""
    if not case.ioc_report: return
    own = conn is None
    if own: conn = _get_conn()
    # Upsert each severity level
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = sum(1 for i in case.ioc_report.iocs if i.severity == sev)
        conn.execute("""
            INSERT INTO case_severity (analysis_id, severity, count)
            VALUES (?,?,?)
            ON CONFLICT(analysis_id, severity) DO UPDATE SET count=excluded.count
        """, (case.analysis_id, sev, count))

    # Persist IOCs
    conn.execute("DELETE FROM case_iocs WHERE analysis_id=?", (case.analysis_id,))
    for ioc in case.ioc_report.iocs:
        conn.execute("""
            INSERT INTO case_iocs
                (analysis_id, ioc_type, value, threat_score, severity,
                 mitre_tactic, mitre_technique, sources, context, reasons)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (case.analysis_id, ioc.ioc_type, ioc.value, ioc.threat_score,
              ioc.severity, getattr(ioc,"mitre_tactic",""),
              getattr(ioc,"mitre_technique",""),
              json.dumps(ioc.sources), ioc.context,
              json.dumps(ioc.reasons)))
    conn.commit()
    if own: conn.close()


def _load_cases_from_db():
    """Reload case metadata from DB into in-memory index on startup."""
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT * FROM cases ORDER BY created_at DESC"
        ).fetchall()
        for row in rows:
            aid = row["analysis_id"]
            if aid not in _cache:
                c = CaseState(
                    analysis_id = aid,
                    case_number = row["case_number"],
                    file_name   = row["file_name"],
                    file_hash   = row["file_hash"],
                    pcap_db_id  = row["pcap_db_id"],
                    created_at  = row["created_at"],
                    status      = row["status"] or "complete",
                    source      = row["source"] if "source" in row.keys() else "cli",
                )
                _cache[aid] = c
                _hash_index[row["file_hash"]] = aid
        conn.close()
        if rows:
            log.info(f"Loaded {len(rows)} case(s) from DB")
    except Exception as e:
        log.warning(f"Could not load cases from DB: {e}")


# Bootstrap on import
_load_cases_from_db()


# ── Public API ─────────────────────────────────────────────────────────────────

def create_case(case_number: str, file_name: str, file_hash: str,
               source: str = "cli") -> CaseState:
    aid  = str(uuid.uuid4())
    now  = datetime.datetime.utcnow().isoformat() + "Z"
    case = CaseState(analysis_id=aid, case_number=case_number.strip(),
                     file_name=file_name, file_hash=file_hash, created_at=now,
                     source=source if source in ("cli","web") else "cli")
    _cache[aid]             = case
    _hash_index[file_hash]  = aid
    _persist_case(case)
    init_case_folder(case)   # create output folder immediately
    log.info(f"[INFO] New case: {case_number!r}  id={aid}")
    return case


def get_case(analysis_id: str) -> Optional[CaseState]:
    return _cache.get(analysis_id) if analysis_id else None


def find_by_hash(file_hash: str) -> Optional[CaseState]:
    aid = _hash_index.get(file_hash)
    return _cache.get(aid) if aid else None


def find_by_case_number(case_number: str) -> Optional[CaseState]:
    for c in _cache.values():
        if c.case_number == case_number:
            return c
    return None


def list_cases() -> list[CaseState]:
    return sorted(_cache.values(), key=lambda c: c.created_at, reverse=True)


def case_dir(case: "CaseState") -> "Path":
    """
    Return the Path to this case's output folder.
    Format: cases/<CASE_NUMBER>_<analysis_id[:8]>/
    Sanitises case_number to be filesystem-safe.
    """
    from pathlib import Path
    safe_name = "".join(
        c if c.isalnum() or c in "-_." else "_"
        for c in case.case_number
    ).strip("_")
    folder_name = f"{safe_name}_{case.analysis_id[:8]}"
    # Segregate into cases/cli/ or cases/web/ based on origin
    subfolder = case.source if case.source in ("cli", "web") else "cli"
    return Path(CASES_DIR) / subfolder / folder_name


def init_case_folder(case: "CaseState") -> "Path":
    """
    Create the case output folder and write a metadata stub.
    Called immediately after create_case() so the folder exists
    before any analysis runs — both from CLI and Web.

    Folder structure:
        cases/<case_name>_<aid8>/
            case_meta.json       ← case metadata (always present)
            <pcap_filename>      ← copy of original PCAP (written by pipeline)
            iocs.csv             ← IOC export (written by flush_case)
            iocs.json            ← IOC export (written by flush_case)
            summary.json         ← analysis summary (written by flush_case)
            report.pdf           ← PDF report (written on demand)
    """
    import json
    from pathlib import Path

    folder = case_dir(case)
    folder.mkdir(parents=True, exist_ok=True)

    meta = {
        "analysis_id":  case.analysis_id,
        "case_number":  case.case_number,
        "file_name":    case.file_name,
        "file_hash":    case.file_hash,
        "created_at":   case.created_at,
        "status":       case.status,
        "source":       case.source,
    }
    (folder / "case_meta.json").write_text(json.dumps(meta, indent=2))
    log.info(f"[INFO] Case folder created: {folder}")
    return folder


def flush_case_folder(case: "CaseState"):
    """
    Write all exportable artefacts to the case folder after pipeline completes.
    Called inside flush_case() — safe to call multiple times (overwrites).
    """
    import json
    from pathlib import Path

    if not case.ioc_report:
        return

    folder = case_dir(case)
    folder.mkdir(parents=True, exist_ok=True)

    # IOC exports
    try:
        from modules.ioc_aggregator import export_csv, export_json as export_ioc_json
        (folder / "iocs.csv").write_text(export_csv(case.ioc_report))
        (folder / "iocs.json").write_text(export_ioc_json(case.ioc_report))
    except Exception as e:
        log.warning(f"Could not write IOC exports to case folder: {e}")

    # Analysis summary
    summary = {
        "analysis_id":   case.analysis_id,
        "case_number":   case.case_number,
        "file_name":     case.file_name,
        "file_hash":     case.file_hash,
        "created_at":    case.created_at,
        "status":        case.status,
        "threat_level":  case.threat_level,
        "flows":         len(case.flows or []),
        "beacons":       case.beacon_count,
        "iocs":          case.ioc_count,
        "attack_chains": case.chain_count,
    }
    (folder / "summary.json").write_text(json.dumps(summary, indent=2))
    log.info(f"[INFO] Case folder updated: {folder}")


def flush_case(case: CaseState):
    """Call after pipeline completes — writes metadata to DB and artefacts to case folder."""
    _persist_case(case)
    _persist_severity(case)
    persist_timeline(case)
    flush_case_folder(case)   # write IOCs, summary to case output folder
    # Link pcap_files row to this case
    if case.pcap_db_id:
        try:
            conn = _get_conn()
            conn.execute("UPDATE pcap_files SET analysis_id=? WHERE id=?",
                         (case.analysis_id, case.pcap_db_id))
            conn.commit()
            conn.close()
        except Exception as e:
            log.warning(f"Could not link pcap to case: {e}")


def persist_timeline(case: "CaseState",
                     conn: Optional[sqlite3.Connection] = None):
    """Persist traffic timeline buckets to DB."""
    if not case.timeline:
        return
    own = conn is None
    if own: conn = _get_conn()
    try:
        conn.execute("DELETE FROM case_timeline WHERE analysis_id=?",
                     (case.analysis_id,))
        rows = []
        for b in case.timeline:
            if isinstance(b, dict):
                rows.append((case.analysis_id,
                              str(b.get("time", "")),
                              int(b.get("packets", 0)),
                              int(b.get("bytes", 0))))
        if rows:
            conn.executemany("""
                INSERT OR REPLACE INTO case_timeline
                    (analysis_id, bucket_time, packet_count, byte_count)
                VALUES (?,?,?,?)
            """, rows)
        conn.commit()
    finally:
        if own: conn.close()


def get_timeline_from_db(analysis_id: str) -> list[dict]:
    """Returns timeline buckets from DB — works after restart."""
    try:
        conn = _get_conn()
        rows = conn.execute(
            """SELECT bucket_time, packet_count, byte_count
               FROM case_timeline WHERE analysis_id=?
               ORDER BY bucket_time""",
            (analysis_id,)
        ).fetchall()
        conn.close()
        return [{"time": r["bucket_time"],
                 "packets": r["packet_count"],
                 "bytes":   r["byte_count"]}
                for r in rows]
    except Exception:
        return []


def get_severity_from_db(analysis_id: str) -> dict:
    """Returns severity breakdown from DB — works even after restart."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    try:
        conn = _get_conn()
        rows = conn.execute(
            "SELECT severity, count FROM case_severity WHERE analysis_id=?",
            (analysis_id,)
        ).fetchall()
        conn.close()
        for r in rows:
            if r["severity"] in counts:
                counts[r["severity"]] = r["count"]
    except Exception:
        pass
    return counts


def get_iocs_from_db(analysis_id: str) -> list[dict]:
    """
    Returns IOC list from DB normalised to the same key schema
    used by the in-memory path — so templates work identically
    after restart.  Key mapping:
        ioc_type       → type
        threat_score   → score
        mitre_tactic   → tactic
        mitre_technique → technique
    """
    try:
        conn = _get_conn()
        rows = conn.execute(
            """SELECT ioc_type, value, threat_score, severity,
                      mitre_tactic, mitre_technique, sources, context, reasons
               FROM case_iocs WHERE analysis_id=? ORDER BY threat_score DESC""",
            (analysis_id,)
        ).fetchall()
        conn.close()
        result = []
        for r in rows:
            d = dict(r)
            # Normalise to in-memory schema
            d["type"]      = d.pop("ioc_type",      "")
            d["score"]     = d.pop("threat_score",  0)
            d["tactic"]    = d.pop("mitre_tactic",  "")
            d["technique"] = d.pop("mitre_technique","")
            result.append(d)
        return result
    except Exception:
        return []


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
