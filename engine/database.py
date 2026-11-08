"""
engine/database.py
────────────────────────────────────────────────────────────────────────────────
SQLite database layer for the PCAP engine.

Schema:
  pcap_files  — one row per ingested PCAP (metadata + chain-of-custody hash)
  flows       — one row per reconstructed TCP/UDP/ICMP flow (5-tuple)
  packets     — one row per packet, foreign-keyed to a flow
  http_sessions — parsed HTTP request/response pairs extracted from flows

All timestamps are stored as ISO-8601 strings (UTC).
"""

import sqlite3
import os
from pathlib import Path
from engine.logger import get_logger

log = get_logger(__name__)


# ── Schema DDL ─────────────────────────────────────────────────────────────────

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS pcap_files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    filename    TEXT    NOT NULL,
    filepath    TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    file_size   INTEGER NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    first_packet TEXT,
    last_packet  TEXT,
    duration_sec REAL,
    analysed_at  TEXT    DEFAULT (datetime('now')),
    analysis_id  TEXT,
    UNIQUE(sha256)
);

CREATE TABLE IF NOT EXISTS flows (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    pcap_id      INTEGER NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    protocol     TEXT    NOT NULL,
    service      TEXT,
    packet_count INTEGER NOT NULL DEFAULT 0,
    byte_count   INTEGER NOT NULL DEFAULT 0,
    first_seen   TEXT,
    last_seen    TEXT,
    duration_sec REAL,
    flags_seen   TEXT,
    payload_preview TEXT,
    threat_score INTEGER DEFAULT 0,
    tags         TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS packets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id    INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    pcap_id    INTEGER NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    timestamp  TEXT    NOT NULL,
    src_ip     TEXT,
    dst_ip     TEXT,
    src_port   INTEGER,
    dst_port   INTEGER,
    protocol   TEXT,
    length     INTEGER,
    flags      TEXT,
    payload_hex TEXT
);

CREATE TABLE IF NOT EXISTS http_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    flow_id      INTEGER NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
    pcap_id      INTEGER NOT NULL REFERENCES pcap_files(id) ON DELETE CASCADE,
    method       TEXT,
    host         TEXT,
    uri          TEXT,
    user_agent   TEXT,
    status_code  INTEGER,
    content_type TEXT,
    body_size    INTEGER,
    request_time TEXT,
    full_request  TEXT,
    full_response TEXT
);

CREATE INDEX IF NOT EXISTS idx_flows_pcap    ON flows(pcap_id);
CREATE INDEX IF NOT EXISTS idx_flows_src_ip  ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_dst_ip  ON flows(dst_ip);
CREATE INDEX IF NOT EXISTS idx_flows_proto   ON flows(protocol);
CREATE INDEX IF NOT EXISTS idx_packets_flow  ON packets(flow_id);
CREATE INDEX IF NOT EXISTS idx_http_flow     ON http_sessions(flow_id);

-- Persistent case registry (v2.3)
CREATE TABLE IF NOT EXISTS cases (
    analysis_id  TEXT PRIMARY KEY,
    case_number  TEXT NOT NULL,
    file_name    TEXT NOT NULL,
    file_hash    TEXT NOT NULL,
    pcap_db_id   INTEGER REFERENCES pcap_files(id),
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    status       TEXT NOT NULL DEFAULT 'complete',
    beacon_count INTEGER DEFAULT 0,
    ioc_count    INTEGER DEFAULT 0,
    chain_count  INTEGER DEFAULT 0,
    threat_level TEXT DEFAULT 'LOW',
    UNIQUE(case_number)
);

CREATE TABLE IF NOT EXISTS case_severity (
    analysis_id  TEXT NOT NULL REFERENCES cases(analysis_id) ON DELETE CASCADE,
    severity     TEXT NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(analysis_id, severity)
);

CREATE TABLE IF NOT EXISTS case_iocs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     TEXT NOT NULL REFERENCES cases(analysis_id) ON DELETE CASCADE,
    ioc_type        TEXT NOT NULL,
    value           TEXT NOT NULL,
    threat_score    INTEGER DEFAULT 0,
    severity        TEXT DEFAULT 'LOW',
    mitre_tactic    TEXT,
    mitre_technique TEXT,
    sources         TEXT,
    context         TEXT,
    reasons         TEXT
);

-- Timeline buckets (v2.3.1)
CREATE TABLE IF NOT EXISTS case_timeline (
    analysis_id  TEXT NOT NULL REFERENCES cases(analysis_id) ON DELETE CASCADE,
    bucket_time  TEXT NOT NULL,
    packet_count INTEGER NOT NULL DEFAULT 0,
    byte_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(analysis_id, bucket_time)
);
CREATE INDEX IF NOT EXISTS idx_timeline_aid  ON case_timeline(analysis_id);
CREATE INDEX IF NOT EXISTS idx_cases_hash   ON cases(file_hash);
CREATE INDEX IF NOT EXISTS idx_cases_number ON cases(case_number);
CREATE INDEX IF NOT EXISTS idx_iocs_aid     ON case_iocs(analysis_id);
CREATE INDEX IF NOT EXISTS idx_iocs_sev     ON case_iocs(severity);
"""


# ── Public API ─────────────────────────────────────────────────────────────────

def init_db(db_path: str) -> sqlite3.Connection:
    """
    Create (or open) the SQLite database and apply the schema.
    Also runs self-healing migrations for columns added in later versions.
    Returns an open connection — caller is responsible for closing it.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    _run_migrations(conn)
    log.info(f"Database ready: {db_path}")
    return conn


def _run_migrations(conn: sqlite3.Connection):
    """
    Idempotent migrations for columns/tables added after initial release.
    Each ALTER TABLE is wrapped in try/except so it is safe to run every
    time the DB is opened — existing columns are silently skipped.
    """
    migrations = [
        # v2.5: case source tracking (cli vs web)
        "ALTER TABLE cases ADD COLUMN source TEXT DEFAULT 'cli'",
        # v2.3: analysis_id link on pcap_files
        "ALTER TABLE pcap_files ADD COLUMN analysis_id TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
            conn.commit()
        except Exception:
            pass   # column already exists — safe to ignore


def insert_pcap_file(conn: sqlite3.Connection, meta: dict, stats: dict) -> int:
    """Insert a PCAP file record. Returns the new row id."""
    cap = stats.get("capture", {})
    cur = conn.execute("""
        INSERT OR IGNORE INTO pcap_files
            (filename, filepath, sha256, file_size, packet_count,
             first_packet, last_packet, duration_sec)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        meta["filename"],
        meta["path"],
        meta["sha256"],
        meta["file_size"],
        stats["totals"]["packets"],
        cap.get("first_packet"),
        cap.get("last_packet"),
        cap.get("duration_seconds"),
    ))
    conn.commit()
    if cur.lastrowid:
        return cur.lastrowid
    # already exists — return existing id
    row = conn.execute(
        "SELECT id FROM pcap_files WHERE sha256=?", (meta["sha256"],)
    ).fetchone()
    return row["id"] if row else -1


def insert_flow(conn: sqlite3.Connection, flow: dict) -> int:
    """Insert a single flow record. Returns new row id."""
    cur = conn.execute("""
        INSERT INTO flows
            (pcap_id, src_ip, dst_ip, src_port, dst_port, protocol, service,
             packet_count, byte_count, first_seen, last_seen, duration_sec,
             flags_seen, payload_preview)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        flow["pcap_id"],
        flow["src_ip"],
        flow["dst_ip"],
        flow["src_port"],
        flow["dst_port"],
        flow["protocol"],
        flow.get("service", ""),
        flow["packet_count"],
        flow["byte_count"],
        flow.get("first_seen"),
        flow.get("last_seen"),
        flow.get("duration_sec", 0.0),
        flow.get("flags_seen", ""),
        flow.get("payload_preview", ""),
    ))
    # No commit here — caller (store_flows) owns the transaction
    return cur.lastrowid


def insert_packets_bulk(conn: sqlite3.Connection, rows: list[tuple]):
    """Bulk-insert packet rows. Each tuple must match the packets table columns."""
    conn.executemany("""
        INSERT INTO packets
            (flow_id, pcap_id, timestamp, src_ip, dst_ip,
             src_port, dst_port, protocol, length, flags, payload_hex)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)
    """, rows)
    # No commit here — caller owns the transaction


def insert_http_session(conn: sqlite3.Connection, session: dict) -> int:
    cur = conn.execute("""
        INSERT INTO http_sessions
            (flow_id, pcap_id, method, host, uri, user_agent,
             status_code, content_type, body_size, request_time,
             full_request, full_response)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        session["flow_id"],
        session["pcap_id"],
        session.get("method"),
        session.get("host"),
        session.get("uri"),
        session.get("user_agent"),
        session.get("status_code"),
        session.get("content_type"),
        session.get("body_size", 0),
        session.get("request_time"),
        session.get("full_request", ""),
        session.get("full_response", ""),
    ))
    # No commit here — caller owns the transaction
    return cur.lastrowid


def query_flows(conn: sqlite3.Connection, pcap_id: int = None,
                protocol: str = None, min_bytes: int = 0) -> list:
    """Flexible flow query — all filters optional."""
    clauses = ["byte_count >= ?"]
    params  = [min_bytes]
    if pcap_id:
        clauses.append("pcap_id = ?")
        params.append(pcap_id)
    if protocol:
        clauses.append("protocol = ?")
        params.append(protocol.upper())
    where = " AND ".join(clauses)
    return conn.execute(
        f"SELECT * FROM flows WHERE {where} ORDER BY byte_count DESC",
        params
    ).fetchall()


def get_stats(conn: sqlite3.Connection) -> dict:
    """Return a quick summary of what's in the DB."""
    return {
        "pcap_files":    conn.execute("SELECT COUNT(*) FROM pcap_files").fetchone()[0],
        "flows":         conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0],
        "packets":       conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0],
        "http_sessions": conn.execute("SELECT COUNT(*) FROM http_sessions").fetchone()[0],
        "total_bytes":   conn.execute("SELECT COALESCE(SUM(byte_count),0) FROM flows").fetchone()[0],
    }
