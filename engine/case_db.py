"""
Chronos-DFIR Case Database — DuckDB persistence for investigations.

Manages cases, phases, files, analysis results, journal entries, IOCs,
and narrative in a single embedded DuckDB file.

Architecture:
  - Single .duckdb file: chronos_cases.duckdb
  - Thread-safe: write lock for mutations, concurrent reads OK
  - All IDs are UUIDs (gen_random_uuid)
  - Soft-delete for cases (status='archived')
"""

import duckdb
import json
import logging
import os
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger("chronos.case_db")

_DB_PATH = os.environ.get("CHRONOS_CASE_DB", "chronos_cases.duckdb")
_conn: Optional[duckdb.DuckDBPyConnection] = None
_write_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Connection Management
# ---------------------------------------------------------------------------

def init_db(db_path: Optional[str] = None) -> duckdb.DuckDBPyConnection:
    """Initialize the database connection and create schema if needed."""
    global _conn, _DB_PATH
    if db_path:
        _DB_PATH = db_path
    _conn = duckdb.connect(_DB_PATH)
    _create_schema(_conn)
    logger.info(f"Case DB initialized at {_DB_PATH}")
    return _conn


def get_conn() -> duckdb.DuckDBPyConnection:
    """Get the database connection, initializing if needed."""
    global _conn
    if _conn is None:
        init_db()
    return _conn


def _create_schema(conn: duckdb.DuckDBPyConnection):
    """Create all tables if they don't exist."""
    conn.execute("INSTALL 'uuid'; LOAD 'uuid';")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            case_id     UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            name        VARCHAR NOT NULL,
            created_at  TIMESTAMP DEFAULT current_timestamp,
            updated_at  TIMESTAMP DEFAULT current_timestamp,
            status      VARCHAR DEFAULT 'open',
            description VARCHAR DEFAULT '',
            investigator VARCHAR DEFAULT ''
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS phases (
            phase_id     UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            case_id      UUID NOT NULL REFERENCES cases(case_id),
            phase_number INTEGER NOT NULL,
            title        VARCHAR NOT NULL,
            objective    VARCHAR DEFAULT '',
            notes        VARCHAR DEFAULT '',
            status       VARCHAR DEFAULT 'active',
            created_at   TIMESTAMP DEFAULT current_timestamp
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_files (
            file_id            UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            phase_id           UUID REFERENCES phases(phase_id),
            case_id            UUID NOT NULL REFERENCES cases(case_id),
            original_filename  VARCHAR NOT NULL,
            processed_filename VARCHAR NOT NULL,
            sha256             VARCHAR DEFAULT '',
            file_size          BIGINT DEFAULT 0,
            file_category      VARCHAR DEFAULT 'generic',
            row_count          INTEGER DEFAULT 0,
            time_range_start   VARCHAR DEFAULT '',
            time_range_end     VARCHAR DEFAULT '',
            technology         VARCHAR DEFAULT '',
            uploaded_at        TIMESTAMP DEFAULT current_timestamp
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_results (
            result_id       UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            file_id         UUID REFERENCES case_files(file_id),
            case_id         UUID NOT NULL REFERENCES cases(case_id),
            phase_id        UUID REFERENCES phases(phase_id),
            analysis_type   VARCHAR DEFAULT 'forensic_report',
            result_json     VARCHAR DEFAULT '{}',
            risk_score      INTEGER DEFAULT 0,
            sigma_hit_count INTEGER DEFAULT 0,
            created_at      TIMESTAMP DEFAULT current_timestamp
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS journal_entries (
            entry_id   UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            case_id    UUID NOT NULL REFERENCES cases(case_id),
            phase_id   UUID REFERENCES phases(phase_id),
            entry_type VARCHAR DEFAULT 'note',
            content    VARCHAR NOT NULL,
            author     VARCHAR DEFAULT 'investigator',
            created_at TIMESTAMP DEFAULT current_timestamp
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_iocs (
            ioc_id          UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            case_id         UUID NOT NULL REFERENCES cases(case_id),
            phase_id        UUID REFERENCES phases(phase_id),
            file_id         UUID REFERENCES case_files(file_id),
            ioc_type        VARCHAR NOT NULL,
            ioc_value       VARCHAR NOT NULL,
            first_seen      VARCHAR DEFAULT '',
            last_seen       VARCHAR DEFAULT '',
            context         VARCHAR DEFAULT '',
            enrichment_json VARCHAR DEFAULT '{}'
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS case_narrative (
            narrative_id   UUID DEFAULT gen_random_uuid() PRIMARY KEY,
            case_id        UUID NOT NULL REFERENCES cases(case_id),
            content_md     VARCHAR DEFAULT '',
            generated_at   TIMESTAMP DEFAULT current_timestamp,
            last_edited_at TIMESTAMP DEFAULT current_timestamp,
            version        INTEGER DEFAULT 1
        )
    """)


# ---------------------------------------------------------------------------
# Case CRUD
# ---------------------------------------------------------------------------

def create_case(name: str, description: str = "", investigator: str = "") -> str:
    """Create a new case. Returns case_id as string."""
    conn = get_conn()
    with _write_lock:
        result = conn.execute(
            """INSERT INTO cases (name, description, investigator)
               VALUES (?, ?, ?)
               RETURNING case_id::VARCHAR""",
            [name, description, investigator]
        ).fetchone()
    return result[0]


def get_case(case_id: str) -> Optional[Dict[str, Any]]:
    """Get a single case with its phase and file counts."""
    conn = get_conn()
    row = conn.execute(
        """SELECT c.case_id::VARCHAR, c.name, c.created_at::VARCHAR,
                  c.updated_at::VARCHAR, c.status, c.description, c.investigator,
                  (SELECT COUNT(*) FROM phases p WHERE p.case_id = c.case_id) as phase_count,
                  (SELECT COUNT(*) FROM case_files f WHERE f.case_id = c.case_id) as file_count
           FROM cases c WHERE c.case_id = ?::UUID AND c.status != 'archived'""",
        [case_id]
    ).fetchone()
    if row is None:
        return None
    return {
        "case_id": row[0], "name": row[1], "created_at": row[2],
        "updated_at": row[3], "status": row[4], "description": row[5],
        "investigator": row[6], "phase_count": row[7], "file_count": row[8],
    }


def list_cases(status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all cases, optionally filtered by status."""
    conn = get_conn()
    query = """SELECT c.case_id::VARCHAR, c.name, c.created_at::VARCHAR,
                      c.updated_at::VARCHAR, c.status, c.description, c.investigator,
                      (SELECT COUNT(*) FROM phases p WHERE p.case_id = c.case_id) as phase_count,
                      (SELECT COUNT(*) FROM case_files f WHERE f.case_id = c.case_id) as file_count
               FROM cases c WHERE c.status != 'archived'"""
    params = []
    if status_filter:
        query += " AND c.status = ?"
        params.append(status_filter)
    query += " ORDER BY c.updated_at DESC"

    rows = conn.execute(query, params).fetchall()
    return [
        {"case_id": r[0], "name": r[1], "created_at": r[2], "updated_at": r[3],
         "status": r[4], "description": r[5], "investigator": r[6],
         "phase_count": r[7], "file_count": r[8]}
        for r in rows
    ]


def update_case(case_id: str, **fields) -> bool:
    """Update case fields. Returns True if updated."""
    allowed = {"name", "description", "investigator", "status"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    conn = get_conn()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [case_id]
    with _write_lock:
        conn.execute(
            f"UPDATE cases SET {set_clause}, updated_at = current_timestamp WHERE case_id = ?::UUID",
            values
        )
    return True


def delete_case(case_id: str) -> bool:
    """Soft-delete (archive) a case."""
    return update_case(case_id, status="archived")


# ---------------------------------------------------------------------------
# Phase CRUD
# ---------------------------------------------------------------------------

def create_phase(case_id: str, title: str, objective: str = "",
                 phase_number: Optional[int] = None) -> str:
    """Create a phase within a case. Auto-numbers if phase_number is None."""
    conn = get_conn()
    if phase_number is None:
        row = conn.execute(
            "SELECT COALESCE(MAX(phase_number), 0) + 1 FROM phases WHERE case_id = ?::UUID",
            [case_id]
        ).fetchone()
        phase_number = row[0]

    with _write_lock:
        result = conn.execute(
            """INSERT INTO phases (case_id, phase_number, title, objective)
               VALUES (?::UUID, ?, ?, ?)
               RETURNING phase_id::VARCHAR""",
            [case_id, phase_number, title, objective]
        ).fetchone()
        conn.execute(
            "UPDATE cases SET updated_at = current_timestamp WHERE case_id = ?::UUID",
            [case_id]
        )
    return result[0]


def get_phases(case_id: str) -> List[Dict[str, Any]]:
    """Get all phases for a case with file counts."""
    conn = get_conn()
    rows = conn.execute(
        """SELECT p.phase_id::VARCHAR, p.phase_number, p.title, p.objective,
                  p.notes, p.status, p.created_at::VARCHAR,
                  (SELECT COUNT(*) FROM case_files f WHERE f.phase_id = p.phase_id) as file_count
           FROM phases p WHERE p.case_id = ?::UUID
           ORDER BY p.phase_number""",
        [case_id]
    ).fetchall()
    return [
        {"phase_id": r[0], "phase_number": r[1], "title": r[2], "objective": r[3],
         "notes": r[4], "status": r[5], "created_at": r[6], "file_count": r[7]}
        for r in rows
    ]


def update_phase(phase_id: str, **fields) -> bool:
    """Update phase fields."""
    allowed = {"title", "objective", "notes", "status"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    conn = get_conn()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [phase_id]
    with _write_lock:
        conn.execute(f"UPDATE phases SET {set_clause} WHERE phase_id = ?::UUID", values)
    return True


# ---------------------------------------------------------------------------
# File Registration
# ---------------------------------------------------------------------------

def register_file(
    case_id: str,
    original_filename: str,
    processed_filename: str,
    sha256: str = "",
    file_size: int = 0,
    file_category: str = "generic",
    row_count: int = 0,
    time_range_start: str = "",
    time_range_end: str = "",
    technology: str = "",
    phase_id: Optional[str] = None,
) -> str:
    """Register an uploaded file in the case database. Returns file_id."""
    conn = get_conn()
    with _write_lock:
        result = conn.execute(
            """INSERT INTO case_files
               (case_id, phase_id, original_filename, processed_filename,
                sha256, file_size, file_category, row_count,
                time_range_start, time_range_end, technology)
               VALUES (?::UUID, ?::UUID, ?, ?, ?, ?, ?, ?, ?, ?, ?)
               RETURNING file_id::VARCHAR""",
            [case_id, phase_id, original_filename, processed_filename,
             sha256, file_size, file_category, row_count,
             time_range_start, time_range_end, technology]
        ).fetchone()
        conn.execute(
            "UPDATE cases SET updated_at = current_timestamp WHERE case_id = ?::UUID",
            [case_id]
        )
    return result[0]


def get_case_files(case_id: str, phase_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get files for a case, optionally filtered by phase."""
    conn = get_conn()
    query = """SELECT f.file_id::VARCHAR, f.phase_id::VARCHAR, f.original_filename,
                      f.processed_filename, f.sha256, f.file_size, f.file_category,
                      f.row_count, f.time_range_start, f.time_range_end,
                      f.technology, f.uploaded_at::VARCHAR,
                      p.title as phase_title, p.phase_number
               FROM case_files f
               LEFT JOIN phases p ON f.phase_id = p.phase_id
               WHERE f.case_id = ?::UUID"""
    params = [case_id]
    if phase_id:
        query += " AND f.phase_id = ?::UUID"
        params.append(phase_id)
    query += " ORDER BY f.uploaded_at"

    rows = conn.execute(query, params).fetchall()
    return [
        {"file_id": r[0], "phase_id": r[1], "original_filename": r[2],
         "processed_filename": r[3], "sha256": r[4], "file_size": r[5],
         "file_category": r[6], "row_count": r[7], "time_range_start": r[8],
         "time_range_end": r[9], "technology": r[10], "uploaded_at": r[11],
         "phase_title": r[12], "phase_number": r[13]}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Analysis Results
# ---------------------------------------------------------------------------

def save_analysis(
    file_id: str, case_id: str, phase_id: str,
    analysis_type: str, result_json: str,
    risk_score: int = 0, sigma_hit_count: int = 0,
) -> str:
    """Save analysis results for a file."""
    conn = get_conn()
    with _write_lock:
        result = conn.execute(
            """INSERT INTO analysis_results
               (file_id, case_id, phase_id, analysis_type, result_json,
                risk_score, sigma_hit_count)
               VALUES (?::UUID, ?::UUID, ?::UUID, ?, ?, ?, ?)
               RETURNING result_id::VARCHAR""",
            [file_id, case_id, phase_id, analysis_type, result_json,
             risk_score, sigma_hit_count]
        ).fetchone()
    return result[0]


def get_analysis(case_id: str, phase_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get analysis results for a case."""
    conn = get_conn()
    query = """SELECT result_id::VARCHAR, file_id::VARCHAR, phase_id::VARCHAR,
                      analysis_type, result_json, risk_score, sigma_hit_count,
                      created_at::VARCHAR
               FROM analysis_results WHERE case_id = ?::UUID"""
    params = [case_id]
    if phase_id:
        query += " AND phase_id = ?::UUID"
        params.append(phase_id)
    query += " ORDER BY created_at DESC"

    rows = conn.execute(query, params).fetchall()
    return [
        {"result_id": r[0], "file_id": r[1], "phase_id": r[2],
         "analysis_type": r[3], "result_json": r[4], "risk_score": r[5],
         "sigma_hit_count": r[6], "created_at": r[7]}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Journal Entries
# ---------------------------------------------------------------------------

def add_journal_entry(
    case_id: str, content: str,
    entry_type: str = "note", author: str = "investigator",
    phase_id: Optional[str] = None,
) -> str:
    """Add a journal entry (note, finding, or AI insight)."""
    conn = get_conn()
    with _write_lock:
        result = conn.execute(
            """INSERT INTO journal_entries (case_id, phase_id, entry_type, content, author)
               VALUES (?::UUID, ?::UUID, ?, ?, ?)
               RETURNING entry_id::VARCHAR""",
            [case_id, phase_id, entry_type, content, author]
        ).fetchone()
        conn.execute(
            "UPDATE cases SET updated_at = current_timestamp WHERE case_id = ?::UUID",
            [case_id]
        )
    return result[0]


def get_journal(case_id: str, phase_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get journal entries for a case."""
    conn = get_conn()
    query = """SELECT entry_id::VARCHAR, phase_id::VARCHAR, entry_type,
                      content, author, created_at::VARCHAR
               FROM journal_entries WHERE case_id = ?::UUID"""
    params = [case_id]
    if phase_id:
        query += " AND phase_id = ?::UUID"
        params.append(phase_id)
    query += " ORDER BY created_at"

    rows = conn.execute(query, params).fetchall()
    return [
        {"entry_id": r[0], "phase_id": r[1], "entry_type": r[2],
         "content": r[3], "author": r[4], "created_at": r[5]}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# IOC Management
# ---------------------------------------------------------------------------

def upsert_ioc(
    case_id: str, ioc_type: str, ioc_value: str,
    phase_id: Optional[str] = None, file_id: Optional[str] = None,
    first_seen: str = "", last_seen: str = "",
    context: str = "", enrichment_json: str = "{}",
) -> str:
    """Insert or update an IOC for a case."""
    conn = get_conn()
    with _write_lock:
        # Check if IOC already exists for this case
        existing = conn.execute(
            """SELECT ioc_id::VARCHAR FROM case_iocs
               WHERE case_id = ?::UUID AND ioc_type = ? AND ioc_value = ?""",
            [case_id, ioc_type, ioc_value]
        ).fetchone()

        if existing:
            # Update with latest context
            conn.execute(
                """UPDATE case_iocs
                   SET last_seen = ?, context = ?,
                       enrichment_json = CASE WHEN ? != '{}' THEN ? ELSE enrichment_json END
                   WHERE ioc_id = ?::UUID""",
                [last_seen, context, enrichment_json, enrichment_json, existing[0]]
            )
            return existing[0]
        else:
            result = conn.execute(
                """INSERT INTO case_iocs
                   (case_id, phase_id, file_id, ioc_type, ioc_value,
                    first_seen, last_seen, context, enrichment_json)
                   VALUES (?::UUID, ?::UUID, ?::UUID, ?, ?, ?, ?, ?, ?)
                   RETURNING ioc_id::VARCHAR""",
                [case_id, phase_id, file_id, ioc_type, ioc_value,
                 first_seen, last_seen, context, enrichment_json]
            ).fetchone()
            return result[0]


def get_case_iocs(case_id: str, phase_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Get all IOCs for a case with cross-phase counts."""
    conn = get_conn()
    query = """SELECT i.ioc_id::VARCHAR, i.ioc_type, i.ioc_value,
                      i.first_seen, i.last_seen, i.context, i.enrichment_json,
                      i.phase_id::VARCHAR, i.file_id::VARCHAR
               FROM case_iocs i WHERE i.case_id = ?::UUID"""
    params = [case_id]
    if phase_id:
        query += " AND i.phase_id = ?::UUID"
        params.append(phase_id)
    query += " ORDER BY i.ioc_type, i.ioc_value"

    rows = conn.execute(query, params).fetchall()
    return [
        {"ioc_id": r[0], "ioc_type": r[1], "ioc_value": r[2],
         "first_seen": r[3], "last_seen": r[4], "context": r[5],
         "enrichment_json": r[6], "phase_id": r[7], "file_id": r[8]}
        for r in rows
    ]


# ---------------------------------------------------------------------------
# Narrative
# ---------------------------------------------------------------------------

def save_narrative(case_id: str, content_md: str, version: int = 1) -> str:
    """Save or update the case narrative."""
    conn = get_conn()
    with _write_lock:
        existing = conn.execute(
            "SELECT narrative_id::VARCHAR FROM case_narrative WHERE case_id = ?::UUID",
            [case_id]
        ).fetchone()

        if existing:
            conn.execute(
                """UPDATE case_narrative
                   SET content_md = ?, last_edited_at = current_timestamp, version = ?
                   WHERE narrative_id = ?::UUID""",
                [content_md, version, existing[0]]
            )
            return existing[0]
        else:
            result = conn.execute(
                """INSERT INTO case_narrative (case_id, content_md, version)
                   VALUES (?::UUID, ?, ?)
                   RETURNING narrative_id::VARCHAR""",
                [case_id, content_md, version]
            ).fetchone()
            return result[0]


def get_narrative(case_id: str) -> Optional[Dict[str, Any]]:
    """Get the current narrative for a case."""
    conn = get_conn()
    row = conn.execute(
        """SELECT narrative_id::VARCHAR, content_md,
                  generated_at::VARCHAR, last_edited_at::VARCHAR, version
           FROM case_narrative WHERE case_id = ?::UUID""",
        [case_id]
    ).fetchone()
    if row is None:
        return None
    return {
        "narrative_id": row[0], "content_md": row[1],
        "generated_at": row[2], "last_edited_at": row[3], "version": row[4],
    }


def close_db():
    """Close the database connection."""
    global _conn
    if _conn:
        _conn.close()
        _conn = None
