"""Tests for engine/ingestor.py — Chronos-DFIR multi-format parser.
Run: pytest tests/test_ingestor.py -v
"""
import os
import tempfile
import polars as pl
import pytest

from engine.ingestor import (
    ingest_file,
    normalize_and_save,
    _read_whitespace_csv,
    _sanitize_plist_val,
)


# ── CSV Round-trip ───────────────────────────────────────────────────

def test_csv_ingest_basic():
    """CSV file should produce a LazyFrame with correct schema."""
    with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
        f.write("Time,EventID,Source\n2025-01-01 10:00:00,4624,WS01\n2025-01-02 11:00:00,4625,WS02\n")
        path = f.name
    try:
        lf, df_eager, cat = ingest_file(path, ".csv")
        assert lf is not None, "CSV should produce LazyFrame"
        assert df_eager is None
        schema = lf.collect_schema()
        assert "Time" in schema.names()
        assert "EventID" in schema.names()
    finally:
        os.unlink(path)


def test_csv_round_trip_normalize():
    """CSV → ingest → normalize_and_save → read back should preserve data."""
    with tempfile.NamedTemporaryFile(suffix=".csv", mode="w", delete=False) as f:
        f.write("_time,event_id,source\n2025-01-01 10:00:00,4624,WS01\n")
        path = f.name
    out_path = path + ".out.csv"
    try:
        lf, df_eager, cat = ingest_file(path, ".csv")
        rc = normalize_and_save(lf, df_eager, out_path)
        result = pl.read_csv(out_path)
        assert "Time" in result.columns, "Header '_time' should be normalized to 'Time'"
        assert "_id" in result.columns, "Should have _id index column"
        assert result.height == 1
    finally:
        os.unlink(path)
        if os.path.exists(out_path):
            os.unlink(out_path)


# ── Whitespace-separated (PSList) ────────────────────────────────────

def test_whitespace_csv_basic():
    """Whitespace-separated file should parse headers and data correctly."""
    content = "PID  Name       CPU\n1234 svchost.exe 5.2\n5678 chrome.exe  12.1\n"
    with tempfile.NamedTemporaryFile(suffix=".pslist", mode="w", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        df = _read_whitespace_csv(path)
        assert df.height == 2
        assert "PID" in df.columns
        assert "Name" in df.columns
        assert df["Name"][0] == "svchost.exe"
    finally:
        os.unlink(path)


def test_whitespace_csv_short_rows():
    """Short rows should be padded, not crash."""
    content = "A  B  C\n1  2  3\n4  5\n"
    with tempfile.NamedTemporaryFile(suffix=".txt", mode="w", delete=False) as f:
        f.write(content)
        path = f.name
    try:
        df = _read_whitespace_csv(path)
        assert df.height == 2
        assert df["C"][1] == ""  # padded
    finally:
        os.unlink(path)


# ── TSV ──────────────────────────────────────────────────────────────

def test_tsv_ingest():
    """TSV should produce a LazyFrame."""
    with tempfile.NamedTemporaryFile(suffix=".tsv", mode="w", delete=False) as f:
        f.write("Time\tEventID\n2025-01-01\t100\n")
        path = f.name
    try:
        lf, df_eager, cat = ingest_file(path, ".tsv")
        assert lf is not None
    finally:
        os.unlink(path)


# ── SQLite ───────────────────────────────────────────────────────────

def test_sqlite_ingest():
    """SQLite should produce an eager DataFrame with string columns."""
    import sqlite3
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE events (Time TEXT, EventID TEXT, Source TEXT)")
        conn.execute("INSERT INTO events VALUES ('2025-01-01', '4624', 'DC01')")
        conn.commit()
        conn.close()

        lf, df_eager, cat = ingest_file(path, ".db")
        assert df_eager is not None
        assert df_eager.height == 1
        assert "Time" in df_eager.columns
    finally:
        os.unlink(path)


# ── Plist sanitization ──────────────────────────────────────────────

def test_sanitize_plist_val():
    """Plist sanitizer should convert bytes/dicts to safe types."""
    assert _sanitize_plist_val(None) is None
    assert _sanitize_plist_val(b"\xde\xad") == "dead"
    assert _sanitize_plist_val({"key": "val"}) == "{'key': 'val'}"
    assert _sanitize_plist_val("hello") == "hello"
    assert _sanitize_plist_val(42) == 42


def test_plist_ingest():
    """Single plist file should produce a DataFrame."""
    import plistlib
    data = [{"Label": "com.test", "Program": "/usr/bin/test"}]
    with tempfile.NamedTemporaryFile(suffix=".plist", delete=False) as f:
        plistlib.dump(data, f)
        path = f.name
    try:
        lf, df_eager, cat = ingest_file(path, ".plist")
        assert df_eager is not None
        assert df_eager.height == 1
        assert "Label" in df_eager.columns
    finally:
        os.unlink(path)


# ── XLSX ─────────────────────────────────────────────────────────────

def test_xlsx_ingest():
    """Excel file should produce an eager DataFrame."""
    with tempfile.NamedTemporaryFile(suffix=".xlsx", delete=False) as f:
        path = f.name
    try:
        pl.DataFrame({"Time": ["2025-01-01"], "Event": ["test"]}).write_excel(path)
        lf, df_eager, cat = ingest_file(path, ".xlsx")
        assert df_eager is not None
        assert df_eager.height == 1
    finally:
        os.unlink(path)


# ── Sigma basic fire ─────────────────────────────────────────────────

def test_sigma_basic_rule_fires():
    """A simple Sigma rule should match when conditions are met."""
    try:
        from engine.sigma_engine import match_sigma_rules
    except ImportError:
        pytest.skip("sigma_engine not available")

    df = pl.DataFrame({
        "EventID": ["4624", "4624", "1"],
        "LogonType": ["10", "10", "3"],
        "SourceHostname": ["attacker.evil.com", "attacker.evil.com", "normal.corp"],
    })

    test_rule = [{
        "title": "Test RDP Logon",
        "level": "high",
        "detection": {
            "selection": {
                "EventID": "4624",
                "LogonType": "10",
            },
            "condition": "selection",
        },
        "tags": ["attack.t1021.001"],
    }]

    hits = match_sigma_rules(df, rules=test_rule)
    assert len(hits) == 1
    assert hits[0]["title"] == "Test RDP Logon"
    assert hits[0]["matched_rows"] == 2
