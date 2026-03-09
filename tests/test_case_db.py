"""
Unit tests for engine/case_db.py — DuckDB case management.

Uses a temporary in-memory database for isolation.
"""

import pytest
from engine import case_db


@pytest.fixture(autouse=True)
def isolated_db(tmp_path):
    """Each test gets a fresh DuckDB file."""
    db_path = str(tmp_path / "test_cases.duckdb")
    case_db.init_db(db_path)
    yield
    case_db.close_db()


# ---------------------------------------------------------------------------
# Case CRUD
# ---------------------------------------------------------------------------

def test_create_case():
    case_id = case_db.create_case("Incident-2026-001", description="Ransomware", investigator="analyst1")
    assert case_id is not None
    assert len(case_id) == 36  # UUID format


def test_get_case():
    case_id = case_db.create_case("Test Case", description="desc", investigator="inv")
    case = case_db.get_case(case_id)
    assert case is not None
    assert case["name"] == "Test Case"
    assert case["description"] == "desc"
    assert case["investigator"] == "inv"
    assert case["status"] == "open"
    assert case["phase_count"] == 0
    assert case["file_count"] == 0


def test_list_cases():
    case_db.create_case("Case A")
    case_db.create_case("Case B")
    cases = case_db.list_cases()
    assert len(cases) == 2
    names = {c["name"] for c in cases}
    assert names == {"Case A", "Case B"}


def test_list_cases_filter():
    case_db.create_case("Open Case")
    cid = case_db.create_case("Closed Case")
    case_db.update_case(cid, status="closed")
    open_cases = case_db.list_cases(status_filter="open")
    assert len(open_cases) == 1
    assert open_cases[0]["name"] == "Open Case"


def test_update_case():
    case_id = case_db.create_case("Original")
    case_db.update_case(case_id, name="Updated", investigator="new_analyst")
    case = case_db.get_case(case_id)
    assert case["name"] == "Updated"
    assert case["investigator"] == "new_analyst"


def test_update_case_ignores_invalid_fields():
    case_id = case_db.create_case("Test")
    result = case_db.update_case(case_id, invalid_field="hack")
    assert result is False


def test_delete_case():
    case_id = case_db.create_case("To Delete")
    case_db.delete_case(case_id)
    # Archived cases don't appear in list or get
    assert case_db.get_case(case_id) is None
    assert len(case_db.list_cases()) == 0


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------

def test_create_phase():
    case_id = case_db.create_case("Phase Test")
    phase_id = case_db.create_phase(case_id, "Collection", objective="Gather evidence")
    assert phase_id is not None
    phases = case_db.get_phases(case_id)
    assert len(phases) == 1
    assert phases[0]["title"] == "Collection"
    assert phases[0]["phase_number"] == 1
    assert phases[0]["objective"] == "Gather evidence"


def test_phase_auto_numbering():
    case_id = case_db.create_case("Numbering Test")
    case_db.create_phase(case_id, "Phase 1")
    case_db.create_phase(case_id, "Phase 2")
    case_db.create_phase(case_id, "Phase 3")
    phases = case_db.get_phases(case_id)
    assert [p["phase_number"] for p in phases] == [1, 2, 3]


def test_update_phase():
    case_id = case_db.create_case("Phase Update")
    phase_id = case_db.create_phase(case_id, "Original")
    case_db.update_phase(phase_id, title="Renamed", notes="Updated notes")
    phases = case_db.get_phases(case_id)
    assert phases[0]["title"] == "Renamed"
    assert phases[0]["notes"] == "Updated notes"


# ---------------------------------------------------------------------------
# File Registration
# ---------------------------------------------------------------------------

def test_register_file():
    case_id = case_db.create_case("File Test")
    phase_id = case_db.create_phase(case_id, "Collection")
    file_id = case_db.register_file(
        case_id=case_id,
        original_filename="Security.evtx",
        processed_filename="Security_abc123.csv",
        sha256="aabbccdd" * 8,
        file_size=1024000,
        file_category="evtx",
        row_count=38000,
        technology="windows_evtx",
        phase_id=phase_id,
    )
    assert file_id is not None

    files = case_db.get_case_files(case_id)
    assert len(files) == 1
    assert files[0]["original_filename"] == "Security.evtx"
    assert files[0]["sha256"] == "aabbccdd" * 8
    assert files[0]["row_count"] == 38000

    # Verify case file_count updated
    case = case_db.get_case(case_id)
    assert case["file_count"] == 1


def test_get_files_by_phase():
    case_id = case_db.create_case("Phase Filter")
    p1 = case_db.create_phase(case_id, "Phase 1")
    p2 = case_db.create_phase(case_id, "Phase 2")
    case_db.register_file(case_id, "file1.csv", "file1.csv", phase_id=p1)
    case_db.register_file(case_id, "file2.csv", "file2.csv", phase_id=p2)
    case_db.register_file(case_id, "file3.csv", "file3.csv", phase_id=p1)

    p1_files = case_db.get_case_files(case_id, phase_id=p1)
    assert len(p1_files) == 2
    p2_files = case_db.get_case_files(case_id, phase_id=p2)
    assert len(p2_files) == 1


# ---------------------------------------------------------------------------
# Journal
# ---------------------------------------------------------------------------

def test_journal_entry():
    case_id = case_db.create_case("Journal Test")
    entry_id = case_db.add_journal_entry(
        case_id, "Found suspicious PowerShell execution",
        entry_type="finding", author="analyst1"
    )
    assert entry_id is not None

    entries = case_db.get_journal(case_id)
    assert len(entries) == 1
    assert entries[0]["content"] == "Found suspicious PowerShell execution"
    assert entries[0]["entry_type"] == "finding"
    assert entries[0]["author"] == "analyst1"


def test_journal_multiple_types():
    case_id = case_db.create_case("Multi Journal")
    case_db.add_journal_entry(case_id, "Initial triage", entry_type="note")
    case_db.add_journal_entry(case_id, "Lateral movement detected", entry_type="finding")
    case_db.add_journal_entry(case_id, "AI: Possible APT29", entry_type="insight")

    entries = case_db.get_journal(case_id)
    assert len(entries) == 3
    types = [e["entry_type"] for e in entries]
    assert "note" in types
    assert "finding" in types
    assert "insight" in types


# ---------------------------------------------------------------------------
# IOC Management
# ---------------------------------------------------------------------------

def test_upsert_ioc():
    case_id = case_db.create_case("IOC Test")
    ioc_id = case_db.upsert_ioc(
        case_id, ioc_type="ip", ioc_value="192.168.1.100",
        first_seen="2026-03-01", context="C2 beacon"
    )
    assert ioc_id is not None

    iocs = case_db.get_case_iocs(case_id)
    assert len(iocs) == 1
    assert iocs[0]["ioc_value"] == "192.168.1.100"
    assert iocs[0]["context"] == "C2 beacon"


def test_ioc_dedup():
    case_id = case_db.create_case("IOC Dedup")
    id1 = case_db.upsert_ioc(case_id, "ip", "10.0.0.1", context="First seen")
    id2 = case_db.upsert_ioc(case_id, "ip", "10.0.0.1", context="Updated context",
                              last_seen="2026-03-09")
    # Should return same ID (upsert, not duplicate)
    assert id1 == id2
    iocs = case_db.get_case_iocs(case_id)
    assert len(iocs) == 1
    assert iocs[0]["context"] == "Updated context"


# ---------------------------------------------------------------------------
# Narrative
# ---------------------------------------------------------------------------

def test_save_narrative():
    case_id = case_db.create_case("Narrative Test")
    nid = case_db.save_narrative(case_id, "# Investigation Summary\n\nRansomware incident.", version=1)
    assert nid is not None

    narrative = case_db.get_narrative(case_id)
    assert narrative is not None
    assert "Ransomware" in narrative["content_md"]
    assert narrative["version"] == 1


def test_narrative_versioning():
    case_id = case_db.create_case("Version Test")
    nid1 = case_db.save_narrative(case_id, "Version 1 content", version=1)
    nid2 = case_db.save_narrative(case_id, "Version 2 content", version=2)
    # Should update same narrative (not create duplicate)
    assert nid1 == nid2
    narrative = case_db.get_narrative(case_id)
    assert narrative["content_md"] == "Version 2 content"
    assert narrative["version"] == 2


def test_narrative_not_found():
    case_id = case_db.create_case("No Narrative")
    assert case_db.get_narrative(case_id) is None


# ---------------------------------------------------------------------------
# Analysis Results
# ---------------------------------------------------------------------------

def test_save_analysis():
    case_id = case_db.create_case("Analysis Test")
    phase_id = case_db.create_phase(case_id, "Analysis Phase")
    file_id = case_db.register_file(case_id, "test.evtx", "test.csv", phase_id=phase_id)

    result_id = case_db.save_analysis(
        file_id=file_id, case_id=case_id, phase_id=phase_id,
        analysis_type="forensic_report",
        result_json='{"risk_score": 85, "sigma_hits": 12}',
        risk_score=85, sigma_hit_count=12,
    )
    assert result_id is not None

    results = case_db.get_analysis(case_id)
    assert len(results) == 1
    assert results[0]["risk_score"] == 85
    assert results[0]["sigma_hit_count"] == 12
