"""
Integration tests for engine/case_router.py — Case Management API.

Uses httpx AsyncClient with a test-isolated DuckDB.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from engine import case_db


@pytest_asyncio.fixture(autouse=True)
async def setup_test_db(tmp_path):
    """Initialize a fresh test DB before each test."""
    db_path = str(tmp_path / "test_api_cases.duckdb")
    case_db.init_db(db_path)
    yield
    case_db.close_db()


@pytest_asyncio.fixture
async def client():
    """Create an async test client for the FastAPI app."""
    from app import app
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


# ---------------------------------------------------------------------------
# Case CRUD Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_case_endpoint(client):
    resp = await client.post("/api/cases", json={
        "name": "API Test Case",
        "description": "Created via test",
        "investigator": "pytest"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert "case_id" in data
    assert data["name"] == "API Test Case"
    assert data["status"] == "open"


@pytest.mark.asyncio
async def test_list_cases_endpoint(client):
    await client.post("/api/cases", json={"name": "Case 1"})
    await client.post("/api/cases", json={"name": "Case 2"})

    resp = await client.get("/api/cases")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2


@pytest.mark.asyncio
async def test_get_case_endpoint(client):
    create_resp = await client.post("/api/cases", json={"name": "Detail Case"})
    case_id = create_resp.json()["case_id"]

    resp = await client.get(f"/api/cases/{case_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["name"] == "Detail Case"
    assert "phases" in data


@pytest.mark.asyncio
async def test_update_case_endpoint(client):
    create_resp = await client.post("/api/cases", json={"name": "To Update"})
    case_id = create_resp.json()["case_id"]

    resp = await client.put(f"/api/cases/{case_id}", json={
        "name": "Updated Name",
        "investigator": "new_analyst"
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "updated"

    # Verify update persisted
    get_resp = await client.get(f"/api/cases/{case_id}")
    assert get_resp.json()["name"] == "Updated Name"


@pytest.mark.asyncio
async def test_delete_case_endpoint(client):
    create_resp = await client.post("/api/cases", json={"name": "To Delete"})
    case_id = create_resp.json()["case_id"]

    resp = await client.delete(f"/api/cases/{case_id}")
    assert resp.status_code == 200
    assert resp.json()["status"] == "archived"

    # Should not appear in list or get
    get_resp = await client.get(f"/api/cases/{case_id}")
    assert get_resp.status_code == 404


# ---------------------------------------------------------------------------
# Phase Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_phase_endpoint(client):
    create_resp = await client.post("/api/cases", json={"name": "Phase Case"})
    case_id = create_resp.json()["case_id"]

    resp = await client.post(f"/api/cases/{case_id}/phases", json={
        "title": "Collection",
        "objective": "Gather all evidence"
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["title"] == "Collection"
    assert data["case_id"] == case_id


@pytest.mark.asyncio
async def test_list_phases_endpoint(client):
    create_resp = await client.post("/api/cases", json={"name": "Multi Phase"})
    case_id = create_resp.json()["case_id"]

    await client.post(f"/api/cases/{case_id}/phases", json={"title": "Phase 1"})
    await client.post(f"/api/cases/{case_id}/phases", json={"title": "Phase 2"})

    resp = await client.get(f"/api/cases/{case_id}/phases")
    assert resp.status_code == 200
    assert resp.json()["total"] == 2


# ---------------------------------------------------------------------------
# Journal Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_journal_endpoints(client):
    create_resp = await client.post("/api/cases", json={"name": "Journal Case"})
    case_id = create_resp.json()["case_id"]

    # Add entry
    resp = await client.post(f"/api/cases/{case_id}/journal", json={
        "content": "Initial triage completed",
        "entry_type": "note",
        "author": "analyst"
    })
    assert resp.status_code == 200
    assert "entry_id" in resp.json()

    # List entries
    resp = await client.get(f"/api/cases/{case_id}/journal")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["entries"][0]["content"] == "Initial triage completed"


# ---------------------------------------------------------------------------
# Narrative Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_narrative_endpoints(client):
    create_resp = await client.post("/api/cases", json={"name": "Narrative Case"})
    case_id = create_resp.json()["case_id"]

    # Initially no narrative
    resp = await client.get(f"/api/cases/{case_id}/narrative")
    assert resp.status_code == 200
    assert resp.json()["narrative"] is None

    # Save narrative
    resp = await client.put(f"/api/cases/{case_id}/narrative", json={
        "content_md": "# Summary\nRansomware incident detected.",
        "version": 1
    })
    assert resp.status_code == 200
    assert resp.json()["status"] == "saved"

    # Verify
    resp = await client.get(f"/api/cases/{case_id}/narrative")
    assert resp.status_code == 200
    assert "Ransomware" in resp.json()["content_md"]


# ---------------------------------------------------------------------------
# IOC Endpoints
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_ioc_endpoint(client):
    create_resp = await client.post("/api/cases", json={"name": "IOC Case"})
    case_id = create_resp.json()["case_id"]

    # Add IOCs directly via case_db (no POST endpoint for IOCs in router)
    case_db.upsert_ioc(case_id, "ip", "192.168.1.100", context="C2")
    case_db.upsert_ioc(case_id, "domain", "evil.com", context="Phishing")

    resp = await client.get(f"/api/cases/{case_id}/iocs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert data["by_type"]["ip"] == 1
    assert data["by_type"]["domain"] == 1
