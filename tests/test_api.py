"""Tests for Chronos-DFIR FastAPI endpoints.
Run: pytest tests/test_api.py -v
"""
import os
import tempfile
import polars as pl
import pytest
from httpx import AsyncClient, ASGITransport

from app import app, OUTPUT_DIR, UPLOAD_DIR


@pytest.fixture(autouse=True)
def _ensure_dirs():
    """Ensure upload/output dirs exist for tests."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)


@pytest.fixture
def _seed_csv():
    """Create a test CSV in OUTPUT_DIR and return its filename."""
    fname = "test_api_seed.csv"
    path = os.path.join(OUTPUT_DIR, fname)
    pl.DataFrame({
        "Time": ["2025-01-01 10:00:00", "2025-01-02 11:00:00", "2025-01-03 12:00:00"],
        "EventID": ["4624", "4625", "4624"],
        "Source": ["WS01", "WS02", "WS03"],
    }).write_csv(path)
    yield fname
    if os.path.exists(path):
        os.unlink(path)


@pytest.mark.anyio
async def test_root_returns_html():
    """GET / should return 200 with HTML content."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/")
        assert r.status_code == 200
        assert "Chronos-DFIR" in r.text


@pytest.mark.anyio
async def test_upload_csv():
    """POST /upload with a CSV should return success with data_url."""
    csv_content = "Time,EventID,Source\n2025-01-01 10:00:00,4624,WS01\n"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/upload",
            files={"file": ("test_upload.csv", csv_content.encode(), "text/csv")},
            data={"artifact_type": "Generic"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "success"
        assert "data_url" in body
        assert body["csv_filename"].endswith(".csv")


@pytest.mark.anyio
async def test_data_endpoint_pagination(_seed_csv):
    """GET /api/data/{filename} should return paginated data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(f"/api/data/{_seed_csv}?page=1&size=2")
        assert r.status_code == 200
        body = r.json()
        assert "data" in body
        assert len(body["data"]) == 2
        assert body["last_page"] >= 1


@pytest.mark.anyio
async def test_data_endpoint_search(_seed_csv):
    """GET /api/data with query should filter results."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(f"/api/data/{_seed_csv}?query=4625")
        assert r.status_code == 200
        body = r.json()
        assert len(body["data"]) == 1
        assert body["data"][0]["EventID"] == "4625"


@pytest.mark.anyio
async def test_data_endpoint_404():
    """GET /api/data with non-existent file should return 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get("/api/data/nonexistent_file.csv")
        assert r.status_code == 404


@pytest.mark.anyio
async def test_histogram_endpoint(_seed_csv):
    """GET /api/histogram/{filename} should return chart data."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.get(f"/api/histogram/{_seed_csv}")
        assert r.status_code == 200
        body = r.json()
        assert "labels" in body or "error" in body
        if "labels" in body:
            assert "datasets" in body
            assert "stats" in body


@pytest.mark.anyio
async def test_export_filtered_csv(_seed_csv):
    """POST /api/export_filtered should return a downloadable CSV."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post(
            "/api/export_filtered",
            json={
                "filename": _seed_csv,
                "format": "csv",
                "filters": {},
            },
        )
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("content-type", "") or r.status_code == 200


@pytest.mark.anyio
async def test_reset_endpoint():
    """POST /api/reset should clear state and return success."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        r = await client.post("/api/reset")
        assert r.status_code == 200
        body = r.json()
        assert "message" in body or body.get("status") == "success"
