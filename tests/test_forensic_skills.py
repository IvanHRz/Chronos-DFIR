"""
Tests for the 5 newly activated forensic skills in engine/forensic.py:
  - correlate_cross_source()
  - map_mitre_from_sigma()
  - group_sessions()
  - detect_execution_artifacts()
  - generate_waf_threat_profiles()
"""
import pytest
import polars as pl
from engine.forensic import (
    correlate_cross_source,
    map_mitre_from_sigma,
    group_sessions,
    detect_execution_artifacts,
    generate_waf_threat_profiles,
)


# ── correlate_cross_source ────────────────────────────────────────────────

class TestCorrelation:
    def test_empty_df(self):
        df = pl.DataFrame({"col1": []})
        result = correlate_cross_source(df)
        assert result["chains"] == []
        assert result["total_correlated"] == 0

    def test_no_time_column(self):
        df = pl.DataFrame({"SourceIP": ["1.2.3.4", "1.2.3.4", "5.6.7.8"]})
        result = correlate_cross_source(df)
        assert result["correlation_type"] == "none"

    def test_ip_pivot(self):
        df = pl.DataFrame({
            "Time": ["2026-01-01 10:00:00", "2026-01-01 10:01:00", "2026-01-01 10:02:00",
                      "2026-01-01 10:03:00"],
            "SourceIP": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2"],
            "Event": ["login", "file_access", "lateral", "login"],
        })
        result = correlate_cross_source(df, time_window_minutes=10)
        assert result["correlation_type"] == "entity_pivot"
        assert len(result["chains"]) > 0
        chain = result["chains"][0]
        assert chain["pivot_type"] == "ip"
        assert chain["event_count"] == 3
        assert "risk" in chain

    def test_user_pivot(self):
        df = pl.DataFrame({
            "Time": ["2026-01-01 08:00:00"] * 5,
            "Username": ["admin", "admin", "admin", "admin", "guest"],
            "Action": ["login", "powershell", "mimikatz", "lateral", "login"],
        })
        result = correlate_cross_source(df, time_window_minutes=60)
        chains = result["chains"]
        assert any(c["pivot_type"] == "user" for c in chains)

    def test_time_window_filters(self):
        """Events spread over hours should NOT correlate with a 1-minute window."""
        df = pl.DataFrame({
            "Time": ["2026-01-01 01:00:00", "2026-01-01 05:00:00", "2026-01-01 10:00:00"],
            "SourceIP": ["10.0.0.1", "10.0.0.1", "10.0.0.1"],
        })
        result = correlate_cross_source(df, time_window_minutes=1)
        assert result["total_correlated"] == 0


# ── map_mitre_from_sigma ─────────────────────────────────────────────────

class TestMitreMapping:
    def test_empty_hits(self):
        assert map_mitre_from_sigma([]) == []

    def test_single_hit(self):
        hits = [{
            "title": "PowerShell Encoded Command",
            "mitre_technique": "T1059.001",
            "level": "high",
            "matched_rows": 5,
            "tags": ["attack.execution"],
        }]
        result = map_mitre_from_sigma(hits)
        assert len(result) == 1
        assert result[0]["tactic"] == "execution"
        assert result[0]["tactic_id"] == "TA0002"
        assert result[0]["tactic_description"] == "Running malicious code"
        assert result[0]["techniques"][0]["technique"] == "T1059.001"
        assert result[0]["max_severity"] == "high"

    def test_kill_chain_order(self):
        hits = [
            {"title": "Lateral RDP", "mitre_technique": "T1021.001",
             "level": "high", "matched_rows": 2, "tags": ["attack.lateral_movement"]},
            {"title": "Exploit", "mitre_technique": "T1190",
             "level": "critical", "matched_rows": 10, "tags": ["attack.initial_access"]},
        ]
        result = map_mitre_from_sigma(hits)
        assert len(result) == 2
        assert result[0]["tactic"] == "initial_access"
        assert result[1]["tactic"] == "lateral_movement"
        assert result[0]["tactic_order"] < result[1]["tactic_order"]

    def test_multiple_techniques_same_tactic(self):
        hits = [
            {"title": "PowerShell", "mitre_technique": "T1059.001",
             "level": "high", "matched_rows": 3, "tags": ["attack.execution"]},
            {"title": "WMI Exec", "mitre_technique": "T1047",
             "level": "medium", "matched_rows": 1, "tags": ["attack.execution"]},
        ]
        result = map_mitre_from_sigma(hits)
        assert len(result) == 1
        assert len(result[0]["techniques"]) == 2
        assert result[0]["total_hits"] == 4
        assert result[0]["max_severity"] == "high"

    def test_dir_path_fallback(self):
        """When tags don't contain tactic, fall back to file path."""
        hits = [{
            "title": "Registry Run Key",
            "mitre_technique": "T1547.001",
            "level": "medium",
            "matched_rows": 2,
            "tags": [],
            "file": "rules/sigma/ta0003_persistence/registry_run_keys.yml",
        }]
        result = map_mitre_from_sigma(hits)
        assert result[0]["tactic"] == "persistence"


# ── group_sessions ───────────────────────────────────────────────────────

class TestSessionGrouper:
    def test_empty_df(self):
        df = pl.DataFrame({"col1": [1, 2, 3]})
        assert group_sessions(df) == []

    def test_no_ip_column(self):
        df = pl.DataFrame({"Time": ["2026-01-01"], "Event": ["login"]})
        assert group_sessions(df) == []

    def test_basic_profiling(self):
        df = pl.DataFrame({
            "Time": ["2026-01-01 10:00:00", "2026-01-01 10:05:00",
                      "2026-01-01 10:10:00", "2026-01-01 11:00:00"],
            "SourceIP": ["10.0.0.1", "10.0.0.1", "10.0.0.1", "10.0.0.2"],
            "URI": ["/login", "/admin", "/api/data", "/login"],
        })
        result = group_sessions(df)
        assert len(result) >= 1
        top = result[0]
        assert top["attacker_ip"] == "10.0.0.1"
        assert top["request_count"] == 3
        assert "dwell_time_seconds" in top

    def test_with_user_agent(self):
        df = pl.DataFrame({
            "SourceIP": ["1.1.1.1"] * 3,
            "UserAgent": ["Mozilla/5.0", "Mozilla/5.0", "curl/7.68"],
        })
        result = group_sessions(df)
        assert len(result) == 1
        assert "user_agent" in result[0]

    def test_filters_empty_ips(self):
        df = pl.DataFrame({
            "SourceIP": ["", "-", None, "10.0.0.1", "10.0.0.1", "10.0.0.1"],
        })
        result = group_sessions(df)
        assert all(r["attacker_ip"] not in ("", "-") for r in result)


# ── detect_execution_artifacts ───────────────────────────────────────────

class TestExecutionArtifacts:
    def test_empty_df(self):
        df = pl.DataFrame({"col1": [1]})
        result = detect_execution_artifacts(df)
        assert result["artifact_types_detected"] == [] or "generic_execution_refs" not in result.get("artifact_types_detected", [])

    def test_shimcache_detection(self):
        df = pl.DataFrame({
            "ControlSet": ["001", "001"],
            "Path": [r"C:\Windows\Temp\malware.exe", r"C:\Program Files\app.dll"],
            "LastModified": ["2026-01-01", "2026-01-02"],
        })
        result = detect_execution_artifacts(df)
        assert "shimcache" in result["artifact_types_detected"]

    def test_amcache_detection(self):
        df = pl.DataFrame({
            "OriginalFileName": ["cmd.exe", "powershell.exe"],
            "SHA1": ["a" * 40, "b" * 40],
            "ProgramId": ["001", "002"],
        })
        result = detect_execution_artifacts(df)
        assert "amcache" in result["artifact_types_detected"]

    def test_prefetch_detection(self):
        df = pl.DataFrame({
            "Executable": ["CMD.EXE", "POWERSHELL.EXE"],
            "RunCount": [15, 42],
        })
        result = detect_execution_artifacts(df)
        assert "prefetch" in result["artifact_types_detected"]
        assert len(result["prefetch"]) == 2

    def test_srum_detection(self):
        df = pl.DataFrame({
            "AppId": ["chrome.exe", "explorer.exe"],
            "BytesIn": [1000000, 500],
            "BytesOut": [200000, 100],
        })
        result = detect_execution_artifacts(df)
        assert "srum" in result["artifact_types_detected"]


# ── generate_waf_threat_profiles ─────────────────────────────────────────

class TestWafProfiles:
    def test_empty_df(self):
        df = pl.DataFrame({"col1": []})
        assert generate_waf_threat_profiles(df) == []

    def test_no_ip_column(self):
        df = pl.DataFrame({"Event": ["test"] * 5})
        assert generate_waf_threat_profiles(df) == []

    def test_basic_waf_profiling(self):
        df = pl.DataFrame({
            "ClientIP": ["10.0.0.1"] * 5 + ["10.0.0.2"] * 2,
            "RequestPath": ["/login", "/admin", "/api", "/wp-admin", "/xmlrpc", "/", "/about"],
            "ViolationCategory": ["SQLi", "SQLi", "XSS", "Brute", "RCE", "Scan", "Scan"],
            "Timestamp": ["2026-01-01 10:00:00"] * 7,
        })
        result = generate_waf_threat_profiles(df)
        assert len(result) >= 1
        top = result[0]
        assert top["ip"] == "10.0.0.1"
        assert top["total"] == 5
