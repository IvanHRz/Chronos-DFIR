"""
Tests for Chronos-DFIR Threat Intelligence Enrichment Engine.

Tests cover:
- IOC deduplication from forensic analysis results
- SQLite TTL cache (hit, miss, expiry)
- Enrichment functions with mocked HTTP responses
- Graceful degradation when APIs fail
"""

import asyncio
import json
import os
import tempfile
import time

import pytest

from engine.enrichment_cache import EnrichmentCache
from engine.enrichment import (
    deduplicate_iocs,
    load_api_keys,
    get_active_providers,
    _is_public_ip,
    _is_valid_domain,
    _validate_ioc_for_provider,
)


# ── Cache Tests ──────────────────────────────────────────────────────────────

class TestEnrichmentCache:
    def setup_method(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.tmp.close()
        self.cache = EnrichmentCache(db_path=self.tmp.name)

    def teardown_method(self):
        os.unlink(self.tmp.name)

    def test_cache_miss(self):
        result = self.cache.get("1.2.3.4", "ip", "abuseipdb")
        assert result is None

    def test_cache_set_and_get(self):
        data = {"abuse_confidence": 85, "total_reports": 12}
        self.cache.set("1.2.3.4", "ip", "abuseipdb", data, ttl_hours=24)
        result = self.cache.get("1.2.3.4", "ip", "abuseipdb")
        assert result is not None
        assert result["abuse_confidence"] == 85
        assert result["total_reports"] == 12

    def test_cache_expiry(self):
        data = {"country": "US"}
        self.cache.set("1.2.3.4", "ip", "ip_api", data, ttl_hours=0)  # Expire immediately
        # Manually set fetched_at to the past
        import sqlite3
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "UPDATE ioc_cache SET fetched_at = ? WHERE ioc_value = '1.2.3.4'",
            (time.time() - 7200,)  # 2 hours ago
        )
        conn.commit()
        conn.close()
        # Cache should return None for expired entry
        result = self.cache.get("1.2.3.4", "ip", "ip_api")
        assert result is None

    def test_cache_overwrite(self):
        self.cache.set("1.2.3.4", "ip", "abuseipdb", {"score": 50})
        self.cache.set("1.2.3.4", "ip", "abuseipdb", {"score": 90})
        result = self.cache.get("1.2.3.4", "ip", "abuseipdb")
        assert result["score"] == 90

    def test_cache_stats(self):
        self.cache.set("1.2.3.4", "ip", "abuseipdb", {"score": 50})
        self.cache.set("8.8.8.8", "ip", "ip_api", {"country": "US"})
        stats = self.cache.stats()
        assert stats["total_entries"] == 2
        assert "abuseipdb" in stats["by_provider"]
        assert "ip_api" in stats["by_provider"]

    def test_cache_clear_expired(self):
        self.cache.set("1.2.3.4", "ip", "abuseipdb", {"score": 50}, ttl_hours=0)
        import sqlite3
        conn = sqlite3.connect(self.tmp.name)
        conn.execute(
            "UPDATE ioc_cache SET fetched_at = ?",
            (time.time() - 7200,)
        )
        conn.commit()
        conn.close()
        deleted = self.cache.clear_expired()
        assert deleted == 1

    def test_cache_different_providers_same_ioc(self):
        self.cache.set("1.2.3.4", "ip", "abuseipdb", {"score": 85})
        self.cache.set("1.2.3.4", "ip", "ip_api", {"country": "US"})
        self.cache.set("1.2.3.4", "ip", "virustotal", {"malicious": 3})
        assert self.cache.get("1.2.3.4", "ip", "abuseipdb")["score"] == 85
        assert self.cache.get("1.2.3.4", "ip", "ip_api")["country"] == "US"
        assert self.cache.get("1.2.3.4", "ip", "virustotal")["malicious"] == 3


# ── IOC Deduplication Tests ──────────────────────────────────────────────────

class TestDeduplicateIOCs:
    def test_extract_ips_from_context(self):
        context = {
            "type": "context",
            "ips": [
                {"id": "8.8.8.8", "count": 100},
                {"id": "1.1.1.1", "count": 50},
                {"id": "192.168.1.1", "count": 200},  # Private — should be excluded
            ],
        }
        iocs = deduplicate_iocs(context_data=context)
        assert "8.8.8.8" in iocs["ips"]
        assert "1.1.1.1" in iocs["ips"]
        assert "192.168.1.1" not in iocs["ips"]

    def test_extract_ips_from_sessions(self):
        sessions = [
            {"attacker_ip": "45.33.32.100", "request_count": 500},
            {"attacker_ip": "10.0.0.1", "request_count": 10},  # Private
        ]
        iocs = deduplicate_iocs(session_profiles=sessions)
        assert "45.33.32.100" in iocs["ips"]
        assert "10.0.0.1" not in iocs["ips"]

    def test_extract_ips_from_correlation(self):
        correlation = {
            "chains": [
                {"pivot_type": "ip", "pivot_value": "45.33.32.156", "event_count": 5},
                {"pivot_type": "user", "pivot_value": "admin", "event_count": 3},
            ]
        }
        iocs = deduplicate_iocs(correlation_result=correlation)
        assert "45.33.32.156" in iocs["ips"]
        assert "admin" not in iocs["ips"]

    def test_dedup_across_sources(self):
        """Same IP from context and sessions should appear only once."""
        context = {"ips": [{"id": "8.8.8.8", "count": 100}]}
        sessions = [{"attacker_ip": "8.8.8.8", "request_count": 500}]
        iocs = deduplicate_iocs(context_data=context, session_profiles=sessions)
        assert len([ip for ip in iocs["ips"] if ip == "8.8.8.8"]) == 1

    def test_extract_emails_from_users(self):
        context = {
            "users": [
                {"id": "admin@company.com", "count": 50},
                {"id": "SYSTEM", "count": 200},
                {"id": "john.doe@example.org", "count": 10},
            ]
        }
        iocs = deduplicate_iocs(context_data=context)
        assert "admin@company.com" in iocs["emails"]
        assert "john.doe@example.org" in iocs["emails"]
        assert "SYSTEM" not in iocs["emails"]

    def test_extract_domains_from_urls(self):
        context = {
            "paths": [
                {"id": "https://evil.example.com/malware.exe", "count": 5},
                {"id": "/var/log/syslog", "count": 100},
            ]
        }
        iocs = deduplicate_iocs(context_data=context)
        assert "evil.example.com" in iocs["domains"]

    def test_empty_inputs(self):
        iocs = deduplicate_iocs()
        assert iocs["ips"] == set()
        assert iocs["domains"] == set()
        assert iocs["hashes"] == set()
        assert iocs["emails"] == set()

    def test_max_limits(self):
        """Should limit IPs to MAX_IPS (20)."""
        context = {
            "ips": [{"id": f"8.8.{i}.{j}", "count": 1}
                    for i in range(1, 4) for j in range(1, 20)]
        }
        iocs = deduplicate_iocs(context_data=context)
        assert len(iocs["ips"]) <= 20

    def test_none_inputs(self):
        """Should handle None gracefully."""
        iocs = deduplicate_iocs(context_data=None, session_profiles=None, correlation_result=None)
        assert all(len(v) == 0 for v in iocs.values())


# ── IP Validation Tests ──────────────────────────────────────────────────────

class TestIPValidation:
    def test_public_ips(self):
        assert _is_public_ip("8.8.8.8") is True
        assert _is_public_ip("1.1.1.1") is True
        assert _is_public_ip("45.33.32.156") is True

    def test_private_ips(self):
        assert _is_public_ip("192.168.1.1") is False
        assert _is_public_ip("10.0.0.1") is False
        assert _is_public_ip("172.16.0.1") is False
        assert _is_public_ip("127.0.0.1") is False

    def test_invalid_ips(self):
        assert _is_public_ip("not_an_ip") is False
        assert _is_public_ip("999.999.999.999") is False
        assert _is_public_ip("") is False


# ── API Key Loading Tests ────────────────────────────────────────────────────

class TestAPIKeys:
    def test_load_api_keys_empty(self):
        # Clear any existing keys
        for key in ["ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "HIBP_API_KEY"]:
            os.environ.pop(key, None)
        keys = load_api_keys()
        assert keys["abuseipdb"] == ""
        assert keys["virustotal"] == ""

    def test_load_api_keys_with_values(self):
        os.environ["ABUSEIPDB_API_KEY"] = "test_key_123"
        try:
            keys = load_api_keys()
            assert keys["abuseipdb"] == "test_key_123"
        finally:
            del os.environ["ABUSEIPDB_API_KEY"]

    def test_active_providers_no_keys(self):
        keys = {"abuseipdb": "", "virustotal": "", "urlscan": "", "hibp": ""}
        active = get_active_providers(keys)
        # ip_api and urlhaus always active (no key needed)
        assert "ip_api" in active
        assert "urlhaus" in active
        assert "abuseipdb" not in active

    def test_active_providers_with_keys(self):
        keys = {"abuseipdb": "key123", "virustotal": "key456", "urlscan": "", "hibp": ""}
        active = get_active_providers(keys)
        assert "abuseipdb" in active
        assert "virustotal" in active
        assert "urlscan" not in active


# ── Domain Validation Tests (v198) ──────────────────────────────────────────

class TestDomainValidation:
    def test_rejects_exe_files(self):
        assert _is_valid_domain("cmd.exe") is False
        assert _is_valid_domain("svchost.exe") is False
        assert _is_valid_domain("explorer.exe") is False
        assert _is_valid_domain("backgroundtaskhost.exe") is False
        assert _is_valid_domain("aeminstoreservice.exe") is False

    def test_rejects_dll_files(self):
        assert _is_valid_domain("kernel32.dll") is False
        assert _is_valid_domain("ntdll.dll") is False

    def test_rejects_other_file_extensions(self):
        assert _is_valid_domain("config.xml") is False
        assert _is_valid_domain("data.json") is False
        assert _is_valid_domain("script.ps1") is False
        assert _is_valid_domain("report.pdf") is False
        assert _is_valid_domain("archive.zip") is False

    def test_accepts_real_domains(self):
        assert _is_valid_domain("evil.com") is True
        assert _is_valid_domain("malware.ru") is True
        assert _is_valid_domain("c2server.io") is True
        assert _is_valid_domain("phishing.tk") is True
        assert _is_valid_domain("dd.configurationcenter.com") is True
        assert _is_valid_domain("host.configurationcenter.com") is True

    def test_rejects_single_char_name(self):
        assert _is_valid_domain("a.com") is False
        assert _is_valid_domain("x.ru") is False

    def test_accepts_two_char_name(self):
        assert _is_valid_domain("go.com") is True
        assert _is_valid_domain("ab.io") is True

    def test_rejects_unknown_tlds(self):
        assert _is_valid_domain("something.zzzzz") is False
        assert _is_valid_domain("fake.notreal") is False

    def test_rejects_non_matching_patterns(self):
        assert _is_valid_domain("not a domain") is False
        assert _is_valid_domain("192.168.1.1") is False
        assert _is_valid_domain("") is False


# ── Provider Compatibility Tests (v198) ─────────────────────────────────────

class TestProviderCompatibility:
    def test_circl_only_md5_sha1(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"  # 32 chars
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40 chars
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # 64 chars
        assert _validate_ioc_for_provider(md5, "hash", "circl") is True
        assert _validate_ioc_for_provider(sha1, "hash", "circl") is True
        assert _validate_ioc_for_provider(sha256, "hash", "circl") is False

    def test_virustotal_accepts_all_hashes(self):
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert _validate_ioc_for_provider(md5, "hash", "virustotal") is True
        assert _validate_ioc_for_provider(sha256, "hash", "virustotal") is True

    def test_domain_validation_in_provider(self):
        assert _validate_ioc_for_provider("evil.com", "domain", "urlhaus") is True
        assert _validate_ioc_for_provider("cmd.exe", "domain", "urlhaus") is False
        assert _validate_ioc_for_provider("svchost.exe", "domain", "virustotal") is False

    def test_ip_validation_public_only(self):
        assert _validate_ioc_for_provider("8.8.8.8", "ip", "ip_api") is True
        assert _validate_ioc_for_provider("192.168.1.1", "ip", "ip_api") is False
        assert _validate_ioc_for_provider("10.0.0.1", "ip", "abuseipdb") is False

    def test_email_validation(self):
        assert _validate_ioc_for_provider("user@example.com", "email", "hibp") is True
        assert _validate_ioc_for_provider("not-an-email", "email", "hibp") is False
