"""
Chronos-DFIR Threat Intelligence Enrichment Engine.

Async API client for enriching IOCs (IPs, domains, hashes, emails)
with data from multiple threat intelligence providers.

Architecture:
  - Non-blocking: enrichment is optional, forensic report works without it
  - Graceful degradation: partial results returned on API failures
  - Rate-limited: per-provider semaphores to respect free-tier limits
  - Cached: SQLite TTL cache prevents duplicate API calls
"""

import asyncio
import httpx
import ipaddress
import logging
import os
import re
import time as _time
from typing import Any, Dict, List, Optional, Set

from engine.enrichment_cache import EnrichmentCache

logger = logging.getLogger("chronos.enrichment")

# ---------------------------------------------------------------------------
# API Key Loading
# ---------------------------------------------------------------------------

def load_api_keys() -> Dict[str, str]:
    """Load API keys from environment variables."""
    return {
        "abuseipdb": os.environ.get("ABUSEIPDB_API_KEY", ""),
        "virustotal": os.environ.get("VIRUSTOTAL_API_KEY", ""),
        "urlscan": os.environ.get("URLSCAN_API_KEY", ""),
        "hibp": os.environ.get("HIBP_API_KEY", ""),
        "abusech": os.environ.get("ABUSECH_API_KEY", ""),
        "otx": os.environ.get("OTX_API_KEY", ""),
        "greynoise": os.environ.get("GREYNOISE_API_KEY", ""),
    }


def get_active_providers(keys: Dict[str, str]) -> List[str]:
    """Return list of providers that have API keys configured."""
    # Free providers that don't need keys
    active = ["ip_api", "urlhaus", "circl", "internetdb", "threatfox_free"]
    for provider, key in keys.items():
        if key:
            active.append(provider)
            # abuse.ch key enables both malwarebazaar and threatfox
            if provider == "abusech":
                active.extend(["malwarebazaar", "threatfox"])
    return list(set(active))


# ---------------------------------------------------------------------------
# IOC Deduplication
# ---------------------------------------------------------------------------

_PRIVATE_IP_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.", "192.168.", "127.", "0.", "169.254.")

_IP_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32,64}$")
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$")

# --- Strict domain validation (prevents .exe/.dll false positives) ---
_VALID_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int",
    "io", "co", "us", "uk", "de", "fr", "ru", "cn", "jp", "br", "au", "ca",
    "in", "it", "nl", "es", "se", "no", "fi", "dk", "pl", "cz", "at", "ch",
    "be", "pt", "kr", "tw", "hk", "sg", "nz", "za", "mx", "ar", "cl", "ve",
    "info", "biz", "me", "tv", "cc", "xyz", "online", "site", "top",
    "cloud", "dev", "app", "tech", "ai", "sh", "ly", "gg", "la",
    "pro", "mobi", "name", "travel", "museum", "aero", "coop",
    # Malicious TLDs commonly seen in CTI
    "tk", "ml", "ga", "cf", "gq", "su", "pw", "ws", "to", "buzz", "icu",
    "work", "click", "link", "fun", "monster", "rest",
})

_FILE_EXTENSIONS = frozenset({
    "exe", "dll", "sys", "msi", "bat", "cmd", "ps1", "vbs", "js", "wsf",
    "scr", "com", "pif", "lnk", "tmp", "log", "dat", "bin", "cab", "inf",
    "evtx", "etl", "dmp", "pf", "db", "sqlite", "config", "xml", "json",
    "txt", "csv", "html", "htm", "php", "asp", "aspx", "jsp",
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf",
    "zip", "rar", "7z", "gz", "tar", "iso", "img",
    "py", "rb", "pl", "sh", "bash", "csh", "ksh",
})


def _is_valid_domain(value: str) -> bool:
    """Validate that a string is a real internet domain, not a filename.

    Rejects: cmd.exe, svchost.exe, explorer.exe, etc.
    Accepts: evil.com, malware.ru, c2.example.io, etc.

    Strategy: TLD allowlist is the primary filter. Since exe/dll/sys/etc.
    are not valid TLDs, they get rejected. Overlapping entries like "com"
    (both a file extension and TLD) are allowed since they're real TLDs.
    """
    if not _DOMAIN_PATTERN.match(value):
        return False
    parts = value.rsplit(".", 1)
    if len(parts) != 2:
        return False
    tld = parts[1].lower()
    if tld not in _VALID_TLDS:
        return False
    # Reject very short names (a.com, b.ru) — usually noise
    if len(parts[0]) <= 1:
        return False
    return True


def _validate_ioc_for_provider(ioc_value: str, ioc_type: str, provider: str) -> bool:
    """Check if an IOC value is valid/compatible for a specific provider."""
    if ioc_type == "ip":
        if not _IP_PATTERN.match(ioc_value):
            return False
        if provider in ("ip_api", "abuseipdb", "greynoise"):
            return _is_public_ip(ioc_value)
        return True
    elif ioc_type == "domain":
        return _is_valid_domain(ioc_value)
    elif ioc_type == "hash":
        if not _HASH_PATTERN.match(ioc_value):
            return False
        hash_len = len(ioc_value)
        if provider == "circl":
            return hash_len in (32, 40)  # CIRCL only supports MD5/SHA-1
        return hash_len in (32, 40, 64)
    elif ioc_type == "email":
        return bool(_EMAIL_PATTERN.match(ioc_value))
    return False


def _is_public_ip(ip: str) -> bool:
    """Check if an IP is public (not private/reserved)."""
    # Strip IPv4-mapped IPv6 prefix
    clean_ip = ip.removeprefix("::ffff:")
    if not _IP_PATTERN.match(clean_ip):
        return False
    try:
        return ipaddress.ip_address(clean_ip).is_global
    except ValueError:
        return False


def deduplicate_iocs(
    context_data: Optional[dict] = None,
    session_profiles: Optional[list] = None,
    correlation_result: Optional[dict] = None,
    hunt_data: Optional[dict] = None,
) -> Dict[str, Set[str]]:
    """
    Extract unique IOCs from forensic analysis results.

    Collects IPs, domains, hashes, and emails from:
    - context_data (Task 1: sub_analyze_context)
    - session_profiles (Task 6: group_sessions)
    - correlation_result (Task 5: correlate_cross_source)
    - hunt_data (Task 2: sub_analyze_hunting — Top Network Destinations)
    """
    iocs: Dict[str, Set[str]] = {
        "ips": set(),
        "domains": set(),
        "hashes": set(),
        "emails": set(),
    }

    # --- Extract from context_data (Task 1) ---
    if isinstance(context_data, dict):
        # IPs from context
        for ip_entry in context_data.get("ips", []):
            ip = ip_entry.get("id", "") if isinstance(ip_entry, dict) else str(ip_entry)
            if _is_public_ip(ip):
                iocs["ips"].add(ip)

        # Users that look like emails
        for user_entry in context_data.get("users", []):
            user = user_entry.get("id", "") if isinstance(user_entry, dict) else str(user_entry)
            if _EMAIL_PATTERN.match(user):
                iocs["emails"].add(user.lower())

        # Paths that might contain domains or hashes
        for path_entry in context_data.get("paths", []):
            path = path_entry.get("id", "") if isinstance(path_entry, dict) else str(path_entry)
            # Extract domain-like strings from URLs
            if "://" in path:
                try:
                    host = path.split("://")[1].split("/")[0].split(":")[0]
                    if _is_valid_domain(host) and not _IP_PATTERN.match(host):
                        iocs["domains"].add(host.lower())
                except (IndexError, ValueError):
                    pass

    # --- Extract from session profiles (Task 6) ---
    if isinstance(session_profiles, list):
        for profile in session_profiles:
            if isinstance(profile, dict):
                ip = profile.get("attacker_ip", "")
                if _is_public_ip(ip):
                    iocs["ips"].add(ip)

    # --- Extract from correlation (Task 5) ---
    if isinstance(correlation_result, dict):
        for chain in correlation_result.get("chains", []):
            if isinstance(chain, dict):
                pivot = chain.get("pivot_value", "")
                pivot_type = chain.get("pivot_type", "")
                if pivot_type == "ip" and _is_public_ip(pivot):
                    iocs["ips"].add(pivot)

    # --- Extract from hunting data (Task 2: Top Network Destinations) ---
    if isinstance(hunt_data, dict):
        network = hunt_data.get("network", {})
        if isinstance(network, dict):
            for dest in network.get("destinations", []):
                ip = dest.get("Clean_Dst", "") if isinstance(dest, dict) else ""
                if ip and _is_public_ip(ip):
                    iocs["ips"].add(ip)

    # Limit to top N to avoid excessive API calls
    MAX_IPS = 20
    MAX_DOMAINS = 10
    MAX_HASHES = 10
    MAX_EMAILS = 5

    return {
        "ips": set(list(iocs["ips"])[:MAX_IPS]),
        "domains": set(list(iocs["domains"])[:MAX_DOMAINS]),
        "hashes": set(list(iocs["hashes"])[:MAX_HASHES]),
        "emails": set(list(iocs["emails"])[:MAX_EMAILS]),
    }


_HASH_COL_PATTERNS = frozenset({
    "md5", "sha1", "sha256", "hashes", "filehash", "hash", "imphash",
    "sha256hash", "md5hash", "processfilehashmd5", "processfilehashsha1",
    "processfilehashsha256", "parentfilehashmd5", "parentfilehashsha256",
})


def extract_hashes_from_sigma(sigma_hits: list) -> Set[str]:
    """Extract unique file hashes from Sigma evidence rows for auto-enrichment."""
    hashes: Set[str] = set()
    if not isinstance(sigma_hits, list):
        return hashes
    for hit in sigma_hits:
        for row in hit.get("sample_evidence", []):
            if not isinstance(row, dict):
                continue
            for col, val in row.items():
                if col.lower() in _HASH_COL_PATTERNS and val:
                    clean = str(val).strip()
                    if re.match(r'^[a-fA-F0-9]{32,64}$', clean):
                        hashes.add(clean)
    return hashes


# ---------------------------------------------------------------------------
# Per-Provider Enrichment Functions
# ---------------------------------------------------------------------------

async def _enrich_ip_geoip(
    ip: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """IP-API.com — Geolocation + ASN (no key needed, 45 req/min)."""
    cached = cache.get(ip, "ip", "ip_api")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "status,country,countryCode,regionName,city,isp,org,as,asname,query"},
                timeout=5.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    result = {
                        "provider": "ip_api",
                        "country": data.get("country", ""),
                        "country_code": data.get("countryCode", ""),
                        "region": data.get("regionName", ""),
                        "city": data.get("city", ""),
                        "isp": data.get("isp", ""),
                        "org": data.get("org", ""),
                        "asn": data.get("as", ""),
                        "asname": data.get("asname", ""),
                    }
                    cache.set(ip, "ip", "ip_api", result)
                    return result
        except Exception as e:
            logger.debug(f"IP-API error for {ip}: {e}")
    return {}


async def _enrich_ip_abuse(
    ip: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """AbuseIPDB — IP reputation (1000 checks/day)."""
    if not api_key:
        return {}

    cached = cache.get(ip, "ip", "abuseipdb")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                headers={"Key": api_key, "Accept": "application/json"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "provider": "abuseipdb",
                    "abuse_confidence": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "usage_type": data.get("usageType", ""),
                    "domain": data.get("domain", ""),
                    "last_reported": data.get("lastReportedAt", ""),
                }
                cache.set(ip, "ip", "abuseipdb", result)
                return result
        except Exception as e:
            logger.debug(f"AbuseIPDB error for {ip}: {e}")
    return {}


async def _enrich_domain_urlhaus(
    domain: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """URLhaus (abuse.ch) — Malicious URL database (no key needed)."""
    cached = cache.get(domain, "domain", "urlhaus")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.post(
                "https://urlhaus-api.abuse.ch/v1/host/",
                data={"host": domain},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "provider": "urlhaus",
                    "query_status": data.get("query_status", ""),
                    "urls_total": data.get("urls", 0) if isinstance(data.get("urls"), int) else len(data.get("urls", [])),
                    "threat_type": "",
                    "tags": [],
                }
                urls = data.get("urls", [])
                if isinstance(urls, list) and urls:
                    first = urls[0]
                    result["threat_type"] = first.get("threat", "")
                    result["tags"] = first.get("tags", []) or []
                cache.set(domain, "domain", "urlhaus", result)
                return result
        except Exception as e:
            logger.debug(f"URLhaus error for {domain}: {e}")
    return {}


def _vt_error_result(status_code: int, ioc_value: str) -> Dict[str, Any]:
    """Return a structured error result for VirusTotal API failures."""
    error_map = {
        401: "Invalid API key",
        403: "API quota exceeded or forbidden",
        404: "Not found in VirusTotal database",
        429: "Rate limited — too many requests",
    }
    msg = error_map.get(status_code, f"HTTP {status_code}")
    logger.warning(f"VirusTotal returned {status_code} for {ioc_value}: {msg}")
    return {"provider": "virustotal", "error": msg, "status_code": status_code}


async def _enrich_ip_virustotal(
    ip: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """VirusTotal — IP lookup (4 req/min, 500/day)."""
    if not api_key:
        return {}

    cached = cache.get(ip, "ip", "virustotal")
    if cached is not None:
        return cached

    async with semaphore:
        await _get_vt_limiter().acquire()
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result = {
                    "provider": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "country": attrs.get("country", ""),
                    "as_owner": attrs.get("as_owner", ""),
                }
                cache.set(ip, "ip", "virustotal", result)
                return result
            else:
                return _vt_error_result(resp.status_code, ip)
        except Exception as e:
            logger.debug(f"VirusTotal error for {ip}: {e}")
    return {}


async def _enrich_hash_virustotal(
    hash_val: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """VirusTotal — File hash lookup (4 req/min, 500/day)."""
    if not api_key:
        return {}

    cached = cache.get(hash_val, "hash", "virustotal")
    if cached is not None:
        return cached

    async with semaphore:
        await _get_vt_limiter().acquire()
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/files/{hash_val}",
                headers={"x-apikey": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result = {
                    "provider": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "type_description": attrs.get("type_description", ""),
                    "popular_threat_name": attrs.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                    "sha256": attrs.get("sha256", hash_val),
                }
                cache.set(hash_val, "hash", "virustotal", result)
                return result
            else:
                return _vt_error_result(resp.status_code, hash_val)
        except Exception as e:
            logger.debug(f"VirusTotal hash error for {hash_val}: {e}")
    return {}


async def _enrich_domain_virustotal(
    domain: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """VirusTotal — Domain lookup (4 req/min, 500/day)."""
    if not api_key:
        return {}

    cached = cache.get(domain, "domain", "virustotal")
    if cached is not None:
        return cached

    async with semaphore:
        await _get_vt_limiter().acquire()
        try:
            resp = await client.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers={"x-apikey": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                result = {
                    "provider": "virustotal",
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "registrar": attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date", ""),
                }
                cache.set(domain, "domain", "virustotal", result)
                return result
            else:
                return _vt_error_result(resp.status_code, domain)
        except Exception as e:
            logger.debug(f"VirusTotal domain error for {domain}: {e}")
    return {}


async def _enrich_email_hibp(
    email: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """HaveIBeenPwned — Credential breach check."""
    if not api_key:
        return {}

    cached = cache.get(email, "email", "hibp")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={
                    "hibp-api-key": api_key,
                    "user-agent": "Chronos-DFIR",
                },
                params={"truncateResponse": "true"},
                timeout=10.0,
            )
            if resp.status_code == 200:
                breaches = resp.json()
                result = {
                    "provider": "hibp",
                    "breach_count": len(breaches),
                    "breaches": [b.get("Name", "") for b in breaches[:10]],
                }
                cache.set(email, "email", "hibp", result)
                return result
            elif resp.status_code == 404:
                result = {"provider": "hibp", "breach_count": 0, "breaches": []}
                cache.set(email, "email", "hibp", result)
                return result
        except Exception as e:
            logger.debug(f"HIBP error for {email}: {e}")
    return {}


async def _enrich_domain_urlscan(
    domain: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """URLScan.io — Passive domain scanning (100/day)."""
    if not api_key:
        return {}

    cached = cache.get(domain, "domain", "urlscan")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f"domain:{domain}", "size": 5},
                headers={"API-Key": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                results_list = data.get("results", [])
                result = {
                    "provider": "urlscan",
                    "total_results": data.get("total", 0),
                    "verdicts": [],
                }
                for r in results_list[:3]:
                    verdict = r.get("verdicts", {}).get("overall", {})
                    if verdict:
                        result["verdicts"].append({
                            "score": verdict.get("score", 0),
                            "malicious": verdict.get("malicious", False),
                        })
                cache.set(domain, "domain", "urlscan", result)
                return result
        except Exception as e:
            logger.debug(f"URLScan error for {domain}: {e}")
    return {}


# ---------------------------------------------------------------------------
# NEW Providers — CIRCL, MalwareBazaar, ThreatFox, OTX, GreyNoise
# ---------------------------------------------------------------------------

async def _enrich_hash_circl(
    hash_val: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """CIRCL hashlookup — Known-file database (NSRL). No key needed."""
    cached = cache.get(hash_val, "hash", "circl")
    if cached is not None:
        return cached

    # Determine hash type by length
    hash_type = "sha256" if len(hash_val) == 64 else "sha1" if len(hash_val) == 40 else "md5"

    async with semaphore:
        try:
            resp = await client.get(
                f"https://hashlookup.circl.lu/lookup/{hash_type}/{hash_val}",
                timeout=8.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "provider": "circl",
                    "known": True,
                    "file_name": data.get("FileName", ""),
                    "file_size": data.get("FileSize", ""),
                    "product_name": data.get("ProductName", ""),
                    "os_name": data.get("OpSystemName", ""),
                    "source": data.get("source", "NSRL"),
                }
                cache.set(hash_val, "hash", "circl", result, ttl_hours=168)
                return result
            elif resp.status_code == 404:
                result = {"provider": "circl", "known": False}
                cache.set(hash_val, "hash", "circl", result, ttl_hours=24)
                return result
        except Exception as e:
            logger.debug(f"CIRCL error for {hash_val}: {e}")
    return {}


async def _enrich_hash_malwarebazaar(
    hash_val: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """MalwareBazaar (abuse.ch) — Malware sample lookup."""
    if not api_key:
        return {}

    cached = cache.get(hash_val, "hash", "malwarebazaar")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.post(
                "https://mb-api.abuse.ch/api/v1/",
                data={"query": "get_info", "hash": hash_val},
                headers={"Auth-Key": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    sample = data["data"][0]
                    result = {
                        "provider": "malwarebazaar",
                        "found": True,
                        "file_type": sample.get("file_type", ""),
                        "file_type_mime": sample.get("file_type_mime", ""),
                        "signature": sample.get("signature", ""),
                        "delivery_method": sample.get("delivery_method", ""),
                        "tags": sample.get("tags", []) or [],
                        "first_seen": sample.get("first_seen", ""),
                        "reporter": sample.get("reporter", ""),
                    }
                    cache.set(hash_val, "hash", "malwarebazaar", result, ttl_hours=12)
                    return result
                else:
                    result = {"provider": "malwarebazaar", "found": False}
                    cache.set(hash_val, "hash", "malwarebazaar", result, ttl_hours=6)
                    return result
        except Exception as e:
            logger.debug(f"MalwareBazaar error for {hash_val}: {e}")
    return {}


async def _enrich_ioc_threatfox(
    ioc_value: str,
    ioc_type: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """ThreatFox (abuse.ch) — IOC-to-campaign mapping."""
    if not api_key:
        return {}

    cached = cache.get(ioc_value, ioc_type, "threatfox")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ioc_value},
                headers={"Auth-Key": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    hit = data["data"][0]
                    result = {
                        "provider": "threatfox",
                        "found": True,
                        "malware": hit.get("malware_printable", ""),
                        "malware_alias": hit.get("malware_alias", ""),
                        "confidence_level": hit.get("confidence_level", 0),
                        "threat_type": hit.get("threat_type", ""),
                        "tags": hit.get("tags", []) or [],
                        "first_seen": hit.get("first_seen_utc", ""),
                        "reporter": hit.get("reporter", ""),
                    }
                    cache.set(ioc_value, ioc_type, "threatfox", result, ttl_hours=6)
                    return result
                else:
                    result = {"provider": "threatfox", "found": False}
                    cache.set(ioc_value, ioc_type, "threatfox", result, ttl_hours=6)
                    return result
        except Exception as e:
            logger.debug(f"ThreatFox error for {ioc_value}: {e}")
    return {}


async def _enrich_ioc_otx(
    ioc_value: str,
    ioc_type: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """OTX AlienVault — Community threat intelligence."""
    if not api_key:
        return {}

    cached = cache.get(ioc_value, ioc_type, "otx")
    if cached is not None:
        return cached

    # Map IOC type to OTX indicator type
    otx_type_map = {
        "ip": "IPv4",
        "domain": "domain",
        "hash": "file",
        "url": "url",
    }
    otx_type = otx_type_map.get(ioc_type, "")
    if not otx_type:
        return {}

    async with semaphore:
        try:
            resp = await client.get(
                f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_value}/general",
                headers={"X-OTX-API-KEY": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                pulse_info = data.get("pulse_info", {})
                result = {
                    "provider": "otx",
                    "pulse_count": pulse_info.get("count", 0),
                    "pulses": [p.get("name", "") for p in pulse_info.get("pulses", [])[:5]],
                    "reputation": data.get("reputation", 0),
                    "country": data.get("country_name", ""),
                    "validation": [v.get("name", "") for v in data.get("validation", [])],
                }
                cache.set(ioc_value, ioc_type, "otx", result, ttl_hours=12)
                return result
        except Exception as e:
            logger.debug(f"OTX error for {ioc_value}: {e}")
    return {}


async def _enrich_ip_greynoise(
    ip: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    api_key: str,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """GreyNoise Community — IP noise classification."""
    if not api_key:
        return {}

    cached = cache.get(ip, "ip", "greynoise")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": api_key},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "provider": "greynoise",
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", "unknown"),
                    "name": data.get("name", ""),
                    "message": data.get("message", ""),
                    "link": data.get("link", ""),
                }
                cache.set(ip, "ip", "greynoise", result, ttl_hours=12)
                return result
            elif resp.status_code == 404:
                result = {"provider": "greynoise", "noise": False, "classification": "unknown"}
                cache.set(ip, "ip", "greynoise", result, ttl_hours=12)
                return result
        except Exception as e:
            logger.debug(f"GreyNoise error for {ip}: {e}")
    return {}


# ---------------------------------------------------------------------------
# Free API Providers (no key required)
# ---------------------------------------------------------------------------

async def _enrich_ip_internetdb(
    ip: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """Shodan InternetDB — Free IP enrichment (ports, vulns, hostnames)."""
    cached = cache.get(ip, "ip", "internetdb")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.get(
                f"https://internetdb.shodan.io/{ip}",
                timeout=8.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "provider": "internetdb",
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "vulns": data.get("vulns", []),
                    "cpes": data.get("cpes", []),
                    "tags": data.get("tags", []),
                }
                cache.set(ip, "ip", "internetdb", result)
                return result
        except Exception as e:
            logger.debug(f"InternetDB error for {ip}: {e}")
    return {}


async def _enrich_ioc_threatfox_free(
    ioc_value: str,
    ioc_type: str,
    client: httpx.AsyncClient,
    cache: EnrichmentCache,
    semaphore: asyncio.Semaphore,
) -> Dict[str, Any]:
    """ThreatFox (abuse.ch) — Free IOC search (no key required)."""
    cached = cache.get(ioc_value, ioc_type, "threatfox_free")
    if cached is not None:
        return cached

    async with semaphore:
        try:
            resp = await client.post(
                "https://threatfox-api.abuse.ch/api/v1/",
                json={"query": "search_ioc", "search_term": ioc_value},
                timeout=10.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok" and data.get("data"):
                    hits = data["data"]
                    result = {
                        "provider": "threatfox_free",
                        "threat_type": hits[0].get("threat_type", ""),
                        "malware": hits[0].get("malware_printable", ""),
                        "confidence": hits[0].get("confidence_level", 0),
                        "first_seen": hits[0].get("first_seen_utc", ""),
                        "tags": hits[0].get("tags", []),
                        "hits": len(hits),
                    }
                    cache.set(ioc_value, ioc_type, "threatfox_free", result)
                    return result
        except Exception as e:
            logger.debug(f"ThreatFox free error for {ioc_value}: {e}")
    return {}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

# --- VT Token Bucket Rate Limiter (4 req/min) ---
class _VTRateLimiter:
    """Token bucket rate limiter for VirusTotal (4 req/min).
    First 4 requests fire immediately; subsequent wait minimum needed time."""
    def __init__(self, rate: float = 4.0, per: float = 60.0):
        self._rate = rate
        self._per = per
        self._allowance = rate
        self._last_check = _time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        async with self._lock:
            now = _time.monotonic()
            elapsed = now - self._last_check
            self._last_check = now
            self._allowance += elapsed * (self._rate / self._per)
            if self._allowance > self._rate:
                self._allowance = self._rate
            if self._allowance < 1.0:
                wait = (1.0 - self._allowance) * (self._per / self._rate)
                await asyncio.sleep(wait)
                self._allowance = 0.0
            else:
                self._allowance -= 1.0

_vt_limiter = None

def _get_vt_limiter():
    global _vt_limiter
    if _vt_limiter is None:
        _vt_limiter = _VTRateLimiter()
    return _vt_limiter


# Rate limit semaphores per provider (legacy static — _get_semaphore() is used at runtime)
_SEMAPHORES = {
    "ip_api": asyncio.Semaphore(10),
    "abuseipdb": asyncio.Semaphore(5),
    "virustotal": asyncio.Semaphore(1),
    "urlhaus": asyncio.Semaphore(5),
    "urlscan": asyncio.Semaphore(3),
    "hibp": asyncio.Semaphore(3),
    "circl": asyncio.Semaphore(10),
    "malwarebazaar": asyncio.Semaphore(3),
    "threatfox": asyncio.Semaphore(3),
    "otx": asyncio.Semaphore(5),
    "greynoise": asyncio.Semaphore(5),
    "internetdb": asyncio.Semaphore(10),
    "threatfox_free": asyncio.Semaphore(5),
}

# Lazy singleton for semaphores (recreated per event loop)
_semaphore_cache: Dict[str, asyncio.Semaphore] = {}


def _get_semaphore(provider: str) -> asyncio.Semaphore:
    """Get or create a semaphore for the given provider."""
    if provider not in _semaphore_cache:
        limits = {
            "ip_api": 10, "abuseipdb": 5, "virustotal": 1,
            "urlhaus": 5, "urlscan": 3, "hibp": 3,
            "circl": 10, "malwarebazaar": 3, "threatfox": 3,
            "otx": 5, "greynoise": 5,
            "internetdb": 10, "threatfox_free": 5,
        }
        _semaphore_cache[provider] = asyncio.Semaphore(limits.get(provider, 5))
    return _semaphore_cache[provider]


async def enrich_all_iocs(
    iocs: Dict[str, Set[str]],
    keys: Dict[str, str],
    cache: Optional[EnrichmentCache] = None,
) -> Dict[str, Any]:
    """
    Orchestrate enrichment for all IOC types in parallel.

    Returns:
    {
        "ip_enrichment": [{"ip": str, "geo": {...}, "abuse": {...}, "vt": {...}}, ...],
        "domain_enrichment": [{"domain": str, "urlhaus": {...}, "vt": {...}, "urlscan": {...}}, ...],
        "hash_enrichment": [{"hash": str, "vt": {...}}, ...],
        "email_enrichment": [{"email": str, "hibp": {...}}, ...],
        "providers_used": ["ip_api", "abuseipdb", ...],
        "total_enriched": int,
    }
    """
    if cache is None:
        cache = EnrichmentCache()
        cache.clear_expired()

    result = {
        "ip_enrichment": [],
        "domain_enrichment": [],
        "hash_enrichment": [],
        "email_enrichment": [],
        "providers_used": get_active_providers(keys),
        "total_enriched": 0,
    }

    async with httpx.AsyncClient(
        follow_redirects=True,
        limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
    ) as client:

        # --- Helper: enrich single IP (all providers in parallel) ---
        async def _enrich_single_ip(ip):
            tasks = [
                _enrich_ip_geoip(ip, client, cache, _get_semaphore("ip_api")),
                _enrich_ip_abuse(ip, client, cache, keys.get("abuseipdb", ""), _get_semaphore("abuseipdb")),
                _enrich_ip_internetdb(ip, client, cache, _get_semaphore("internetdb")),
                _enrich_ioc_threatfox_free(ip, "ip", client, cache, _get_semaphore("threatfox_free")),
            ]
            if keys.get("virustotal"):
                tasks.append(_enrich_ip_virustotal(ip, client, cache, keys["virustotal"], _get_semaphore("virustotal")))
            if keys.get("greynoise"):
                tasks.append(_enrich_ip_greynoise(ip, client, cache, keys["greynoise"], _get_semaphore("greynoise")))
            if keys.get("abusech"):
                tasks.append(_enrich_ioc_threatfox(ip, "ip", client, cache, keys["abusech"], _get_semaphore("threatfox")))
            if keys.get("otx"):
                tasks.append(_enrich_ioc_otx(ip, "ip", client, cache, keys["otx"], _get_semaphore("otx")))

            ip_results = await asyncio.gather(*tasks, return_exceptions=True)
            ip_data = {"ip": ip, "geo": {}, "abuse": {}, "vt": {}, "greynoise": {}, "threatfox": {}, "otx": {},
                        "internetdb": {}, "threatfox_free": {}}
            for r in ip_results:
                if isinstance(r, dict) and r:
                    provider = r.get("provider", "")
                    if provider == "ip_api":
                        ip_data["geo"] = r
                    elif provider == "abuseipdb":
                        ip_data["abuse"] = r
                    elif provider == "virustotal":
                        ip_data["vt"] = r
                    elif provider == "greynoise":
                        ip_data["greynoise"] = r
                    elif provider == "threatfox":
                        ip_data["threatfox"] = r
                    elif provider == "otx":
                        ip_data["otx"] = r
                    elif provider == "internetdb":
                        ip_data["internetdb"] = r
                    elif provider == "threatfox_free":
                        ip_data["threatfox_free"] = r
            return ip_data

        # --- Helper: enrich single domain ---
        async def _enrich_single_domain(domain):
            if not _is_valid_domain(domain):
                return {"domain": domain}  # Skip invalid domains (e.g. .exe files)
            tasks = [
                _enrich_domain_urlhaus(domain, client, cache, _get_semaphore("urlhaus")),
                _enrich_ioc_threatfox_free(domain, "domain", client, cache, _get_semaphore("threatfox_free")),
            ]
            if keys.get("virustotal"):
                tasks.append(_enrich_domain_virustotal(domain, client, cache, keys["virustotal"], _get_semaphore("virustotal")))
            if keys.get("urlscan"):
                tasks.append(_enrich_domain_urlscan(domain, client, cache, keys["urlscan"], _get_semaphore("urlscan")))
            if keys.get("abusech"):
                tasks.append(_enrich_ioc_threatfox(domain, "domain", client, cache, keys["abusech"], _get_semaphore("threatfox")))
            if keys.get("otx"):
                tasks.append(_enrich_ioc_otx(domain, "domain", client, cache, keys["otx"], _get_semaphore("otx")))

            domain_results = await asyncio.gather(*tasks, return_exceptions=True)
            domain_data = {"domain": domain, "urlhaus": {}, "vt": {}, "urlscan": {}, "threatfox": {}, "otx": {},
                           "threatfox_free": {}}
            for r in domain_results:
                if isinstance(r, dict) and r:
                    provider = r.get("provider", "")
                    if provider in domain_data:
                        domain_data[provider] = r
            return domain_data

        # --- Helper: enrich single hash ---
        async def _enrich_single_hash(hash_val):
            tasks = [
                _enrich_ioc_threatfox_free(hash_val, "hash", client, cache, _get_semaphore("threatfox_free")),
            ]
            # CIRCL only supports MD5 (32) and SHA-1 (40)
            if _validate_ioc_for_provider(hash_val, "hash", "circl"):
                tasks.append(_enrich_hash_circl(hash_val, client, cache, _get_semaphore("circl")))
            if keys.get("virustotal"):
                tasks.append(_enrich_hash_virustotal(hash_val, client, cache, keys["virustotal"], _get_semaphore("virustotal")))
            if keys.get("abusech"):
                tasks.append(_enrich_hash_malwarebazaar(hash_val, client, cache, keys["abusech"], _get_semaphore("malwarebazaar")))
                tasks.append(_enrich_ioc_threatfox(hash_val, "hash", client, cache, keys["abusech"], _get_semaphore("threatfox")))
            if keys.get("otx"):
                tasks.append(_enrich_ioc_otx(hash_val, "hash", client, cache, keys["otx"], _get_semaphore("otx")))

            hash_results = await asyncio.gather(*tasks, return_exceptions=True)
            hash_data = {"hash": hash_val, "circl": {}, "vt": {}, "malwarebazaar": {}, "threatfox": {}, "otx": {}}
            for r in hash_results:
                if isinstance(r, dict) and r:
                    provider = r.get("provider", "")
                    if provider in hash_data:
                        hash_data[provider] = r
            return hash_data

        # --- Helper: enrich single email ---
        async def _enrich_single_email(email):
            hibp_result = await _enrich_email_hibp(
                email, client, cache, keys["hibp"], _get_semaphore("hibp")
            )
            if hibp_result:
                return {"email": email, "hibp": hibp_result}
            return None

        # --- Run ALL IOCs in parallel (semaphores control concurrency) ---
        all_tasks = []
        task_types = []  # Track which type each task belongs to

        for ip in iocs.get("ips", set()):
            all_tasks.append(_enrich_single_ip(ip))
            task_types.append("ip")

        for domain in iocs.get("domains", set()):
            all_tasks.append(_enrich_single_domain(domain))
            task_types.append("domain")

        for hash_val in iocs.get("hashes", set()):
            all_tasks.append(_enrich_single_hash(hash_val))
            task_types.append("hash")

        if keys.get("hibp"):
            for email in iocs.get("emails", set()):
                all_tasks.append(_enrich_single_email(email))
                task_types.append("email")

        try:
            all_results = await asyncio.wait_for(
                asyncio.gather(*all_tasks, return_exceptions=True),
                timeout=90.0,
            )
        except asyncio.TimeoutError:
            logger.warning("Enrichment timed out at 90s, returning partial results")
            all_results = []

        for i, res in enumerate(all_results):
            if isinstance(res, Exception):
                continue
            t = task_types[i]
            if t == "ip" and isinstance(res, dict):
                if any(v for k, v in res.items() if k != "ip"):
                    result["ip_enrichment"].append(res)
                    result["total_enriched"] += 1
            elif t == "domain" and isinstance(res, dict):
                if any(v for k, v in res.items() if k != "domain"):
                    result["domain_enrichment"].append(res)
                    result["total_enriched"] += 1
            elif t == "hash" and isinstance(res, dict):
                if any(v for k, v in res.items() if k != "hash"):
                    result["hash_enrichment"].append(res)
                    result["total_enriched"] += 1
            elif t == "email" and res is not None:
                result["email_enrichment"].append(res)
                result["total_enriched"] += 1

    return result


async def enrich_single_ioc(
    ioc_value: str,
    ioc_type: str,
    keys: Optional[Dict[str, str]] = None,
    cache: Optional[EnrichmentCache] = None,
) -> Dict[str, Any]:
    """
    On-demand enrichment for a single IOC.
    Used by the /api/enrichment/lookup endpoint.
    """
    if keys is None:
        keys = load_api_keys()
    if cache is None:
        cache = EnrichmentCache()

    iocs = {"ips": set(), "domains": set(), "hashes": set(), "emails": set()}

    if ioc_type == "ip":
        iocs["ips"].add(ioc_value)
    elif ioc_type == "domain":
        iocs["domains"].add(ioc_value)
    elif ioc_type == "hash":
        iocs["hashes"].add(ioc_value)
    elif ioc_type == "email":
        iocs["emails"].add(ioc_value)
    else:
        return {"error": f"Unknown IOC type: {ioc_type}"}

    result = await enrich_all_iocs(iocs, keys, cache)

    # Flatten to single IOC result
    for key in ["ip_enrichment", "domain_enrichment", "hash_enrichment", "email_enrichment"]:
        if result.get(key):
            return result[key][0]

    return {"ioc": ioc_value, "type": ioc_type, "status": "no_results"}
