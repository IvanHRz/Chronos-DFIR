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
    }


def get_active_providers(keys: Dict[str, str]) -> List[str]:
    """Return list of providers that have API keys configured."""
    # ip_api and urlhaus don't need keys
    active = ["ip_api", "urlhaus"]
    for provider, key in keys.items():
        if key:
            active.append(provider)
    return active


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


def _is_public_ip(ip: str) -> bool:
    """Check if an IP is public (not private/reserved)."""
    if not _IP_PATTERN.match(ip):
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def deduplicate_iocs(
    context_data: Optional[dict] = None,
    session_profiles: Optional[list] = None,
    correlation_result: Optional[dict] = None,
) -> Dict[str, Set[str]]:
    """
    Extract unique IOCs from forensic analysis results.

    Collects IPs, domains, hashes, and emails from:
    - context_data (Task 1: sub_analyze_context)
    - session_profiles (Task 6: group_sessions)
    - correlation_result (Task 5: correlate_cross_source)
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
                    if _DOMAIN_PATTERN.match(host) and not _IP_PATTERN.match(host):
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
        await asyncio.sleep(15)  # VT rate limit: 4 req/min
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
        await asyncio.sleep(15)  # VT rate limit
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
        await asyncio.sleep(15)  # VT rate limit
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
# Orchestrator
# ---------------------------------------------------------------------------

# Rate limit semaphores per provider
_SEMAPHORES = {
    "ip_api": asyncio.Semaphore(10),      # 45 req/min
    "abuseipdb": asyncio.Semaphore(5),    # 1000/day
    "virustotal": asyncio.Semaphore(1),   # 4 req/min — strictest
    "urlhaus": asyncio.Semaphore(5),      # no limit
    "urlscan": asyncio.Semaphore(3),      # 100/day
    "hibp": asyncio.Semaphore(3),         # rate limited
}

# Lazy singleton for semaphores (recreated per event loop)
_semaphore_cache: Dict[str, asyncio.Semaphore] = {}


def _get_semaphore(provider: str) -> asyncio.Semaphore:
    """Get or create a semaphore for the given provider."""
    if provider not in _semaphore_cache:
        limits = {
            "ip_api": 10, "abuseipdb": 5, "virustotal": 1,
            "urlhaus": 5, "urlscan": 3, "hibp": 3,
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

        # --- Enrich IPs ---
        for ip in iocs.get("ips", set()):
            tasks = [
                _enrich_ip_geoip(ip, client, cache, _get_semaphore("ip_api")),
                _enrich_ip_abuse(ip, client, cache, keys.get("abuseipdb", ""), _get_semaphore("abuseipdb")),
            ]
            # Only add VT if we have a key (expensive rate limit)
            if keys.get("virustotal"):
                tasks.append(
                    _enrich_ip_virustotal(ip, client, cache, keys["virustotal"], _get_semaphore("virustotal"))
                )

            ip_results = await asyncio.gather(*tasks, return_exceptions=True)

            ip_data = {"ip": ip, "geo": {}, "abuse": {}, "vt": {}}
            for r in ip_results:
                if isinstance(r, dict) and r:
                    provider = r.get("provider", "")
                    if provider == "ip_api":
                        ip_data["geo"] = r
                    elif provider == "abuseipdb":
                        ip_data["abuse"] = r
                    elif provider == "virustotal":
                        ip_data["vt"] = r

            if any(v for k, v in ip_data.items() if k != "ip"):
                result["ip_enrichment"].append(ip_data)
                result["total_enriched"] += 1

        # --- Enrich Domains ---
        for domain in iocs.get("domains", set()):
            tasks = [
                _enrich_domain_urlhaus(domain, client, cache, _get_semaphore("urlhaus")),
            ]
            if keys.get("virustotal"):
                tasks.append(
                    _enrich_domain_virustotal(domain, client, cache, keys["virustotal"], _get_semaphore("virustotal"))
                )
            if keys.get("urlscan"):
                tasks.append(
                    _enrich_domain_urlscan(domain, client, cache, keys["urlscan"], _get_semaphore("urlscan"))
                )

            domain_results = await asyncio.gather(*tasks, return_exceptions=True)

            domain_data = {"domain": domain, "urlhaus": {}, "vt": {}, "urlscan": {}}
            for r in domain_results:
                if isinstance(r, dict) and r:
                    provider = r.get("provider", "")
                    if provider == "urlhaus":
                        domain_data["urlhaus"] = r
                    elif provider == "virustotal":
                        domain_data["vt"] = r
                    elif provider == "urlscan":
                        domain_data["urlscan"] = r

            if any(v for k, v in domain_data.items() if k != "domain"):
                result["domain_enrichment"].append(domain_data)
                result["total_enriched"] += 1

        # --- Enrich Hashes ---
        if keys.get("virustotal"):
            for hash_val in iocs.get("hashes", set()):
                vt_result = await _enrich_hash_virustotal(
                    hash_val, client, cache, keys["virustotal"], _get_semaphore("virustotal")
                )
                if vt_result:
                    result["hash_enrichment"].append({"hash": hash_val, "vt": vt_result})
                    result["total_enriched"] += 1

        # --- Enrich Emails ---
        if keys.get("hibp"):
            for email in iocs.get("emails", set()):
                hibp_result = await _enrich_email_hibp(
                    email, client, cache, keys["hibp"], _get_semaphore("hibp")
                )
                if hibp_result:
                    result["email_enrichment"].append({"email": email, "hibp": hibp_result})
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
