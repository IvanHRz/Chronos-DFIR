"""
Chronos-DFIR Settings Router.

Manages API key configuration, provider status, and enrichment cache.
Keys are saved to .env and os.environ for immediate effect without restart.
"""

import logging
import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import BaseModel

logger = logging.getLogger("chronos.settings")

settings_router = APIRouter(prefix="/api/settings", tags=["settings"])

# Path to .env file in project root
_ENV_PATH = Path(__file__).parent.parent / ".env"

# Provider metadata (static)
PROVIDERS = [
    {
        "id": "ip_api",
        "name": "IP-API.com",
        "icon": "fa-globe",
        "description": "IP geolocation, ASN, ISP data",
        "key_required": False,
        "rate_limit": "45 req/min",
        "env_var": None,
        "signup_url": None,
    },
    {
        "id": "urlhaus",
        "name": "URLhaus (abuse.ch)",
        "icon": "fa-bug",
        "description": "Malicious URL detection from threat feeds",
        "key_required": False,
        "rate_limit": "Unlimited",
        "env_var": None,
        "signup_url": None,
    },
    {
        "id": "abuseipdb",
        "name": "AbuseIPDB",
        "icon": "fa-shield-halved",
        "description": "IP abuse reputation scoring",
        "key_required": True,
        "rate_limit": "1,000 checks/day",
        "env_var": "ABUSEIPDB_API_KEY",
        "signup_url": "https://www.abuseipdb.com/account/api",
    },
    {
        "id": "virustotal",
        "name": "VirusTotal",
        "icon": "fa-virus",
        "description": "IP, domain, file hash analysis",
        "key_required": True,
        "rate_limit": "4 req/min, 500/day",
        "env_var": "VIRUSTOTAL_API_KEY",
        "signup_url": "https://www.virustotal.com/gui/my-apikey",
    },
    {
        "id": "urlscan",
        "name": "URLScan.io",
        "icon": "fa-magnifying-glass",
        "description": "Passive domain/URL scanning",
        "key_required": True,
        "rate_limit": "100 scans/day",
        "env_var": "URLSCAN_API_KEY",
        "signup_url": "https://urlscan.io/user/profile/",
    },
    {
        "id": "hibp",
        "name": "HaveIBeenPwned",
        "icon": "fa-user-lock",
        "description": "Email credential breach lookup",
        "key_required": True,
        "rate_limit": "Rate limited (paid)",
        "env_var": "HIBP_API_KEY",
        "signup_url": "https://haveibeenpwned.com/API/Key",
    },
    # ── TIER 2: New providers ──
    {
        "id": "circl",
        "name": "CIRCL hashlookup",
        "icon": "fa-database",
        "description": "Known-file database (NSRL) — identify legit vs suspicious files",
        "key_required": False,
        "rate_limit": "Unlimited",
        "env_var": None,
        "signup_url": None,
    },
    {
        "id": "malwarebazaar",
        "name": "MalwareBazaar (abuse.ch)",
        "icon": "fa-biohazard",
        "description": "Malware hash lookup — samples, families, delivery methods",
        "key_required": True,
        "rate_limit": "Fair use",
        "env_var": "ABUSECH_API_KEY",
        "signup_url": "https://auth.abuse.ch/",
    },
    {
        "id": "threatfox",
        "name": "ThreatFox (abuse.ch)",
        "icon": "fa-crosshairs",
        "description": "IOC-to-campaign mapping — IPs, domains, hashes linked to malware",
        "key_required": True,
        "rate_limit": "Fair use",
        "env_var": "ABUSECH_API_KEY",
        "signup_url": "https://auth.abuse.ch/",
    },
    {
        "id": "otx",
        "name": "OTX AlienVault",
        "icon": "fa-satellite-dish",
        "description": "Community threat intel with MITRE ATT&CK mapping",
        "key_required": True,
        "rate_limit": "Generous",
        "env_var": "OTX_API_KEY",
        "signup_url": "https://otx.alienvault.com/api",
    },
    {
        "id": "greynoise",
        "name": "GreyNoise",
        "icon": "fa-wave-square",
        "description": "IP noise classifier — distinguish scanners from targeted attacks",
        "key_required": True,
        "rate_limit": "Community free",
        "env_var": "GREYNOISE_API_KEY",
        "signup_url": "https://www.greynoise.io/",
    },
    # ── TIER 3: New free providers ──
    {
        "id": "internetdb",
        "name": "Shodan InternetDB",
        "icon": "fa-network-wired",
        "description": "Free IP enrichment — open ports, vulnerabilities, hostnames",
        "key_required": False,
        "rate_limit": "Unlimited",
        "env_var": None,
        "signup_url": None,
    },
    {
        "id": "threatfox_free",
        "name": "ThreatFox Free",
        "icon": "fa-crosshairs",
        "description": "Free IOC search — malware campaigns, threat types (no key needed)",
        "key_required": False,
        "rate_limit": "Fair use",
        "env_var": None,
        "signup_url": None,
    },
]


def _mask_key(key: str) -> str:
    """Mask API key showing only last 4 chars."""
    if not key or len(key) < 8:
        return ""
    return "****..." + key[-4:]


def _read_env_keys() -> dict:
    """Read current .env file and parse key=value pairs."""
    keys = {}
    if _ENV_PATH.exists():
        for line in _ENV_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                k, v = line.split("=", 1)
                keys[k.strip()] = v.strip()
    return keys


def _write_env_key(env_var: str, value: str):
    """Write or update a single key in .env file."""
    lines = []
    found = False
    if _ENV_PATH.exists():
        for line in _ENV_PATH.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                if k == env_var:
                    lines.append(f"{env_var}={value}")
                    found = True
                    continue
            lines.append(line)
    if not found:
        lines.append(f"{env_var}={value}")
    _ENV_PATH.write_text("\n".join(lines) + "\n")


# ── Request Models ──

class ApiKeyRequest(BaseModel):
    provider: str
    key: str


class TestKeyRequest(BaseModel):
    provider: str


# ── Endpoints ──

@settings_router.get("/config")
async def get_settings_config():
    """Return provider list with status indicators and cache stats."""
    try:
        from engine.enrichment import load_api_keys
        from engine.enrichment_cache import EnrichmentCache

        keys = load_api_keys()
        cache = EnrichmentCache()
        cache_stats = cache.stats()

        providers_status = []
        for p in PROVIDERS:
            status = {
                **p,
                "configured": False,
                "masked_key": "",
                "active": not p["key_required"],  # free providers always active
            }
            if p["env_var"]:
                key = keys.get(p["id"], "")
                status["configured"] = bool(key)
                status["masked_key"] = _mask_key(key)
                status["active"] = bool(key)
            providers_status.append(status)

        return {
            "providers": providers_status,
            "cache": cache_stats,
        }
    except Exception as e:
        logger.error(f"Settings config error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@settings_router.post("/api-keys")
async def save_api_key(req: ApiKeyRequest):
    """Save API key to .env and os.environ (immediate effect, no restart needed)."""
    try:
        # Find the provider
        provider = next((p for p in PROVIDERS if p["id"] == req.provider), None)
        if not provider:
            return JSONResponse(status_code=400, content={"error": f"Unknown provider: {req.provider}"})
        if not provider["env_var"]:
            return JSONResponse(status_code=400, content={"error": f"{req.provider} does not require an API key"})

        env_var = provider["env_var"]

        # Set in os.environ for immediate effect
        os.environ[env_var] = req.key

        # Persist to .env file
        _write_env_key(env_var, req.key)

        logger.info(f"API key saved for {req.provider}")
        return {
            "status": "saved",
            "provider": req.provider,
            "masked": _mask_key(req.key),
        }
    except Exception as e:
        logger.error(f"Save API key error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})


@settings_router.post("/test-key")
async def test_api_key(req: TestKeyRequest):
    """Test an API key by making a minimal request to the provider."""
    try:
        from engine.enrichment import load_api_keys
        keys = load_api_keys()
        key = keys.get(req.provider, "")

        if not key:
            return {"valid": False, "error": "No API key configured for this provider"}

        import httpx
        import time

        start = time.monotonic()
        async with httpx.AsyncClient(timeout=15.0) as client:
            if req.provider == "abuseipdb":
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": "8.8.8.8", "maxAgeInDays": "1"},
                    headers={"Key": key, "Accept": "application/json"},
                )
            elif req.provider == "virustotal":
                # Check a well-known benign hash (empty file)
                test_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{test_hash}",
                    headers={"x-apikey": key},
                )
            elif req.provider == "urlscan":
                resp = await client.get(
                    "https://urlscan.io/api/v1/search/?q=domain:google.com&size=1",
                    headers={"API-Key": key},
                )
            elif req.provider == "hibp":
                resp = await client.get(
                    "https://haveibeenpwned.com/api/v3/breachedaccount/test@example.com",
                    headers={"hibp-api-key": key, "user-agent": "Chronos-DFIR"},
                )
                # HIBP returns 404 for non-breached accounts — that's still a valid key
                if resp.status_code == 404:
                    latency = int((time.monotonic() - start) * 1000)
                    return {"valid": True, "latency_ms": latency, "details": "API key valid (test account not breached)"}
            else:
                return {"valid": False, "error": f"No test available for {req.provider}"}

            latency = int((time.monotonic() - start) * 1000)
            if resp.status_code in (200, 404):
                return {"valid": True, "latency_ms": latency, "details": f"HTTP {resp.status_code} — API accessible"}
            elif resp.status_code in (401, 403):
                return {"valid": False, "latency_ms": latency, "error": f"HTTP {resp.status_code} — Invalid or expired key"}
            else:
                return {"valid": False, "latency_ms": latency, "error": f"HTTP {resp.status_code} — Unexpected response"}

    except httpx.TimeoutException:
        return {"valid": False, "error": "Request timed out (15s)"}
    except Exception as e:
        logger.error(f"Test key error: {e}")
        return {"valid": False, "error": str(e)}


@settings_router.post("/clear-cache")
async def clear_enrichment_cache():
    """Clear all enrichment cache entries."""
    try:
        from engine.enrichment_cache import EnrichmentCache
        cache = EnrichmentCache()
        cache.clear_all()
        return {"status": "cleared", "message": "Enrichment cache cleared"}
    except Exception as e:
        logger.error(f"Clear cache error: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
