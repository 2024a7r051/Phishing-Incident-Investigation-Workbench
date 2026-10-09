"""
AbuseIPDB Threat Intel Enricher:
Queries AbuseIPDB API v2 to check IP reputation, abuse confidence score, and reported categories.
Falls back gracefully if no API key is configured.
"""
import httpx
from typing import Dict, Any
from ..config import settings

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

class AbuseIPDBEnricher:
    @staticmethod
    async def check_ip(ip: str, timeout: float = 4.0) -> Dict[str, Any]:
        """Queries AbuseIPDB for a given IPv4 address."""
        if not ip:
            return {"queried": False, "reason": "No IP provided"}

        api_key = settings.ABUSEIPDB_API_KEY
        if not api_key:
            return {
                "queried": False,
                "configured": False,
                "note": "AbuseIPDB API key not configured (set ABUSEIPDB_API_KEY to enable live checks)."
            }

        headers = {
            "Key": api_key,
            "Accept": "application/json"
        }
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(ABUSEIPDB_CHECK_URL, headers=headers, params=params)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    return {
                        "queried": True,
                        "configured": True,
                        "abuse_score": data.get("abuseConfidenceScore", 0),
                        "total_reports": data.get("totalReports", 0),
                        "country_code": data.get("countryCode"),
                        "isp": data.get("isp"),
                        "domain": data.get("domain"),
                        "is_tor": data.get("isTor", False),
                    }
                else:
                    return {
                        "queried": False,
                        "configured": True,
                        "status_code": resp.status_code,
                        "error": resp.text
                    }
        except Exception as e:
            return {
                "queried": False,
                "configured": True,
                "error": str(e)
            }
