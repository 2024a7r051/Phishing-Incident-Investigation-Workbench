"""
VirusTotal Threat Intel Enricher:
Queries VirusTotal v3 REST API for URLs and File Hashes (SHA256/MD5).
Falls back gracefully if no API key is provided.
"""
import base64
import httpx
from typing import Dict, Any
from ..config import settings

VT_BASE_URL = "https://www.virustotal.com/api/v3"

class VirusTotalEnricher:
    @staticmethod
    async def check_url(url: str, timeout: float = 4.0) -> Dict[str, Any]:
        """Queries VirusTotal for URL reputation using base64 encoded URL identifier."""
        if not url:
            return {"queried": False, "reason": "No URL provided"}

        api_key = settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return {
                "queried": False,
                "configured": False,
                "note": "VirusTotal API key not configured (set VIRUSTOTAL_API_KEY to enable live checks)."
            }

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{VT_BASE_URL}/urls/{url_id}"
        headers = {"x-apikey": api_key}

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    return {
                        "queried": True,
                        "configured": True,
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "harmless_count": stats.get("harmless", 0),
                        "undetected_count": stats.get("undetected", 0),
                    }
                elif resp.status_code == 404:
                    return {"queried": True, "configured": True, "status": "unseen_in_virustotal"}
                else:
                    return {"queried": False, "configured": True, "status_code": resp.status_code}
        except Exception as e:
            return {"queried": False, "configured": True, "error": str(e)}

    @staticmethod
    async def check_hash(file_hash: str, timeout: float = 4.0) -> Dict[str, Any]:
        """Queries VirusTotal for file hash analysis stats."""
        if not file_hash:
            return {"queried": False, "reason": "No hash provided"}

        api_key = settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return {
                "queried": False,
                "configured": False,
                "note": "VirusTotal API key not configured (set VIRUSTOTAL_API_KEY to enable live checks)."
            }

        endpoint = f"{VT_BASE_URL}/files/{file_hash}"
        headers = {"x-apikey": api_key}

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    return {
                        "queried": True,
                        "configured": True,
                        "malicious_count": stats.get("malicious", 0),
                        "suspicious_count": stats.get("suspicious", 0),
                        "names": attrs.get("names", [])[:3],
                    }
                elif resp.status_code == 404:
                    return {"queried": True, "configured": True, "status": "unseen_in_virustotal"}
                else:
                    return {"queried": False, "configured": True, "status_code": resp.status_code}
        except Exception as e:
            return {"queried": False, "configured": True, "error": str(e)}
