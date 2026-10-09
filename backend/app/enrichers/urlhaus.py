"""
URLhaus Threat Intel Enricher:
Queries abuse.ch URLhaus API (completely public, no API key required).
Checks if URLs or domains are known malware distribution / phishing sites.
"""
import httpx
from typing import Dict, Any, Optional

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

class URLhausEnricher:
    @staticmethod
    async def check_url(url: str, timeout: float = 4.0) -> Dict[str, Any]:
        """Queries URLhaus for threat status of a URL."""
        if not url:
            return {"queried": False, "status": "unknown"}

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(URLHAUS_API_URL, data={"url": url})
                if resp.status_code == 200:
                    data = resp.json()
                    query_status = data.get("query_status", "no_results")
                    if query_status == "ok":
                        return {
                            "queried": True,
                            "found": True,
                            "urlhaus_status": data.get("url_status"),
                            "threat": data.get("threat"),
                            "tags": data.get("tags") or [],
                            "reporter": data.get("reporter"),
                            "date_added": data.get("date_added"),
                        }
                    else:
                        return {
                            "queried": True,
                            "found": False,
                            "status": "clean_or_unlisted"
                        }
        except Exception as e:
            return {
                "queried": False,
                "error": str(e),
                "status": "lookup_failed"
            }

        return {"queried": True, "found": False, "status": "no_results"}
