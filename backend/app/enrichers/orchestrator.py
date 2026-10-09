"""
Enrichment Orchestration Service:
Executes URLhaus, AbuseIPDB, VirusTotal, and Domain Lookalike analysis asynchronously.
"""
import asyncio
from typing import Dict, Any, List
from .urlhaus import URLhausEnricher
from .abuseipdb import AbuseIPDBEnricher
from .virustotal import VirusTotalEnricher
from .domain_reputation import DomainTyposquattingDetector

class ThreatIntelEnrichmentService:
    @staticmethod
    async def enrich_all(iocs: Dict[str, Any], origin_ip: str = "") -> Dict[str, Any]:
        """Runs parallel enrichment lookups across all extracted IOCs."""
        urls = [u["raw"] for u in iocs.get("urls", [])][:5]  # limit to top 5 to avoid throttling
        ips = [ip["raw"] for ip in iocs.get("ips", [])]
        domains = [d["raw"] for d in iocs.get("domains", [])]
        hashes = [h["raw"] for h in iocs.get("hashes", []) if h.get("type") == "sha256"][:3]

        if origin_ip and origin_ip not in ips:
            ips.append(origin_ip)

        # 1. Lookalike domain check (fast, offline)
        domain_findings = DomainTyposquattingDetector.inspect_domains(domains)

        # 2. Async tasks for URLhaus
        urlhaus_tasks = [URLhausEnricher.check_url(u) for u in urls]
        # 3. Async tasks for AbuseIPDB
        abuseipdb_tasks = [AbuseIPDBEnricher.check_ip(ip) for ip in ips[:3]]
        # 4. Async tasks for VirusTotal URLs & hashes
        vt_url_tasks = [VirusTotalEnricher.check_url(u) for u in urls[:2]]
        vt_hash_tasks = [VirusTotalEnricher.check_hash(h) for h in hashes]

        # Gather results concurrently
        urlhaus_results = await asyncio.gather(*urlhaus_tasks, return_exceptions=True)
        abuseipdb_results = await asyncio.gather(*abuseipdb_tasks, return_exceptions=True)
        vt_url_results = await asyncio.gather(*vt_url_tasks, return_exceptions=True)
        vt_hash_results = await asyncio.gather(*vt_hash_tasks, return_exceptions=True)

        # Structure normalized output
        enriched_urls = []
        for idx, u in enumerate(urls):
            uh_res = urlhaus_results[idx] if idx < len(urlhaus_results) and not isinstance(urlhaus_results[idx], Exception) else {}
            vt_res = vt_url_results[idx] if idx < len(vt_url_results) and not isinstance(vt_url_results[idx], Exception) else {}
            enriched_urls.append({
                "url": u,
                "urlhaus": uh_res,
                "virustotal": vt_res
            })

        enriched_ips = []
        for idx, ip in enumerate(ips[:3]):
            a_res = abuseipdb_results[idx] if idx < len(abuseipdb_results) and not isinstance(abuseipdb_results[idx], Exception) else {}
            enriched_ips.append({
                "ip": ip,
                "abuseipdb": a_res
            })

        enriched_hashes = []
        for idx, h in enumerate(hashes):
            vt_res = vt_hash_results[idx] if idx < len(vt_hash_results) and not isinstance(vt_hash_results[idx], Exception) else {}
            enriched_hashes.append({
                "hash": h,
                "virustotal": vt_res
            })

        return {
            "domain_reputation": domain_findings,
            "urls": enriched_urls,
            "ips": enriched_ips,
            "hashes": enriched_hashes,
        }
