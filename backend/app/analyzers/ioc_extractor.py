"""
IOC Extractor:
Gathers IP addresses, domain names, URLs, email addresses, and hashes.
Provides both raw and defanged representations for safe reporting.
"""
import re
from typing import Dict, Any, List
from ..utils.defang import defang_ip, defang_domain, defang_url, defang_email

class IOCExtractor:
    def __init__(self, text: str, parsed_email: Dict[str, Any], url_list: List[Dict[str, Any]]):
        self.text = text
        self.parsed_email = parsed_email
        self.url_list = url_list

    def extract(self) -> Dict[str, List[Dict[str, str]]]:
        ips = self._extract_ips()
        urls = self._extract_urls()
        domains = self._extract_domains(urls)
        emails = self._extract_emails()
        hashes = self._extract_hashes()

        return {
            "ips": ips,
            "domains": domains,
            "urls": urls,
            "emails": emails,
            "hashes": hashes,
        }

    def _extract_ips(self) -> List[Dict[str, str]]:
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        found = set(ip_pattern.findall(self.text))

        # Filter out obvious false positives (like localhost or private ranges if desired, but keep for full visibility)
        clean_ips = []
        for ip in found:
            # Basic octet validity check
            parts = ip.split(".")
            if all(0 <= int(p) <= 255 for p in parts):
                clean_ips.append({
                    "raw": ip,
                    "defanged": defang_ip(ip),
                    "type": "ipv4"
                })
        return clean_ips

    def _extract_urls(self) -> List[Dict[str, str]]:
        res = []
        for u in self.url_list:
            res.append({
                "raw": u["url"],
                "defanged": defang_url(u["url"]),
                "type": "url"
            })
        return res

    def _extract_domains(self, urls: List[Dict[str, str]]) -> List[Dict[str, str]]:
        domains = set()
        for u in urls:
            raw = u["raw"]
            match = re.search(r'https?://([^/:\s]+)', raw)
            if match:
                domains.add(match.group(1).lower())

        # Also pull sender domain
        from_header = self.parsed_email.get("meta", {}).get("from", "")
        if "@" in from_header:
            domain_part = from_header.split("@")[-1].replace(">", "").strip().lower()
            if domain_part:
                domains.add(domain_part)

        return [{"raw": d, "defanged": defang_domain(d), "type": "domain"} for d in domains]

    def _extract_emails(self) -> List[Dict[str, str]]:
        pattern = re.compile(r'[\w\.-]+@[\w\.-]+\.\w+')
        found = set(pattern.findall(self.text))
        return [{"raw": e, "defanged": defang_email(e), "type": "email"} for e in found]

    def _extract_hashes(self) -> List[Dict[str, str]]:
        res = []
        for att in self.parsed_email.get("attachments", []):
            if att.get("md5"):
                res.append({"raw": att["md5"], "defanged": att["md5"], "type": "md5", "context": att.get("filename")})
            if att.get("sha256"):
                res.append({"raw": att["sha256"], "defanged": att["sha256"], "type": "sha256", "context": att.get("filename")})
        return res
