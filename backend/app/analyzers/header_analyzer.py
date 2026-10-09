"""
Header Analyzer:
1. Parses email hops (Received lines) from origin to destination.
2. Extracts authentication results (SPF, DKIM, DMARC).
3. Identifies spoofing discrepancies (Return-Path vs From vs Reply-To).
"""
import re
from typing import Dict, Any, List

class HeaderAnalyzer:
    def __init__(self, headers: List[Dict[str, str]]):
        self.headers = headers

    def analyze(self) -> Dict[str, Any]:
        hops = self._extract_hops()
        auth = self._extract_auth_results()
        mismatches = self._detect_address_mismatches()

        return {
            "hops": hops,
            "origin_ip": hops[0]["ip"] if hops and hops[0].get("ip") else None,
            "authentication": auth,
            "mismatches": mismatches,
        }

    def _extract_hops(self) -> List[Dict[str, Any]]:
        """Parses 'Received' headers in order."""
        received_headers = [h["value"] for h in self.headers if h["name"].lower() == "received"]
        
        # Chronological order is usually bottom-up (first relay is at bottom of headers)
        received_headers.reverse()

        hops = []
        ip_regex = re.compile(r'\[?(\b(?:\d{1,3}\.){3}\d{1,3}\b)\]?')
        by_regex = re.compile(r'by\s+([^\s;]+)', re.IGNORECASE)
        from_regex = re.compile(r'from\s+([^\s;]+)', re.IGNORECASE)

        for idx, r_val in enumerate(received_headers):
            clean_val = " ".join(r_val.split())
            ip_match = ip_regex.search(clean_val)
            by_match = by_regex.search(clean_val)
            from_match = from_regex.search(clean_val)

            hops.append({
                "hop": idx + 1,
                "raw": clean_val,
                "ip": ip_match.group(1) if ip_match else None,
                "by": by_match.group(1) if by_match else None,
                "from": from_match.group(1) if from_match else None,
            })
        return hops

    def _extract_auth_results(self) -> Dict[str, Any]:
        """Extracts SPF, DKIM, and DMARC status from Authentication-Results headers."""
        results = {
            "spf": {"status": "none", "details": ""},
            "dkim": {"status": "none", "details": ""},
            "dmarc": {"status": "none", "details": ""},
            "raw": []
        }

        auth_headers = [
            h["value"] for h in self.headers 
            if h["name"].lower() in ["authentication-results", "arc-authentication-results", "received-spf"]
        ]

        results["raw"] = auth_headers

        combined = " ".join(auth_headers).lower()

        # Check SPF
        if "spf=pass" in combined or "pass (spf" in combined:
            results["spf"]["status"] = "pass"
        elif "spf=fail" in combined or "fail (spf" in combined:
            results["spf"]["status"] = "fail"
        elif "spf=softfail" in combined:
            results["spf"]["status"] = "softfail"
        elif "spf=neutral" in combined:
            results["spf"]["status"] = "neutral"

        # Check DKIM
        if "dkim=pass" in combined or "pass (dkim" in combined:
            results["dkim"]["status"] = "pass"
        elif "dkim=fail" in combined or "fail (dkim" in combined:
            results["dkim"]["status"] = "fail"

        # Check DMARC
        if "dmarc=pass" in combined or "pass (dmarc" in combined:
            results["dmarc"]["status"] = "pass"
        elif "dmarc=fail" in combined or "fail (dmarc" in combined:
            results["dmarc"]["status"] = "fail"

        return results

    def _detect_address_mismatches(self) -> List[Dict[str, str]]:
        """Identifies suspicious discrepancies between From, Reply-To, and Return-Path."""
        flags = []
        header_map = {}
        for h in self.headers:
            name = h["name"].lower()
            if name not in header_map:
                header_map[name] = h["value"]

        from_val = header_map.get("from", "")
        reply_to_val = header_map.get("reply-to", "")
        return_path_val = header_map.get("return-path", "")

        def extract_email(val: str) -> str:
            match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', val)
            return match.group(0).lower() if match else ""

        from_email = extract_email(from_val)
        reply_to_email = extract_email(reply_to_val)
        return_path_email = extract_email(return_path_val)

        if reply_to_email and from_email and reply_to_email != from_email:
            flags.append({
                "type": "REPLY_TO_MISMATCH",
                "severity": "medium",
                "message": f"Reply-To address ({reply_to_email}) differs from From address ({from_email})."
            })

        if return_path_email and from_email:
            from_domain = from_email.split("@")[-1] if "@" in from_email else ""
            rp_domain = return_path_email.split("@")[-1] if "@" in return_path_email else ""
            if from_domain and rp_domain and from_domain != rp_domain:
                flags.append({
                    "type": "RETURN_PATH_DOMAIN_MISMATCH",
                    "severity": "high",
                    "message": f"Sender domain ({from_domain}) differs from Return-Path domain ({rp_domain}). High risk of spoofing."
                })

        return flags
