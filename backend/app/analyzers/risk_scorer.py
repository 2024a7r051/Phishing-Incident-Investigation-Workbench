"""
Risk Scorer:
Aggregates findings from HeaderAnalyzer, URLAnalyzer, and Attachments.
Computes a transparent 0-100 risk score with detailed rule breakdowns and verdicts.
"""
from typing import Dict, Any, List

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".bat", ".cmd", ".ps1", 
    ".docm", ".xlsm", ".pptm", ".iso", ".img", ".wsf", ".hta", ".zip"
}

class RiskScorer:
    def __init__(self, parsed_email: Dict[str, Any], header_res: Dict[str, Any], urls: List[Dict[str, Any]], enrichment: Dict[str, Any] = None):
        self.parsed = parsed_email
        self.headers = header_res
        self.urls = urls
        self.enrichment = enrichment or {}

    def calculate(self) -> Dict[str, Any]:
        score = 0
        factors = []

        # 1. Threat Intel findings
        # 1.1 Lookalike / Typosquatting
        for dom_finding in self.enrichment.get("domain_reputation", []):
            if dom_finding.get("type") in ["TYPOSQUATTING_LOOKALIKE", "IDN_HOMOGRAPH"]:
                score += 30
                factors.append({
                    "rule": "TYPOSQUATTING_DETECTED",
                    "points": 30,
                    "reason": dom_finding.get("reason")
                })
            elif dom_finding.get("type") == "SUSPICIOUS_TLD":
                score += 15
                factors.append({
                    "rule": "SUSPICIOUS_TLD",
                    "points": 15,
                    "reason": dom_finding.get("reason")
                })

        # 1.2 URLhaus detections
        for u in self.enrichment.get("urls", []):
            if u.get("urlhaus", {}).get("found"):
                score += 40
                factors.append({
                    "rule": "URLHAUS_MALWARE_URL",
                    "points": 40,
                    "reason": f"URL listed in abuse.ch URLhaus threat database: {u.get('urlhaus', {}).get('threat') or 'Malware delivery'}."
                })

        # 1.3 AbuseIPDB confidence score
        for ip_data in self.enrichment.get("ips", []):
            abuse_score = ip_data.get("abuseipdb", {}).get("abuse_score", 0)
            if abuse_score >= 50:
                score += 25
                factors.append({
                    "rule": "ABUSEIPDB_HIGH_CONFIDENCE",
                    "points": 25,
                    "reason": f"Sender IP {ip_data.get('ip')} has high abuse confidence score ({abuse_score}%)."
                })

        # 1. Authentication checks
        auth = self.headers.get("authentication", {})
        spf_status = auth.get("spf", {}).get("status")
        dkim_status = auth.get("dkim", {}).get("status")
        dmarc_status = auth.get("dmarc", {}).get("status")

        if spf_status == "fail":
            score += 25
            factors.append({"rule": "SPF_FAIL", "points": 25, "reason": "SPF validation explicitly failed."})
        elif spf_status == "softfail":
            score += 15
            factors.append({"rule": "SPF_SOFTFAIL", "points": 15, "reason": "SPF returned softfail (unauthorized sender IP)."})

        if dkim_status == "fail":
            score += 20
            factors.append({"rule": "DKIM_FAIL", "points": 20, "reason": "DKIM cryptographic signature verification failed."})

        if dmarc_status == "fail":
            score += 25
            factors.append({"rule": "DMARC_FAIL", "points": 25, "reason": "DMARC policy alignment check failed."})

        # 2. Header Mismatches (Spoofing)
        for mismatch in self.headers.get("mismatches", []):
            if mismatch.get("type") == "RETURN_PATH_DOMAIN_MISMATCH":
                score += 20
                factors.append({"rule": "RETURN_PATH_MISMATCH", "points": 20, "reason": mismatch.get("message")})
            elif mismatch.get("type") == "REPLY_TO_MISMATCH":
                score += 15
                factors.append({"rule": "REPLY_TO_MISMATCH", "points": 15, "reason": mismatch.get("message")})

        # 3. URL checks
        ip_hosts = [u for u in self.urls if u.get("is_ip_host")]
        if ip_hosts:
            score += 25
            factors.append({"rule": "RAW_IP_URL", "points": 25, "reason": f"Found {len(ip_hosts)} URLs with direct IP hosts instead of domain names."})

        anchor_mismatches = [u for u in self.urls if u.get("mismatch")]
        if anchor_mismatches:
            score += 30
            factors.append({"rule": "ANCHOR_TEXT_SPOOF", "points": 30, "reason": "Anchor text displays brand domain but links to an external host."})

        # 4. Attachment checks
        for att in self.parsed.get("attachments", []):
            fname = att.get("filename", "").lower()
            for ext in SUSPICIOUS_EXTENSIONS:
                if fname.endswith(ext):
                    score += 35
                    factors.append({
                        "rule": "SUSPICIOUS_ATTACHMENT_EXTENSION",
                        "points": 35,
                        "reason": f"Attachment '{att.get('filename')}' carries high-risk executable/macro extension ({ext})."
                    })
                    break

        # Bound score between 0 and 100
        total_score = min(score, 100)

        # Determine verdict
        if total_score >= 70:
            verdict = "MALICIOUS"
            severity = "HIGH"
        elif total_score >= 35:
            verdict = "SUSPICIOUS"
            severity = "MEDIUM"
        else:
            verdict = "BENIGN / LOW RISK"
            severity = "LOW"

        return {
            "score": total_score,
            "verdict": verdict,
            "severity": severity,
            "factors": factors,
        }
