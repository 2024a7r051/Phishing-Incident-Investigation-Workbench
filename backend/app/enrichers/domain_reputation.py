"""
Domain Reputation & Typosquatting / Lookalike Detector:
1. Calculates Levenshtein distance between extracted domains and high-value target brand domains.
2. Flags punycode (IDN homograph attacks, e.g. xn--...).
3. Flags suspicious top-level domains (.xyz, .top, .buzz, .cc, .tk, .work).
"""
import re
from typing import Dict, Any, List

TARGET_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix", 
    "chase", "bankofamerica", "wellsfargo", "dhl", "fedex", "dropbox",
    "facebook", "instagram", "linkedin", "office365", "outlook"
]

SUSPICIOUS_TLDS = {
    "cc", "xyz", "top", "buzz", "tk", "work", "loan", "click", "fit", "rest", "surf"
}

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes basic edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

class DomainTyposquattingDetector:
    @staticmethod
    def inspect_domains(domains: List[str]) -> List[Dict[str, Any]]:
        findings = []

        for raw_domain in domains:
            domain = raw_domain.lower().strip()
            if not domain:
                continue

            # Check IDN Homograph / Punycode
            if domain.startswith("xn--"):
                findings.append({
                    "domain": domain,
                    "type": "IDN_HOMOGRAPH",
                    "severity": "HIGH",
                    "reason": "Internationalized Domain Name (Punycode) detected. Frequently abused for visual spoofing."
                })

            # Check suspicious TLD
            tld = domain.split(".")[-1] if "." in domain else ""
            if tld in SUSPICIOUS_TLDS:
                findings.append({
                    "domain": domain,
                    "type": "SUSPICIOUS_TLD",
                    "severity": "MEDIUM",
                    "reason": f"Uses high-abuse top-level domain (.{tld})."
                })

            # Check lookalikes against major brands
            domain_name = domain.split(".")[0]
            for brand in TARGET_BRANDS:
                # If exact match, legitimate or direct sub domain
                if domain_name == brand:
                    continue

                # Lookalike check: Distance 1 or 2, or contains brand name with extra hyphens/characters
                dist = levenshtein_distance(domain_name, brand)
                if (1 <= dist <= 2 and len(domain_name) >= 4) or (brand in domain_name and domain_name != brand):
                    findings.append({
                        "domain": domain,
                        "type": "TYPOSQUATTING_LOOKALIKE",
                        "severity": "HIGH",
                        "target_brand": brand,
                        "reason": f"Possible typosquatting/lookalike impersonating '{brand}'."
                    })
                    break

        return findings
