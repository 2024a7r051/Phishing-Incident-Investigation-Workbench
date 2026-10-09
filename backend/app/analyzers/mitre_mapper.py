"""
MITRE ATT&CK Framework Mapper for Phishing Incidents:
Correlates findings from header, attachment, URL, and threat intel analyzers
to specific MITRE ATT&CK Enterprise Techniques and Sub-techniques.
"""
from typing import Dict, Any, List

MITRE_TECHNIQUES = {
    "T1566.001": {
        "id": "T1566.001",
        "name": "Phishing: Spearphishing Attachment",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/001/"
    },
    "T1566.002": {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1566/002/"
    },
    "T1036.005": {
        "id": "T1036.005",
        "name": "Masquerading: Match Legitimate Name or Location",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1036/005/"
    },
    "T1586.002": {
        "id": "T1586.002",
        "name": "Compromise Accounts: Email Accounts",
        "tactic": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1586/002/"
    },
    "T1059": {
        "id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/"
    },
    "T1204.001": {
        "id": "T1204.001",
        "name": "User Execution: Malicious Link",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/001/"
    },
    "T1204.002": {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1204/002/"
    }
}

class MitreAttackMapper:
    @staticmethod
    def map_findings(
        headers: Dict[str, Any],
        urls: List[Dict[str, Any]],
        attachments: List[Dict[str, Any]],
        enrichment: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        mapped = []
        seen = set()

        def add_technique(tech_id: str, evidence: str):
            if tech_id in MITRE_TECHNIQUES and tech_id not in seen:
                seen.add(tech_id)
                data = MITRE_TECHNIQUES[tech_id].copy()
                data["evidence"] = evidence
                mapped.append(data)

        # 1. Attachment-based techniques
        if attachments:
            add_technique(
                "T1566.001",
                f"Email delivers {len(attachments)} attachment(s): " + ", ".join([a.get('filename', '') for a in attachments])
            )
            for a in attachments:
                fname = a.get('filename', '').lower()
                if any(fname.endswith(ext) for ext in ['.exe', '.vbs', '.js', '.bat', '.ps1', '.hta']):
                    add_technique("T1204.002", f"Executable payload delivered via attachment ({a.get('filename')}).")
                    add_technique("T1059", f"Scripting/executable binary intended for execution: {a.get('filename')}.")

        # 2. Link-based techniques
        if urls:
            add_technique("T1566.002", f"Email delivers {len(urls)} external hyperlink(s) in HTML/text body.")
            spoofed_urls = [u for u in urls if u.get("mismatch")]
            if spoofed_urls:
                add_technique(
                    "T1036.005",
                    "Hyperlink anchor text explicitly mimics legitimate corporate domain to evade user suspicion."
                )
            add_technique("T1204.001", "Social engineering lures user into visiting malicious destination.")

        # 3. Domain Lookalikes / Masquerading
        lookalikes = enrichment.get("domain_reputation", [])
        if any(l.get("type") == "TYPOSQUATTING_LOOKALIKE" for l in lookalikes):
            add_technique(
                "T1036.005",
                "Adversary registered lookalike domain mimicking legitimate target brand."
            )

        # 4. Header spoofing
        if headers.get("mismatches"):
            add_technique(
                "T1586.002",
                "Discrepancy between sender headers (Return-Path / Reply-To / From) indicating unauthorized relay or hijacked account."
            )

        return mapped
