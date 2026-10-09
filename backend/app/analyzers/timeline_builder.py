"""
Investigation Timeline Builder:
Reconstructs an interactive chronological incident investigation chain:
Message Origin -> Relay Hops -> Delivery -> Payload Extraction -> Threat Correlation -> Final Verdict.
"""
from typing import Dict, Any, List

class TimelineBuilder:
    @staticmethod
    def build(
        meta: Dict[str, Any],
        hops: List[Dict[str, Any]],
        urls: List[Dict[str, Any]],
        attachments: List[Dict[str, Any]],
        enrichment: Dict[str, Any],
        risk: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        timeline = []

        # 1. Message Dispatched / Origin
        date_str = meta.get("date") or "Event Genesis"
        timeline.append({
            "stage": "ORIGIN",
            "title": "Email Sent by Sender",
            "timestamp": date_str,
            "badge": "DISPATCH",
            "severity": "neutral",
            "description": f"Message dispatched from {meta.get('from', 'Unknown')} to {meta.get('to', 'Unknown')}."
        })

        # 2. Relay Hops
        for h in hops:
            timeline.append({
                "stage": "RELAY",
                "title": f"Mail Relay Hop #{h.get('hop')}",
                "timestamp": date_str,
                "badge": f"IP: {h.get('ip') or 'Unknown'}",
                "severity": "neutral",
                "description": f"Relayed through {h.get('by', 'gateway')} from {h.get('from', 'sender')}."
            })

        # 3. Authentication Verification
        auth = enrichment.get("authentication", {})
        # 4. Payload & Link Extraction
        for u in urls:
            is_susp = u.get("mismatch") or u.get("is_ip_host")
            timeline.append({
                "stage": "PAYLOAD_URL",
                "title": "Hyperlink Identified in Body",
                "timestamp": date_str,
                "badge": "URL",
                "severity": "danger" if is_susp else "warning",
                "description": f"Destination: {u.get('defanged')} (Domain: {u.get('domain')}). " +
                               ("🚨 ANCHOR TEXT SPOOF DETECTED!" if u.get("mismatch") else "")
            })

        for a in attachments:
            timeline.append({
                "stage": "PAYLOAD_FILE",
                "title": "Attachment Extracted",
                "timestamp": date_str,
                "badge": "FILE",
                "severity": "danger",
                "description": f"File '{a.get('filename')}' ({round(a.get('size_bytes', 0)/1024, 1)} KB). SHA256: {a.get('sha256')}."
            })

        # 5. Threat Intelligence Correlation
        for dr in enrichment.get("domain_reputation", []):
            timeline.append({
                "stage": "THREAT_INTEL",
                "title": f"Threat Intel Hit: {dr.get('type')}",
                "timestamp": "Analysis Phase",
                "badge": "LOOKALIKE",
                "severity": "danger",
                "description": f"Domain {dr.get('domain')} flagged: {dr.get('reason')}"
            })

        # 6. Final Incident Verdict
        timeline.append({
            "stage": "VERDICT",
            "title": f"Incident Verdict: {risk.get('verdict')}",
            "timestamp": "Triage Completion",
            "badge": f"SCORE {risk.get('score')}/100",
            "severity": "danger" if risk.get("score", 0) >= 70 else ("warning" if risk.get("score", 0) >= 35 else "success"),
            "description": f"Risk assessment finalized with {len(risk.get('factors', []))} triggered security rules."
        })

        return timeline
