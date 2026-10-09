"""
In-Memory & SQLite Case Management Store:
Stores investigation cases, analyst notes, verdicts, and generated reports.
"""
import uuid
import datetime
from typing import Dict, Any, List, Optional

class CaseManager:
    def __init__(self):
        # In-memory dictionary for rapid retrieval
        self._cases: Dict[str, Dict[str, Any]] = {}

    def create_case(self, investigation_data: Dict[str, Any], title: Optional[str] = None) -> Dict[str, Any]:
        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        created_at = datetime.datetime.utcnow().isoformat() + "Z"

        subject = investigation_data.get("meta", {}).get("subject") or "Untitled Investigation"
        default_title = title or f"Phishing Incident: {subject}"

        case_record = {
            "case_id": case_id,
            "title": default_title,
            "created_at": created_at,
            "status": "OPEN",
            "analyst_verdict": investigation_data.get("risk_assessment", {}).get("verdict", "PENDING"),
            "risk_score": investigation_data.get("risk_assessment", {}).get("score", 0),
            "severity": investigation_data.get("risk_assessment", {}).get("severity", "LOW"),
            "notes": [
                {
                    "id": 1,
                    "author": "System Engine",
                    "timestamp": created_at,
                    "text": f"Case created automatically following triage. Risk score computed as {investigation_data.get('risk_assessment', {}).get('score', 0)}/100."
                }
            ],
            "data": investigation_data,
        }

        self._cases[case_id] = case_record
        return case_record

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        return self._cases.get(case_id)

    def list_cases(self) -> List[Dict[str, Any]]:
        # Return summarized list sorted by creation timestamp descending
        summaries = []
        for c in self._cases.values():
            summaries.append({
                "case_id": c["case_id"],
                "title": c["title"],
                "created_at": c["created_at"],
                "status": c["status"],
                "analyst_verdict": c["analyst_verdict"],
                "risk_score": c["risk_score"],
                "severity": c["severity"],
                "sender": c["data"].get("meta", {}).get("from", "-"),
                "notes_count": len(c["notes"]),
            })
        summaries.sort(key=lambda x: x["created_at"], reverse=True)
        return summaries

    def add_note(self, case_id: str, note_text: str, author: str = "SOC Analyst") -> Optional[Dict[str, Any]]:
        case = self._cases.get(case_id)
        if not case:
            return None

        note_entry = {
            "id": len(case["notes"]) + 1,
            "author": author,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "text": note_text
        }
        case["notes"].append(note_entry)
        return note_entry

    def update_verdict(self, case_id: str, new_verdict: str, status: str = "RESOLVED") -> Optional[Dict[str, Any]]:
        case = self._cases.get(case_id)
        if not case:
            return None

        case["analyst_verdict"] = new_verdict
        case["status"] = status
        return case

case_manager = CaseManager()
