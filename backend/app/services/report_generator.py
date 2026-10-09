"""
Incident Report Generator:
Produces clean, self-contained standalone HTML and JSON Incident Evidence Reports
suitable for SOC archival, compliance audits, and distribution to CERT/CSIRT teams.
"""
from typing import Dict, Any

class ReportGenerator:
    @staticmethod
    def generate_html_report(case: Dict[str, Any]) -> str:
        case_id = case.get("case_id", "UNKNOWN")
        data = case.get("data", {})
        meta = data.get("meta", {})
        risk = data.get("risk_assessment", {})
        auth = data.get("header_analysis", {}).get("authentication", {})
        mitre = data.get("mitre_attack", [])
        urls = data.get("url_analysis", [])
        attachments = data.get("attachments", [])
        notes = case.get("notes", [])

        risk_color = "#ef4444" if risk.get("score", 0) >= 70 else ("#f59e0b" if risk.get("score", 0) >= 35 else "#10b981")

        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Incident Report: {case_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; line-height: 1.5; }}
        .header {{ border-bottom: 2px solid #334155; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: flex-start; }}
        .title {{ font-size: 24px; font-weight: bold; color: #fff; }}
        .sub {{ font-size: 13px; color: #94a3b8; margin-top: 4px; }}
        .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 20px; margin-bottom: 24px; }}
        .h2 {{ font-size: 16px; font-weight: bold; text-transform: uppercase; color: #cbd5e1; margin-top: 0; margin-bottom: 12px; }}
        .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }}
        .item {{ font-size: 13px; }}
        .label {{ color: #94a3b8; font-size: 11px; text-transform: uppercase; font-weight: bold; }}
        .value {{ font-family: monospace; color: #e2e8f0; margin-top: 2px; word-break: break-all; }}
        .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
        .score-box {{ background: {risk_color}20; border: 1px solid {risk_color}; color: {risk_color}; font-size: 24px; font-weight: bold; padding: 12px 20px; border-radius: 8px; text-align: center; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 8px; }}
        th, td {{ text-align: left; padding: 8px 12px; border-bottom: 1px solid #334155; }}
        th {{ color: #94a3b8; text-transform: uppercase; font-size: 11px; }}
        .danger {{ color: #ef4444; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <div class="title">🛡️ SOC PHISHING INCIDENT REPORT</div>
            <div class="sub">Case Reference: <strong>{case_id}</strong> | Generated: {case.get("created_at")}</div>
        </div>
        <div class="score-box">
            {risk.get("score", 0)} / 100<br>
            <span style="font-size: 11px; text-transform: uppercase;">VERDICT: {case.get("analyst_verdict", "PENDING")}</span>
        </div>
    </div>

    <div class="card">
        <div class="h2">Incident Overview</div>
        <div class="grid">
            <div class="item"><div class="label">Subject</div><div class="value">{meta.get("subject", "-")}</div></div>
            <div class="item"><div class="label">Date Dispatched</div><div class="value">{meta.get("date", "-")}</div></div>
            <div class="item"><div class="label">Claimed Sender</div><div class="value">{meta.get("from", "-")}</div></div>
            <div class="item"><div class="label">Return-Path</div><div class="value">{meta.get("return_path", "-")}</div></div>
            <div class="item"><div class="label">Recipient</div><div class="value">{meta.get("to", "-")}</div></div>
            <div class="item"><div class="label">Origin Relay IP</div><div class="value">{data.get("header_analysis", {}).get("origin_ip", "-")}</div></div>
        </div>
    </div>

    <div class="card">
        <div class="h2">Email Authentication Record</div>
        <div class="grid">
            <div class="item"><div class="label">SPF Check</div><div class="value">{auth.get("spf", {}).get("status", "none").upper()}</div></div>
            <div class="item"><div class="label">DKIM Signature</div><div class="value">{auth.get("dkim", {}).get("status", "none").upper()}</div></div>
            <div class="item"><div class="label">DMARC Policy</div><div class="value">{auth.get("dmarc", {}).get("status", "none").upper()}</div></div>
            <div class="item"><div class="label">Status</div><div class="value">{case.get("status")}</div></div>
        </div>
    </div>

    <div class="card">
        <div class="h2">MITRE ATT&CK® Techniques Mapped</div>
        <table>
            <thead>
                <tr><th>Technique ID</th><th>Name</th><th>Tactic</th><th>Observed Evidence</th></tr>
            </thead>
            <tbody>"""

        for m in mitre:
            html += f"""
                <tr>
                    <td><strong>{m.get('id')}</strong></td>
                    <td>{m.get('name')}</td>
                    <td>{m.get('tactic')}</td>
                    <td class="danger">{m.get('evidence')}</td>
                </tr>"""

        html += """
            </tbody>
        </table>
    </div>

    <div class="card">
        <div class="h2">Extracted Hyperlinks & URLs</div>
        <table>
            <thead>
                <tr><th>Defanged Destination</th><th>Domain</th><th>Host Type</th><th>Spoofing Flag</th></tr>
            </thead>
            <tbody>"""

        for u in urls:
            html += f"""
                <tr>
                    <td class="value">{u.get('defanged')}</td>
                    <td>{u.get('domain')}</td>
                    <td>{'IP Host' if u.get('is_ip_host') else 'FQDN'}</td>
                    <td class="{'danger' if u.get('mismatch') else ''}">{'⚠️ ANCHOR MISMATCH' if u.get('mismatch') else 'None'}</td>
                </tr>"""

        html += """
            </tbody>
        </table>
    </div>

    <div class="card">
        <div class="h2">Attachments & Payload Analysis</div>
        <table>
            <thead>
                <tr><th>Filename</th><th>Size</th><th>Detected Format</th><th>Entropy</th><th>SHA256</th></tr>
            </thead>
            <tbody>"""

        for a in attachments:
            deep = a.get("deep_analysis", {})
            html += f"""
                <tr>
                    <td><strong>{a.get('filename')}</strong></td>
                    <td>{round(a.get('size_bytes', 0)/1024, 1)} KB</td>
                    <td>{deep.get('detected_format', a.get('content_type'))}</td>
                    <td>{deep.get('entropy', 0.0)}</td>
                    <td class="value">{a.get('sha256')}</td>
                </tr>"""

        html += """
            </tbody>
        </table>
    </div>

    <div class="card">
        <div class="h2">Analyst Investigation Notes</div>"""

        for n in notes:
            html += f"""
            <div style="border-left: 3px solid #6366f1; padding-left: 12px; margin-bottom: 12px;">
                <div style="font-size: 11px; color: #94a3b8;"><strong>{n.get('author')}</strong> • {n.get('timestamp')}</div>
                <div style="font-size: 13px; color: #e2e8f0; margin-top: 2px;">{n.get('text')}</div>
            </div>"""

        html += """
    </div>
</body>
</html>"""
        return html
