import pytest
from app.services.investigation import InvestigationService
from app.utils.defang import defang_url, defang_ip

def test_defang_helpers():
    assert defang_url("http://evil.com/login") == "hxxp://evil[.]com/login"
    assert defang_ip("192.168.1.1") == "192[.]168[.]1[.]1"

@pytest.mark.anyio
async def test_full_investigation_pipeline():
    with open("sample_emails/suspicious_invoice.eml", "rb") as f:
        content = f.read()

    report = await InvestigationService.run_investigation(content, filename="suspicious_invoice.eml")

    # Check parsed metadata
    assert "PayPal Account Security" in report["meta"]["from"]
    assert "Action Required" in report["meta"]["subject"]

    # Check header analysis
    auth = report["header_analysis"]["authentication"]
    assert auth["spf"]["status"] == "fail"
    assert auth["dkim"]["status"] == "fail"
    assert auth["dmarc"]["status"] == "fail"

    # Check origin IP
    assert report["header_analysis"]["origin_ip"] == "185.220.101.45"

    # Check URLs & Anchor Spoof
    urls = report["url_analysis"]
    assert len(urls) >= 2
    spoofed = [u for u in urls if u["mismatch"]]
    assert len(spoofed) >= 1  # Displayed paypal.com, actually went to 194.87.139.12

    # Check Attachment
    attachments = report["attachments"]
    assert len(attachments) == 1
    assert attachments[0]["filename"] == "Invoice_OCT_2026.exe"

    # Check Threat Intel & Typosquatting
    enrichment = report["enrichment"]
    assert "domain_reputation" in enrichment
    lookalikes = [dr for dr in enrichment["domain_reputation"] if dr.get("type") in ["TYPOSQUATTING_LOOKALIKE", "SUSPICIOUS_TLD"]]
    assert len(lookalikes) >= 1  # update-paypal-security.cc detected as lookalike and .cc tld

    # Check Deep Attachment Analysis
    deep_att = attachments[0]["deep_analysis"]
    assert deep_att["detected_type"] == "PE_EXECUTABLE"

    # Check MITRE ATT&CK Mapping
    mitre = report["mitre_attack"]
    assert len(mitre) >= 2
    technique_ids = [m["id"] for m in mitre]
    assert "T1566.001" in technique_ids  # Spearphishing attachment
    assert "T1566.002" in technique_ids  # Spearphishing link

    # Check Timeline Reconstruction
    timeline = report["timeline"]
    assert len(timeline) >= 4
    stages = [tl["stage"] for tl in timeline]
    assert "ORIGIN" in stages
    assert "VERDICT" in stages

    # Check Risk Assessment
    risk = report["risk_assessment"]
    assert risk["score"] >= 70
    assert risk["verdict"] == "MALICIOUS"
