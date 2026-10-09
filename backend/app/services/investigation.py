"""
Investigation Pipeline Service:
Coordinates EmailParser, HeaderAnalyzer, URLAnalyzer, IOCExtractor, and RiskScorer.
"""
from typing import Dict, Any
from ..analyzers.email_parser import EmailParser
from ..analyzers.header_analyzer import HeaderAnalyzer
from ..analyzers.url_analyzer import URLAnalyzer
from ..analyzers.ioc_extractor import IOCExtractor
from ..analyzers.risk_scorer import RiskScorer
from ..analyzers.mitre_mapper import MitreAttackMapper
from ..analyzers.attachment_analyzer import DeepAttachmentAnalyzer
from ..analyzers.timeline_builder import TimelineBuilder
from ..enrichers.orchestrator import ThreatIntelEnrichmentService

class InvestigationService:
    @staticmethod
    async def run_investigation(raw_email_bytes: bytes, filename: str = "sample.eml") -> Dict[str, Any]:
        # 1. Parse raw email
        parser = EmailParser(raw_email_bytes)
        parsed_email = parser.parse()

        # 2. Analyze headers
        header_analyzer = HeaderAnalyzer(parsed_email["headers"])
        headers_res = header_analyzer.analyze()

        # 3. Analyze URLs
        body_text = parsed_email["body"]["text"] or ""
        body_html = parsed_email["body"]["html"] or ""
        url_analyzer = URLAnalyzer(text_content=body_text, html_content=body_html)
        urls_res = url_analyzer.analyze()

        # 4. Deep Attachment Inspection
        deep_attachments = []
        for att in parsed_email["attachments"]:
            raw_bytes = att.pop("_raw_bytes", b"")
            deep_res = DeepAttachmentAnalyzer.inspect(att, raw_bytes)
            att["deep_analysis"] = deep_res
            deep_attachments.append(att)
        parsed_email["attachments"] = deep_attachments

        # 5. Extract IOCs across headers, bodies, attachments
        origin_ip = headers_res.get('origin_ip', '') or ''
        all_text_for_iocs = (
            f"{body_text} "
            f"{origin_ip} "
            + " ".join([h.get("value", "") for h in parsed_email["headers"]])
        )
        ioc_extractor = IOCExtractor(all_text_for_iocs, parsed_email, urls_res)
        iocs_res = ioc_extractor.extract()

        # 6. Threat Intelligence Enrichment
        enrichment_res = await ThreatIntelEnrichmentService.enrich_all(iocs_res, origin_ip=origin_ip)

        # 7. Compute Risk Score & Factors
        scorer = RiskScorer(parsed_email, headers_res, urls_res, enrichment=enrichment_res)
        score_res = scorer.calculate()

        # 8. MITRE ATT&CK Mapping
        mitre_res = MitreAttackMapper.map_findings(
            headers=headers_res,
            urls=urls_res,
            attachments=parsed_email["attachments"],
            enrichment=enrichment_res
        )

        # 9. Investigation Timeline Reconstruction
        timeline_res = TimelineBuilder.build(
            meta=parsed_email["meta"],
            hops=headers_res.get("hops", []),
            urls=urls_res,
            attachments=parsed_email["attachments"],
            enrichment=enrichment_res,
            risk=score_res
        )

        return {
            "file_info": {
                "filename": filename,
                "size_bytes": parsed_email["raw_size"],
                "sha256": parsed_email["sha256"],
            },
            "meta": parsed_email["meta"],
            "body": parsed_email["body"],
            "attachments": parsed_email["attachments"],
            "header_analysis": headers_res,
            "url_analysis": urls_res,
            "iocs": iocs_res,
            "enrichment": enrichment_res,
            "mitre_attack": mitre_res,
            "timeline": timeline_res,
            "risk_assessment": score_res,
        }
