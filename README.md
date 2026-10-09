# 🎣 Phishing Incident Investigation Workbench

An automated SOC Analyst workbench for triage, header analysis, hyperlink inspection, attachment hashing, and rule-based risk scoring of suspicious phishing emails.

---

## 🚀 Quick Start

### 1. Activate Environment & Run Backend
```bash
# In the project root directory
source venv/bin/activate
export PYTHONPATH=backend
uvicorn app.main:app --reload --port 8000
```

### 2. Open the Workbench
Open your browser and navigate to:
```
http://localhost:8000
```

---

## 🔍 Features Built

### Phase 1 — Foundation & Core Analysis Engine
1. **Email Parser (`backend/app/analyzers/email_parser.py`)**: Ingests RFC 822 / `.eml` and MIME structures, decodes headers and bodies, calculates SHA256/MD5 for attachments.
2. **Header & Hop Analyzer (`backend/app/analyzers/header_analyzer.py`)**: Traces chronological relay hops (`Received:` headers), extracts origin IP, parses **SPF**, **DKIM**, and **DMARC** authentication statuses, and detects sender address spoofing.
3. **URL & Hyperlink Analyzer (`backend/app/analyzers/url_analyzer.py`)**: Extracts hyperlinks and detects **Anchor Text Spoofing** (e.g. text claims `paypal.com` but destination points elsewhere).
4. **IOC Extraction & Defanging (`backend/app/analyzers/ioc_extractor.py` & `defang.py`)**: Pulls and defangs IPs, URLs, domains, emails, and file hashes (`hxxp://`, `[.]`).
5. **Interactive SOC Dashboard (`backend/app/main.py`)**: Dark-themed investigation workbench with sample loader and defanged export.

---

### Phase 2 — Threat Intelligence & Reputation Enrichment
1. **Domain Reputation & Typosquatting Engine (`backend/app/enrichers/domain_reputation.py`)**:
   - Computes Levenshtein distance against high-value target brands.
   - Detects IDN Homograph / Punycode attacks (`xn--...`).
   - Flags high-abuse suspicious TLDs (`.cc`, `.xyz`, `.top`, `.buzz`, `.tk`, `.work`).
2. **URLhaus Threat Intelligence (`backend/app/enrichers/urlhaus.py`)**: Checks active malware/phishing feeds.
3. **AbuseIPDB Integration (`backend/app/enrichers/abuseipdb.py`)**: Queries IP abuse scores.
4. **VirusTotal Integration (`backend/app/enrichers/virustotal.py`)**: Queries URL and hash detections.
5. **Enrichment Orchestration Service (`backend/app/enrichers/orchestrator.py`)**: Concurrently executes threat lookups.

---

### Phase 3 — Deep Analysis & Incident Timeline
1. **Deep Attachment Inspection (`backend/app/analyzers/attachment_analyzer.py`)**:
   - Inspects file magic bytes (`MZ` PE executables, PDFs, ZIP archives, OLE documents, ELF binaries).
   - Detects disguised executables and double extension obfuscation (e.g. `report.pdf.exe`).
   - Computes Shannon entropy (flags packed/encrypted payloads > 7.1).
2. **MITRE ATT&CK® Enterprise Mapper (`backend/app/analyzers/mitre_mapper.py`)**:
   - Maps indicators to Enterprise ATT&CK techniques: `T1566.001`, `T1566.002`, `T1036.005`, `T1586.002`, `T1204.001`, `T1204.002`, `T1059`.
3. **Chronological Investigation Timeline (`backend/app/analyzers/timeline_builder.py`)**:
   - Reconstructs end-to-end incident lifecycle: Origin $\rightarrow$ Relay Hops $\rightarrow$ Delivery $\rightarrow$ Payload Extraction $\rightarrow$ Threat Intel Correlation $\rightarrow$ Final Verdict.

---

### Phase 4 — Case Management & Incident Reporting
1. **Case Management Store (`backend/app/services/case_manager.py`)**:
   - Generates tracked investigation case references (`CASE-XXXXXXXX`).
   - Maintains analyst notes with timestamps and author signatures.
   - Supports verdict override and sign-off workflows (`OPEN`, `RESOLVED`, `CONFIRMED_MALICIOUS`).
2. **Audit Report Generator (`backend/app/services/report_generator.py`)**:
   - Compiles comprehensive, standalone HTML incident reports complete with header authentication results, MITRE ATT&CK techniques, extracted IOC tables, and audit logs.
3. **One-Click Case Action Workflow (`backend/app/main.py`)**:
   - From any analysis result on the dashboard, analysts can click **"Open Incident Case"** to persist the dossier, followed by **"Download Audit Report"** to view and print the official record.

### 🔑 API Key Configuration (Optional)
Free threat intelligence keys can be configured via environment variables:
```bash
export VIRUSTOTAL_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
```
*(URLhaus and the Typosquatting engine work without any API keys!)*

---

## 🧪 Running Automated Tests

```bash
source venv/bin/activate
PYTHONPATH=backend pytest backend/tests/ -v
```
