"""
FastAPI application for Phishing Incident Investigation Workbench.
Includes:
- API endpoint to analyze uploaded .eml files or raw text.
- Built-in responsive SOC Analyst Investigation Dashboard UI.
"""
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from typing import Optional, Dict, Any
from .services.investigation import InvestigationService
from .services.case_manager import case_manager
from .services.report_generator import ReportGenerator

app = FastAPI(
    title="Phishing Incident Investigation Workbench",
    description="SOC Analyst workbench for automated phishing email triage, header inspection, URL safety, and IOC extraction.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/investigate/upload")
async def investigate_file(file: UploadFile = File(...)):
    """Receives an uploaded .eml file and executes the complete analysis pipeline."""
    try:
        content = await file.read()
        if not content:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")
        
        result = await InvestigationService.run_investigation(content, filename=file.filename or "sample.eml")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process email: {str(e)}")

@app.post("/api/investigate/raw")
async def investigate_raw_text(raw_email: str = Form(...)):
    """Receives raw MIME or RFC822 email text string and executes analysis pipeline."""
    try:
        content_bytes = raw_email.encode("utf-8")
        result = await InvestigationService.run_investigation(content_bytes, filename="raw_input.eml")
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process raw email: {str(e)}")

@app.get("/api/health")
def health_check():
    return {"status": "healthy", "service": "phishing-workbench-api"}

# --- Case Management & Reporting Endpoints ---

@app.post("/api/cases")
async def create_case_from_investigation(payload: Dict[str, Any]):
    """Creates a new tracked case from an investigation result."""
    case = case_manager.create_case(payload)
    return case

@app.get("/api/cases")
def list_cases():
    """Returns list of all active and resolved cases."""
    return case_manager.list_cases()

@app.get("/api/cases/{case_id}")
def get_case_details(case_id: str):
    """Fetches full case dossier by case reference ID."""
    case = case_manager.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case

@app.post("/api/cases/{case_id}/notes")
def add_case_note(case_id: str, note: Dict[str, str]):
    """Appends an analyst note to a case."""
    text = note.get("text", "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="Note text cannot be empty")
    author = note.get("author", "SOC Analyst")
    entry = case_manager.add_note(case_id, text, author)
    if not entry:
        raise HTTPException(status_code=404, detail="Case not found")
    return entry

@app.patch("/api/cases/{case_id}/verdict")
def update_case_verdict(case_id: str, payload: Dict[str, str]):
    """Signs off or modifies the analyst verdict."""
    verdict = payload.get("verdict")
    status = payload.get("status", "RESOLVED")
    case = case_manager.update_verdict(case_id, verdict, status)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return case

@app.get("/api/cases/{case_id}/report", response_class=HTMLResponse)
def export_html_report(case_id: str):
    """Generates and serves a standalone incident report."""
    case = case_manager.get_case(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return ReportGenerator.generate_html_report(case)

@app.get("/", response_class=HTMLResponse)
def index_view():
    """Serves the interactive SOC analyst workbench frontend."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎣 Phishing Incident Investigation Workbench</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        body { background-color: #0b0f17; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .card { background: #131b2a; border: 1px solid #1e293b; border-radius: 0.75rem; }
        .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }
        .badge-fail { background: #451a1a; color: #f87171; border: 1px solid #7f1d1d; }
        .badge-pass { background: #143522; color: #4ade80; border: 1px solid #14532d; }
        .badge-warn { background: #3c2a13; color: #facc15; border: 1px solid #713f12; }
    </style>
</head>
<body class="min-h-screen pb-16">
    <!-- Navbar -->
    <header class="border-b border-slate-800 bg-slate-950/70 backdrop-blur px-6 py-4 flex items-center justify-between sticky top-0 z-50">
        <div class="flex items-center space-x-3">
            <span class="text-2xl">🎣</span>
            <div>
                <h1 class="text-lg font-bold text-white tracking-wide">PHISH<span class="text-indigo-400">BENCH</span></h1>
                <p class="text-xs text-slate-400">SOC Incident Investigation Workbench</p>
            </div>
        </div>
        <div class="flex items-center space-x-4">
            <span class="text-xs bg-indigo-950 text-indigo-300 border border-indigo-700/50 px-2.5 py-1 rounded-full font-mono">
                <i class="fa-solid fa-shield-halved mr-1"></i> Phase 1 MVP Active
            </span>
        </div>
    </header>

    <main class="max-w-7xl mx-auto px-6 mt-8">
        <!-- Input section -->
        <section class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
            <!-- Upload Box -->
            <div class="card p-6 flex flex-col justify-between">
                <div>
                    <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-2">
                        <i class="fa-solid fa-file-arrow-up mr-2 text-indigo-400"></i>Upload .EML Sample
                    </h2>
                    <p class="text-xs text-slate-400 mb-4">Select or drop a raw RFC822 email file (.eml / .msg).</p>
                    <div id="dropzone" class="border-2 border-dashed border-slate-700 hover:border-indigo-500 rounded-lg p-6 text-center cursor-pointer transition">
                        <i class="fa-solid fa-cloud-arrow-up text-3xl text-slate-500 mb-2"></i>
                        <p class="text-sm text-slate-300" id="file-name-label">Click to select file or drag & drop</p>
                        <p class="text-xs text-slate-500 mt-1">.eml, .msg up to 25MB</p>
                        <input type="file" id="file-input" class="hidden" accept=".eml,.msg,text/plain">
                    </div>
                </div>
                <button id="btn-upload" class="mt-4 w-full bg-indigo-600 hover:bg-indigo-500 text-white font-medium py-2.5 rounded-lg text-sm transition flex items-center justify-center space-x-2">
                    <i class="fa-solid fa-magnifying-glass-chart"></i>
                    <span>Run Deep Analysis</span>
                </button>
            </div>

            <!-- Paste Box & Quick Test -->
            <div class="card p-6 flex flex-col justify-between">
                <div>
                    <div class="flex items-center justify-between mb-2">
                        <h2 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                            <i class="fa-solid fa-code mr-2 text-indigo-400"></i>Or Paste Raw RFC822 Message
                        </h2>
                        <button id="btn-load-sample" class="text-xs text-indigo-400 hover:underline">
                            Load Demo Phishing Sample
                        </button>
                    </div>
                    <textarea id="raw-textarea" class="w-full h-36 bg-slate-900 border border-slate-700 rounded-lg p-3 text-xs mono text-slate-200 focus:outline-none focus:border-indigo-500 resize-none" placeholder="Paste headers + MIME body here..."></textarea>
                </div>
                <button id="btn-analyze-raw" class="mt-4 w-full bg-slate-800 hover:bg-slate-700 text-slate-200 font-medium py-2.5 rounded-lg text-sm border border-slate-700 transition flex items-center justify-center space-x-2">
                    <i class="fa-solid fa-bolt"></i>
                    <span>Analyze Raw Text</span>
                </button>
            </div>
        </section>

        <!-- Loading Spinner -->
        <div id="loader" class="hidden text-center py-12">
            <i class="fa-solid fa-circle-notch fa-spin text-4xl text-indigo-500 mb-3"></i>
            <p class="text-sm text-slate-400">Dissecting headers, extracting IOCs, and evaluating risk indicators...</p>
        </div>

        <!-- Investigation Results View -->
        <div id="results" class="hidden space-y-6">
            <!-- Top Summary Banner -->
            <div class="card p-6 flex flex-col md:flex-row items-center justify-between gap-6">
                <div class="flex items-center space-x-5">
                    <div id="risk-score-badge" class="w-20 h-20 rounded-2xl flex flex-col items-center justify-center font-bold text-3xl shadow-lg">
                        <span id="risk-score-value">0</span>
                        <span class="text-[10px] tracking-wider uppercase font-semibold text-white/80">RISK</span>
                    </div>
                    <div>
                        <div class="flex items-center space-x-3 mb-1">
                            <h2 class="text-xl font-bold text-white" id="verdict-title">VERDICT: PENDING</h2>
                            <span id="severity-pill" class="text-xs px-2.5 py-0.5 rounded-full font-bold uppercase"></span>
                        </div>
                        <p class="text-xs text-slate-400" id="file-sha-label">SHA256: -</p>
                        <p class="text-xs text-slate-300 mt-1" id="subject-label"><strong class="text-slate-400">Subject:</strong> -</p>
                    </div>
                </div>

                <div class="flex flex-col items-end space-y-3 w-full md:w-auto">
                    <div class="grid grid-cols-3 gap-4 text-center border-t md:border-t-0 md:border-l border-slate-800 pt-4 md:pt-0 md:pl-6 w-full md:w-auto">
                        <div>
                            <p class="text-xs text-slate-400">SPF Status</p>
                            <p id="spf-pill" class="text-xs font-mono font-bold mt-1 px-2 py-0.5 rounded">-</p>
                        </div>
                        <div>
                            <p class="text-xs text-slate-400">DKIM Status</p>
                            <p id="dkim-pill" class="text-xs font-mono font-bold mt-1 px-2 py-0.5 rounded">-</p>
                        </div>
                        <div>
                            <p class="text-xs text-slate-400">DMARC Status</p>
                            <p id="dmarc-pill" class="text-xs font-mono font-bold mt-1 px-2 py-0.5 rounded">-</p>
                        </div>
                    </div>
                    <!-- Case & Report Actions -->
                    <div class="flex items-center space-x-2 pt-2">
                        <button id="btn-create-case" class="bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold px-3 py-1.5 rounded transition flex items-center space-x-1.5">
                            <i class="fa-solid fa-folder-plus"></i>
                            <span id="case-btn-text">Open Incident Case</span>
                        </button>
                        <a id="btn-export-report" href="#" target="_blank" class="hidden bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs font-semibold px-3 py-1.5 rounded transition items-center space-x-1.5">
                            <i class="fa-solid fa-file-pdf"></i>
                            <span>Download Audit Report</span>
                        </a>
                    </div>
                </div>
            </div>

            <!-- Risk Factors Breakdown -->
            <div class="card p-6">
                <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400 mb-4">
                    <i class="fa-solid fa-triangle-exclamation text-amber-400 mr-2"></i>Risk Factors Triggered
                </h3>
                <div id="risk-factors-container" class="space-y-2">
                    <!-- Populated dynamically -->
                </div>
            </div>

            <!-- Detailed Grid -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- Email Metadata & Route -->
                <div class="card p-6 space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                        <i class="fa-solid fa-envelope-open-text text-indigo-400 mr-2"></i>Email Metadata & Routing Hops
                    </h3>
                    <div class="space-y-2 text-xs">
                        <div class="flex justify-between py-1 border-b border-slate-800"><span class="text-slate-500">From:</span><span id="meta-from" class="text-slate-200 mono"></span></div>
                        <div class="flex justify-between py-1 border-b border-slate-800"><span class="text-slate-500">To:</span><span id="meta-to" class="text-slate-200 mono"></span></div>
                        <div class="flex justify-between py-1 border-b border-slate-800"><span class="text-slate-500">Return-Path:</span><span id="meta-return-path" class="text-slate-200 mono"></span></div>
                        <div class="flex justify-between py-1 border-b border-slate-800"><span class="text-slate-500">Origin IP:</span><span id="meta-origin-ip" class="text-indigo-400 mono font-bold"></span></div>
                    </div>
                    <h4 class="text-xs font-bold uppercase text-slate-400 mt-4 mb-2">Relay Path (Received Headers):</h4>
                    <div id="hops-container" class="space-y-2 max-h-48 overflow-y-auto pr-1"></div>
                </div>

                <!-- URL Analysis -->
                <div class="card p-6 space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                        <i class="fa-solid fa-link text-indigo-400 mr-2"></i>Extracted URLs & Hyperlinks (<span id="url-count">0</span>)
                    </h3>
                    <div id="urls-container" class="space-y-3 max-h-80 overflow-y-auto pr-1"></div>
                </div>
            </div>

            <!-- Threat Intelligence Enrichment Card -->
            <div class="card p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                        <i class="fa-solid fa-radar text-indigo-400 mr-2"></i>Threat Intelligence & Reputation Enrichment
                    </h3>
                    <span class="text-xs text-slate-500 font-mono">URLhaus • AbuseIPDB • VirusTotal • Lookalike Engine</span>
                </div>
                <div id="intel-container" class="space-y-3">
                    <!-- Populated dynamically -->
                </div>
            </div>

            <!-- IOC & Attachments Grid -->
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <!-- IOC Table -->
                <div class="card p-6 space-y-4">
                    <div class="flex items-center justify-between">
                        <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                            <i class="fa-solid fa-crosshairs text-indigo-400 mr-2"></i>Extracted IOCs (Defanged)
                        </h3>
                        <button id="copy-iocs" class="text-xs text-indigo-400 hover:text-indigo-300">
                            <i class="fa-regular fa-copy mr-1"></i>Copy Defanged List
                        </button>
                    </div>
                    <div id="iocs-container" class="space-y-3 max-h-60 overflow-y-auto pr-1 text-xs mono"></div>
                </div>

                <!-- Attachments -->
                <div class="card p-6 space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                        <i class="fa-solid fa-paperclip text-indigo-400 mr-2"></i>Deep Attachment Inspection (<span id="att-count">0</span>)
                    </h3>
                    <div id="attachments-container" class="space-y-3 max-h-60 overflow-y-auto pr-1"></div>
                </div>
            </div>

            <!-- MITRE ATT&CK Mapping Card -->
            <div class="card p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                        <i class="fa-solid fa-network-wired text-indigo-400 mr-2"></i>MITRE ATT&CK® Enterprise Mapping
                    </h3>
                    <span class="text-xs text-slate-500 font-mono">Adversary Tactics & Techniques</span>
                </div>
                <div id="mitre-container" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                    <!-- Populated dynamically -->
                </div>
            </div>

            <!-- Chronological Investigation Timeline -->
            <div class="card p-6">
                <div class="flex items-center justify-between mb-4">
                    <h3 class="text-sm font-semibold uppercase tracking-wider text-slate-400">
                        <i class="fa-solid fa-timeline text-indigo-400 mr-2"></i>Chronological Investigation Timeline
                    </h3>
                    <span class="text-xs text-slate-500 font-mono">End-to-End Incident Sequence</span>
                </div>
                <div id="timeline-container" class="relative pl-6 border-l-2 border-slate-800 space-y-6">
                    <!-- Populated dynamically -->
                </div>
            </div>
        </div>
    </main>

    <script>
        const fileInput = document.getElementById('file-input');
        const dropzone = document.getElementById('dropzone');
        const fileNameLabel = document.getElementById('file-name-label');
        const btnUpload = document.getElementById('btn-upload');
        const btnAnalyzeRaw = document.getElementById('btn-analyze-raw');
        const rawTextarea = document.getElementById('raw-textarea');
        const btnLoadSample = document.getElementById('btn-load-sample');
        const loader = document.getElementById('loader');
        const results = document.getElementById('results');

        let selectedFile = null;

        dropzone.onclick = () => fileInput.click();
        fileInput.onchange = (e) => {
            if (e.target.files.length) {
                selectedFile = e.target.files[0];
                fileNameLabel.textContent = selectedFile.name + " (" + (selectedFile.size / 1024).toFixed(1) + " KB)";
            }
        };

        dropzone.ondragover = (e) => { e.preventDefault(); dropzone.classList.add('border-indigo-500'); };
        dropzone.ondragleave = () => dropzone.classList.remove('border-indigo-500');
        dropzone.ondrop = (e) => {
            e.preventDefault();
            dropzone.classList.remove('border-indigo-500');
            if (e.dataTransfer.files.length) {
                selectedFile = e.dataTransfer.files[0];
                fileNameLabel.textContent = selectedFile.name + " (" + (selectedFile.size / 1024).toFixed(1) + " KB)";
            }
        };

        btnUpload.onclick = async () => {
            if (!selectedFile) {
                alert('Please choose or drop an .eml file first.');
                return;
            }
            const fd = new FormData();
            fd.append('file', selectedFile);
            runAnalysis('/api/investigate/upload', { method: 'POST', body: fd });
        };

        btnAnalyzeRaw.onclick = async () => {
            const text = rawTextarea.value.trim();
            if (!text) {
                alert('Please enter or paste RFC822 email text.');
                return;
            }
            const fd = new FormData();
            fd.append('raw_email', text);
            runAnalysis('/api/investigate/raw', { method: 'POST', body: fd });
        };

        btnLoadSample.onclick = () => {
            rawTextarea.value = `From: "Security Alert" <alert@paypal-update-account.cc>
To: target-analyst@example.com
Subject: [URGENT] Your PayPal Account Has Been Suspended!
Date: Fri, 09 Oct 2026 12:00:00 +0000
Message-ID: <evil-1234@paypal-update-account.cc>
Return-Path: <bounce@attacker-relay.net>
Authentication-Results: mx.google.com; spf=fail (google.com: domain of attacker-relay.net does not designate 185.220.101.5 as permitted sender); dkim=fail; dmarc=fail
Received: from mail.attacker-relay.net (185.220.101.5) by mx.google.com with ESMTPS id abc123xyz; Fri, 09 Oct 2026 12:00:01 +0000
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Dear Customer,</p>
<p>We detected unauthorized login attempts from a new IP address. Your account is temporarily suspended.</p>
<p>Please re-verify your identity immediately by clicking below:</p>
<p><a href="http://194.87.139.12/login/paypal">https://www.paypal.com/verify-account</a></p>
<p>Or visit our emergency backup portal: http://evil-harvest-phish.biz/auth</p>
</body>
</html>`;
        };

        async function runAnalysis(url, options) {
            results.classList.add('hidden');
            loader.classList.remove('hidden');
            try {
                const res = await fetch(url, options);
                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.detail || 'Analysis request failed');
                }
                const data = await res.json();
                renderResults(data);
            } catch (err) {
                alert('Error running investigation: ' + err.message);
            } finally {
                loader.classList.add('hidden');
            }
        }

        function renderResults(data) {
            results.classList.remove('hidden');

            const score = data.risk_assessment.score;
            const verdict = data.risk_assessment.verdict;
            const scoreBadge = document.getElementById('risk-score-badge');
            
            document.getElementById('risk-score-value').textContent = score;
            document.getElementById('verdict-title').textContent = "VERDICT: " + verdict;
            document.getElementById('file-sha-label').textContent = "SHA256: " + data.file_info.sha256;
            document.getElementById('subject-label').innerHTML = `<strong class="text-slate-400">Subject:</strong> ${data.meta.subject || '(No Subject)'}`;

            // Styling risk badge
            scoreBadge.className = 'w-20 h-20 rounded-2xl flex flex-col items-center justify-center font-bold text-3xl shadow-lg ' + 
                (score >= 70 ? 'bg-red-700 text-white' : (score >= 35 ? 'bg-amber-600 text-white' : 'bg-emerald-600 text-white'));

            const sevPill = document.getElementById('severity-pill');
            sevPill.textContent = data.risk_assessment.severity + " SEVERITY";
            sevPill.className = 'text-xs px-2.5 py-0.5 rounded-full font-bold uppercase ' +
                (score >= 70 ? 'badge-fail' : (score >= 35 ? 'badge-warn' : 'badge-pass'));

            // Auth badges
            const setAuthBadge = (id, status) => {
                const el = document.getElementById(id);
                el.textContent = (status || 'NONE').toUpperCase();
                el.className = 'text-xs font-mono font-bold mt-1 px-2 py-0.5 rounded ' + 
                    (status === 'pass' ? 'badge-pass' : (status === 'fail' ? 'badge-fail' : 'badge-warn'));
            };

            const auth = data.header_analysis.authentication;
            setAuthBadge('spf-pill', auth.spf.status);
            setAuthBadge('dkim-pill', auth.dkim.status);
            setAuthBadge('dmarc-pill', auth.dmarc.status);

            // Risk Factors
            const rfContainer = document.getElementById('risk-factors-container');
            rfContainer.innerHTML = '';
            if (data.risk_assessment.factors.length === 0) {
                rfContainer.innerHTML = '<p class="text-xs text-slate-400 italic">No suspicious risk factors detected.</p>';
            } else {
                data.risk_assessment.factors.forEach(f => {
                    rfContainer.innerHTML += `
                        <div class="flex items-center justify-between p-2.5 rounded bg-slate-900 border border-slate-800 text-xs">
                            <span class="text-slate-300"><i class="fa-solid fa-flag text-red-400 mr-2"></i>${f.reason}</span>
                            <span class="font-mono text-red-400 font-bold ml-2">+${f.points} pts</span>
                        </div>
                    `;
                });
            }

            // Metadata
            document.getElementById('meta-from').textContent = data.meta.from || '-';
            document.getElementById('meta-to').textContent = data.meta.to || '-';
            document.getElementById('meta-return-path').textContent = data.meta.return_path || '-';
            document.getElementById('meta-origin-ip').textContent = data.header_analysis.origin_ip || 'Not identified';

            // Hops
            const hopsContainer = document.getElementById('hops-container');
            hopsContainer.innerHTML = '';
            if (!data.header_analysis.hops.length) {
                hopsContainer.innerHTML = '<p class="text-xs text-slate-500">No Received headers parsed.</p>';
            } else {
                data.header_analysis.hops.forEach(h => {
                    hopsContainer.innerHTML += `
                        <div class="p-2 rounded bg-slate-900 border border-slate-800/80 text-[11px] mono">
                            <div class="flex justify-between text-slate-400 mb-1">
                                <span class="font-bold text-indigo-400">Hop #${h.hop}</span>
                                <span class="text-amber-400">${h.ip || 'No IP'}</span>
                            </div>
                            <div class="text-slate-500 truncate" title="${h.raw}">From: ${h.from || '-'} | By: ${h.by || '-'}</div>
                        </div>
                    `;
                });
            }

            // URLs
            const urlContainer = document.getElementById('urls-container');
            document.getElementById('url-count').textContent = data.url_analysis.length;
            urlContainer.innerHTML = '';
            if (!data.url_analysis.length) {
                urlContainer.innerHTML = '<p class="text-xs text-slate-500 italic">No URLs found in message body.</p>';
            } else {
                data.url_analysis.forEach(u => {
                    urlContainer.innerHTML += `
                        <div class="p-2.5 rounded bg-slate-900 border ${u.mismatch || u.is_ip_host ? 'border-red-900/50 bg-red-950/10' : 'border-slate-800'} text-xs">
                            <div class="flex items-center justify-between mb-1">
                                <span class="mono text-indigo-300 font-semibold truncate" title="${u.defanged}">${u.defanged}</span>
                                ${u.mismatch ? '<span class="badge-fail text-[10px] px-1.5 py-0.5 rounded font-bold">TEXT SPOOF</span>' : ''}
                                ${u.is_ip_host ? '<span class="badge-warn text-[10px] px-1.5 py-0.5 rounded font-bold ml-1">IP HOST</span>' : ''}
                            </div>
                            <div class="text-slate-500 text-[11px]">Domain: <span class="text-slate-300 mono">${u.domain}</span></div>
                            ${u.display_text ? `<div class="text-slate-500 text-[11px] truncate">Anchor text: "${u.display_text}"</div>` : ''}
                        </div>
                    `;
                });
            }

            // Threat Intelligence Enrichment
            const intelContainer = document.getElementById('intel-container');
            intelContainer.innerHTML = '';
            const enrich = data.enrichment || {};
            let hasIntel = false;

            // Domain lookalikes
            if (enrich.domain_reputation && enrich.domain_reputation.length > 0) {
                hasIntel = true;
                enrich.domain_reputation.forEach(dr => {
                    intelContainer.innerHTML += `
                        <div class="p-3 rounded bg-red-950/20 border border-red-800/50 text-xs flex items-center justify-between">
                            <div>
                                <span class="badge-fail text-[10px] px-2 py-0.5 rounded font-bold mr-2">${dr.type}</span>
                                <span class="mono text-white font-semibold">${dr.domain}</span>
                                <p class="text-slate-400 mt-1">${dr.reason}</p>
                            </div>
                            <span class="text-red-400 font-bold uppercase text-[11px]">${dr.severity}</span>
                        </div>
                    `;
                });
            }

            // URLhaus detections
            if (enrich.urls && enrich.urls.length > 0) {
                enrich.urls.forEach(u => {
                    if (u.urlhaus && u.urlhaus.found) {
                        hasIntel = true;
                        intelContainer.innerHTML += `
                            <div class="p-3 rounded bg-red-950/20 border border-red-800/50 text-xs flex items-center justify-between">
                                <div>
                                    <span class="badge-fail text-[10px] px-2 py-0.5 rounded font-bold mr-2">URLHAUS THREAT</span>
                                    <span class="mono text-white truncate max-w-xs inline-block align-middle">${u.url}</span>
                                    <p class="text-slate-400 mt-1">Threat: ${u.urlhaus.threat || 'Malware'} | Tags: ${(u.urlhaus.tags || []).join(', ')}</p>
                                </div>
                                <span class="text-red-400 font-bold uppercase text-[11px]">ACTIVE THREAT</span>
                            </div>
                        `;
                    }
                });
            }

            // AbuseIPDB detections
            if (enrich.ips && enrich.ips.length > 0) {
                enrich.ips.forEach(ipItem => {
                    const aip = ipItem.abuseipdb;
                    if (aip && aip.abuse_score > 0) {
                        hasIntel = true;
                        intelContainer.innerHTML += `
                            <div class="p-3 rounded bg-slate-900 border border-slate-800 text-xs flex items-center justify-between">
                                <div>
                                    <span class="badge-warn text-[10px] px-2 py-0.5 rounded font-bold mr-2">ABUSEIPDB</span>
                                    <span class="mono text-white font-semibold">${ipItem.ip}</span>
                                    <p class="text-slate-400 mt-1">Reports: ${aip.total_reports} | ISP: ${aip.isp || 'Unknown'} | Country: ${aip.country_code || '-'}</p>
                                </div>
                                <span class="text-amber-400 font-bold text-xs">${aip.abuse_score}% Confidence</span>
                            </div>
                        `;
                    }
                });
            }

            if (!hasIntel) {
                intelContainer.innerHTML = '<p class="text-xs text-slate-500 italic">No external threat hits found or API keys unconfigured (domain reputation engine active).</p>';
            }

            // IOCs
            const iocContainer = document.getElementById('iocs-container');
            iocContainer.innerHTML = '';
            const allDefanged = [];

            const renderIocGroup = (title, items) => {
                if (!items || !items.length) return;
                iocContainer.innerHTML += `<div class="text-[10px] font-bold uppercase tracking-wider text-slate-400 mt-2">${title} (${items.length}):</div>`;
                items.forEach(i => {
                    allDefanged.push(i.defanged);
                    iocContainer.innerHTML += `
                        <div class="flex items-center justify-between p-1.5 rounded bg-slate-900 border border-slate-800">
                            <span class="text-slate-300">${i.defanged}</span>
                            <span class="text-slate-500 text-[10px] uppercase">${i.type}</span>
                        </div>
                    `;
                });
            };

            renderIocGroup('IP Addresses', data.iocs.ips);
            renderIocGroup('Domains', data.iocs.domains);
            renderIocGroup('URLs', data.iocs.urls);
            renderIocGroup('File Hashes', data.iocs.hashes);

            document.getElementById('copy-iocs').onclick = () => {
                navigator.clipboard.writeText(allDefanged.join('\\n'));
                alert('Copied ' + allDefanged.length + ' defanged IOCs to clipboard!');
            };

            // Attachments
            const attContainer = document.getElementById('attachments-container');
            document.getElementById('att-count').textContent = data.attachments.length;
            attContainer.innerHTML = '';
            if (!data.attachments.length) {
                attContainer.innerHTML = '<p class="text-xs text-slate-500 italic">No attachments present in email.</p>';
            } else {
                data.attachments.forEach(a => {
                    const deep = a.deep_analysis || {};
                    attContainer.innerHTML += `
                        <div class="p-3 rounded bg-slate-900 border ${deep.is_disguised_executable ? 'border-red-800 bg-red-950/20' : 'border-slate-800'} text-xs">
                            <div class="flex justify-between font-bold text-slate-200 mb-1">
                                <span class="mono">${a.filename}</span>
                                <span class="text-slate-500">${(a.size_bytes / 1024).toFixed(1)} KB</span>
                            </div>
                            <div class="flex items-center space-x-2 text-[11px] text-slate-400 mt-1">
                                <span class="bg-slate-800 px-2 py-0.5 rounded text-indigo-300 font-mono">${deep.detected_format || a.content_type}</span>
                                <span class="text-slate-500">Entropy: ${deep.entropy || 0.0} ${deep.is_high_entropy ? '(Packed/Encrypted)' : ''}</span>
                            </div>
                            ${deep.is_disguised_executable ? `<p class="text-red-400 font-semibold mt-1">⚠️ ${deep.mismatch_reason}</p>` : ''}
                            <div class="text-[10px] text-slate-500 mono mt-1">SHA256: ${a.sha256}</div>
                        </div>
                    `;
                });
            }

            // MITRE ATT&CK
            const mitreContainer = document.getElementById('mitre-container');
            mitreContainer.innerHTML = '';
            if (!data.mitre_attack || !data.mitre_attack.length) {
                mitreContainer.innerHTML = '<p class="text-xs text-slate-500 italic col-span-3">No specific MITRE ATT&CK techniques identified.</p>';
            } else {
                data.mitre_attack.forEach(m => {
                    mitreContainer.innerHTML += `
                        <div class="p-3 rounded bg-slate-900 border border-slate-800 hover:border-indigo-500/50 transition">
                            <div class="flex items-center justify-between mb-1">
                                <span class="text-xs font-mono font-bold text-indigo-400">${m.id}</span>
                                <span class="text-[10px] uppercase font-bold text-slate-400 bg-slate-800 px-2 py-0.5 rounded">${m.tactic}</span>
                            </div>
                            <h4 class="text-xs font-semibold text-white">${m.name}</h4>
                            <p class="text-[11px] text-slate-400 mt-1">${m.evidence}</p>
                        </div>
                    `;
                });
            }

            // Timeline
            const timelineContainer = document.getElementById('timeline-container');
            timelineContainer.innerHTML = '';
            if (!data.timeline || !data.timeline.length) {
                timelineContainer.innerHTML = '<p class="text-xs text-slate-500 italic">No timeline events recorded.</p>';
            } else {
                data.timeline.forEach((tl, idx) => {
                    const dotClass = tl.severity === 'danger' ? 'bg-red-500 ring-4 ring-red-950' : 
                                    (tl.severity === 'warning' ? 'bg-amber-400 ring-4 ring-amber-950' : 
                                    (tl.severity === 'success' ? 'bg-emerald-400 ring-4 ring-emerald-950' : 'bg-slate-400 ring-4 ring-slate-800'));
                    timelineContainer.innerHTML += `
                        <div class="relative">
                            <div class="absolute -left-[31px] top-1.5 w-3 h-3 rounded-full ${dotClass}"></div>
                            <div class="p-3 rounded bg-slate-900 border border-slate-800/80">
                                <div class="flex items-center justify-between mb-1">
                                    <span class="text-xs font-bold text-white">${tl.title}</span>
                                    <span class="text-[10px] font-mono text-slate-400">${tl.timestamp}</span>
                                </div>
                                <span class="inline-block mt-2 text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-400">${tl.badge}</span>
                            </div>
                        </div>
                    `;
                });
            }

            // Wire Case Creation & Report Export
            let currentInvestigationData = data;
            const btnCreateCase = document.getElementById('btn-create-case');
            const caseBtnText = document.getElementById('case-btn-text');
            const btnExportReport = document.getElementById('btn-export-report');

            btnCreateCase.onclick = async () => {
                btnCreateCase.disabled = true;
                caseBtnText.textContent = "Creating Case...";
                try {
                    const res = await fetch('/api/cases', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(currentInvestigationData)
                    });
                    if (!res.ok) throw new Error("Failed to create case");
                    const caseObj = await res.json();
                    
                    caseBtnText.textContent = "Case: " + caseObj.case_id;
                    btnCreateCase.className = "bg-emerald-600 text-white text-xs font-semibold px-3 py-1.5 rounded transition flex items-center space-x-1.5";
                    
                    btnExportReport.href = `/api/cases/${caseObj.case_id}/report`;
                    btnExportReport.classList.remove('hidden');
                    btnExportReport.classList.add('flex');
                    alert(`Incident Case successfully opened: ${caseObj.case_id}!\nYou can now view and download the official audit report.`);
                } catch (e) {
                    alert('Error creating case: ' + e.message);
                    caseBtnText.textContent = "Open Incident Case";
                    btnCreateCase.disabled = false;
                }
            };
        }
    </script>
</body>
</html>
    """
