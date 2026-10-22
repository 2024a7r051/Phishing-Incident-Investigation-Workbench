import base64
import os

def get_base64_img(rel_path):
    abs_p = os.path.join("/Users/shivika/Downloads/Project", rel_path)
    if os.path.exists(abs_p):
        with open(abs_p, "rb") as f:
            return f"data:image/png;base64,{base64.b64encode(f.read()).decode('utf-8')}"
    return ""

img_dash = get_base64_img("docs/images/dashboard_overview.png")
img_dossier = get_base64_img("docs/images/threat_dossier.png")
img_results = get_base64_img("docs/images/investigation_results.png")

html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MDC Project Presentation - Automated Phishing Incident Investigation Workbench</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {{
            --bg-dark: #07090e;
            --card-bg: #0f1422;
            --card-border: #1e263d;
            --primary: #6366f1;
            --primary-glow: rgba(99, 102, 241, 0.25);
            --cyan: #38bdf8;
            --red: #f43f5e;
            --green: #10b981;
            --amber: #f59e0b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background-color: var(--bg-dark);
            color: var(--text-main);
            font-family: 'Plus Jakarta Sans', -apple-system, sans-serif;
            overflow-x: hidden;
            display: flex;
            flex-direction: column;
            align-items: center;
            min-height: 100vh;
        }}
        .deck-container {{
            width: 100%;
            max-width: 1200px;
            padding: 24px 20px 80px;
        }}
        .nav-bar {{
            position: sticky;
            top: 12px;
            z-index: 100;
            background: rgba(15, 20, 34, 0.85);
            backdrop-filter: blur(16px);
            border: 1px solid var(--card-border);
            border-radius: 9999px;
            padding: 10px 24px;
            margin-bottom: 24px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        .logo {{
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 800;
            font-size: 14px;
            letter-spacing: 0.5px;
        }}
        .logo span {{ color: var(--cyan); }}
        .nav-controls {{
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .btn-ctrl {{
            background: #1a2238;
            border: 1px solid var(--card-border);
            color: var(--text-main);
            padding: 8px 16px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .btn-ctrl:hover {{
            background: var(--primary);
            border-color: var(--primary);
            transform: translateY(-1px);
        }}
        .btn-live {{
            background: linear-gradient(135deg, #6366f1, #38bdf8);
            border: none;
            color: #fff;
            padding: 8px 18px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            text-decoration: none;
            display: flex;
            align-items: center;
            gap: 6px;
            box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);
        }}
        .btn-live:hover {{
            opacity: 0.95;
            transform: translateY(-1px);
        }}
        .slide {{
            display: none;
            background: var(--card-bg);
            border: 1px solid var(--card-border);
            border-radius: 20px;
            padding: 44px;
            min-height: 640px;
            position: relative;
            box-shadow: 0 20px 50px rgba(0,0,0,0.6);
            animation: fadeIn 0.35s cubic-bezier(0.16, 1, 0.3, 1);
        }}
        .slide.active {{
            display: block;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(12px) scale(0.99); }}
            to {{ opacity: 1; transform: translateY(0) scale(1); }}
        }}
        .slide-tag {{
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 1.5px;
            text-transform: uppercase;
            color: var(--cyan);
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .slide-title {{
            font-size: 28px;
            font-weight: 800;
            color: #fff;
            margin-bottom: 24px;
            letter-spacing: -0.5px;
        }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .grid-3 {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }}
        .grid-4 {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; }}
        .card {{
            background: #141b2d;
            border: 1px solid #232d4b;
            border-radius: 14px;
            padding: 22px;
            position: relative;
        }}
        .card-title {{
            font-size: 15px;
            font-weight: 700;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        .card-text {{
            font-size: 13px;
            color: var(--text-muted);
            line-height: 1.6;
        }}
        .code-box {{
            background: #090c14;
            border: 1px solid #1c243a;
            border-radius: 10px;
            padding: 14px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 11px;
            color: #cbd5e1;
            line-height: 1.5;
            margin-top: 10px;
            overflow-x: auto;
        }}
        .badge {{
            display: inline-block;
            font-size: 10px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 6px;
            text-transform: uppercase;
        }}
        .badge-red {{ background: rgba(244, 63, 94, 0.15); color: var(--red); border: 1px solid rgba(244, 63, 94, 0.3); }}
        .badge-green {{ background: rgba(16, 185, 129, 0.15); color: var(--green); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-cyan {{ background: rgba(56, 189, 248, 0.15); color: var(--cyan); border: 1px solid rgba(56, 189, 248, 0.3); }}
        .badge-amber {{ background: rgba(245, 158, 11, 0.15); color: var(--amber); border: 1px solid rgba(245, 158, 11, 0.3); }}
        .slide-counter {{
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            font-family: 'JetBrains Mono', monospace;
        }}
        .speaker-notes {{
            background: #090d18;
            border-left: 3px solid var(--primary);
            padding: 12px 16px;
            border-radius: 0 8px 8px 0;
            margin-top: 24px;
            font-size: 12px;
            color: #cbd5e1;
        }}
        .speaker-notes strong {{ color: var(--cyan); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; display: block; margin-bottom: 4px; }}
        img.slide-img {{
            width: 100%;
            border-radius: 12px;
            border: 1px solid #232d4b;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        }}
        @media print {{
            .nav-bar {{ display: none; }}
            .slide {{ display: block !important; page-break-after: always; margin-bottom: 20px; }}
        }}
    </style>
</head>
<body>

    <div class="deck-container">
        <!-- Persistent Top Navigation -->
        <div class="nav-bar">
            <div class="logo">
                <i class="fa-solid fa-shield-halved text-indigo-400"></i>
                <div>PHISH<span>BENCH</span> <span style="font-weight:400; color:#64748b; font-size:12px;">| MDC EVALUATION</span></div>
            </div>
            <div class="nav-controls">
                <button class="btn-ctrl" onclick="prevSlide()"><i class="fa-solid fa-chevron-left"></i> Prev</button>
                <span class="slide-counter" id="counter">1 / 10</span>
                <button class="btn-ctrl" onclick="nextSlide()">Next <i class="fa-solid fa-chevron-right"></i></button>
                <button class="btn-ctrl" onclick="window.print()"><i class="fa-solid fa-file-pdf"></i> Print / Save PDF</button>
                <a href="https://phishing-incident-investigation-wor.vercel.app" target="_blank" class="btn-live"><i class="fa-solid fa-arrow-up-right-from-square"></i> Live Prototype</a>
            </div>
        </div>

        <!-- SLIDE 1: TITLE SLIDE -->
        <div class="slide active" id="slide-1">
            <div class="slide-tag"><i class="fa-solid fa-graduation-cap"></i> Major Degree / Course (MDC) Project Evaluation</div>
            <h1 class="slide-title" style="font-size: 40px; line-height: 1.2; margin-bottom: 16px;">
                Automated Phishing Incident<br><span style="color:var(--cyan);">Investigation Workbench</span>
            </h1>
            <p style="font-size: 16px; color: var(--text-muted); max-width: 800px; line-height: 1.6; margin-bottom: 32px;">
                A full-stack, enterprise-grade Security Operations Center (SOC) platform engineered for rapid email forensic triage, anchor text spoof detection, threat intelligence enrichment, and MITRE ATT&CK® mapping.
            </p>

            <div class="grid-3" style="margin-bottom: 30px;">
                <div class="card" style="border-color: rgba(99, 102, 241, 0.4);">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--cyan); font-weight: 700;">Student / Presenter</div>
                    <div style="font-size: 16px; font-weight: 800; color: #fff; margin-top: 4px;">Shivangi Gupta</div>
                </div>
                <div class="card" style="border-color: rgba(56, 189, 248, 0.4);">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--cyan); font-weight: 700;">Specialization Domain</div>
                    <div style="font-size: 16px; font-weight: 800; color: #fff; margin-top: 4px;">Cybersecurity & SOC Forensics</div>
                </div>
                <div class="card" style="border-color: rgba(16, 185, 129, 0.4);">
                    <div style="font-size: 11px; text-transform: uppercase; color: var(--green); font-weight: 700;">Deployment Status</div>
                    <div style="font-size: 16px; font-weight: 800; color: #fff; margin-top: 4px;">Live Global on Vercel Edge</div>
                </div>
            </div>

            <div class="speaker-notes">
                <strong>What to speak for Slide 1:</strong>
                "Good morning/afternoon Sir. Today I am presenting my MDC Project: The Automated Phishing Incident Investigation Workbench. It is a full-stack security platform built to automate the end-to-end investigation of suspicious phishing emails for SOC analysts."
            </div>
        </div>

        <!-- SLIDE 2: PROBLEM STATEMENT -->
        <div class="slide" id="slide-2">
            <div class="slide-tag"><i class="fa-solid fa-triangle-exclamation"></i> Context & Industry Challenges</div>
            <h2 class="slide-title">Problem Statement & Motivation</h2>
            <div class="grid-3">
                <div class="card" style="border-top: 3px solid var(--red);">
                    <div class="card-title" style="color:var(--red);"><i class="fa-solid fa-skull-crossbones"></i> The Attack Vector</div>
                    <p class="card-text">
                        Over <strong>90% of cyber breaches</strong> begin with email phishing. Threat actors employ sophisticated deception like brand typosquatting, IDN homographs, and disguised double extensions that bypass traditional spam filters.
                    </p>
                </div>
                <div class="card" style="border-top: 3px solid var(--amber);">
                    <div class="card-title" style="color:var(--amber);"><i class="fa-solid fa-clock-rotate-left"></i> The Manual Bottleneck</div>
                    <p class="card-text">
                        SOC analysts receive hundreds of alerts daily. Triage requires manually reading raw RFC 822 text files, checking SPF/DKIM records, and querying 5+ disconnected tabs (VirusTotal, URLhaus, AbuseIPDB).
                        <br><br>
                        <strong>Average time per email: 15–20 minutes.</strong>
                    </p>
                </div>
                <div class="card" style="border-top: 3px solid var(--green);">
                    <div class="card-title" style="color:var(--green);"><i class="fa-solid fa-wand-magic-sparkles"></i> The Solution</div>
                    <p class="card-text">
                        An automated investigation workbench that ingests raw <code>.eml</code> files or headers, decomposes components, scans for anchor spoofing and payload entropy, and delivers a complete dossier in <strong>under 2 seconds</strong>.
                    </p>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 2:</strong>
                "Sir, the problem is that phishing is responsible for 90% of breaches, but investigating an alert currently takes an analyst 15 to 20 minutes across multiple separate tools. Our system automates this entire forensic workflow to under 2 seconds."
            </div>
        </div>

        <!-- SLIDE 3: OBJECTIVES -->
        <div class="slide" id="slide-3">
            <div class="slide-tag"><i class="fa-solid fa-bullseye"></i> Scope & Goals</div>
            <h2 class="slide-title">Project Objectives & Scope</h2>
            <div class="grid-2">
                <div class="card">
                    <div class="card-title"><span class="badge badge-cyan">01</span> Email Header Forensics & Route Tracing</div>
                    <p class="card-text">Parse RFC 822 multipart MIME structures, reconstruct chronological relay hops across <code>Received:</code> headers, and evaluate SPF, DKIM, and DMARC alignment status.</p>
                </div>
                <div class="card">
                    <div class="card-title"><span class="badge badge-cyan">02</span> Anchor Text Spoofing & Hyperlink Audit</div>
                    <p class="card-text">Audit all HTML anchor tags to catch visual spoofing where display text says <code>paypal.com</code> but the destination points to an unauthorized external IP host.</p>
                </div>
                <div class="card">
                    <div class="card-title"><span class="badge badge-cyan">03</span> Deep Binary & Attachment Inspection</div>
                    <p class="card-text">Inspect magic bytes (detecting <code>MZ</code> PE executables, PDFs, ZIPs), flag disguised double extensions (<code>.pdf.exe</code>), and compute Shannon entropy for packed malware.</p>
                </div>
                <div class="card">
                    <div class="card-title"><span class="badge badge-cyan">04</span> MITRE ATT&CK® & Audit Reporting</div>
                    <p class="card-text">Correlate indicators with official MITRE Enterprise techniques (T1566, T1036, T1059), generate an incident timeline, and export self-contained HTML audit reports.</p>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 3:</strong>
                "Our project objectives focus on 4 pillars: automated header route tracing, detecting hyperlink anchor deception, deep binary magic-byte inspection of attachments, and generating standardized MITRE ATT&CK audit reports."
            </div>
        </div>

        <!-- SLIDE 4: ARCHITECTURE & METHODOLOGY -->
        <div class="slide" id="slide-4">
            <div class="slide-tag"><i class="fa-solid fa-diagram-project"></i> Pipeline Engineering</div>
            <h2 class="slide-title">System Architecture & Methodology</h2>
            <div class="grid-4">
                <div class="card" style="border-color: rgba(99, 102, 241, 0.4);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--primary);">PHASE 1</div>
                    <div class="card-title" style="margin-top: 4px;">Ingestion & Parsing</div>
                    <p class="card-text">
                        • Raw RFC 822 / .eml input<br>
                        • MIME multipart decoding<br>
                        • RFC 2047 word decoder<br>
                        • Body & HTML separation
                    </p>
                </div>
                <div class="card" style="border-color: rgba(56, 189, 248, 0.4);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--cyan);">PHASE 2</div>
                    <div class="card-title" style="margin-top: 4px;">Analytical Forensics</div>
                    <p class="card-text">
                        • Hop-by-hop relay tracing<br>
                        • SPF/DKIM/DMARC audit<br>
                        • Anchor spoof detection<br>
                        • Magic bytes & Entropy
                    </p>
                </div>
                <div class="card" style="border-color: rgba(244, 63, 94, 0.4);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--red);">PHASE 3</div>
                    <div class="card-title" style="margin-top: 4px;">Threat Intelligence</div>
                    <p class="card-text">
                        • Levenshtein lookalikes<br>
                        • URLhaus active malware<br>
                        • AbuseIPDB abuse scores<br>
                        • VirusTotal multi-scanner
                    </p>
                </div>
                <div class="card" style="border-color: rgba(16, 185, 129, 0.4);">
                    <div style="font-size: 11px; font-weight: 700; color: var(--green);">PHASE 4</div>
                    <div class="card-title" style="margin-top: 4px;">Triage & Audit</div>
                    <p class="card-text">
                        • 0-100 Weighted scoring<br>
                        • MITRE ATT&CK Matrix<br>
                        • Incident timeline chain<br>
                        • Case management & reports
                    </p>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 4:</strong>
                "Here is our 4-stage pipeline: Stage 1 ingests the raw email. Stage 2 executes byte-level forensic analysis. Stage 3 enriches IOCs with live threat intel. Stage 4 maps the attack to MITRE ATT&CK and outputs an audit report."
            </div>
        </div>

        <!-- SLIDE 5: CORE ALGORITHMS -->
        <div class="slide" id="slide-5">
            <div class="slide-tag"><i class="fa-solid fa-code"></i> Mathematical & Security Logic</div>
            <h2 class="slide-title">Key Algorithms Embedded in Code</h2>
            <div class="grid-2">
                <div class="card">
                    <div class="card-title" style="color:var(--cyan);"><i class="fa-solid fa-link-slash"></i> Anchor Text Spoofing Detector</div>
                    <p class="card-text">Compares the domain token in visible link text against the actual destination hostname:</p>
                    <div class="code-box">claimed_domain = extract_domain(display_text)
actual_domain = urlparse(href).netloc
if claimed_domain != actual_domain:
    return True # ANCHOR_TEXT_SPOOF (+30 pts)</div>
                </div>
                <div class="card">
                    <div class="card-title" style="color:var(--red);"><i class="fa-solid fa-chart-line"></i> Shannon Entropy Calculation</div>
                    <p class="card-text">Measures binary byte randomness ($0.0$ to $8.0$). Payloads exceeding $7.1$ indicate packing/encryption:</p>
                    <div class="code-box">H(X) = - Σ (P(x_i) * log2(P(x_i)))
if entropy > 7.1:
    flag_packed_payload() # Malware evasion</div>
                </div>
                <div class="card">
                    <div class="card-title" style="color:var(--primary);"><i class="fa-solid fa-magnifying-glass"></i> Levenshtein Distance Lookalikes</div>
                    <p class="card-text">Calculates minimum edit operations to detect brand impersonation completely offline:</p>
                    <div class="code-box">dist = levenshtein_distance(domain, brand)
if 1 <= dist <= 2 or brand in domain:
    flag_typosquatting() # e.g. update-paypal.cc</div>
                </div>
                <div class="card">
                    <div class="card-title" style="color:var(--green);"><i class="fa-solid fa-gauge-high"></i> Weighted Risk Scoring Engine</div>
                    <p class="card-text">Point-based evaluation with strict security ceilings:</p>
                    <div class="code-box">Score = SPF_fail(25) + DKIM_fail(20) + Anchor_spoof(30)
        + Executable(35) + URLhaus_hit(40)
Verdict: >= 70 MALICIOUS | >= 35 SUSPICIOUS | < 35 BENIGN</div>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 5:</strong>
                "We didn't just wrap APIs; we implemented real algorithms. Levenshtein distance detects brand typosquatting offline, and Shannon entropy calculates whether an attachment is encrypted or packed to bypass antiviruses."
            </div>
        </div>

        <!-- SLIDE 6: PROTOTYPE INTERFACE -->
        <div class="slide" id="slide-6">
            <div class="slide-tag"><i class="fa-solid fa-desktop"></i> Demonstration & Supporting Material</div>
            <h2 class="slide-title">Working Prototype: SOC Analyst Workbench</h2>
            <div class="grid-2" style="align-items: center;">
                <div>
                    <img src="{img_dash}" class="slide-img" alt="Dashboard Screenshot">
                </div>
                <div class="card">
                    <div class="card-title" style="color:var(--cyan);"><i class="fa-solid fa-sliders"></i> User Interface Capabilities</div>
                    <p class="card-text" style="font-size: 14px;">
                        • <strong>Dual Ingestion:</strong> Drag-and-drop <code>.eml</code> / <code>.msg</code> files or paste raw RFC 822 text directly.<br><br>
                        • <strong>1-Click Demo Sample:</strong> Pre-loaded realistic phishing email for instant evaluation without external test files.<br><br>
                        • <strong>Automated Defanging:</strong> Replaces <code>http://</code> with <code>hxxp://</code> and brackets dots (<code>192[.]168[.]1[.]1</code>) to prevent accidental analyst clicks.<br><br>
                        • <strong>Globally Accessible:</strong> Fully responsive, high-contrast dark theme deployed on Vercel.
                    </p>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 6:</strong>
                "This is the live prototype interface. Analysts have two ways to input data: drag and drop an .eml file, or paste raw headers. It also features a one-click demo button for quick evaluation."
            </div>
        </div>

        <!-- SLIDE 7: RESULTS DEMO -->
        <div class="slide" id="slide-7">
            <div class="slide-tag"><i class="fa-solid fa-chart-pie"></i> Evaluation & Live Output</div>
            <h2 class="slide-title">Automated Investigation Results Output</h2>
            <div class="grid-2" style="align-items: center;">
                <div>
                    <img src="{img_results}" class="slide-img" alt="Investigation Results">
                </div>
                <div class="card" style="border-color: rgba(244, 63, 94, 0.4);">
                    <div class="card-title" style="color:var(--red);"><i class="fa-solid fa-triangle-exclamation"></i> Real Sample Detection Findings</div>
                    <p class="card-text" style="font-size: 13px;">
                        • <strong>Verdict & Score:</strong> <span class="badge badge-red">100 / 100 MALICIOUS</span><br><br>
                        • <strong>Authentication:</strong> SPF = FAIL, DKIM = FAIL, DMARC = FAIL<br><br>
                        • <strong>Anchor Text Spoof:</strong> Text says <code>paypal.com/verify</code> but target URL is <code>194.87.139.12</code>.<br><br>
                        • <strong>Binary Detection:</strong> <code>Invoice_OCT_2026.exe</code> flagged via <code>MZ</code> header bytes.<br><br>
                        • <strong>Typosquatting:</strong> Flagged <code>update-paypal-security.cc</code> as brand impersonation.<br><br>
                        • <strong>Triage Speed:</strong> Total processing executed in <strong>1.1 seconds</strong>.
                    </p>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 7:</strong>
                "Here are the live results on a real test sample: The system caught the anchor spoof where paypal.com actually directed to an unauthorized IP, caught the executable payload, and assigned an accurate 100/100 Malicious verdict."
            </div>
        </div>

        <!-- SLIDE 8: MITRE & TIMELINE -->
        <div class="slide" id="slide-8">
            <div class="slide-tag"><i class="fa-solid fa-shield-virus"></i> Industry Framework Alignment</div>
            <h2 class="slide-title">MITRE ATT&CK Mapping & Incident Timeline</h2>
            <div class="grid-2">
                <div class="card">
                    <div class="card-title" style="color:var(--primary);"><i class="fa-solid fa-network-wired"></i> MITRE ATT&CK® Enterprise Techniques</div>
                    <p class="card-text">
                        Every incident finding is automatically mapped to standardized tactics & techniques:
                    </p>
                    <div style="margin-top: 10px; font-size: 12px; line-height: 1.8;">
                        • <span class="badge badge-cyan">T1566.001</span> Spearphishing Attachment (Initial Access)<br>
                        • <span class="badge badge-cyan">T1566.002</span> Spearphishing Link (Initial Access)<br>
                        • <span class="badge badge-cyan">T1036.005</span> Masquerading Brand Name (Defense Evasion)<br>
                        • <span class="badge badge-cyan">T1586.002</span> Compromise Email Accounts (Resource Dev)<br>
                        • <span class="badge badge-cyan">T1204</span> User Execution of Malicious Link / File<br>
                        • <span class="badge badge-cyan">T1059</span> Command & Scripting Interpreter (Execution)
                    </div>
                </div>
                <div class="card">
                    <div class="card-title" style="color:var(--cyan);"><i class="fa-solid fa-timeline"></i> Chronological Chain of Custody</div>
                    <p class="card-text">
                        Reconstructs the complete lifecycle sequence for legal and compliance auditability:
                    </p>
                    <div style="margin-top: 10px; font-size: 12px; line-height: 1.8;">
                        <strong>1. ORIGIN:</strong> Dispatched from untrusted server (185.220.101.45)<br>
                        <strong>2. RELAY:</strong> Hop #1 processed by gateway<br>
                        <strong>3. AUTH:</strong> SPF, DKIM, and DMARC evaluated<br>
                        <strong>4. PAYLOAD:</strong> Hyperlinks extracted and anchor tested<br>
                        <strong>5. BINARY:</strong> Attachment decoded, hash and entropy checked<br>
                        <strong>6. THREAT INTEL:</strong> Lookalike & URLhaus correlation<br>
                        <strong>7. VERDICT:</strong> Final risk verdict and case persistence
                    </div>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 8:</strong>
                "Our workbench maps all findings to the global MITRE ATT&CK matrix so security teams know the attacker's tactics. It also creates a chronological timeline from origin server to the final verdict."
            </div>
        </div>

        <!-- SLIDE 9: PROGRESS & VERIFICATION -->
        <div class="slide" id="slide-9">
            <div class="slide-tag"><i class="fa-solid fa-list-check"></i> Project Milestones</div>
            <h2 class="slide-title">Progress, Verification & Milestones</h2>
            <div style="display:flex; flex-direction:column; gap:12px;">
                <div class="card" style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px;">
                    <div>
                        <div style="font-weight:700; color:#fff;">Phase 1: Ingestion & Core Forensics Engine</div>
                        <div style="font-size:12px; color:var(--text-muted);">RFC 822 parsing, hop tracing, SPF/DKIM/DMARC checks, anchor spoofing, and IOC defanging.</div>
                    </div>
                    <span class="badge badge-green">100% COMPLETED</span>
                </div>
                <div class="card" style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px;">
                    <div>
                        <div style="font-weight:700; color:#fff;">Phase 2: Threat Intelligence & Reputation Enrichment</div>
                        <div style="font-size:12px; color:var(--text-muted);">Levenshtein distance typosquatting engine, URLhaus malware feeds, AbuseIPDB integration.</div>
                    </div>
                    <span class="badge badge-green">100% COMPLETED</span>
                </div>
                <div class="card" style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px;">
                    <div>
                        <div style="font-weight:700; color:#fff;">Phase 3: Deep Inspection & Timeline Reconstruction</div>
                        <div style="font-size:12px; color:var(--text-muted);">Magic bytes inspection (MZ/PDF/ZIP), Shannon entropy analysis, and MITRE ATT&CK mapping.</div>
                    </div>
                    <span class="badge badge-green">100% COMPLETED</span>
                </div>
                <div class="card" style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px;">
                    <div>
                        <div style="font-weight:700; color:#fff;">Phase 4: Case Management & Audit Reporting</div>
                        <div style="font-size:12px; color:var(--text-muted);">Case persistence (CASE-XXXXXXXX), analyst note logging, and standalone HTML audit report generator.</div>
                    </div>
                    <span class="badge badge-green">100% COMPLETED</span>
                </div>
                <div class="card" style="display:flex; justify-content:space-between; align-items:center; padding:16px 20px;">
                    <div>
                        <div style="font-weight:700; color:#fff;">Automated Verification & Global Deployment</div>
                        <div style="font-size:12px; color:var(--text-muted);">100% passing test suite in pytest, deployed globally on Vercel Serverless with GitHub CI/CD.</div>
                    </div>
                    <span class="badge badge-green">100% COMPLETED</span>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 9:</strong>
                "Regarding project progress: All 4 planned phases have been 100% completed, fully tested with automated pytest suites, and successfully deployed to the cloud."
            </div>
        </div>

        <!-- SLIDE 10: CONCLUSION & DEMO -->
        <div class="slide" id="slide-10">
            <div class="slide-tag"><i class="fa-solid fa-flag-checkered"></i> Evaluation Conclusion</div>
            <h2 class="slide-title">Conclusion & Live Demonstration Links</h2>
            <div class="grid-2">
                <div class="card">
                    <div class="card-title" style="color:var(--cyan);"><i class="fa-solid fa-award"></i> Key Deliverables Summary</div>
                    <p class="card-text" style="font-size: 13px; line-height: 1.8;">
                        • <strong>Solves Real-World Problem:</strong> Reduces email triage from 15 minutes to < 2 seconds.<br>
                        • <strong>High Engineering Standards:</strong> Clean modular architecture with zero external dependency for core lookalike algorithms.<br>
                        • <strong>Operational Readiness:</strong> Equipped with case management, audit report export, and one-click defanged IOC sharing.<br>
                        • <strong>Full Documentation:</strong> Includes complete Word specification (.docx), GitHub repo, and live URL.
                    </p>
                </div>
                <div class="card" style="border-color: rgba(99, 102, 241, 0.5);">
                    <div class="card-title" style="color:var(--primary);"><i class="fa-solid fa-globe"></i> Live Resources & Links</div>
                    <p class="card-text" style="font-size: 13px; line-height: 1.8;">
                        🌐 <strong>Live Cloud Web App:</strong><br>
                        <a href="https://phishing-incident-investigation-wor.vercel.app" target="_blank" style="color:var(--cyan); text-decoration:underline;">https://phishing-incident-investigation-wor.vercel.app</a><br><br>
                        📂 <strong>GitHub Repository:</strong><br>
                        <a href="https://github.com/Shivangi-gupta-loo1/Phishing-Incident-Investigation-Workbench" target="_blank" style="color:var(--cyan); text-decoration:underline;">github.com/Shivangi-gupta-loo1/Phishing-Incident-Investigation-Workbench</a><br><br>
                        📄 <strong>Word Documentation File:</strong><br>
                        <code>Phishing_Investigation_Workbench_Documentation.docx</code>
                    </p>
                </div>
            </div>
            <div class="speaker-notes">
                <strong>What to speak for Slide 10:</strong>
                "Thank you Sir. The platform is live and accessible online. I would now like to give a quick 1-minute live demonstration of the website. I welcome any questions."
            </div>
        </div>

    </div>

    <script>
        let currentSlide = 1;
        const totalSlides = 10;

        function updateSlide(n) {{
            document.querySelectorAll('.slide').forEach(s => s.classList.remove('active'));
            const target = document.getElementById('slide-' + n);
            if (target) {{
                target.classList.add('active');
                document.getElementById('counter').innerText = n + ' / ' + totalSlides;
            }}
        }}

        function nextSlide() {{
            if (currentSlide < totalSlides) {{
                currentSlide++;
                updateSlide(currentSlide);
            }}
        }}

        function prevSlide() {{
            if (currentSlide > 1) {{
                currentSlide--;
                updateSlide(currentSlide);
            }}
        }}

        document.addEventListener('keydown', (e) => {{
            if (e.key === 'ArrowRight' || e.key === ' ') {{
                nextSlide();
            }} else if (e.key === 'ArrowLeft') {{
                prevSlide();
            }}
        }});
    </script>
</body>
</html>
"""

with open("/Users/shivika/Downloads/Project/presentation.html", "w") as f:
    f.write(html_content)

print("Created presentation.html successfully!")
