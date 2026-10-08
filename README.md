# 🛡️ ComplianceShield — Multi-Framework Audit Readiness Engine & SAST Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Security-OWASP%20Top%2010%20%7C%20CWE-00f0ff?style=for-the-badge&logo=shield" alt="OWASP & CWE">
  <img src="https://img.shields.io/badge/Compliance-SOC%202%20%7C%20ISO%2027001%20%7C%20HIPAA%20%7C%20GDPR%20%7C%20PCI--DSS-10b981?style=for-the-badge&logo=securityscorecard" alt="Regulatory Frameworks">
  <img src="https://img.shields.io/badge/Architecture-100%25%20Client--Side%20SAST-a855f7?style=for-the-badge&logo=javascript" alt="Client Side SAST">
  <img src="https://img.shields.io/badge/Responsive-Mobile%20%26%20Desktop%20Ready-f59e0b?style=for-the-badge&logo=responsive" alt="Responsive">
  <img src="https://img.shields.io/badge/Zero%20Dependencies-Pure%20Vanilla%20Web-3b82f6?style=for-the-badge&logo=html5" alt="Zero Dependencies">
</p>

---

## 📌 Executive Summary

**ComplianceShield** is an audit readiness platform and client-side **Static Application Security Testing (SAST)** scanner. It enables engineering, DevSecOps, and security teams to evaluate web applications against **SOC 2 Type II**, **ISO/IEC 27001:2022**, **HIPAA**, **GDPR**, **PCI-DSS v4.0**, and **NIST CSF 2.0**—while actively scanning code for exploitable vulnerabilities like **SQL Injection (database hijacking)**, **hardcoded cloud secrets/API keys**, **remote code execution sinks (`eval`)**, and **cryptographic weaknesses**.

Built from the ground up with **zero third-party dependencies**, **zero server data transmission**, and **100% offline privacy**, it bridges the critical gap between software engineering codebases and certified compliance attestation.

---

## 🌟 Key Highlights for Engineering Leaders & Recruiters

* 🎯 **Full Regulatory Cross-Mapping**: Unified security matrix cross-referencing 6 enterprise standards simultaneously without redundant questionnaires.
* ⚡ **Client-Side SAST Engine**: In-browser heuristic regex scanner detecting OWASP Top 10 vulnerabilities and high-entropy secret leaks in real-time.
* 🔒 **Air-Gapped Privacy**: Executes entirely in browser memory (`localStorage` persistence). Proprietary source code and API credentials are **never sent to external servers**.
* 📋 **Audit Evidence Playbook**: Identifies exact artifacts certified auditors require (e.g., AWS IAM policies, S3 Object Lock compliance modes, GitHub branch protections, signed BAAs).
* 📑 **One-Click Policy & Report Generator**: Instant generation of audit documents (Incident Response Plans, BCDR, GDPR Erasure) with formatted executive **Print-to-PDF** summaries.
* 📱 **Mobile & Desktop Responsive Design**: Touch-optimized interface featuring high-contrast cybersecurity ergonomics, glassmorphic HUDs, and dynamic SVG gauges.

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    subgraph Inputs ["Input Layer"]
        A[User Source Code & .env] --> D[Client-Side SAST Engine]
        B[Application Domain & Stack Heuristics] --> E[Compliance Heuristic Engine]
        C[Industry Preset Profiles] --> F[Control Assessment Matrix]
    end

    subgraph CoreEngine ["ComplianceShield Analysis Core"]
        D -->|CWE-89, CWE-798, CWE-94| G[Vulnerability Scoring & Severity Classifier]
        E -->|TLS, Backups, PR Policies| F
        F --> H[Dynamic Multi-Framework Readiness Calculator]
        G -->|Auto-Sync Findings| F
    end

    subgraph Frameworks ["Supported Standards"]
        H --> F1[SOC 2 Type II]
        H --> F2[ISO/IEC 27001:2022]
        H --> F3[HIPAA Security & Privacy]
        H --> F4[GDPR EU/UK]
        H --> F5[PCI-DSS v4.0]
        H --> F6[NIST CSF 2.0]
    end

    subgraph Outputs ["Actionable Outputs"]
        H --> O1[Executive Audit Report - PDF & JSON]
        H --> O2[3-Phase Remediation Roadmap]
        H --> O3[Legal & Security Policy Templates]
    end
```

---

## 🔍 Core Capabilities

### 1. Static Code Security & Secret Scanner (Client-Side SAST)
Detects dangerous coding patterns before deployment or third-party audits:

| Category | Attack Vector & Hacker Threat | Detection Rule / CWE | Remediation Output |
| :--- | :--- | :--- | :--- |
| **SQL Injection (SQLi)** | Attackers inject `' OR 1=1 --` or `UNION SELECT` to bypass authentication, hijack database privileges, or dump confidential tables. | **CWE-89** / OWASP A03:2021 | Parameterized queries (`$1, $2` or `?`) and ORM prepared statement replacements. |
| **Cloud Secrets & API Keys** | Bots scan public commits to steal credentials, spawn unauthorized crypto miners, or access AWS/DB clusters. | **CWE-798** / OWASP A07:2021 | Automated detection of AWS `AKIA...`, OpenAI `sk-...`, GitHub tokens `ghp_...`, and DB URLs (`postgres://user:pass@host`). |
| **Remote Code Execution (RCE)** | Attackers supply command separators (`;`, `|`) to execute arbitrary host commands or reverse shells. | **CWE-95 / CWE-78** | Flagging `eval()`, `Function()`, and `child_process.exec()` with sanitization fixes. |
| **Cross-Site Scripting (XSS)** | Injection of malicious scripts that steal authorization cookies and session tokens. | **CWE-79** / OWASP A03:2021 | Deprecation of `innerHTML` / `dangerouslySetInnerHTML` in favor of sanitized text content. |
| **Broken Cryptography** | Fast rainbow table cracking of password databases. | **CWE-328** / OWASP A02:2021 | Enforcing salted hashes (`bcrypt`, `Argon2id`) over deprecated MD5/SHA-1. |
| **COPPA & Minor Age Gating** | Collecting PII from minors under 13/16/18 without neutral age verification or parental consent triggers massive civil penalties. | **CWE-359** / FTC COPPA 16 CFR § 312 | Neutral Date of Birth (DOB) gating on auth/signup flows, parental consent capture, and blocking auto-profiling of children. |
| **Google Fonts Runtime Leaks** | Dynamic fetching of Google Fonts transmits European users' IP addresses to foreign servers without consent (Landgericht München ruling). | **CWE-359** / GDPR Art 6(1)(f) | Disabling Flutter runtime fetching (`allowRuntimeFetching = false`), local TTF bundling in `assets/`, or web `@font-face` self-hosting. |
| **Session Replay Wiretap Risk** | Session recording tools (FullStory, LogRocket, Smartlook, Clarity) intercept keystrokes and user sessions without prior opt-in consent. | **CWE-359** / PA & FL Wiretap Acts | Requiring explicit cookie banner consent prior to initialization and enforcing full DOM/input masking (`maskAllInputs: true`). |
| **Commercial Email Non-Compliance** | Dispatching promotional emails without automated one-click unsubscribe links and physical postal addresses violates anti-spam laws. | **CWE-359** / CAN-SPAM, CASL, Spam Act | Adding `{{unsubscribe_url}}` / `List-Unsubscribe` headers and valid physical corporate postal address to all email dispatch routines. |

### 2. Global Jurisdictional Readiness Engine ("Can It Be Launched Here?")
Analyzes code findings and compliance gaps against sovereign privacy frameworks to determine whether an application can legally launch:

* **Jurisdiction Database**: Evaluates **12 global legal authorities** and **46+ sovereign countries/territories** (EU/EEA 30 nations, US Federal, US California, US PA/FL Wiretap, India, UK, Canada, Australia, Brazil, China, Japan, Saudi Arabia).
* **Automated Verdict Classification**:
  * 🟢 **Allowed / Ready**: All statutory requirements met; zero legal blockers detected.
  * 🟡 **Restricted**: Permitted with operational warnings (e.g. cookie consent or data retention gaps).
  * 🔴 **Blocked**: Active legal blockers detected (e.g. illegal IP leaks, unconsented wiretapping, missing child age gates).
* **Statutory Citations & Remediation**: Every blocked country card displays the exact governing statute, potential statutory fines (e.g., CASL $10M CAD, GDPR €20M / 4%, DPDP ₹250 Cr, FTC $51,744/violation), detailed legal reasoning, and line-level code fixes.
* **Country Search & Filter**: Search by any country name (e.g., *Germany*, *India*, *Canada*, *Japan*) or filter by status (*All*, *Ready*, *Restricted*, *Blocked*).

### 3. Flutter & Project Repository Bundle Scanner
* **Folder & Multi-File Upload**: Drag & drop or browse full project directories (`webkitdirectory`) to scan entire mobile or web repositories at once.
* **Multi-Language Support**: Scans Dart (`.dart`), JavaScript (`.js`), TypeScript (`.ts`), HTML (`.html`), Python (`.py`), and configuration files.
* **1-Click Presets**: Pre-loaded test cases for COPPA, Google Fonts, Session Replay, Commercial Email, and complete multi-file Flutter app bundles.

### 4. Multi-Framework Regulatory Coverage
Cross-maps controls across the world's most critical certifications:
* **SOC 2 Type II**: Trust Services Criteria (CC6 Access, CC7 Monitoring, CC8 Change Management, A1 Availability).
* **ISO/IEC 27001:2022**: Modern ISMS Annex A Controls (A.5 Organizational, A.8 Technological, A.8.24 Cryptography).
* **HIPAA Security & Privacy Rule**: Technical Safeguards (§164.312), Administrative Safeguards (§164.308), and Business Associate Agreements (BAAs).
* **GDPR (EU/UK)**: Article 17 (Right to Erasure), Article 20 (Data Portability), Article 32 (Security of Processing), and 72-Hour Breach Notification.
* **PCI-DSS v4.0**: Cardholder data encryption at rest (AES-256), TLS 1.2+ in transit, MFA, and vulnerability scanning.
* **NIST CSF 2.0**: Govern, Identify, Protect, Detect, Respond, and Recover tiers.

### 5. Pre-Configured Industry Profiles (1-Click Demo)
* ☁️ **B2B SaaS Enterprise Platform**: Focuses on SOC 2 Type II, multi-tenant RBAC, and centralized logging.
* 🏥 **Telehealth & Patient Portal**: Focuses on HIPAA Technical Safeguards and sub-processor BAAs.
* 💳 **FinTech & Payments API**: Focuses on PCI-DSS v4, cardholder encryption, and vulnerability scanning.
* 🌍 **Global Consumer Web App**: Focuses on GDPR data subject rights (erasure, cookie opt-in, breach disclosure).

### 6. Audit-Ready Policy Template Generator
Generates customized, markdown-formatted compliance policies with 1-click clipboard copy:
* 🚨 **Incident Response Plan & 72-Hour Breach Protocol** (SOC 2 CC7.3 & GDPR Art 33)
* 🔑 **Access Control & Multi-Factor Authentication Policy** (SOC 2 CC6.1 & ISO 27001 A.8.5)
* 🗑️ **Data Retention & Right-to-be-Forgotten Policy** (GDPR Art 17)
* 💾 **Business Continuity & Disaster Recovery (BCDR) Plan** (SOC 2 A1.2 & ISO 27001 A.8.14)
* 🤝 **Third-Party Vendor Risk Assessment Policy** (SOC 2 CC9.2)
* 🩺 **HIPAA Business Associate Agreement (BAA) Addendum**

---

## 🚀 Quick Start & Installation

No installations, build steps, or servers required. Runs natively in any modern web browser.

### Option 1: Direct File Launch
```powershell
start D:\compliance-checker\index.html
```

### Option 2: Run via Local Static Server
```bash
cd D:\compliance-checker
# Python 3
python -m http.server 3000

# or Node.js
npx serve .
```
Visit `http://localhost:3000` in your browser.

---

## 📂 Project Structure

```text
D:\compliance-checker\
├── index.html        # Semantic HTML5 application shell, HUD widgets & modals
├── styles.css        # Responsive dark cybersecurity design system (Vanilla CSS)
├── app.js            # SAST regex engine, compliance matrices & policy generator
├── USER_GUIDE.md     # In-depth end-user walkthrough and auditor guide
└── README.md         # Architecture, technical overview & developer specs
```

---

## 🛠️ Technology Stack

* **Frontend Architecture**: Pure Semantic HTML5 & Modern Vanilla JavaScript (ES6+ Modules & Classes)
* **Design & Styling**: Custom Vanilla CSS3 featuring custom properties, Flexbox/Grid layouts, glassmorphism, and responsive breakpoints
* **Typography**: Google Fonts (*Plus Jakarta Sans* & *JetBrains Mono*)
* **Persistence Layer**: Browser `localStorage` API for state retention
* **Code Security Analysis**: Client-side regex tokenization and AST-style pattern matching

---

## 👨‍💻 Author & Engineering Highlights

This project demonstrates core competencies in:
* **Application Security (AppSec) & DevSecOps**: Static code analysis rule construction, vulnerability triage, and OWASP mitigation.
* **Governance, Risk & Compliance (GRC) Engineering**: Regulatory cross-mapping across enterprise standards.
* **Modern Frontend Architecture**: Zero-dependency, performant, mobile-first design with accessible user experiences.
* **Data Privacy**: Client-side execution ensuring compliance with sensitive proprietary codebases.

---

## 📄 License
This project is open-source under the [MIT License](LICENSE).
