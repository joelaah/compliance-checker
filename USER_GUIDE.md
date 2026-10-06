# 📘 ComplianceShield — User Guide & Walkthrough

Welcome to **ComplianceShield**, an all-in-one compliance readiness auditor and client-side code security inspector for **SOC 2 Type II**, **ISO/IEC 27001:2022**, **HIPAA**, **GDPR**, **PCI-DSS v4.0**, and **NIST CSF 2.0**.

---

## ⚡ Quick Launch

1. **Double-click** or run:
   ```powershell
   start D:\compliance-checker\index.html
   ```
2. The application opens instantly in your default web browser (Chrome, Edge, Firefox, Safari).
3. **No installation, no npm, and no server required!** Everything runs 100% locally in your browser with zero latency and full privacy.

---

## 🧭 Step-by-Step Walkthrough

### Step 1: Set Up Your Application Scope
* At the top of the dashboard, enter your **Application Name** (e.g., `Acme Cloud Platform`) and optional **Endpoint/Domain** (e.g., `https://app.acme.com`).
* Choose your target environment: **Production**, **Staging**, or **MVP**.
* Click **"Quick Audit"** to perform automated heuristic checks (detects TLS/HTTPS, Git PR approvals, and baseline backups).

---

### Step 2: Try 1-Click Industry Templates (Presets)
If you want to see how compliance looks for different types of businesses, use the **App Template** dropdown in the top bar:
* ☁️ **B2B SaaS Enterprise Platform**: Focuses on SOC 2 Type II, multi-tenant RBAC, and centralized logging.
* 🏥 **Telehealth & Patient Portal**: Focuses on HIPAA Technical Safeguards and Business Associate Agreements (BAAs).
* 💳 **FinTech & Payments API**: Focuses on PCI-DSS v4, cardholder encryption, and vulnerability scanning.
* 🌍 **Global Consumer Web App**: Focuses on GDPR data subject rights (erasure, cookie consent, breach disclosure).

---

### Step 3: Run the Code & Secret Scanner (Finding Hackable Flaws)
Click the **"Code & Secret Scanner"** tab to inspect source code for vulnerabilities hackers look for:
1. **Try the Presets**: Click any preset button to see a real-world vulnerable or secure snippet:
   * **💉 SQL Injection Flaw**: Shows how direct concatenation in SQL allows attackers to bypass login (`' OR 1=1 --`) or dump database tables.
   * **🔑 Hardcoded Keys & Secrets**: Shows how exposed AWS keys, OpenAI tokens, or database passwords leak credentials.
   * **⚡ Dangerous eval / RCE**: Shows how dynamic code evaluation and command injection allow hackers to execute server commands.
   * **🛡️ Clean Secure Code**: Demonstrates safe parameterized queries (`$1, $2`), environment variables, and password hashing (`bcrypt`).
2. **Scan Your Own Code**:
   * Paste any code snippet (JavaScript, TypeScript, Python, SQL, PHP, `.env`) into the editor.
   * Or drag & drop a source file directly into the drop zone.
   * Click **"⚡ Scan Code for Flaws"**.
3. **Review Vulnerability Findings**:
   * Inspect the exact line numbers, severity tags (Critical / High), hacker attack explanations, and **Before vs After secure code fixes**.
4. **Sync with Compliance Matrix**:
   * Click **"🔄 Sync Findings to Compliance Matrix"** to automatically flag relevant compliance controls (e.g., `OPS-01`, `DATA-03`, `IAM-01`) as gaps!

---

### Step 4: Complete the Audit Checklist
Click the **"Audit Checklist"** tab to evaluate controls:
* Use the **Category dropdown** to filter by domain (e.g., *Access & IAM*, *Data & Encryption*, *Audit & Logging*).
* Click any framework card at the top (e.g., **SOC 2**, **HIPAA**, or **GDPR**) to isolate controls for that specific standard.
* For each control card:
  * Click **✓ Compliant** if implemented.
  * Click **✕ Gap** if missing or needs remediation.
  * Click **— Skip** to clear answer.
  * Click **"View Audit Evidence Proof →"** to see what auditors will ask to see (e.g., IAM screenshots, S3 Object Lock, branch protection rules).

---

### Step 5: Review Critical Gaps & Phased Roadmap
* **Critical Gaps Tab**: Lists all non-compliant findings prioritized by severity (High, Medium, Low).
* **Remediation Roadmap Tab**: Provides a 3-phase execution checklist:
  * **Phase 1 (Week 1–2)**: Immediate blockers (MFA, TLS, Backups, Right to Erasure).
  * **Phase 2 (Week 3–4)**: DevSecOps (PR protection, centralized logging, BAAs).
  * **Phase 3 (Week 5–6)**: Formal attestation (Pentesting, DR drills, quarterly access reviews).

---

### Step 6: Generate Legal & Security Policies
Click the **"Policy Generator"** tab to preview and copy pre-written, audit-ready compliance documents:
* 🚨 **Incident Response Plan & 72-Hour Breach Protocol** (SOC 2 CC7.3 & GDPR Art 33)
* 🔑 **Access Control & Multi-Factor Authentication Policy** (SOC 2 CC6.1 & ISO 27001 A.8.5)
* 🗑️ **Data Retention & Right-to-be-Forgotten Policy** (GDPR Art 17)
* 💾 **Business Continuity & Disaster Recovery Plan** (SOC 2 A1.2 & ISO 27001 A.8.14)
* 🤝 **Third-Party Vendor Risk Assessment Policy** (SOC 2 CC9.2)
* 🩺 **HIPAA Business Associate Agreement (BAA) Addendum**

Click **"Copy Markdown"** to copy the policy with your app name and domain filled in!

---

### Step 7: Export the Executive Audit Report
1. Click **"Export Report"** in the top navigation header.
2. View the executive summary with framework readiness scores, control breakdown, and gap register.
3. Click **"Print / Save as PDF"** for a clean, formal document suitable for leadership or auditors.
4. Click **"Download JSON"** to export machine-readable compliance records.

---

## 🔒 Privacy & Offline Capability
* All data is saved locally in your browser's `localStorage`.
* No source code or credentials are ever transmitted over the network.
* Works completely offline without internet connectivity.
