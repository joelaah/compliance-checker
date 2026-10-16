# Regulatory Compliance Policy: GDPR & Global Data Privacy

**Identifier**: `POL-GDPR-PRIVACY-V2`  
**Standard**: General Data Protection Regulation (EU) 2016/679, UK GDPR, California CCPA/CPRA, US COPPA (15 U.S.C. §§ 6501-6506), India DPDP Act 2023  
**Classification**: Mandatory Legal Baseline  
**Enforcement Authority**: European Data Protection Board (EDPB), FTC, California Privacy Protection Agency (CPPA)

---

## 1. Scope & Objective
This policy governs data privacy, user tracking, consent acquisition, international data transfer boundaries, and child safety across all client applications (Flutter Web, iOS, Android), backend APIs, database systems, and telemetry services.

---

## 2. Mandatory Regulatory Articles & Controls

### Article 6: Lawfulness of Processing & Prior Consent
- **Clause 6(1)(a)**: Data processing requires unambiguous, affirmative opt-in consent from the data subject prior to data transmission.
- **Enforcement Rule**: Telemetry, analytics, and third-party tracking SDKs (e.g., LogRocket, FullStory, Hotjar, Microsoft Clarity) MUST NOT be initialized without explicit prior opt-in consent.
- **Class Action Risk**: Pennsylvania Wiretap Act, California CIPA, and Florida Security of Communications Act mandate statutory damages between $1,000 and $5,000 per violation for unconsented real-time session capture.

### Article 8: Child Protection & Age Verification (COPPA Alignment)
- **Clause 8(1)**: Where information society services are offered directly to a child, processing is lawful only if the child is at least 16 years old (or national derogations down to 13 years old), unless verifiable parental consent (VPC) is obtained.
- **COPPA & India DPDP Mandate**: Any user registration, signup, or authentication flow MUST incorporate a neutral age gate prior to credential ingestion.
- **Penalty**: FTC fines up to $51,744 per violation under US COPPA; up to ₹250 Crore under India DPDP Act 2023 Section 9; up to €20,000,000 or 4% of total worldwide annual turnover under EU GDPR.

### Article 17: Right to Erasure ("Right to be Forgotten")
- **Clause 17(1)**: The data subject has the right to obtain the erasure of personal data without undue delay.
- **Technical Requirement**: User database schemas must support cascading deletions or hard anonymization upon account termination. Orphaned tracking records violate this requirement.

### Article 25: Data Protection by Design and by Default
- **Clause 25(1)**: Technical and organizational measures must be implemented to minimize data collection and encrypt personal identifying information (PII).
- **Technical Requirement**: Client storage mechanisms such as Flutter `SharedPreferences`, browser `localStorage`, or unencrypted caches MUST NOT store plain authentication tokens, passwords, or PII. Encrypted Keystore/Keychain (`flutter_secure_storage`) is mandatory.

### Articles 44-49: International Transfers & Dynamic IP Leaks (Schrems II)
- **Precedent**: Munich Regional Court (Landgericht München I) Case Az. 3 O 17493/20.
- **Enforcement Rule**: Dynamic runtime fetching of external web fonts (e.g., Google Fonts via `fonts.googleapis.com` or `GoogleFonts.*` in Flutter without bundled assets) transmits the user's dynamic IP address and browser fingerprint to US-based server infrastructure without valid transfer mechanisms (SCCs) or consent.
- **Remediation**: Font assets MUST be bundled locally in `pubspec.yaml` or self-hosted in static assets, and `GoogleFonts.config.allowRuntimeFetching = false;` must be declared at application initialization.

---

## 3. Commercial Electronic Messaging (CAN-SPAM, CASL, ePrivacy)
- **US CAN-SPAM Act & Canada CASL (10,000,000 CAD penalty)**:
  - Commercial email dispatchers (Nodemailer, Resend, SendGrid, SES, Mailgun) must include:
    1. A clear, conspicuously displayed one-click unsubscribe mechanism (`List-Unsubscribe` header and body link).
    2. A valid physical postal address of the sender.
  - Emails lacking either element are strictly non-compliant and trigger automated mailbox quarantine.

---

## 4. Verification Checkpoint Matrix

| Rule ID | Regulatory Reference | Threshold | Remediation Directive |
| :--- | :--- | :--- | :--- |
| `SEC-PRIV-COPPA-AGEGATE` | GDPR Art 8 / COPPA § 6502 | Registration endpoint | Inject neutral DOB age gate + VPC block for age < 13/16 |
| `SEC-PRIV-GOOGLE-FONTS` | GDPR Art 6 & 44 / LG München | Font loading invocation | Set `allowRuntimeFetching = false` & vendor font files in assets |
| `SEC-PRIV-SESSION-REPLAY`| GDPR Art 6 / CIPA Wiretap | Session recording init | Wrap SDK init in `if (hasConsent)` guard + redact input fields |
| `SEC-COMM-EMAIL-COMPLIANCE`| CAN-SPAM / CASL / ePrivacy | Mail dispatch payload | Include `unsubscribe` link/header and sender postal address |
| `SEC-FLUTTER-SHARED-PREFS-PII`| GDPR Art 25 / SOC2 CC6.1 | Client storage writes | Migrate tokens/PII from `SharedPreferences` to `FlutterSecureStorage` |
