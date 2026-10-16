# Regulatory Compliance Policy: SOC 2 Type II Trust Services Criteria

**Identifier**: `POL-SOC2-TSC-2022-V1`  
**Standard**: AICPA Trust Services Criteria (Security, Availability, Processing Integrity, Confidentiality, Privacy)  
**Classification**: Enterprise Compliance Standard  
**Enforcement Authority**: Independent CPA Auditor Examination & Customer Security Reviews

---

## 1. Scope & Objective
This document outlines technical specifications required to achieve and maintain continuous SOC 2 Type II compliance across cloud infrastructure, development environments, and CI/CD pipelines.

---

## 2. Trust Services Criteria Mapping

### CC6.1: Logical Access Security & Perimeter Defense
- **Requirement**: The entity restricts logical access to systems, data, and sensitive components through role-based access control, least privilege, and multi-factor authentication.
- **Rule Association**:
  - `SEC-SECRET-AWS`, `SEC-SECRET-GITHUB`, `SEC-SECRET-OPENAI`: Zero plaintext API keys or credentials allowed in repository branches or commit history.
  - `SEC-SUPABASE-SERVICE-KEY`: Supabase `service_role` credentials must remain isolated in secure backend vaults.

### CC6.3: Revocation & Authorization Boundaries
- Dynamic access controls must immediately invalidate tokens upon user deletion or permission revocation.

### CC6.6: Boundary Protection & Injection Defense
- Protection against boundary traversal, malicious injection, and arbitrary remote execution.
- **Rule Association**:
  - `SEC-SQLI-01`, `SEC-SQLI-02`: Mandatory parameterization across all SQL queries.
  - `SEC-CMD-INJECT`: Prohibit dynamic shell execution without array parameter boundaries.
  - `SEC-RCE-EVAL`: Dynamic `eval` strictly prohibited in production runtimes.

### CC6.7: Transmission Encryption
- All data in transit over public networks must utilize modern cryptographic protocols (TLS 1.2+ / TLS 1.3). Broken legacy algorithms (MD5, SHA-1) are prohibited (`SEC-CRYPTO-WEAK`).

### CC7.1: Continuous Vulnerability Monitoring & CI/CD Gates
- Automated static analysis (SAST) and agentic verification must run on every pull request to prevent non-compliant code from merging to production branches.

### CC8.1: Change Management & Traceable Audit Trails
- All code changes must produce auditable telemetry. Cortex-Compliance audit outputs (`latest_audit.json` and Supabase `compliance_audits`) maintain immutable records of scans, timestamps, author signatures, and patch resolutions.
