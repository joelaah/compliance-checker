# Regulatory Compliance Policy: OWASP Top 10 Security Controls

**Identifier**: `POL-OWASP-2021-V1`  
**Standard**: OWASP Top 10 Application Security Risks (2021 Edition) & NIST SP 800-53 Rev 5  
**Classification**: High-Impact Vulnerability Baseline  
**Enforcement Authority**: Global Application Security Standards / PCI-DSS Requirement 6.5

---

## 1. Scope & Objective
This specification mandates defensive engineering controls across all software layers to mitigate high-severity exploits, data breaches, and systemic vulnerabilities identified in the OWASP Top 10.

---

## 2. Core Security Controls & Remediation Standards

### A01:2021 - Broken Access Control (CWE-284, CWE-862)
- **Violation Patterns**: Missing server-side authorization checks, exposed administrative endpoints, missing Row Level Security (RLS) on database tables.
- **Remediation Standard**:
  - Enforce Principle of Least Privilege (PoLP).
  - Supabase/PostgreSQL tables MUST enable RLS (`ALTER TABLE ... ENABLE ROW LEVEL SECURITY;`).
  - Access policies must validate `auth.uid() = user_id` for individual rows.

### A02:2021 - Cryptographic Failures (CWE-259, CWE-327, CWE-328)
- **Violation Patterns**:
  - Use of obsolete hash functions (MD5, SHA-1) for password hashing or message authentication (`SEC-CRYPTO-WEAK`).
  - Hardcoded symmetric cryptographic keys or hardcoded JWT signing secrets (`SEC-SECRET-JWT`).
- **Remediation Standard**:
  - Passwords must be hashed using adaptive, salted functions: Argon2id (preferred) or bcrypt with work factor >= 12.
  - Secret keys must be loaded exclusively via environment variables or secret vaults (AWS Secrets Manager, HashiCorp Vault).

### A03:2021 - Injection (CWE-78, CWE-79, CWE-89, CWE-95)
- **Violation Patterns**:
  - **SQL Injection (CWE-89 / `SEC-SQLI-01`, `SEC-SQLI-02`)**: Raw string concatenation, f-strings, or unparameterized queries sent to database drivers (`query(...)`, `cursor.execute(...)`).
  - **Command Injection (CWE-78 / `SEC-CMD-INJECT`)**: Executing shell commands (`child_process.exec`, `os.system`, `subprocess.Popen(..., shell=True)`) with concatenated user parameters.
  - **Cross-Site Scripting (CWE-79 / `SEC-XSS-DOM`)**: Injecting unescaped user input into DOM via `innerHTML`, `outerHTML`, or `dangerouslySetInnerHTML`.
  - **Dynamic Code Evaluation (CWE-95 / `SEC-RCE-EVAL`)**: Invoking `eval()`, `new Function()`, or dynamic runtime code compilers.
- **Remediation Standard**:
  - Use parameterized prepared statements (`$1, $2` or `?`).
  - Use `execFile` with argument arrays instead of shell commands.
  - Use `textContent`, safe templating engines, or DOMPurify sanitization.
  - Eliminate `eval()`; use structured JSON parsers or safe AST evaluation.

### A04:2021 - Insecure Design (CWE-209, CWE-256, CWE-501)
- **Violation Patterns**: Missing business logic controls, unverified age checks, non-consensual session telemetry (`SEC-PRIV-COPPA-AGEGATE`, `SEC-PRIV-SESSION-REPLAY`).
- **Remediation Standard**:
  - Threat modeling integrated into CI/CD.
  - Strict input validation schemas (Pydantic, Zod) on all ingress boundaries.

### A07:2021 - Identification and Authentication Failures (CWE-798)
- **Violation Patterns**:
  - Hardcoded cloud credentials: AWS Access Keys (`AKIA...`), OpenAI API keys (`sk-...`), GitHub PATs (`ghp_...`), Database connection URIs (`postgres://user:pass@host:port/db`).
- **Remediation Standard**:
  - Secrets must be injected via runtime environment variables.
  - Pre-commit secret scanning must block code commits containing entropy-dense strings or known token prefixes.

---

## 3. Automated Vulnerability Mapping

| Rule ID | Category | Severity | CWE | OWASP 2021 | Target Sink |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `SEC-SQLI-01` | Database Attacks | Critical | CWE-89 | A03: Injection | Concatenated SQL strings |
| `SEC-SQLI-02` | Database Attacks | Critical | CWE-89 | A03: Injection | Raw DB query execution |
| `SEC-SECRET-AWS` | Secret Leak | Critical | CWE-798 | A07: Auth Failures | AWS Access Key patterns |
| `SEC-SECRET-OPENAI` | Secret Leak | Critical | CWE-798 | A07: Auth Failures | OpenAI sk- patterns |
| `SEC-SECRET-GITHUB` | Secret Leak | Critical | CWE-798 | A07: Auth Failures | GitHub ghp_ / pat_ tokens |
| `SEC-SECRET-DB` | Secret Leak | Critical | CWE-798 | A07: Auth Failures | DB URI credentials |
| `SEC-SECRET-JWT` | Secret Leak | High | CWE-321 | A02: Crypto Failures | Hardcoded JWT tokens/keys |
| `SEC-RCE-EVAL` | Remote Code Exec | Critical | CWE-95 | A03: Injection | `eval()`, `new Function` |
| `SEC-CMD-INJECT` | Remote Code Exec | Critical | CWE-78 | A03: Injection | `exec()`, `os.system` |
| `SEC-XSS-DOM` | Injection & XSS | High | CWE-79 | A03: Injection | `innerHTML`, `dangerouslySet`|
| `SEC-CRYPTO-WEAK` | Cryptography | High | CWE-328 | A02: Crypto Failures | MD5 / SHA-1 usage |
