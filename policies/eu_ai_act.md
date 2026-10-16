# Regulatory Compliance Policy: EU Artificial Intelligence Act (EU AI Act)

**Identifier**: `POL-EU-AIACT-2024-V1`  
**Standard**: Regulation (EU) 2024/1689 (Harmonised Rules on Artificial Intelligence)  
**Classification**: Legal Mandate for AI Systems & Autonomous Agents  
**Enforcement Authority**: European Artificial Intelligence Board (EAIB) & National Supervisory Authorities  
**Penalties**: Up to €35,000,000 or 7% of worldwide annual turnover for prohibited AI practices; up to €15,000,000 or 3% for high-risk non-compliance

---

## 1. Scope & Objective
This policy governs autonomous agent workflows, local and remote Large Language Models (LLMs), Agentic Retrieval-Augmented Generation (RAG) pipelines, and automated remediation bots operating within Cortex-Compliance.

---

## 2. Risk Classification & System Requirements

### Article 5: Prohibited AI Practices
- AI systems that deploy subliminal techniques, exploit vulnerabilities of specific groups, or conduct social scoring are banned unconditionally.
- In software development: Autonomous code generation systems must not autonomously inject un-audited exploits or deceptive backdoors into production codebases.

### Article 10: Data Governance & RAG Knowledge Corpora
- Training, validation, and retrieval datasets used in RAG systems MUST be subjected to data governance practices:
  1. Assessment of biases and privacy risks.
  2. Data provenance: All vector embeddings stored in LanceDB and Supabase pgvector must include cryptographically verifiable source file paths, line ranges, and regulatory policy hashes.
  3. No unconsented copyrighted or sensitive personal data ingested into indexing stores.

### Article 13: Transparency & Provision of Information to Users
- High-risk and agentic AI systems must be designed to enable users to interpret system output.
- **Agentic RAG Mandate**:
  - Every AI-generated compliance verdict MUST cite exact policy articles and verifiable code snippets (zero ungrounded hallucinations).
  - Every auto-generated patch must be accompanied by human-readable explanation, Unified Diff, and confidence scores (0.00 to 1.00).

### Article 14: Human Oversight ("Human-in-the-Loop")
- AI systems must allow natural persons to oversee their operations during deployment:
  - Cortex-Compliance automated PR bots MUST suggest patches as mergeable PR comments rather than silently force-pushing to protected main branches.
  - The Flutter Web Command Center must provide a 1-click human approval / reject control for suggested remediation diffs.

### Article 72: Post-Market Monitoring & Audit Logging
- Continuous audit logs of all AI evaluations, agent state transitions, tool invocations, and retrieval grades must be immutably recorded in dual-tier storage (`compliance_audits` in Supabase and local LanceDB).
