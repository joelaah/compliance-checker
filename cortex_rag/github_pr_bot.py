"""GitHub PR Bot for Cortex-Compliance.

Analyzes PR changes and posts interactive inline code review comments with
GitHub 1-click mergeable suggestions, regulatory citations, and statutory penalty tables.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from cortex_rag.config import settings
from cortex_rag.state import AuditFinding, ComplianceReport, SeverityLevel, VerdictStatus


class GitHubPRBot:
    """Automates pull request and issue compliance telemetry feedback."""

    def __init__(self, token: Optional[str] = None, repo: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN") or settings.github_token
        self.repo = repo or os.getenv("GITHUB_REPOSITORY") or settings.github_repository
        self.api_base = "https://api.github.com"

    def format_suggestion_comment(self, finding: AuditFinding) -> str:
        """Format an inline PR comment with a 1-click merge suggestion."""
        st1 = finding.stage1
        verd = finding.verdict
        pt = finding.patch

        sev_badge = {
            SeverityLevel.CRITICAL: "🚨 **CRITICAL VULNERABILITY**",
            SeverityLevel.HIGH: "⚠️ **HIGH SEVERITY**",
            SeverityLevel.MEDIUM: "🟡 **MEDIUM SEVERITY**",
            SeverityLevel.LOW: "ℹ️ **LOW SEVERITY**",
            SeverityLevel.INFO: "💡 **INFORMATIONAL**",
        }.get(st1.severity, "⚠️ **COMPLIANCE ALERT**")

        lines = [
            f"### {sev_badge}: {st1.title}",
            "",
            f"- **Rule ID**: `{st1.rule_id}`",
            f"- **Standard**: {st1.owasp or 'OWASP Top 10'} | {st1.cwe or 'CWE'}",
            f"- **Compliance Control**: `{st1.compliance_control}`",
            "",
            f"**Root Cause**: {verd.root_cause_analysis if verd else st1.exploit}",
            "",
        ]

        # Citations Table
        if finding.citations:
            lines.extend([
                "#### ⚖️ Regulatory Legal Liabilities",
                "| Authority & Policy | Article / Clause | Statutory Penalties / Risks |",
                "| :--- | :--- | :--- |",
            ])
            for c in finding.citations[:3]:
                lines.append(f"| {c.policy_title} | {c.section_or_article} | {c.penalty_framework or c.legal_risk} |")
            lines.append("")

        # 1-Click Code Suggestion
        if pt and pt.proposed_code:
            lines.extend([
                "#### 🛠️ Self-Healing Auto-Patch (1-Click Apply)",
                "```suggestion",
                pt.proposed_code.strip(),
                "```",
                "",
                f"> **Why this works**: {pt.explanation}",
            ])

        return "\n".join(lines)

    def format_summary_comment(self, report: ComplianceReport) -> str:
        """Generate high-level markdown summary for the PR / Issue."""
        health_icon = "🟢" if report.health_score >= 85 else ("🟡" if report.health_score >= 60 else "🔴")

        lines = [
            f"## {health_icon} Cortex-Compliance Audit Report",
            f"**Audit ID**: `{report.audit_id}` | **Score**: **{report.health_score}/100**",
            "",
            "| Metric | Count | Status |",
            "| :--- | :--- | :--- |",
            f"| Total Findings | {report.total_findings} | Analyzed |",
            f"| Confirmed Violations | {report.confirmed_violations} | ❌ Action Required |",
            f"| Mitigated Externally | {report.mitigated_count} | ✅ Verified |",
            f"| False Positives | {report.false_positives} | 🛡️ Suppressed |",
            "",
            f"**Summary**: {report.scan_summary}",
            "",
            "### 📋 Detailed Finding Log",
            "| Rule | File | Severity | Verdict | Status |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ]

        for f in report.findings:
            st1 = f.stage1
            verd = f.verdict
            v_status = verd.status.value if verd else "PENDING"
            lines.append(f"| `{st1.rule_id}` | `{Path(st1.file_path).name}:{st1.line}` | `{st1.severity.value}` | `{v_status}` | {'🛠️ Patch Ready' if f.patch else 'Review'} |")

        lines.extend([
            "",
            "---",
            "*Telemetry synchronized with LanceDB vector memory and Supabase Realtime Command Center.*",
        ])
        return "\n".join(lines)

    def post_pr_summary(self, pr_number: int, report: ComplianceReport) -> bool:
        """Post the audit summary comment to a GitHub PR."""
        if not self.token or not self.repo:
            print("[GitHub Bot] Missing GITHUB_TOKEN or GITHUB_REPOSITORY. Skipping network post.")
            return False

        url = f"{self.api_base}/repos/{self.repo}/issues/{pr_number}/comments"
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }
        body = {"body": self.format_summary_comment(report)}

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.post(url, headers=headers, json=body)
                if res.status_code in (200, 201):
                    print(f"[GitHub Bot] Successfully posted comment to PR #{pr_number}")
                    return True
                else:
                    print(f"[GitHub Bot] Failed to post comment: HTTP {res.status_code} - {res.text}")
        except Exception as exc:
            print(f"[GitHub Bot] Error communicating with GitHub API: {exc}")
        return False


def main() -> None:
    """CLI runner for PR Bot."""
    audit_file = sys.argv[1] if len(sys.argv) > 1 else str(settings.audit_output_path)
    p = Path(audit_file)
    if not p.exists():
        print(f"[GitHub Bot] Audit file not found: {p}")
        return

    report = ComplianceReport(**json.loads(p.read_text(encoding="utf-8")))
    bot = GitHubPRBot()
    summary_md = bot.format_summary_comment(report)

    # If running in GitHub Actions PR context
    event_path = os.getenv("GITHUB_EVENT_PATH")
    if event_path and Path(event_path).exists():
        try:
            event_data = json.loads(Path(event_path).read_text(encoding="utf-8"))
            pr_num = event_data.get("pull_request", {}).get("number")
            if pr_num:
                bot.post_pr_summary(pr_num, report)
                return
        except Exception:
            pass

    # Fallback: print formatted summary to stdout
    print(summary_md)


if __name__ == "__main__":
    main()
