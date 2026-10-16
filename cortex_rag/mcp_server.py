"""Model Context Protocol (MCP) Server for Cortex-Compliance.

Exposes tools so Cursor, Claude Code, and Windsurf can query compliance rules,
scan code in real-time, retrieve regulatory citations, and verify auto-patches.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from cortex_rag.config import settings
from cortex_rag.hybrid_indexer import HybridIndexer
from cortex_rag.stage1_scanner import RULES, scan_code_string
from cortex_rag.state import ComplianceReport


def _get_mcp_server():
    """Create and configure the FastMCP / MCPServer instance."""
    try:
        from mcp.server.mcpserver import MCPServer
        mcp = MCPServer("cortex-compliance")
    except ImportError:
        from mcp.server.fastmcp import FastMCP  # type: ignore
        mcp = FastMCP("cortex-compliance")
    indexer = HybridIndexer()
    indexer.index_policies()

    @mcp.tool()
    def scan_compliance(code: str, file_path: str = "snippet.code") -> str:
        """Scan code against all regulatory compliance rules (SQLi, secrets, COPPA, Google Fonts, RCE, etc.)."""
        findings = scan_code_string(code, file_path=file_path)
        if not findings:
            return json.dumps({"status": "CLEAN", "violations": 0, "message": "No compliance violations detected."})

        results = []
        for f in findings:
            citations = indexer.query_policies(f"{f.rule_id} {f.category} {f.title}", top_k=2)
            results.append({
                "rule_id": f.rule_id,
                "line": f.line,
                "severity": f.severity.value,
                "title": f.title,
                "category": f.category,
                "cwe": f.cwe,
                "owasp": f.owasp,
                "snippet": f.snippet,
                "recommended_fix": f.good_code,
                "citations": [{"policy": c.policy_title, "section": c.section_or_article, "risk": c.legal_risk} for c in citations],
            })

        return json.dumps({"status": "VIOLATIONS_FOUND", "count": len(results), "findings": results}, indent=2)

    @mcp.tool()
    def query_regulations(query: str, top_k: int = 3) -> str:
        """Query regulatory policy rulebooks (GDPR, OWASP Top 10, SOC2, EU AI Act, COPPA, Flutter/Supabase)."""
        citations = indexer.query_policies(query, top_k=top_k)
        payload = [
            {
                "policy_id": c.policy_id,
                "policy_title": c.policy_title,
                "section": c.section_or_article,
                "text": c.text,
                "legal_risk": c.legal_risk,
                "penalty_framework": c.penalty_framework,
                "relevance_score": c.relevance_score,
            }
            for c in citations
        ]
        return json.dumps(payload, indent=2)

    @mcp.tool()
    def verify_code_patch(original_code: str, proposed_code: str, rule_id: str) -> str:
        """Verify whether a proposed remediation patch cleanly resolves the specified violation."""
        # 1. Scan original code - should fail
        before_hits = [f for f in scan_code_string(original_code) if f.rule_id == rule_id]
        # 2. Scan proposed code - should pass
        after_hits = [f for f in scan_code_string(proposed_code) if f.rule_id == rule_id]

        resolved = len(before_hits) > 0 and len(after_hits) == 0
        new_issues = [f.rule_id for f in scan_code_string(proposed_code) if f.rule_id != rule_id]

        return json.dumps({
            "rule_id": rule_id,
            "resolved": resolved,
            "introduced_new_issues": new_issues,
            "verdict": "SAFE_TO_APPLY" if (resolved and not new_issues) else "NEEDS_REVISION",
        }, indent=2)

    @mcp.tool()
    def get_audit_history(limit: int = 5) -> str:
        """Retrieve recent compliance audit runs and telemetry summaries."""
        out_path = settings.get_absolute_path(settings.audit_output_path)
        if out_path.exists():
            try:
                data = json.loads(out_path.read_text(encoding="utf-8"))
                return json.dumps({
                    "latest_audit_id": data.get("audit_id"),
                    "health_score": data.get("health_score"),
                    "total_findings": data.get("total_findings"),
                    "confirmed_violations": data.get("confirmed_violations"),
                    "summary": data.get("scan_summary"),
                }, indent=2)
            except Exception:
                pass
        return json.dumps({"status": "NO_PREVIOUS_AUDIT_FOUND"})

    return mcp


def main():
    """Run the MCP server via stdio transport."""
    server = _get_mcp_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
