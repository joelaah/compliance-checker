"""Comprehensive end-to-end test suite for Cortex-Compliance."""

import json
from pathlib import Path
import pytest

from cortex_rag.polyglot_chunker import PolyglotChunker
from cortex_rag.hybrid_indexer import HybridIndexer
from cortex_rag.compliance_agent import ComplianceAgentPipeline
from cortex_rag.github_pr_bot import GitHubPRBot
from cortex_rag.mcp_server import _get_mcp_server
from cortex_rag.state import SeverityLevel, VerdictStatus


def test_hybrid_indexer_policy_search():
    indexer = HybridIndexer()
    indexed_count = indexer.index_policies()
    assert indexed_count > 0, "Should index at least one policy document"

    # Search for child privacy rules
    citations = indexer.query_policies("COPPA age gate children", top_k=2)
    assert len(citations) > 0
    assert any("COPPA" in c.text or "Article 8" in c.section_or_article or "Age" in c.section_or_article for c in citations)


def test_compliance_agent_pipeline_execution(tmp_path):
    # Create test sample file with a vulnerability
    vulnerable_file = tmp_path / "UserController.js"
    vulnerable_file.write_text("""
const express = require('express');
const app = express();

app.post('/api/auth/register', async (req, res) => {
    const user = await db.users.create(req.body);
    res.json(user);
});
""", encoding="utf-8")

    pipeline = ComplianceAgentPipeline()
    report = pipeline.run([str(vulnerable_file)])

    assert report.total_findings > 0
    assert report.confirmed_violations > 0
    assert report.health_score < 100
    assert len(report.findings) > 0

    finding = report.findings[0]
    assert finding.stage1.rule_id == "SEC-PRIV-COPPA-AGEGATE"
    assert finding.verdict is not None
    assert finding.verdict.status == VerdictStatus.CONFIRMED_VIOLATION
    assert finding.patch is not None
    assert "diff" in finding.patch.patch_diff.lower() or "---" in finding.patch.patch_diff


def test_github_pr_bot_formatting(tmp_path):
    vulnerable_file = tmp_path / "DbService.py"
    vulnerable_file.write_text("""
def query_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
""", encoding="utf-8")

    pipeline = ComplianceAgentPipeline()
    report = pipeline.run([str(vulnerable_file)])

    bot = GitHubPRBot()
    summary = bot.format_summary_comment(report)
    assert "Cortex-Compliance Audit Report" in summary
    assert "SEC-SQLI" in summary or "SQL Injection" in summary

    finding = report.findings[0]
    comment = bot.format_suggestion_comment(finding)
    assert "```suggestion" in comment
    assert "Regulatory Legal Liabilities" in comment or "OWASP" in comment


def test_mcp_server_tools():
    server = _get_mcp_server()
    # FastMCP stores tools in its internal registry
    # Let's verify scan_compliance works directly
    from cortex_rag.stage1_scanner import scan_code_string
    hits = scan_code_string('const key = "AKIAIOSFODNN7EXAMPLE";')
    assert any(h.rule_id == "SEC-SECRET-AWS" for h in hits)


def test_corrective_rag_query_reformulation():
    from cortex_rag.compliance_agent import ComplianceAgentPipeline

    pipeline = ComplianceAgentPipeline()
    state = {
        "stage1_findings": [
            {
                "finding_id": "test-1",
                "file_path": "query.go",
                "line": 10,
                "rule_id": "SEC-SQLI-01",
                "category": "Database Attacks",
                "title": "SQL Injection Flaw",
            }
        ],
        "retrieved_citations": [],
        "pipeline_steps": [],
        "iteration_count": 0,
    }

    # Trigger rewrite query node
    rewritten_state = pipeline.rewrite_query_node(state)
    assert rewritten_state["iteration_count"] == 1
    assert len(rewritten_state["retrieved_citations"]) > 0
    assert any("Stage 2: Corrective RAG Query Reformulation" in step for step in rewritten_state["pipeline_steps"])


def test_lancedb_vector_persistence():
    from cortex_rag.hybrid_indexer import HybridIndexer, _has_lancedb_table

    indexer = HybridIndexer()
    cnt = indexer.index_policies()
    assert cnt > 0
    if indexer.lancedb_client:
        assert _has_lancedb_table(indexer.lancedb_client, "compliance_policies")
        tbl = indexer.lancedb_client.open_table("compliance_policies")
        assert tbl.count_rows() > 0
        q_vec = indexer.get_embedding("GDPR data privacy")
        results = tbl.search(q_vec).limit(2).to_list()
        assert len(results) > 0

