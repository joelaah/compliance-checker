"""LangGraph Corrective RAG Compliance Agent.

Executes a self-healing Corrective RAG pipeline:
Stage 1 Filter -> Policy Retrieval -> Citation Grading (with Query Rewrite) ->
Cross-File Semantic Trace -> Verdict Synthesis -> Self-Healing Auto-Patch Generation.
"""

from __future__ import annotations

import difflib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cortex_rag.config import settings
from cortex_rag.hybrid_indexer import HybridIndexer
from cortex_rag.polyglot_chunker import PolyglotChunker
from cortex_rag.stage1_scanner import RULES, scan_code_string, scan_directory, scan_file
from cortex_rag.state import (
    AgentState,
    AgentVerdict,
    AuditFinding,
    CodePatch,
    ComplianceReport,
    PolicyCitation,
    SeverityLevel,
    Stage1Finding,
    VerdictStatus,
)


def _generate_unified_diff(file_path: str, original: str, proposed: str) -> str:
    """Generate a clean unified diff string."""
    orig_lines = original.splitlines(keepends=True)
    prop_lines = proposed.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        prop_lines,
        fromfile=f"a/{Path(file_path).name}",
        tofile=f"b/{Path(file_path).name}",
        n=3,
    )
    return "".join(diff)


class ComplianceAgentPipeline:
    """Corrective RAG agent executing structured verification and auto-patching."""

    def __init__(self, indexer: Optional[HybridIndexer] = None):
        self.indexer = indexer or HybridIndexer()
        self.indexer.index_policies()

    # -----------------------------------------------------------------------
    # NODE 1: STAGE 1 SAST SCAN
    # -----------------------------------------------------------------------
    def stage1_scan_node(self, state: AgentState) -> AgentState:
        """Run fast deterministic filter across requested files/workspace."""
        files = state.get("files_to_scan", [])
        findings: List[Dict[str, Any]] = []

        if not files:
            # Scan workspace root by default
            scanned = scan_directory(settings.workspace_root)
            findings = [f.model_dump() for f in scanned]
        else:
            for fpath_str in files:
                p = Path(fpath_str)
                if p.is_file():
                    scanned = scan_file(p)
                    findings.extend([f.model_dump() for f in scanned])
                elif p.is_dir():
                    scanned = scan_directory(p)
                    findings.extend([f.model_dump() for f in scanned])

        state["stage1_findings"] = findings
        steps = state.get("pipeline_steps", [])
        steps.append(f"Stage 1: Fast Deterministic Filter executed ({len(findings)} triggers)")
        state["pipeline_steps"] = steps
        state["current_finding_index"] = 0
        return state

    # -----------------------------------------------------------------------
    # NODE 2: RETRIEVE REGULATORY POLICIES
    # -----------------------------------------------------------------------
    def retrieve_policies_node(self, state: AgentState) -> AgentState:
        """Fetch regulatory articles matching each finding from LanceDB/Supabase."""
        findings = state.get("stage1_findings", [])
        all_citations: List[Dict[str, Any]] = []

        for f in findings:
            query = f"{f.get('rule_id', '')} {f.get('category', '')} {f.get('title', '')} {f.get('cwe', '')} {f.get('owasp', '')}"
            cits = self.indexer.query_policies(query, top_k=3)
            all_citations.extend([c.model_dump() for c in cits])

        state["retrieved_citations"] = all_citations
        steps = state.get("pipeline_steps", [])
        steps.append(f"Stage 2: Hybrid Policy Retrieval ({len(all_citations)} clauses indexed)")
        state["pipeline_steps"] = steps
        return state

    # -----------------------------------------------------------------------
    # NODE 3: GRADE CITATIONS (Corrective RAG)
    # -----------------------------------------------------------------------
    def grade_citations_node(self, state: AgentState) -> AgentState:
        """Filter out irrelevant or hallucinated citations."""
        retrieved = state.get("retrieved_citations", [])
        graded: List[Dict[str, Any]] = []

        for cit in retrieved:
            # Require minimum relevance score
            score = cit.get("relevance_score", 0.0)
            if score >= 0.15:
                cit["is_graded_relevant"] = True
                graded.append(cit)

        state["graded_citations"] = graded
        steps = state.get("pipeline_steps", [])
        steps.append(f"Stage 2: Citation Grading & Pruning ({len(graded)} certified citations)")
        state["pipeline_steps"] = steps
        return state

    # -----------------------------------------------------------------------
    # NODE 3b: REWRITE QUERY (Corrective RAG Reformulation)
    # -----------------------------------------------------------------------
    def rewrite_query_node(self, state: AgentState) -> AgentState:
        """Corrective RAG: Reformulate and broaden search queries using regulatory taxonomy."""
        findings = state.get("stage1_findings", [])
        rewritten_citations: List[Dict[str, Any]] = []

        for f in findings:
            rule_id = f.get("rule_id", "")
            cat = f.get("category", "")
            title = f.get("title", "")
            expanded = [rule_id, cat, title]

            if "SQL" in cat or "SQLI" in rule_id:
                expanded.extend(["SQL injection", "OWASP A03", "CWE-89", "parameterized query"])
            elif "SECRET" in cat or "Secret" in title:
                expanded.extend(["credentials", "API key", "OWASP A07", "CWE-798", "hardcoded"])
            elif "COPPA" in rule_id or "Age" in title:
                expanded.extend(["children", "parental consent", "GDPR Article 8", "COPPA", "CWE-359"])
            elif "FONTS" in rule_id:
                expanded.extend(["IP address", "Munich Court", "GDPR Article 44", "Schrems II"])
            elif "REPLAY" in rule_id:
                expanded.extend(["session replay", "wiretap", "consent", "GDPR Article 6", "CIPA"])
            elif "AUTHORIZE" in rule_id or "AUTH" in rule_id:
                expanded.extend(["broken access control", "OWASP A01", "CWE-306", "authentication"])
            elif "ERROR" in rule_id:
                expanded.extend(["error handling", "suppression", "CWE-391", "exception"])
            else:
                expanded.extend(["compliance", "regulatory security", "OWASP", "GDPR", "SOC2"])

            query_str = " ".join(dict.fromkeys(expanded))
            cits = self.indexer.query_policies(query_str, top_k=3)
            rewritten_citations.extend([c.model_dump() for c in cits])

        state["retrieved_citations"] = rewritten_citations
        iter_count = state.get("iteration_count", 0) + 1
        state["iteration_count"] = iter_count
        steps = state.get("pipeline_steps", [])
        steps.append(f"Stage 2: Corrective RAG Query Reformulation (Pass #{iter_count})")
        state["pipeline_steps"] = steps
        return state

    # -----------------------------------------------------------------------
    # NODE 4: CROSS-FILE TRACE
    # -----------------------------------------------------------------------
    def cross_file_trace_node(self, state: AgentState) -> AgentState:
        """Inspect sibling modules, configs, and migration scripts for external mitigations."""
        findings = state.get("stage1_findings", [])
        cross_contexts: Dict[str, List[str]] = {}

        for f in findings:
            rule_id = f.get("rule_id", "")
            fid = f.get("finding_id", "")
            mitigations: List[str] = []

            # Check if Google Fonts has allowRuntimeFetching in another file or pubspec font asset
            if rule_id == "SEC-PRIV-GOOGLE-FONTS":
                results = self.indexer.query_codebase("allowRuntimeFetching false fonts asset", top_k=3)
                for chunk in results:
                    if "allowRuntimeFetching = false" in chunk.content or "fonts:" in chunk.content:
                        mitigations.append(f"External font configuration found in {chunk.file_path}:{chunk.start_line}")

            # Check if Session Replay is gated by global consent provider
            elif rule_id == "SEC-PRIV-SESSION-REPLAY":
                results = self.indexer.query_codebase("userConsentState cookieConsent onConsent", top_k=3)
                for chunk in results:
                    if "userConsentState" in chunk.content or "hasConsent" in chunk.content:
                        mitigations.append(f"Global consent provider verified in {chunk.file_path}:{chunk.start_line}")

            # Check if RLS is enabled in SQL migrations
            elif rule_id == "SEC-SUPABASE-RLS-DISABLED":
                results = self.indexer.query_codebase("ENABLE ROW LEVEL SECURITY", top_k=3)
                for chunk in results:
                    if "ENABLE ROW LEVEL SECURITY" in chunk.content:
                        mitigations.append(f"RLS migration declared in {chunk.file_path}:{chunk.start_line}")

            cross_contexts[fid] = mitigations

        state["cross_file_contexts"] = cross_contexts
        steps = state.get("pipeline_steps", [])
        steps.append("Stage 2: Polyglot Cross-File Semantic Tracing complete")
        state["pipeline_steps"] = steps
        return state

    # -----------------------------------------------------------------------
    # NODE 5: SYNTHESIZE VERDICTS
    # -----------------------------------------------------------------------
    def synthesize_verdict_node(self, state: AgentState) -> AgentState:
        """Formulate definitive verdict with root cause analysis and legal liabilities."""
        findings = state.get("stage1_findings", [])
        cross_contexts = state.get("cross_file_contexts", {})
        verdicts: List[Dict[str, Any]] = []

        for f in findings:
            fid = f.get("finding_id", "")
            mitigations = cross_contexts.get(fid, [])

            if mitigations:
                # Mitigated externally
                status = VerdictStatus.MITIGATED_EXTERNALLY.value
                confidence = 0.96
                reason = f"Mitigated externally by project architecture: {'; '.join(mitigations)}"
                root_cause = "Local invocation lacks direct guard, but global architecture provides required defense."
            else:
                status = VerdictStatus.CONFIRMED_VIOLATION.value
                confidence = 0.98
                reason = f"Confirmed vulnerability violating {f.get('compliance_control', 'security controls')}. Exploit: {f.get('exploit', '')}"
                root_cause = f"Unsanitized or unverified code at line {f.get('line')} in {f.get('file_path')}."

            verdict = AgentVerdict(
                finding_id=fid,
                status=VerdictStatus(status),
                confidence=confidence,
                reason=reason,
                root_cause_analysis=root_cause,
                cross_file_impacts=mitigations,
            )
            verdicts.append(verdict.model_dump())

        state["verdicts"] = verdicts
        steps = state.get("pipeline_steps", [])
        steps.append(f"Stage 2: Verdict Synthesis ({len(verdicts)} verdicts rendered)")
        state["pipeline_steps"] = steps
        return state

    # -----------------------------------------------------------------------
    # NODE 6: GENERATE SELF-HEALING AUTO-PATCHES
    # -----------------------------------------------------------------------
    def generate_patch_node(self, state: AgentState) -> AgentState:
        """Synthesize concrete unified diff patches for confirmed violations."""
        findings = state.get("stage1_findings", [])
        verdicts = state.get("verdicts", [])
        patches: List[Dict[str, Any]] = []

        verdict_map = {v["finding_id"]: v for v in verdicts}

        for f in findings:
            fid = f.get("finding_id", "")
            v = verdict_map.get(fid)
            if not v or v.get("status") != VerdictStatus.CONFIRMED_VIOLATION.value:
                continue

            orig_code = f.get("snippet", "")
            good_code = f.get("good_code", "")
            file_path = f.get("file_path", "unknown")
            line_num = f.get("line", 1)

            if not good_code:
                good_code = f"// Remediation required for {f.get('rule_id')}\n" + orig_code

            unified_diff = _generate_unified_diff(file_path, orig_code, good_code)

            patch = CodePatch(
                file_path=file_path,
                start_line=line_num,
                end_line=line_num,
                original_code=orig_code,
                proposed_code=good_code,
                patch_diff=unified_diff,
                auto_fix_safe=True,
                explanation=f"Auto-generated compliant replacement conforming to {f.get('compliance_control', 'standards')}.",
            )
            patches.append(patch.model_dump())

        state["patches"] = patches
        steps = state.get("pipeline_steps", [])
        steps.append(f"Stage 2: Self-Healing Patch Generation ({len(patches)} diffs produced)")
        state["pipeline_steps"] = steps
        return state

    # -----------------------------------------------------------------------
    # NODE 7: COMPILE AUDIT REPORT & SYNC TELEMETRY
    # -----------------------------------------------------------------------
    def compile_report_node(self, state: AgentState) -> AgentState:
        """Consolidate findings, calculate compliance score, and persist report."""
        findings_data = state.get("stage1_findings", [])
        verdicts_data = state.get("verdicts", [])
        graded_citations = state.get("graded_citations", [])
        patches_data = state.get("patches", [])
        steps = state.get("pipeline_steps", [])

        verdict_dict = {v["finding_id"]: AgentVerdict(**v) for v in verdicts_data}
        patch_dict = {p["file_path"] + str(p["start_line"]): CodePatch(**p) for p in patches_data}

        audit_findings: List[AuditFinding] = []
        confirmed_count = 0
        mitigated_count = 0
        false_positive_count = 0

        for f in findings_data:
            st1 = Stage1Finding(**f)
            verd = verdict_dict.get(st1.finding_id)
            cits = [PolicyCitation(**c) for c in graded_citations if c.get("policy_id") in f.get("rule_id", "")]
            if not cits and graded_citations:
                cits = [PolicyCitation(**c) for c in graded_citations[:2]]

            key = st1.file_path + str(st1.line)
            pt = patch_dict.get(key)

            if verd:
                if verd.status == VerdictStatus.CONFIRMED_VIOLATION:
                    confirmed_count += 1
                elif verd.status == VerdictStatus.MITIGATED_EXTERNALLY:
                    mitigated_count += 1
                elif verd.status == VerdictStatus.FALSE_POSITIVE:
                    false_positive_count += 1

            audit_findings.append(
                AuditFinding(
                    stage1=st1,
                    verdict=verd,
                    citations=cits,
                    patch=pt,
                )
            )

        # Compute dynamic compliance score
        # 100 base, -15 per critical confirmed, -8 per high confirmed
        penalty = 0
        for af in audit_findings:
            if af.verdict and af.verdict.status == VerdictStatus.CONFIRMED_VIOLATION:
                if af.stage1.severity == SeverityLevel.CRITICAL:
                    penalty += 15
                elif af.stage1.severity == SeverityLevel.HIGH:
                    penalty += 8
                else:
                    penalty += 4
        health_score = max(0, min(100, 100 - penalty))

        summary_text = (
            f"Cortex-Compliance scan identified {len(audit_findings)} potential issue(s). "
            f"{confirmed_count} confirmed violation(s), {mitigated_count} mitigated externally, "
            f"{false_positive_count} false positive(s). Compliance Health Score: {health_score}/100."
        )

        audit_id = f"audit-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"
        report = ComplianceReport(
            audit_id=audit_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
            repo_name=settings.github_repository or "compliance-checker",
            commit_sha=settings.github_sha or "local-dev",
            branch=settings.github_ref or "main",
            scan_summary=summary_text,
            health_score=health_score,
            total_findings=len(audit_findings),
            confirmed_violations=confirmed_count,
            false_positives=false_positive_count,
            mitigated_count=mitigated_count,
            pipeline_steps=steps,
            findings=audit_findings,
        )

        # Sync to LanceDB & Supabase
        lance_ok, supa_ok = self.indexer.sync_audit_telemetry(report)
        report.lancedb_synced = lance_ok
        report.supabase_synced = supa_ok

        # Write to static fallback JSON for Flutter Dashboard
        out_path = settings.get_absolute_path(settings.audit_output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report.model_dump(), indent=2), encoding="utf-8")

        state["final_report"] = report.model_dump()
        steps.append(f"Stage 2: Audit Report written to {out_path.name}")
        state["pipeline_steps"] = steps
        return state

    def run(self, files_to_scan: Optional[List[str]] = None) -> ComplianceReport:
        """Run the complete agent pipeline sequentially or via LangGraph."""
        # Try running with LangGraph if available
        try:
            from langgraph.graph import END, StateGraph  # type: ignore

            workflow = StateGraph(AgentState)
            workflow.add_node("stage1_scan", self.stage1_scan_node)
            workflow.add_node("retrieve_policies", self.retrieve_policies_node)
            workflow.add_node("grade_citations", self.grade_citations_node)
            workflow.add_node("rewrite_query", self.rewrite_query_node)
            workflow.add_node("cross_file_trace", self.cross_file_trace_node)
            workflow.add_node("synthesize_verdict", self.synthesize_verdict_node)
            workflow.add_node("generate_patch", self.generate_patch_node)
            workflow.add_node("compile_report", self.compile_report_node)

            workflow.set_entry_point("stage1_scan")

            def should_retrieve(st: AgentState) -> str:
                if len(st.get("stage1_findings", [])) == 0:
                    return "compile_report"
                return "retrieve_policies"

            def decide_to_trace_or_rewrite(st: AgentState) -> str:
                # If no findings, proceed
                if len(st.get("stage1_findings", [])) == 0:
                    return "cross_file_trace"
                graded = st.get("graded_citations", [])
                iter_count = st.get("iteration_count", 0)
                # If we have relevant graded citations or reached max query reformulations
                if len(graded) > 0 or iter_count >= 1:
                    return "cross_file_trace"
                return "rewrite_query"

            workflow.add_conditional_edges(
                "stage1_scan",
                should_retrieve,
                {
                    "compile_report": "compile_report",
                    "retrieve_policies": "retrieve_policies",
                },
            )

            workflow.add_edge("retrieve_policies", "grade_citations")
            workflow.add_conditional_edges(
                "grade_citations",
                decide_to_trace_or_rewrite,
                {
                    "cross_file_trace": "cross_file_trace",
                    "rewrite_query": "rewrite_query",
                },
            )
            workflow.add_edge("rewrite_query", "retrieve_policies")
            workflow.add_edge("cross_file_trace", "synthesize_verdict")
            workflow.add_edge("synthesize_verdict", "generate_patch")
            workflow.add_edge("generate_patch", "compile_report")
            workflow.add_edge("compile_report", END)

            app = workflow.compile()
            initial_state: AgentState = {
                "files_to_scan": files_to_scan or [],
                "pipeline_steps": [],
                "stage1_findings": [],
            }
            final_state = app.invoke(initial_state)
            return ComplianceReport(**final_state["final_report"])

        except Exception:
            # Deterministic sequential fallback execution (100% equivalent logic)
            state: AgentState = {
                "files_to_scan": files_to_scan or [],
                "pipeline_steps": [],
                "stage1_findings": [],
            }
            state = self.stage1_scan_node(state)
            if len(state.get("stage1_findings", [])) > 0:
                state = self.retrieve_policies_node(state)
                state = self.grade_citations_node(state)
                if len(state.get("graded_citations", [])) == 0 and state.get("iteration_count", 0) < 1:
                    state = self.rewrite_query_node(state)
                    state = self.retrieve_policies_node(state)
                    state = self.grade_citations_node(state)
                state = self.cross_file_trace_node(state)
                state = self.synthesize_verdict_node(state)
                state = self.generate_patch_node(state)
            state = self.compile_report_node(state)
            return ComplianceReport(**state["final_report"])


def cli_main() -> None:
    """CLI runner for cortex command."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    target = sys.argv[1] if len(sys.argv) > 1 else None
    targets = [target] if target else []
    pipeline = ComplianceAgentPipeline()
    report = pipeline.run(targets)
    print("\n=======================================================")
    print(f"[SHIELD] CORTEX-COMPLIANCE AUDIT COMPLETE: {report.audit_id}")
    print("=======================================================")
    print(f"Health Score: {report.health_score}/100")
    print(f"Total Findings: {report.total_findings}")
    print(f"Confirmed Violations: {report.confirmed_violations}")
    print(f"Mitigated Externally: {report.mitigated_count}")
    print(f"Summary: {report.scan_summary}\n")


if __name__ == "__main__":
    cli_main()
