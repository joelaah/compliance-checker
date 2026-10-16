"""Hybrid Dual-Corpus Indexer (Vector + BM25 Lexical Search).

Manages dual-corpus vector embeddings and full-text indexing across:
1. Regulatory policy documents (`policies/*.md`)
2. Multi-language codebase chunks

Dual-target persistence:
- LanceDB: Local Git-tracked embedded vector store
- Supabase: Cloud `pgvector` + Realtime telemetry
- Resilient In-Memory Engine: Deterministic TF-IDF + token similarity fallback
"""

from __future__ import annotations

import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import httpx

from cortex_rag.config import settings
from cortex_rag.polyglot_chunker import CodeChunk, PolyglotChunker
from cortex_rag.state import AuditFinding, ComplianceReport, PolicyCitation


import hashlib


def compute_deterministic_embedding(text: str, dim: int = 768) -> List[float]:
    """Compute deterministic 768-dim normalized embedding for offline LanceDB vector search."""
    vec = [0.0] * dim
    words = re.findall(r"\w+", text.lower())
    if not words:
        return [1.0 / math.sqrt(dim)] * dim
    for w in words:
        h = int(hashlib.md5(w.encode("utf-8")).hexdigest(), 16)
        idx = h % dim
        sign = 1.0 if ((h >> 10) & 1) == 0 else -1.0
        vec[idx] += sign
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        return [round(x / norm, 6) for x in vec]
    return [round(1.0 / math.sqrt(dim), 6)] * dim


def _has_lancedb_table(client: Any, table_name: str) -> bool:
    """Safely check if a LanceDB table exists across all LanceDB client versions."""
    if not client:
        return False
    try:
        client.open_table(table_name)
        return True
    except Exception:
        return False


class ResilientFallbackEngine:
    """Lightweight in-memory vector/lexical retrieval engine when external services are offline."""

    def __init__(self):
        self.policy_docs: List[Dict[str, Any]] = []
        self.code_docs: List[Dict[str, Any]] = []

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower() for w in re.findall(r"[A-Za-z0-9_]{2,}", text)]

    def add_policy_doc(self, doc: Dict[str, Any]) -> None:
        self.policy_docs.append(doc)

    def add_code_doc(self, doc: Dict[str, Any]) -> None:
        self.code_docs.append(doc)

    def query_policies(self, query: str, top_k: int = 3) -> List[PolicyCitation]:
        query_tokens = Counter(self._tokenize(query))
        if not query_tokens or not self.policy_docs:
            return []

        scored: List[Tuple[float, Dict[str, Any]]] = []
        for doc in self.policy_docs:
            content_str = f"{doc.get('title', '')} {doc.get('section', '')} {doc.get('content', '')} {doc.get('policy_id', '')}"
            doc_tokens = Counter(self._tokenize(content_str))

            # Cosine-like term overlap
            intersection = set(query_tokens.keys()) & set(doc_tokens.keys())
            if not intersection:
                continue

            dot = sum(query_tokens[t] * doc_tokens[t] for t in intersection)
            norm_q = math.sqrt(sum(v * v for v in query_tokens.values()))
            norm_d = math.sqrt(sum(v * v for v in doc_tokens.values()))
            score = dot / (norm_q * norm_d) if (norm_q * norm_d) > 0 else 0.0

            # Boost exact phrase or ID matches
            if any(term in content_str.lower() for term in query.lower().split()):
                score += 0.2

            scored.append((score, doc))

        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[PolicyCitation] = []

        for score, doc in scored[:top_k]:
            clamped_score = min(1.0, max(0.1, score))
            results.append(
                PolicyCitation(
                    policy_id=doc.get("policy_id", "POL-UNKNOWN"),
                    policy_title=doc.get("title", ""),
                    section_or_article=doc.get("section", ""),
                    text=doc.get("content", ""),
                    legal_risk=doc.get("legal_risk", ""),
                    penalty_framework=doc.get("penalty_framework", ""),
                    relevance_score=round(clamped_score, 3),
                    is_graded_relevant=clamped_score >= 0.25,
                )
            )
        return results

    def query_codebase(self, query: str, top_k: int = 5) -> List[CodeChunk]:
        query_tokens = Counter(self._tokenize(query))
        if not query_tokens or not self.code_docs:
            return []

        scored: List[Tuple[float, Dict[str, Any]]] = []
        for doc in self.code_docs:
            content_str = f"{doc.get('symbol_name', '')} {doc.get('content', '')} {doc.get('file_path', '')}"
            doc_tokens = Counter(self._tokenize(content_str))

            intersection = set(query_tokens.keys()) & set(doc_tokens.keys())
            if not intersection:
                continue

            dot = sum(query_tokens[t] * doc_tokens[t] for t in intersection)
            norm_q = math.sqrt(sum(v * v for v in query_tokens.values()))
            norm_d = math.sqrt(sum(v * v for v in doc_tokens.values()))
            score = dot / (norm_q * norm_d) if (norm_q * norm_d) > 0 else 0.0
            scored.append((score, doc))

        scored.sort(key=lambda x: x[0], reverse=True)
        results: List[CodeChunk] = []

        for _, doc in scored[:top_k]:
            results.append(
                CodeChunk(
                    chunk_id=doc.get("chunk_id", ""),
                    file_path=doc.get("file_path", ""),
                    language=doc.get("language", ""),
                    symbol_name=doc.get("symbol_name", ""),
                    chunk_type=doc.get("chunk_type", "block"),
                    start_line=doc.get("start_line", 1),
                    end_line=doc.get("end_line", 1),
                    content=doc.get("content", ""),
                    context_header=doc.get("context_header", ""),
                )
            )
        return results


class HybridIndexer:
    """Production-grade hybrid indexer coordinating LanceDB, Supabase, and Fallback memory."""

    def __init__(self):
        self.chunker = PolyglotChunker()
        self.fallback = ResilientFallbackEngine()
        self.lancedb_client: Optional[Any] = None
        self.supabase_client: Optional[Any] = None
        self._init_lancedb()
        self._init_supabase()

    def _init_lancedb(self) -> None:
        """Attempt initializing LanceDB connection if package is installed."""
        try:
            import lancedb  # type: ignore

            db_path = settings.get_absolute_path(settings.lancedb_path)
            db_path.mkdir(parents=True, exist_ok=True)
            self.lancedb_client = lancedb.connect(str(db_path))
        except Exception:
            self.lancedb_client = None

    def _init_supabase(self) -> None:
        """Attempt initializing Supabase client if URL and Key are provided."""
        if not settings.supabase_url or not (settings.supabase_key or settings.supabase_service_role_key):
            return
        try:
            from supabase import create_client  # type: ignore

            key = settings.supabase_service_role_key or settings.supabase_key
            self.supabase_client = create_client(settings.supabase_url, key)
        except Exception:
            self.supabase_client = None

    def get_ollama_embedding(self, text: str) -> Optional[List[float]]:
        """Fetch 768-dim dense embedding from local Ollama service."""
        if getattr(self, "_ollama_available", None) is False:
            return None
        try:
            url = f"{settings.ollama_base_url}/api/embeddings"
            payload = {"model": settings.ollama_embed_model, "prompt": text}
            with httpx.Client(timeout=0.5) as client:
                res = client.post(url, json=payload)
                if res.status_code == 200:
                    self._ollama_available = True
                    return res.json().get("embedding")
        except Exception:
            self._ollama_available = False
        return None

    def get_embedding(self, text: str) -> List[float]:
        """Fetch dense 768-dim vector embedding via Ollama, falling back to deterministic local vector."""
        emb = self.get_ollama_embedding(text)
        if emb:
            return emb
        return compute_deterministic_embedding(text)

    def index_policies(self, policies_dir: Optional[Path] = None) -> int:
        """Index all markdown policy rulebooks into LanceDB, Supabase, and Fallback engine."""
        target_dir = policies_dir or settings.get_absolute_path(settings.policies_dir)
        if not target_dir.exists():
            return 0

        indexed_count = 0
        policy_records: List[Dict[str, Any]] = []

        for p in target_dir.glob("*.md"):
            chunks = self.chunker.chunk_file(p)
            for chk in chunks:
                # Extract metadata from text
                lines = chk.content.split("\n")
                first_line = lines[0] if lines else chk.symbol_name

                # Extract penalty info if mentioned
                penalty_match = re.search(r"(\$|€|£|₹|penalty|fine|damages)[^\.\n]*", chk.content, re.IGNORECASE)
                penalty_info = penalty_match.group(0).strip() if penalty_match else "Regulatory sanctions"

                doc = {
                    "id": chk.chunk_id,
                    "policy_id": p.stem.upper(),
                    "title": p.name,
                    "section": chk.symbol_name,
                    "content": chk.content,
                    "legal_risk": f"Non-compliance with {chk.symbol_name}",
                    "penalty_framework": penalty_info,
                    "vector": self.get_embedding(f"{p.name} {chk.symbol_name} {chk.content}"),
                }

                # Add to fallback memory
                self.fallback.add_policy_doc(doc)
                policy_records.append(doc)
                indexed_count += 1

        # Sync to LanceDB if available (overwrite mode ensures fresh sync)
        if self.lancedb_client and policy_records:
            try:
                tbl_name = "compliance_policies"
                self.lancedb_client.create_table(tbl_name, data=policy_records, mode="overwrite")
            except Exception:
                pass

        # Sync to Supabase pgvector if available
        if self.supabase_client and policy_records:
            try:
                for doc in policy_records:
                    emb = self.get_ollama_embedding(doc["content"])
                    payload = {
                        "policy_id": doc["policy_id"],
                        "title": doc["title"],
                        "section": doc["section"],
                        "content": doc["content"],
                        "legal_risk": doc["legal_risk"],
                        "penalty_framework": doc["penalty_framework"],
                    }
                    if emb:
                        payload["embedding"] = emb
                    self.supabase_client.table("compliance_policies").insert(payload).execute()
            except Exception:
                pass

        return indexed_count

    def index_codebase(self, root_dir: Optional[Path] = None) -> int:
        """Index target codebase files for cross-file semantic tracing."""
        base_dir = root_dir or settings.workspace_root
        chunks_count = 0
        extensions = {".py", ".dart", ".js", ".ts", ".java", ".go", ".rs", ".sql", ".cs", ".rb", ".php"}
        ignored_dirs = {".git", "node_modules", "build", ".venv", "__pycache__", ".lancedb", ".dart_tool", ".pytest_cache"}

        for root, dirs, files in os.walk(base_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs and not d.startswith(".")]
            for f in files:
                p = Path(root) / f
                if p.suffix.lower() in extensions:
                    file_chunks = self.chunker.chunk_file(p)
                    for chk in file_chunks:
                        doc = {
                            "chunk_id": chk.chunk_id,
                            "file_path": chk.file_path,
                            "language": chk.language,
                            "symbol_name": chk.symbol_name,
                            "chunk_type": chk.chunk_type,
                            "start_line": chk.start_line,
                            "end_line": chk.end_line,
                            "content": chk.content,
                            "context_header": chk.context_header,
                        }
                        self.fallback.add_code_doc(doc)
                        chunks_count += 1

        return chunks_count

    def query_policies(self, query: str, top_k: int = 3) -> List[PolicyCitation]:
        """Hybrid search against policies: tries Supabase -> LanceDB -> Fallback Engine."""
        # 1. Supabase Hybrid RPC
        if self.supabase_client:
            try:
                emb = self.get_ollama_embedding(query)
                if emb:
                    res = self.supabase_client.rpc(
                        "search_policies",
                        {"query_text": query, "query_embedding": emb, "match_count": top_k},
                    ).execute()
                    if res.data:
                        citations: List[PolicyCitation] = []
                        for row in res.data:
                            citations.append(
                                PolicyCitation(
                                    policy_id=row["policy_id"],
                                    policy_title=row["title"],
                                    section_or_article=row["section"],
                                    text=row["content"],
                                    legal_risk=row["legal_risk"],
                                    penalty_framework=row["penalty_framework"],
                                    relevance_score=float(row.get("hybrid_score", 0.8)),
                                    is_graded_relevant=True,
                                )
                            )
                        return citations
            except Exception:
                pass

        # 2. LanceDB Vector Search
        if self.lancedb_client and _has_lancedb_table(self.lancedb_client, "compliance_policies"):
            try:
                q_vec = self.get_embedding(query)
                tbl = self.lancedb_client.open_table("compliance_policies")
                hits = tbl.search(q_vec).limit(top_k).to_list()
                if hits:
                    citations: List[PolicyCitation] = []
                    for hit in hits:
                        dist = float(hit.get("_distance", 0.5))
                        score = max(0.1, min(1.0, 1.0 - (dist / 2.0)))
                        citations.append(
                            PolicyCitation(
                                policy_id=hit.get("policy_id", "POL-LANCE"),
                                policy_title=hit.get("title", ""),
                                section_or_article=hit.get("section", ""),
                                text=hit.get("content", ""),
                                legal_risk=hit.get("legal_risk", ""),
                                penalty_framework=hit.get("penalty_framework", ""),
                                relevance_score=round(score, 3),
                                is_graded_relevant=score >= 0.25,
                            )
                        )
                    if citations:
                        return citations
            except Exception:
                pass

        # 3. Fallback in-memory engine (reliable, zero external dependency)
        return self.fallback.query_policies(query, top_k=top_k)

    def query_codebase(self, query: str, top_k: int = 5) -> List[CodeChunk]:
        """Query indexed codebase chunks for cross-file mitigation traces."""
        return self.fallback.query_codebase(query, top_k=top_k)

    def sync_audit_telemetry(self, report: ComplianceReport) -> Tuple[bool, bool]:
        """Push audit telemetry to LanceDB and Supabase Realtime."""
        lancedb_synced = False
        supabase_synced = False

        # LanceDB Sync
        if self.lancedb_client:
            try:
                tbl_name = "compliance_audits_history"
                record = [
                    {
                        "audit_id": report.audit_id,
                        "timestamp": report.timestamp,
                        "repo_name": report.repo_name,
                        "health_score": report.health_score,
                        "total_findings": report.total_findings,
                        "confirmed_violations": report.confirmed_violations,
                        "summary": report.scan_summary,
                    }
                ]
                if _has_lancedb_table(self.lancedb_client, tbl_name):
                    tbl = self.lancedb_client.open_table(tbl_name)
                    tbl.add(record)
                else:
                    self.lancedb_client.create_table(tbl_name, data=record)
                lancedb_synced = True
            except Exception:
                lancedb_synced = False

        # Supabase Realtime Sync
        if self.supabase_client:
            try:
                audit_row = {
                    "audit_id": report.audit_id,
                    "repo_name": report.repo_name,
                    "commit_sha": report.commit_sha,
                    "branch": report.branch,
                    "health_score": report.health_score,
                    "total_findings": report.total_findings,
                    "confirmed_violations": report.confirmed_violations,
                    "false_positives": report.false_positives,
                    "mitigated_count": report.mitigated_count,
                    "summary": report.scan_summary,
                    "pipeline_steps": report.pipeline_steps,
                }
                self.supabase_client.table("compliance_audits").upsert(audit_row).execute()

                # Insert findings
                for f in report.findings:
                    st1 = f.stage1
                    verd = f.verdict
                    pt = f.patch
                    finding_row = {
                        "audit_id": report.audit_id,
                        "rule_id": st1.rule_id,
                        "file_path": st1.file_path,
                        "line_number": st1.line,
                        "severity": st1.severity.value,
                        "category": st1.category,
                        "title": st1.title,
                        "snippet": st1.snippet,
                        "verdict_status": verd.status.value if verd else "CONFIRMED_VIOLATION",
                        "confidence": verd.confidence if verd else 0.95,
                        "reason": verd.reason if verd else "",
                        "root_cause": verd.root_cause_analysis if verd else "",
                        "citations": [c.model_dump() for c in f.citations],
                        "patch_diff": pt.patch_diff if pt else None,
                        "patch_safe": pt.auto_fix_safe if pt else True,
                    }
                    self.supabase_client.table("compliance_findings").insert(finding_row).execute()

                supabase_synced = True
            except Exception:
                supabase_synced = False

        return lancedb_synced, supabase_synced
