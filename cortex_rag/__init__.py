"""Cortex-Compliance: Polyglot, Self-Healing Agentic RAG Compliance Engine.

Integrates Stage 1 deterministic regex SAST rules with Stage 2 LangGraph Corrective RAG,
backed by LanceDB vector index and Supabase pgvector + Realtime telemetry.
"""

__version__ = "0.1.0"
__all__ = [
    "config",
    "state",
    "stage1_scanner",
    "polyglot_chunker",
    "hybrid_indexer",
    "compliance_agent",
    "github_pr_bot",
    "mcp_server",
]
