-- ==============================================================================
-- Cortex-Compliance: Supabase pgvector + Full-Text Search + Realtime Schema
-- ==============================================================================

-- 1. Enable Required Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "vector";

-- 2. Regulatory Policies Corpus Table (pgvector 768-dim + FTS tsvector)
CREATE TABLE IF NOT EXISTS public.compliance_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    policy_id TEXT NOT NULL,
    title TEXT NOT NULL,
    section TEXT NOT NULL,
    content TEXT NOT NULL,
    legal_risk TEXT DEFAULT '',
    penalty_framework TEXT DEFAULT '',
    embedding vector(768),
    fts tsvector GENERATED ALWAYS AS (
        to_tsvector('english', coalesce(title, '') || ' ' || coalesce(section, '') || ' ' || coalesce(content, ''))
    ) STORED,
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indices for Hybrid Search
CREATE INDEX IF NOT EXISTS idx_compliance_policies_hnsw 
    ON public.compliance_policies 
    USING hnsw (embedding vector_cosine_ops);

CREATE INDEX IF NOT EXISTS idx_compliance_policies_fts 
    ON public.compliance_policies 
    USING gin (fts);

-- 3. Audit Runs Telemetry Table
CREATE TABLE IF NOT EXISTS public.compliance_audits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id TEXT UNIQUE NOT NULL,
    repo_name TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT 'main',
    triggered_by TEXT DEFAULT 'github_action',
    health_score INT NOT NULL CHECK (health_score >= 0 AND health_score <= 100),
    total_findings INT NOT NULL DEFAULT 0,
    confirmed_violations INT NOT NULL DEFAULT 0,
    false_positives INT NOT NULL DEFAULT 0,
    mitigated_count INT NOT NULL DEFAULT 0,
    summary TEXT,
    pipeline_steps JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_audits_created 
    ON public.compliance_audits (created_at DESC);

-- 4. Granular Audit Findings & Auto-Patches Table
CREATE TABLE IF NOT EXISTS public.compliance_findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    audit_id TEXT NOT NULL REFERENCES public.compliance_audits(audit_id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    snippet TEXT,
    verdict_status TEXT NOT NULL,
    confidence FLOAT NOT NULL,
    reason TEXT,
    root_cause TEXT,
    citations JSONB DEFAULT '[]'::jsonb,
    patch_diff TEXT,
    patch_safe BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_compliance_findings_audit 
    ON public.compliance_findings (audit_id);

CREATE INDEX IF NOT EXISTS idx_compliance_findings_rule 
    ON public.compliance_findings (rule_id);

-- 5. Hybrid Search RPC (Reciprocal Rank Fusion of Vector Cosine + FTS)
CREATE OR REPLACE FUNCTION public.search_policies(
    query_text TEXT,
    query_embedding vector(768),
    match_count INT DEFAULT 5,
    rrf_k INT DEFAULT 60
)
RETURNS TABLE (
    id UUID,
    policy_id TEXT,
    title TEXT,
    section TEXT,
    content TEXT,
    legal_risk TEXT,
    penalty_framework TEXT,
    hybrid_score FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    WITH vector_matches AS (
        SELECT 
            p.id,
            ROW_NUMBER() OVER (ORDER BY p.embedding <=> query_embedding) AS rank_vec
        FROM public.compliance_policies p
        WHERE p.embedding IS NOT NULL
        ORDER BY p.embedding <=> query_embedding
        LIMIT match_count * 2
    ),
    fts_matches AS (
        SELECT 
            p.id,
            ROW_NUMBER() OVER (ORDER BY ts_rank_cd(p.fts, websearch_to_tsquery('english', query_text)) DESC) AS rank_fts
        FROM public.compliance_policies p
        WHERE p.fts @@ websearch_to_tsquery('english', query_text)
        LIMIT match_count * 2
    )
    SELECT 
        p.id,
        p.policy_id,
        p.title,
        p.section,
        p.content,
        p.legal_risk,
        p.penalty_framework,
        COALESCE(1.0 / (rrf_k + vm.rank_vec), 0.0) + COALESCE(1.0 / (rrf_k + fm.rank_fts), 0.0) AS hybrid_score
    FROM public.compliance_policies p
    LEFT JOIN vector_matches vm ON p.id = vm.id
    LEFT JOIN fts_matches fm ON p.id = fm.id
    WHERE vm.id IS NOT NULL OR fm.id IS NOT NULL
    ORDER BY hybrid_score DESC
    LIMIT match_count;
END;
$$;

-- 6. Row Level Security (RLS) Configuration
ALTER TABLE public.compliance_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.compliance_audits ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.compliance_findings ENABLE ROW LEVEL SECURITY;

-- Anonymous and Authenticated users can view audit reports on Dashboard
CREATE POLICY "Allow public read access to compliance_policies"
    ON public.compliance_policies FOR SELECT
    USING (true);

CREATE POLICY "Allow public read access to compliance_audits"
    ON public.compliance_audits FOR SELECT
    USING (true);

CREATE POLICY "Allow public read access to compliance_findings"
    ON public.compliance_findings FOR SELECT
    USING (true);

-- Only Service Role or CI Agent can insert audit runs
CREATE POLICY "Allow service_role full write access to policies"
    ON public.compliance_policies FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Allow service_role full write access to audits"
    ON public.compliance_audits FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

CREATE POLICY "Allow service_role full write access to findings"
    ON public.compliance_findings FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);

-- 7. Supabase Realtime Telemetry Publication
ALTER PUBLICATION supabase_realtime ADD TABLE public.compliance_audits;
ALTER PUBLICATION supabase_realtime ADD TABLE public.compliance_findings;
