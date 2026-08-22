-- ============================================================================
-- Vigilagent → Supabase initial schema migration (v1)
-- ============================================================================
-- Consolidates backend/core/schema.sql + backend/agents/alpha_recon/
-- schema_extensions.sql into ONE idempotent migration, fixes the broken
-- `scans(id)` FK references in the old extensions file (the real scan table
-- is `recon_runs`), and adds the three tables the code already queries but
-- that were never defined: agent_proficiency, agent_decisions,
-- task_assignments.
--
-- HOW TO APPLY:
--   Option A (recommended): Supabase Dashboard → SQL Editor → paste this
--     whole file → Run. Safe to re-run (everything is IF NOT EXISTS).
--   Option B: supabase CLI — `supabase db push` from this repo after
--     linking your project (`supabase link --project-ref <ref>`).
--
-- Idempotent: running this against an already-migrated project is a no-op.
-- ============================================================================

-- 1. Vulnerabilities (Verified Findings)
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id VARCHAR(100) NOT NULL,
    endpoint TEXT NOT NULL,
    vuln_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- LOW, MEDIUM, HIGH, CRITICAL
    evidence JSONB NOT NULL,
    validated_by VARCHAR(50), -- agent-alpha, agent-omega
    description TEXT,
    remediation_advice TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(scan_id, endpoint, vuln_type) -- Deduplication Constraint
);

-- 2. Exploit Results (Evidence of Successful Attacks)
CREATE TABLE IF NOT EXISTS exploit_results (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    payload TEXT NOT NULL,
    worker_id VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL, -- EXPLOITED, BLOCKED, FAILED
    response_dump TEXT,
    execution_time_ms INTEGER,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Attack Graph (Relational Intelligence)
CREATE TABLE IF NOT EXISTS attack_graph (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL,
    target_id UUID NOT NULL,
    relationship_type VARCHAR(50) NOT NULL, -- PIVOT, DEPENDENCY, ESCALATION
    metadata JSONB DEFAULT '{}',
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 4. Remediation (AI-Generated Fixes)
CREATE TABLE IF NOT EXISTS remediation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_id UUID REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    strategy TEXT NOT NULL,
    code_fix TEXT,
    applied BOOLEAN DEFAULT FALSE,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Patches (Deployment State)
CREATE TABLE IF NOT EXISTS patches (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    remediation_id UUID REFERENCES remediation(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    diff_content TEXT,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, DEPLOYED, REJECTED
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 6. CI/CD Logs (Validation Tracking)
CREATE TABLE IF NOT EXISTS ci_cd_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_id UUID REFERENCES patches(id) ON DELETE CASCADE,
    action VARCHAR(50) NOT NULL, -- BUILD, TEST, VALIDATE
    result VARCHAR(20) NOT NULL, -- PASS, FAIL
    logs TEXT,
    timestamp TIMESTAMPTZ DEFAULT NOW()
);

-- 7. Distributed Tasks (Node Coordination)
CREATE TABLE IF NOT EXISTS distributed_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id VARCHAR(100) NOT NULL,
    task_type VARCHAR(50) NOT NULL, -- RECON, FUZZ, EXPLOIT, PATCH
    target TEXT NOT NULL,
    priority INTEGER DEFAULT 5,
    status VARCHAR(20) DEFAULT 'PENDING', -- PENDING, RUNNING, COMPLETED, FAILED
    locked_by VARCHAR(50), -- worker-id
    lock_time TIMESTAMPTZ,
    payload JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_vuln_endpoint ON vulnerabilities(endpoint);
CREATE INDEX IF NOT EXISTS idx_vuln_scan ON vulnerabilities(scan_id);
CREATE INDEX IF NOT EXISTS idx_exploit_vuln ON exploit_results(vuln_id);
CREATE INDEX IF NOT EXISTS idx_remediation_vuln ON remediation(vuln_id);
CREATE INDEX IF NOT EXISTS idx_patches_remediation ON patches(remediation_id);
CREATE INDEX IF NOT EXISTS idx_ci_cd_logs_patch ON ci_cd_logs(patch_id);
CREATE INDEX IF NOT EXISTS idx_graph_source ON attack_graph(source_id);
CREATE INDEX IF NOT EXISTS idx_graph_target ON attack_graph(target_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON distributed_tasks(status);
CREATE INDEX IF NOT EXISTS idx_tasks_scan ON distributed_tasks(scan_id);
CREATE INDEX IF NOT EXISTS idx_tasks_scheduling ON distributed_tasks(status, priority DESC, created_at);
CREATE INDEX IF NOT EXISTS idx_tasks_lock ON distributed_tasks(locked_by) WHERE locked_by IS NOT NULL;

-- 8. Dual-store RAG memory (Supabase/pgvector-ready)
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS scan_episodes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id VARCHAR(100) NOT NULL,
    event_type VARCHAR(100) NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS semantic_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    memory_type VARCHAR(100) NOT NULL,
    endpoint_pattern TEXT,
    vuln_type VARCHAR(100),
    content TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}',
    embedding vector(768),
    confidence DOUBLE PRECISION DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_objectives (
    id TEXT PRIMARY KEY,
    scan_id VARCHAR(100) NOT NULL,
    phase VARCHAR(50) NOT NULL,
    title TEXT NOT NULL,
    endpoint_group TEXT DEFAULT '',
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    owasp_category TEXT DEFAULT '',
    priority INTEGER DEFAULT 5,
    blocked_by TEXT[] DEFAULT '{}',
    acceptance_criteria TEXT[] DEFAULT '{}',
    findings TEXT[] DEFAULT '{}',
    owner TEXT DEFAULT '',
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_episodes_scan_created ON scan_episodes(scan_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_semantic_memory_type ON semantic_memory(memory_type);
CREATE INDEX IF NOT EXISTS idx_semantic_memory_vuln_type ON semantic_memory(vuln_type);
CREATE INDEX IF NOT EXISTS idx_semantic_memory_endpoint_pattern ON semantic_memory(endpoint_pattern);
CREATE INDEX IF NOT EXISTS idx_scan_objectives_scan_status_priority ON scan_objectives(scan_id, status, priority);
CREATE INDEX IF NOT EXISTS idx_semantic_memory_embedding
    ON semantic_memory USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100)
    WHERE embedding IS NOT NULL;

-- 9. Durable runtime records
CREATE TABLE IF NOT EXISTS toolcalls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    call_id TEXT NOT NULL UNIQUE,
    scan_id VARCHAR(100) NOT NULL,
    tool_name TEXT NOT NULL,
    agent TEXT NOT NULL DEFAULT 'system',
    args JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(30) NOT NULL DEFAULT 'running',
    result JSONB,
    error TEXT DEFAULT '',
    duration_ms INTEGER DEFAULT 0,
    result_bytes INTEGER DEFAULT 0,
    result_sha256 TEXT DEFAULT '',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS approvals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_id TEXT NOT NULL UNIQUE,
    scan_id VARCHAR(100) NOT NULL,
    tool_name TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(30) NOT NULL DEFAULT 'pending',
    decided_by TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    decided_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scope_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id VARCHAR(100) NOT NULL,
    rule_type VARCHAR(20) NOT NULL, -- allow_host, deny_host, allow_glob, deny_glob
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(scan_id, rule_type, value)
);

CREATE TABLE IF NOT EXISTS http_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id TEXT NOT NULL,
    scan_id VARCHAR(100) NOT NULL,
    method VARCHAR(12) NOT NULL,
    url TEXT NOT NULL,
    url_hash TEXT GENERATED ALWAYS AS (md5(url)) STORED,
    headers JSONB NOT NULL DEFAULT '{}',
    body JSONB,
    elapsed_ms INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS http_responses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_db_id UUID REFERENCES http_requests(id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
    scan_id VARCHAR(100) NOT NULL,
    status INTEGER NOT NULL DEFAULT 0,
    headers JSONB NOT NULL DEFAULT '{}',
    body TEXT DEFAULT '',
    body_preview TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kg_nodes (
    id TEXT PRIMARY KEY,
    scan_id VARCHAR(100) NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    props JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS kg_edges (
    id TEXT PRIMARY KEY,
    scan_id VARCHAR(100) NOT NULL,
    src_id TEXT NOT NULL,
    dst_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    weight DOUBLE PRECISION DEFAULT 1.0,
    props JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_toolcalls_scan_status_created ON toolcalls(scan_id, status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_toolcalls_scan_tool_created ON toolcalls(scan_id, tool_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_approvals_scan_status ON approvals(scan_id, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scope_rules_scan_type ON scope_rules(scan_id, rule_type);
CREATE INDEX IF NOT EXISTS idx_http_requests_scan_method_hash ON http_requests(scan_id, method, url_hash);
CREATE INDEX IF NOT EXISTS idx_http_responses_request_id ON http_responses(request_id);
CREATE INDEX IF NOT EXISTS idx_kg_nodes_scan_kind_label ON kg_nodes(scan_id, kind, label);
CREATE INDEX IF NOT EXISTS idx_kg_nodes_props ON kg_nodes USING GIN (props);
CREATE INDEX IF NOT EXISTS idx_kg_edges_scan_src_kind ON kg_edges(scan_id, src_id, kind);
CREATE INDEX IF NOT EXISTS idx_kg_edges_scan_dst_kind ON kg_edges(scan_id, dst_id, kind);
CREATE INDEX IF NOT EXISTS idx_kg_edges_props ON kg_edges USING GIN (props);

-- 10. Alpha V6 recon/RAG records
CREATE TABLE IF NOT EXISTS recon_runs (
    scan_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    scope JSONB NOT NULL DEFAULT '{}',
    artifact_root TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'running',
    started_at TIMESTAMPTZ DEFAULT NOW(),
    finished_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS recon_entities (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    label TEXT NOT NULL,
    normalized JSONB NOT NULL DEFAULT '{}',
    sources JSONB NOT NULL DEFAULT '[]',
    confidence DOUBLE PRECISION DEFAULT 0,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recon_artifacts (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    artifact_type TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL DEFAULT '',
    bytes INTEGER DEFAULT 0,
    metadata JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS recon_endpoint_scores (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    endpoint_id TEXT NOT NULL,
    score INTEGER NOT NULL,
    reasons JSONB NOT NULL DEFAULT '[]',
    omega_modules JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_runs_status_started ON recon_runs(status, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_recon_entities_scan_kind_label ON recon_entities(scan_id, kind, label);
CREATE INDEX IF NOT EXISTS idx_recon_entities_normalized ON recon_entities USING GIN (normalized);
CREATE INDEX IF NOT EXISTS idx_recon_entities_sources ON recon_entities USING GIN (sources);
CREATE INDEX IF NOT EXISTS idx_recon_artifacts_scan_tool_type ON recon_artifacts(scan_id, tool_name, artifact_type);
CREATE INDEX IF NOT EXISTS idx_recon_endpoint_scores_scan_score ON recon_endpoint_scores(scan_id, score DESC);

-- 11. Alpha V6 deep-recon extensions (FIXED: previously referenced a
--     nonexistent `scans(id)` table → the FK now targets recon_runs).
CREATE TABLE IF NOT EXISTS recon_relationships (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES recon_runs(scan_id) ON DELETE CASCADE,
    src_entity_id TEXT NOT NULL,
    dst_entity_id TEXT NOT NULL,
    relationship TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    evidence JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (src_entity_id, dst_entity_id, relationship)
);

CREATE INDEX IF NOT EXISTS idx_recon_rel_scan ON recon_relationships(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_rel_src ON recon_relationships(src_entity_id);
CREATE INDEX IF NOT EXISTS idx_recon_rel_dst ON recon_relationships(dst_entity_id);

CREATE TABLE IF NOT EXISTS recon_tool_outputs (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES recon_runs(scan_id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    phase TEXT NOT NULL,
    parser_version TEXT DEFAULT 'v1',
    raw_artifact_id TEXT,
    normalized_count INTEGER DEFAULT 0,
    status TEXT NOT NULL,
    errors JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_tool_scan ON recon_tool_outputs(scan_id);

CREATE TABLE IF NOT EXISTS recon_oob_interactions (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES recon_runs(scan_id) ON DELETE CASCADE,
    provider TEXT NOT NULL DEFAULT 'interactsh',
    interaction_type TEXT NOT NULL,
    correlation_id TEXT NOT NULL,
    source_endpoint TEXT DEFAULT '',
    raw JSONB DEFAULT '{}',
    severity TEXT DEFAULT 'high',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_recon_oob_scan ON recon_oob_interactions(scan_id);
CREATE INDEX IF NOT EXISTS idx_recon_oob_corr ON recon_oob_interactions(correlation_id);

-- Add phase tracking columns to recon_runs if not present (idempotent)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                   WHERE table_name='recon_runs' AND column_name='current_phase') THEN
        ALTER TABLE recon_runs ADD COLUMN current_phase TEXT DEFAULT 'initialization';
        ALTER TABLE recon_runs ADD COLUMN phase_data JSONB DEFAULT '{}';
    END IF;
END $$;

-- 12. Agent learning / decisions / cluster tables (referenced by code but
--     never previously defined).
CREATE TABLE IF NOT EXISTS agent_proficiency (
    agent_id TEXT NOT NULL,
    skill TEXT NOT NULL,
    proficiency_score DOUBLE PRECISION DEFAULT 0,
    total_attempts INTEGER DEFAULT 0,
    successful_attempts INTEGER DEFAULT 0,
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (agent_id, skill)
);

CREATE TABLE IF NOT EXISTS agent_decisions (
    decision_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action_type TEXT NOT NULL,
    rationale TEXT DEFAULT '',
    confidence DOUBLE PRECISION DEFAULT 0,
    alternatives_considered JSONB DEFAULT '[]',
    context JSONB DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_agent_decisions_agent_time
    ON agent_decisions(agent_id, timestamp DESC);

CREATE TABLE IF NOT EXISTS task_assignments (
    task_id TEXT NOT NULL,
    scan_id TEXT DEFAULT '',
    worker_id TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    payload JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (task_id)
);

CREATE INDEX IF NOT EXISTS idx_task_assignments_worker_status
    ON task_assignments(worker_id, status);

-- 13. Automatic timestamp management
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

DROP TRIGGER IF EXISTS update_tasks_updated_at ON distributed_tasks;
CREATE TRIGGER update_tasks_updated_at BEFORE UPDATE ON distributed_tasks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
