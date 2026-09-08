-- ARGUS Database Schema
-- Run: psql -U postgres -d argus -f schema.sql

CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "vector";   -- pgvector for compliance rule embeddings

-- ─── scan_jobs ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_jobs (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    repo_full_name      VARCHAR(255) NOT NULL,
    pr_url              TEXT        NOT NULL,
    pr_number           INTEGER     NOT NULL,
    status              VARCHAR(50) NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','running','complete','failed')),
    compliance_frameworks TEXT[]   NOT NULL DEFAULT '{"SOC2","HIPAA","PCI-DSS"}',
    risk_score          INTEGER     CHECK (risk_score BETWEEN 0 AND 100),
    total_findings      INTEGER     NOT NULL DEFAULT 0,
    remediation_pr_url  TEXT,
    arch_image_url      TEXT,
    summary             JSONB,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at        TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_scanjobs_repo    ON scan_jobs(repo_full_name);
CREATE INDEX IF NOT EXISTS idx_scanjobs_status  ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scanjobs_created ON scan_jobs(created_at DESC);

-- ─── findings ──────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id                  UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id             UUID        NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    agent               VARCHAR(50) NOT NULL,
    title               TEXT        NOT NULL,
    description         TEXT        NOT NULL,
    severity            VARCHAR(20) NOT NULL CHECK (severity IN ('critical','high','medium','low','info')),
    cwe_id              VARCHAR(20),
    location            TEXT,
    line_number         INTEGER,
    remediation_hint    TEXT        NOT NULL,
    compliance_refs     TEXT[]      NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_id  ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_cwe      ON findings(cwe_id);

-- ─── agent_traces ──────────────────────────────────────────────────────────
-- Persists the streaming thought trace for replay / audit
CREATE TABLE IF NOT EXISTS agent_traces (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID        NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    agent       VARCHAR(50) NOT NULL,
    trace       TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_traces_scan_agent ON agent_traces(scan_id, agent);

-- ─── compliance_rules ──────────────────────────────────────────────────────
-- Stores embedded compliance articles for pgvector similarity search
CREATE TABLE IF NOT EXISTS compliance_rules (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    framework   VARCHAR(20) NOT NULL,           -- SOC2 | HIPAA | PCI-DSS
    rule_ref    VARCHAR(50) NOT NULL,           -- e.g. CC6.1, 164.312(b)
    title       TEXT        NOT NULL,
    description TEXT        NOT NULL,
    severity    VARCHAR(20) NOT NULL DEFAULT 'high',
    embedding   vector(1536),                   -- text-embedding-3-small
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (framework, rule_ref)
);

CREATE INDEX IF NOT EXISTS idx_rules_framework ON compliance_rules(framework);
CREATE INDEX IF NOT EXISTS idx_rules_embedding ON compliance_rules
    USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ─── attack_chains ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS attack_chains (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id     UUID        NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE UNIQUE,
    steps       TEXT[]      NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Auto-update updated_at trigger ────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_scanjobs_updated
    BEFORE UPDATE ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
