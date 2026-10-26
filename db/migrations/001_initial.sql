-- QuantumShield database baseline.
-- This file is applied transactionally by scripts/db-migrate.sh.
-- Do not edit a migration after it has been applied; add a new numbered file.

CREATE TABLE projects (
    project_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_name VARCHAR(255) NOT NULL CHECK (length(trim(project_name)) > 0),
    owner VARCHAR(255),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_projects_name_lower ON projects (lower(project_name));
CREATE INDEX idx_projects_updated_at ON projects (updated_at DESC);

-- A scan run records execution and input metadata, not uploaded source bytes.
-- Temporary workspace paths and secret-bearing source files are not persisted here.
CREATE TABLE scan_runs (
    scan_run_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    input_kind VARCHAR(40) NOT NULL CHECK (
        input_kind IN ('local_directory', 'zip_archive', 'github_repository', 'sbom', 'cbom', 'other')
    ),
    input_name TEXT,
    source_revision VARCHAR(255),
    source_fingerprint VARCHAR(64) CHECK (
        source_fingerprint IS NULL OR source_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    status VARCHAR(20) NOT NULL DEFAULT 'queued' CHECK (
        status IN ('queued', 'running', 'completed', 'failed', 'cancelled')
    ),
    started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ,
    error_message TEXT,
    CHECK (completed_at IS NULL OR completed_at >= started_at)
);

CREATE INDEX idx_scan_runs_project_started ON scan_runs (project_id, started_at DESC);
CREATE INDEX idx_scan_runs_status_active ON scan_runs (status) WHERE status IN ('queued', 'running');
CREATE INDEX idx_scan_runs_source_fingerprint ON scan_runs (source_fingerprint)
    WHERE source_fingerprint IS NOT NULL;

-- Preserve the full engine output as a snapshot; the JSONB snapshot is the source of truth.
CREATE TABLE assessments (
    assessment_id TEXT PRIMARY KEY CHECK (length(trim(assessment_id)) > 0),
    scan_run_id UUID NOT NULL UNIQUE REFERENCES scan_runs(scan_run_id) ON DELETE CASCADE,
    policy_version VARCHAR(50) NOT NULL,
    assessment_schema_version VARCHAR(50) NOT NULL,
    assessment_json JSONB NOT NULL CHECK (jsonb_typeof(assessment_json) = 'object'),
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(summary_json) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_assessments_policy_version ON assessments (policy_version);

-- Searchable projection of findings, while retaining each full finding and risk object.
CREATE TABLE assessment_findings (
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    finding_id VARCHAR(100) NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    variant VARCHAR(150),
    role VARCHAR(80) NOT NULL,
    status VARCHAR(40) NOT NULL,
    confidence VARCHAR(30),
    file_path TEXT,
    risk_kind VARCHAR(80),
    risk_level VARCHAR(40),
    risk_score NUMERIC(6,2) CHECK (risk_score IS NULL OR risk_score BETWEEN 0 AND 100),
    finding_json JSONB NOT NULL CHECK (jsonb_typeof(finding_json) = 'object'),
    risk_json JSONB CHECK (risk_json IS NULL OR jsonb_typeof(risk_json) = 'object'),
    PRIMARY KEY (assessment_id, finding_id)
);

CREATE INDEX idx_assessment_findings_algorithm ON assessment_findings (algorithm);
CREATE INDEX idx_assessment_findings_role ON assessment_findings (role);
CREATE INDEX idx_assessment_findings_file_path ON assessment_findings (file_path) WHERE file_path IS NOT NULL;
CREATE INDEX idx_assessment_findings_risk_level ON assessment_findings (assessment_id, risk_level)
    WHERE risk_level IS NOT NULL;

CREATE TABLE migration_plans (
    migration_plan_id TEXT PRIMARY KEY CHECK (length(trim(migration_plan_id)) > 0),
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    recommendation_policy_version VARCHAR(50),
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    plan_json JSONB NOT NULL CHECK (jsonb_typeof(plan_json) = 'object'),
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(summary_json) = 'object')
);

CREATE INDEX idx_migration_plans_assessment_generated ON migration_plans (assessment_id, generated_at DESC);

CREATE TABLE compliance_reports (
    report_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    migration_plan_id TEXT REFERENCES migration_plans(migration_plan_id) ON DELETE SET NULL,
    as_of DATE,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    report_json JSONB NOT NULL CHECK (jsonb_typeof(report_json) = 'object'),
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(summary_json) = 'object')
);

CREATE INDEX idx_compliance_reports_assessment_generated
    ON compliance_reports (assessment_id, generated_at DESC);
CREATE INDEX idx_compliance_reports_migration_plan ON compliance_reports (migration_plan_id)
    WHERE migration_plan_id IS NOT NULL;

CREATE TABLE scan_diffs (
    diff_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    baseline_assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    current_assessment_id TEXT NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    diff_json JSONB NOT NULL CHECK (jsonb_typeof(diff_json) = 'object'),
    summary_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(summary_json) = 'object'),
    CHECK (baseline_assessment_id <> current_assessment_id)
);

CREATE INDEX idx_scan_diffs_baseline_generated ON scan_diffs (baseline_assessment_id, generated_at DESC);
CREATE INDEX idx_scan_diffs_current_generated ON scan_diffs (current_assessment_id, generated_at DESC);
