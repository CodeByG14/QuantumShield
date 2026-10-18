# QuantumShield Database Schema Design — Week 6

**Purpose:** Define the PostgreSQL data model for persistent storage of projects, assessments, findings, coverage, risk results, context/policy versions, dependencies, and migration plans.

**Design principles:**
- Keep discovery evidence separate from policy-derived scores for rescoring under new policies
- Use stable identifiers and explicit schema versions
- Support assessment comparison through deterministic fingerprinting
- Track provenance: where did each value come from?
- Never store private key material or secrets

**Status:** Design document for Week 6. Production database connectivity will be implemented in Week 8.

---

## 1. Core Entities and Relationships

```
projects (1) ──┬──> (*) assessments
               │
               └──> (*) project_contexts (versioned)

assessments (1) ──┬──> (*) findings
                  ├──> (*) coverage_records
                  ├──> (*) risk_assessments
                  ├──> (*) dependencies (future)
                  └──> (*) migration_tasks (future)

findings (1) ───> (*) evidence_records

risk_assessments (1) ───> (*) risk_factors
```

---

## 2. Schema Version and Metadata

### `schema_metadata`
Tracks schema evolution and ensures compatibility.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `version` | VARCHAR(20) | PRIMARY KEY | Schema version (e.g., "1.0", "1.1") |
| `applied_at` | TIMESTAMPTZ | NOT NULL | When this version was applied |
| `description` | TEXT | NOT NULL | What changed in this version |

---

## 3. Projects

### `projects`
Top-level entity representing a codebase or system under assessment.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `project_id` | UUID | PRIMARY KEY | Stable project identifier |
| `project_name` | VARCHAR(255) | NOT NULL | Display name |
| `owner` | VARCHAR(255) | | Optional owner/team |
| `description` | TEXT | | Project description |
| `created_at` | TIMESTAMPTZ | NOT NULL | Creation timestamp |
| `updated_at` | TIMESTAMPTZ | NOT NULL | Last update timestamp |
| `archived` | BOOLEAN | NOT NULL DEFAULT FALSE | Soft delete flag |

**Indexes:**
- `idx_projects_name` on `project_name` for search
- `idx_projects_updated` on `updated_at` DESC for recent projects

---

## 4. Project Context (Versioned)

### `project_contexts`
Versioned context configurations for risk assessment. A project can have multiple context versions over time.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `context_id` | UUID | PRIMARY KEY | Unique context version identifier |
| `project_id` | UUID | NOT NULL, FK projects | Parent project |
| `version` | INTEGER | NOT NULL | Monotonic version number for this project |
| `data_sensitivity` | INTEGER | CHECK 0..5 | Project-level data sensitivity |
| `confidentiality_years` | DECIMAL(10,2) | CHECK >= 0 | Required confidentiality lifetime |
| `exposure` | INTEGER | CHECK 0..5 | Exposure level |
| `system_criticality` | INTEGER | CHECK 0..5 | System criticality |
| `migration_years` | DECIMAL(10,2) | CHECK >= 0 | Estimated migration duration |
| `threat_horizon_year` | INTEGER | CHECK 2000..2100 | Threat horizon assumption |
| `created_at` | TIMESTAMPTZ | NOT NULL | When this context was created |
| `created_by` | VARCHAR(255) | | Who created this version |

**Constraints:**
- UNIQUE(`project_id`, `version`)

**Indexes:**
- `idx_context_project_version` on (`project_id`, `version` DESC)

---

## 5. Asset-Level Context Overrides

### `asset_contexts`
Asset/component-level context overrides with explicit precedence.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `asset_context_id` | UUID | PRIMARY KEY | Unique identifier |
| `context_id` | UUID | NOT NULL, FK project_contexts | Parent context version |
| `asset_id` | VARCHAR(500) | NOT NULL | Finding ID, file path, or component identifier |
| `data_sensitivity` | INTEGER | CHECK 0..5 | Override for this asset |
| `confidentiality_years` | DECIMAL(10,2) | CHECK >= 0 | Override for this asset |
| `exposure` | INTEGER | CHECK 0..5 | Override for this asset |
| `system_criticality` | INTEGER | CHECK 0..5 | Override for this asset |
| `migration_years` | DECIMAL(10,2) | CHECK >= 0 | Override for this asset |
| `threat_horizon_year` | INTEGER | CHECK 2000..2100 | Override for this asset |

**Constraints:**
- UNIQUE(`context_id`, `asset_id`)

**Indexes:**
- `idx_asset_context_lookup` on (`context_id`, `asset_id`)

**Note:** NULL values mean "not overridden; fall through to project-level context."

---

## 6. Assessments

### `assessments`
A single scan/assessment run for a project.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `assessment_id` | UUID | PRIMARY KEY | Unique assessment identifier |
| `project_id` | UUID | NOT NULL, FK projects | Parent project |
| `context_id` | UUID | FK project_contexts | Context version used |
| `scan_timestamp` | TIMESTAMPTZ | NOT NULL | When the scan started |
| `completed_at` | TIMESTAMPTZ | | When the scan finished (NULL if in progress) |
| `status` | VARCHAR(20) | NOT NULL | queued, running, completed, failed, cancelled |
| `source_type` | VARCHAR(50) | | git, directory, sbom, cbom, etc. |
| `source_revision` | VARCHAR(255) | | Git commit hash, archive hash, etc. |
| `source_url` | TEXT | | Repository URL or source location |
| `scanner_version` | VARCHAR(50) | NOT NULL | QuantumShield version that ran this |
| `policy_version` | VARCHAR(20) | NOT NULL | Risk policy version (e.g., "1.0") |
| `schema_version` | VARCHAR(20) | NOT NULL | Assessment schema version |
| `error_message` | TEXT | | Error details if status=failed |
| `target_path` | TEXT | | Scanned directory or input file |

**Indexes:**
- `idx_assessment_project_time` on (`project_id`, `scan_timestamp` DESC)
- `idx_assessment_status` on `status` WHERE status IN ('queued', 'running')

---

## 7. Findings (Discovery Evidence)

### `findings`
Cryptographic findings discovered during scanning. Evidence is kept separate from risk scores.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `finding_pk` | BIGSERIAL | PRIMARY KEY | Internal surrogate key |
| `finding_id` | VARCHAR(50) | NOT NULL | Display ID (CRYPTO-001, etc.) |
| `assessment_id` | UUID | NOT NULL, FK assessments | Parent assessment |
| `fingerprint` | VARCHAR(64) | NOT NULL | Stable hash for comparison across assessments |
| `algorithm` | VARCHAR(100) | NOT NULL | Algorithm family (RSA, AES, etc.) |
| `variant` | VARCHAR(100) | | Specific variant (RSA-2048, etc.) |
| `key_size` | INTEGER | CHECK > 0 | Key size in bits |
| `curve` | VARCHAR(100) | | Elliptic curve name |
| `role` | VARCHAR(50) | NOT NULL | key-establishment, signature, hash, etc. |
| `purpose` | TEXT | | Detected or inferred cryptographic purpose |
| `status` | VARCHAR(30) | NOT NULL | confirmed, potential, unable-to-analyze |
| `confidence` | VARCHAR(20) | NOT NULL | high, medium, low, unknown |
| `evidence_gap_reason` | TEXT | | Why analysis failed or is incomplete |
| `primary_file_path` | TEXT | | Primary source file |
| `primary_line_start` | INTEGER | | Starting line number |
| `primary_line_end` | INTEGER | | Ending line number |

**Constraints:**
- UNIQUE(`assessment_id`, `finding_id`)
- UNIQUE(`assessment_id`, `fingerprint`)

**Indexes:**
- `idx_finding_assessment` on `assessment_id`
- `idx_finding_fingerprint` on (`assessment_id`, `fingerprint`)
- `idx_finding_algorithm` on `algorithm`
- `idx_finding_role` on `role`

**Fingerprint calculation:** SHA-256 of `{algorithm, variant, key_size, curve, role, primary_file_path, primary_line_start}` to enable deterministic comparison across assessments.

---

## 8. Evidence Records

### `evidence_records`
Individual pieces of evidence supporting a finding.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `evidence_pk` | BIGSERIAL | PRIMARY KEY | Internal surrogate key |
| `evidence_id` | VARCHAR(50) | NOT NULL | Display ID (CRYPTO-001-E1, etc.) |
| `finding_pk` | BIGINT | NOT NULL, FK findings | Parent finding |
| `file_path` | TEXT | NOT NULL | Source file |
| `line_start` | INTEGER | CHECK >= 1 | Starting line |
| `line_end` | INTEGER | CHECK >= line_start | Ending line |
| `evidence_type` | VARCHAR(50) | NOT NULL | api-call, keyword, certificate, etc. |
| `detection_method` | VARCHAR(50) | NOT NULL | regex, manifest, x509, etc. |
| `rule_id` | VARCHAR(100) | NOT NULL | Detection rule identifier |
| `excerpt` | TEXT | | Safe excerpt (bounded, no secrets) |
| `confidence` | VARCHAR(20) | NOT NULL | high, medium, low |
| `metadata` | JSONB | | Additional structured metadata |

**Indexes:**
- `idx_evidence_finding` on `finding_pk`
- `idx_evidence_file` on `file_path`

---

## 9. Coverage Records

### `coverage_records`
Per-file analysis outcomes for transparency.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `coverage_pk` | BIGSERIAL | PRIMARY KEY | Internal surrogate key |
| `assessment_id` | UUID | NOT NULL, FK assessments | Parent assessment |
| `file_path` | TEXT | NOT NULL | File being reported |
| `outcome` | VARCHAR(20) | NOT NULL | analyzed, partial, failed, unsupported, skipped |
| `stages` | JSONB | | Per-stage status {source: success, x509: failed} |
| `reason` | TEXT | | Why not fully analyzed |

**Constraints:**
- UNIQUE(`assessment_id`, `file_path`)

**Indexes:**
- `idx_coverage_assessment` on `assessment_id`
- `idx_coverage_outcome` on (`assessment_id`, `outcome`)

---

## 10. Risk Assessments (Policy-Derived)

### `risk_assessments`
Risk scores derived from findings using a versioned policy. Separate from discovery so rescoring is possible.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `risk_pk` | BIGSERIAL | PRIMARY KEY | Internal surrogate key |
| `assessment_id` | UUID | NOT NULL, FK assessments | Parent assessment |
| `finding_pk` | BIGINT | NOT NULL, FK findings | Finding being assessed |
| `risk_kind` | VARCHAR(50) | NOT NULL | hndl-confidentiality, signature-transition, classical-weakness, not-hndl-applicable, not-assessed |
| `risk_score` | DECIMAL(5,2) | CHECK 0..100 | Computed score (NULL if not scored) |
| `risk_level` | VARCHAR(20) | | critical, very-high, high, moderate, low (NULL if not scored) |
| `baseline_score` | DECIMAL(5,2) | CHECK 0..100 | Score before escalations |
| `escalations` | JSONB | | Array of escalation reasons |
| `explanation` | JSONB | | Array of explanation strings |
| `missing_inputs` | JSONB | | Array of missing context field names |
| `provisional` | BOOLEAN | NOT NULL | Whether result is provisional |
| `confidence` | VARCHAR(20) | NOT NULL | Finding confidence (repeated for convenience) |
| `policy_version` | VARCHAR(20) | NOT NULL | Risk policy version |

**Constraints:**
- UNIQUE(`assessment_id`, `finding_pk`)
- CHECK: if `risk_kind` in (hndl-confidentiality, signature-transition, classical-weakness) then `risk_score` and `risk_level` NOT NULL

**Indexes:**
- `idx_risk_assessment` on `assessment_id`
- `idx_risk_finding` on `finding_pk`
- `idx_risk_level` on (`assessment_id`, `risk_level`, `risk_kind`)

---

## 11. Risk Factors

### `risk_factors`
Individual factor contributions to a risk score, with provenance tracking.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `factor_pk` | BIGSERIAL | PRIMARY KEY | Internal surrogate key |
| `risk_pk` | BIGINT | NOT NULL, FK risk_assessments | Parent risk assessment |
| `factor_name` | VARCHAR(100) | NOT NULL | quantum_vulnerability, data_sensitivity, etc. |
| `score` | DECIMAL(4,2) | NOT NULL, CHECK 0..5 | Factor score (0..5 scale) |
| `weight` | DECIMAL(5,4) | NOT NULL, CHECK 0..1 | Factor weight (normalized) |
| `contribution` | DECIMAL(6,4) | NOT NULL, CHECK >= 0 | Weighted contribution to final score |
| `basis` | VARCHAR(20) | NOT NULL | observed, supplied, assumed |
| `assumed` | BOOLEAN | NOT NULL | Whether this factor uses an assumption |
| `context_source` | VARCHAR(30) | | finding_override, asset_context, project_context, policy_default, observed |

**Indexes:**
- `idx_factor_risk` on `risk_pk`

**Provenance:** `context_source` explicitly tracks where the value came from in the context hierarchy, enabling transparency and debugging.

---

## 12. Dependencies (Future — Week 7)

### `dependencies`
Relationships between cryptographic findings and packages/components.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `dependency_pk` | BIGSERIAL | PRIMARY KEY | Internal surrogate key |
| `assessment_id` | UUID | NOT NULL, FK assessments | Parent assessment |
| `source_finding_pk` | BIGINT | FK findings | Source finding (nullable for component-to-component) |
| `source_component` | VARCHAR(500) | | Source component identifier |
| `target_component` | VARCHAR(500) | NOT NULL | Target component identifier |
| `relationship_type` | VARCHAR(50) | NOT NULL | uses, depends-on, transitively-depends-on |
| `evidence` | TEXT | | How this dependency was determined |
| `confidence` | VARCHAR(20) | NOT NULL | high, medium, low |

**Indexes:**
- `idx_dep_assessment` on `assessment_id`
- `idx_dep_source` on `source_component`
- `idx_dep_target` on `target_component`

---

## 13. Migration Plans and Tasks (Future — Week 6 Track 2 + later)

### `migration_plans`
Generated migration plans for an assessment.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `plan_id` | UUID | PRIMARY KEY | Unique plan identifier |
| `assessment_id` | UUID | NOT NULL, FK assessments | Parent assessment |
| `recommendation_policy_version` | VARCHAR(20) | NOT NULL | Version of recommendation policy used |
| `generated_at` | TIMESTAMPTZ | NOT NULL | When plan was generated |
| `plan_status` | VARCHAR(20) | NOT NULL | draft, approved, in-progress, completed |

**Indexes:**
- `idx_plan_assessment` on `assessment_id`

### `migration_tasks`
Individual migration tasks within a plan.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `task_pk` | BIGSERIAL | PRIMARY KEY | Internal surrogate key |
| `task_id` | VARCHAR(50) | NOT NULL | Display ID (TASK-001, etc.) |
| `plan_id` | UUID | NOT NULL, FK migration_plans | Parent plan |
| `finding_pk` | BIGINT | FK findings | Affected finding (nullable for component-level tasks) |
| `affected_component` | VARCHAR(500) | | Component or file affected |
| `source_algorithm` | VARCHAR(100) | | Current algorithm |
| `source_role` | VARCHAR(50) | | Cryptographic role |
| `recommended_algorithm` | VARCHAR(100) | | Recommended replacement |
| `recommendation_standard` | VARCHAR(100) | | FIPS 203, FIPS 204, etc. |
| `rationale` | TEXT | NOT NULL | Why this recommendation |
| `compatibility_notes` | TEXT | | Compatibility caveats |
| `prerequisites` | JSONB | | Array of prerequisite task IDs |
| `effort_band` | VARCHAR(20) | | small, medium, large, research |
| `priority` | INTEGER | NOT NULL | Ordering/priority (lower = higher priority) |
| `confidence` | VARCHAR(20) | NOT NULL | high, medium, low, review-required |
| `verification_steps` | JSONB | | Array of verification step descriptions |
| `task_status` | VARCHAR(20) | NOT NULL | pending, in-progress, completed, blocked, deferred |

**Constraints:**
- UNIQUE(`plan_id`, `task_id`)

**Indexes:**
- `idx_task_plan` on `plan_id`
- `idx_task_finding` on `finding_pk`
- `idx_task_priority` on (`plan_id`, `priority`)

---

## 14. Comparison and Reports (Future — Week 7+)

### `assessment_comparisons`
Records of assessment-to-assessment comparisons.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| `comparison_id` | UUID | PRIMARY KEY | Unique comparison identifier |
| `project_id` | UUID | NOT NULL, FK projects | Parent project |
| `baseline_assessment_id` | UUID | NOT NULL, FK assessments | Earlier assessment |
| `current_assessment_id` | UUID | NOT NULL, FK assessments | Later assessment |
| `compared_at` | TIMESTAMPTZ | NOT NULL | When comparison was run |
| `findings_added` | INTEGER | NOT NULL | Count of new findings |
| `findings_removed` | INTEGER | NOT NULL | Count of removed findings |
| `findings_changed` | INTEGER | NOT NULL | Count of changed findings |
| `findings_unchanged` | INTEGER | NOT NULL | Count of unchanged findings |
| `summary` | JSONB | | Structured comparison summary |

**Indexes:**
- `idx_comparison_project` on `project_id`
- `idx_comparison_assessments` on (`baseline_assessment_id`, `current_assessment_id`)

---

## 15. Deletion and Retention Policy

**Soft deletion:**
- Projects: set `archived=TRUE`, retain assessments
- Assessments: retain indefinitely unless explicitly purged by project owner
- Context versions: retain for audit trail

**Hard deletion (administrator action):**
- CASCADE delete from `projects` removes all linked assessments, findings, risks
- Individual assessment deletion removes findings, coverage, risks, but retains project

**No secrets stored:**
- Private key material: never persisted
- Excerpts: bounded to 200 characters and sanitized
- Metadata: reviewed to ensure no credential leakage

---

## 16. Migrations and Versioning

**Schema evolution:**
1. Each migration is a versioned SQL file: `001_initial.sql`, `002_add_asset_contexts.sql`, etc.
2. Use a migration tool (e.g., Alembic, Flyway, or custom) to track applied versions
3. Test migrations on a copy of production data before applying

**Backward compatibility:**
- New columns should be nullable or have defaults
- Renamed columns need a transition period with both old and new
- Breaking changes require a major version bump and documented migration path

---

## 17. Initial SQL Schema Draft (PostgreSQL)

```sql
-- Week 6 Initial Schema for QuantumShield
-- This is a starting point; adjust types, indexes, and constraints as implementation proceeds.

BEGIN;

-- Schema metadata
CREATE TABLE schema_metadata (
    version VARCHAR(20) PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    description TEXT NOT NULL
);

INSERT INTO schema_metadata (version, description)
VALUES ('1.0', 'Week 6 initial schema: projects, assessments, findings, risk with asset-level context');

-- Projects
CREATE TABLE projects (
    project_id UUID PRIMARY KEY,
    project_name VARCHAR(255) NOT NULL,
    owner VARCHAR(255),
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    archived BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_projects_name ON projects(project_name);
CREATE INDEX idx_projects_updated ON projects(updated_at DESC);

-- Project contexts (versioned)
CREATE TABLE project_contexts (
    context_id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    data_sensitivity INTEGER CHECK (data_sensitivity BETWEEN 0 AND 5),
    confidentiality_years DECIMAL(10,2) CHECK (confidentiality_years >= 0),
    exposure INTEGER CHECK (exposure BETWEEN 0 AND 5),
    system_criticality INTEGER CHECK (system_criticality BETWEEN 0 AND 5),
    migration_years DECIMAL(10,2) CHECK (migration_years >= 0),
    threat_horizon_year INTEGER CHECK (threat_horizon_year BETWEEN 2000 AND 2100),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_by VARCHAR(255),
    UNIQUE(project_id, version)
);

CREATE INDEX idx_context_project_version ON project_contexts(project_id, version DESC);

-- Asset-level context overrides
CREATE TABLE asset_contexts (
    asset_context_id UUID PRIMARY KEY,
    context_id UUID NOT NULL REFERENCES project_contexts(context_id) ON DELETE CASCADE,
    asset_id VARCHAR(500) NOT NULL,
    data_sensitivity INTEGER CHECK (data_sensitivity BETWEEN 0 AND 5),
    confidentiality_years DECIMAL(10,2) CHECK (confidentiality_years >= 0),
    exposure INTEGER CHECK (exposure BETWEEN 0 AND 5),
    system_criticality INTEGER CHECK (system_criticality BETWEEN 0 AND 5),
    migration_years DECIMAL(10,2) CHECK (migration_years >= 0),
    threat_horizon_year INTEGER CHECK (threat_horizon_year BETWEEN 2000 AND 2100),
    UNIQUE(context_id, asset_id)
);

CREATE INDEX idx_asset_context_lookup ON asset_contexts(context_id, asset_id);

-- Assessments
CREATE TABLE assessments (
    assessment_id UUID PRIMARY KEY,
    project_id UUID NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    context_id UUID REFERENCES project_contexts(context_id),
    scan_timestamp TIMESTAMPTZ NOT NULL,
    completed_at TIMESTAMPTZ,
    status VARCHAR(20) NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
    source_type VARCHAR(50),
    source_revision VARCHAR(255),
    source_url TEXT,
    scanner_version VARCHAR(50) NOT NULL,
    policy_version VARCHAR(20) NOT NULL,
    schema_version VARCHAR(20) NOT NULL,
    error_message TEXT,
    target_path TEXT
);

CREATE INDEX idx_assessment_project_time ON assessments(project_id, scan_timestamp DESC);
CREATE INDEX idx_assessment_status ON assessments(status) WHERE status IN ('queued', 'running');

-- Findings
CREATE TABLE findings (
    finding_pk BIGSERIAL PRIMARY KEY,
    finding_id VARCHAR(50) NOT NULL,
    assessment_id UUID NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    fingerprint VARCHAR(64) NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    variant VARCHAR(100),
    key_size INTEGER CHECK (key_size > 0),
    curve VARCHAR(100),
    role VARCHAR(50) NOT NULL,
    purpose TEXT,
    status VARCHAR(30) NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    evidence_gap_reason TEXT,
    primary_file_path TEXT,
    primary_line_start INTEGER,
    primary_line_end INTEGER,
    UNIQUE(assessment_id, finding_id),
    UNIQUE(assessment_id, fingerprint)
);

CREATE INDEX idx_finding_assessment ON findings(assessment_id);
CREATE INDEX idx_finding_fingerprint ON findings(assessment_id, fingerprint);
CREATE INDEX idx_finding_algorithm ON findings(algorithm);
CREATE INDEX idx_finding_role ON findings(role);

-- Evidence records
CREATE TABLE evidence_records (
    evidence_pk BIGSERIAL PRIMARY KEY,
    evidence_id VARCHAR(50) NOT NULL,
    finding_pk BIGINT NOT NULL REFERENCES findings(finding_pk) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    line_start INTEGER CHECK (line_start >= 1),
    line_end INTEGER CHECK (line_end >= line_start),
    evidence_type VARCHAR(50) NOT NULL,
    detection_method VARCHAR(50) NOT NULL,
    rule_id VARCHAR(100) NOT NULL,
    excerpt TEXT,
    confidence VARCHAR(20) NOT NULL,
    metadata JSONB
);

CREATE INDEX idx_evidence_finding ON evidence_records(finding_pk);
CREATE INDEX idx_evidence_file ON evidence_records(file_path);

-- Coverage records
CREATE TABLE coverage_records (
    coverage_pk BIGSERIAL PRIMARY KEY,
    assessment_id UUID NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    outcome VARCHAR(20) NOT NULL CHECK (outcome IN ('analyzed', 'partial', 'failed', 'unsupported', 'skipped')),
    stages JSONB,
    reason TEXT,
    UNIQUE(assessment_id, file_path)
);

CREATE INDEX idx_coverage_assessment ON coverage_records(assessment_id);
CREATE INDEX idx_coverage_outcome ON coverage_records(assessment_id, outcome);

-- Risk assessments
CREATE TABLE risk_assessments (
    risk_pk BIGSERIAL PRIMARY KEY,
    assessment_id UUID NOT NULL REFERENCES assessments(assessment_id) ON DELETE CASCADE,
    finding_pk BIGINT NOT NULL REFERENCES findings(finding_pk) ON DELETE CASCADE,
    risk_kind VARCHAR(50) NOT NULL CHECK (risk_kind IN ('hndl-confidentiality', 'signature-transition', 'classical-weakness', 'not-hndl-applicable', 'not-assessed')),
    risk_score DECIMAL(5,2) CHECK (risk_score BETWEEN 0 AND 100),
    risk_level VARCHAR(20) CHECK (risk_level IN ('critical', 'very-high', 'high', 'moderate', 'low')),
    baseline_score DECIMAL(5,2) CHECK (baseline_score BETWEEN 0 AND 100),
    escalations JSONB,
    explanation JSONB,
    missing_inputs JSONB,
    provisional BOOLEAN NOT NULL,
    confidence VARCHAR(20) NOT NULL,
    policy_version VARCHAR(20) NOT NULL,
    UNIQUE(assessment_id, finding_pk)
);

CREATE INDEX idx_risk_assessment ON risk_assessments(assessment_id);
CREATE INDEX idx_risk_finding ON risk_assessments(finding_pk);
CREATE INDEX idx_risk_level ON risk_assessments(assessment_id, risk_level, risk_kind);

-- Risk factors (with provenance)
CREATE TABLE risk_factors (
    factor_pk BIGSERIAL PRIMARY KEY,
    risk_pk BIGINT NOT NULL REFERENCES risk_assessments(risk_pk) ON DELETE CASCADE,
    factor_name VARCHAR(100) NOT NULL,
    score DECIMAL(4,2) NOT NULL CHECK (score BETWEEN 0 AND 5),
    weight DECIMAL(5,4) NOT NULL CHECK (weight BETWEEN 0 AND 1),
    contribution DECIMAL(6,4) NOT NULL CHECK (contribution >= 0),
    basis VARCHAR(20) NOT NULL,
    assumed BOOLEAN NOT NULL,
    context_source VARCHAR(30)
);

CREATE INDEX idx_factor_risk ON risk_factors(risk_pk);

COMMIT;
```

---

## 18. Future Extensions

**Week 7:**
- Dependencies table and relationship tracking
- Assessment comparison tables

**Week 8:**
- Backend API layer
- Authentication and authorization schema (users, roles, permissions)
- Background job tracking

**Week 9:**
- Audit log table
- Policy compliance tracking

**Week 10+:**
- Algorithm-transition test results
- Performance benchmark records
- Configuration-driven agility policy versions

---

## Summary

This schema design provides:
1. ✅ Clear separation of discovery evidence and policy-derived risk scores
2. ✅ Stable identifiers and fingerprints for assessment comparison
3. ✅ Asset-level context overrides with explicit precedence
4. ✅ Context provenance tracking (finding_override > asset > project > policy default)
5. ✅ Versioned contexts and policies for historical analysis
6. ✅ Extensible structure for dependencies and migration plans
7. ✅ No storage of private key material or secrets

The schema is ready for implementation in Week 8 when backend and database connectivity work begins.
