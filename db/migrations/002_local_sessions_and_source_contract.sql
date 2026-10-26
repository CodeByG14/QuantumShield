-- Local browser sessions and safe source/workspace metadata for the backend.
-- Do not store raw browser session tokens or absolute temporary workspace paths.

CREATE TABLE local_sessions (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    display_name VARCHAR(120),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ,
    CHECK (display_name IS NULL OR length(trim(display_name)) > 0),
    CHECK (expires_at IS NULL OR expires_at > created_at)
);

CREATE INDEX idx_local_sessions_expires_at
    ON local_sessions (expires_at) WHERE expires_at IS NOT NULL;

-- Existing projects remain nullable for backward compatibility. New API-created
-- projects must always be associated with the current local session.
ALTER TABLE projects
    ADD COLUMN session_id UUID REFERENCES local_sessions(session_id) ON DELETE CASCADE;

CREATE INDEX idx_projects_session_updated
    ON projects (session_id, updated_at DESC) WHERE session_id IS NOT NULL;

-- One fresh workspace UUID per scan attempt; it identifies a temp directory but
-- deliberately does not store the absolute path. It may remain after cleanup for
-- logs/diagnostics and must never be reused as project_id or assessment_id.
ALTER TABLE scan_runs ADD COLUMN workspace_id UUID;
CREATE UNIQUE INDEX idx_scan_runs_workspace_id
    ON scan_runs (workspace_id) WHERE workspace_id IS NOT NULL;

-- Store a sanitized repository reference when applicable (never credentials,
-- access tokens, query strings, or fragments). Uploads can leave this null.
ALTER TABLE scan_runs ADD COLUMN source_reference TEXT;
ALTER TABLE scan_runs ADD CONSTRAINT scan_runs_source_reference_nonempty
    CHECK (source_reference IS NULL OR length(trim(source_reference)) > 0);

COMMENT ON COLUMN scan_runs.workspace_id IS
    'Random UUID for one temporary workspace; never store the workspace filesystem path here.';
COMMENT ON COLUMN scan_runs.source_reference IS
    'Sanitized source reference such as an HTTPS GitHub repository URL; never include credentials or tokens.';
COMMENT ON COLUMN projects.session_id IS
    'Local browser workspace owner; new application-created projects must set this field.';
COMMENT ON TABLE local_sessions IS
    'Anonymous local UI sessions; token_hash is SHA-256 of a high-entropy cookie token, never the raw token.';
