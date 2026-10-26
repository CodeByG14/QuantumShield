\set ON_ERROR_STOP on

DO $$
DECLARE
    required_table TEXT;
    required_tables TEXT[] := ARRAY[
        'schema_migrations', 'projects', 'scan_runs', 'assessments',
        'assessment_findings', 'migration_plans', 'compliance_reports', 'scan_diffs'
    ];
BEGIN
    FOREACH required_table IN ARRAY required_tables LOOP
        IF to_regclass(format('public.%I', required_table)) IS NULL THEN
            RAISE EXCEPTION 'Required table public.% is missing', required_table;
        END IF;
    END LOOP;
END $$;

-- All inserted rows are rolled back. This validates FK relationships and JSONB constraints
-- without leaving sample project data in the developer database.
BEGIN;

INSERT INTO projects (project_id, project_name, description)
VALUES ('10000000-0000-0000-0000-000000000001', 'database-smoke-test', 'Rolled back by smoke test');

INSERT INTO scan_runs (scan_run_id, project_id, input_kind, input_name, status)
VALUES
    ('20000000-0000-0000-0000-000000000001', '10000000-0000-0000-0000-000000000001', 'local_directory', 'smoke-a', 'completed'),
    ('20000000-0000-0000-0000-000000000002', '10000000-0000-0000-0000-000000000001', 'zip_archive', 'smoke-b.zip', 'completed');

INSERT INTO assessments (assessment_id, scan_run_id, policy_version, assessment_schema_version, assessment_json, summary_json)
VALUES
    ('30000000-0000-0000-0000-000000000001', '20000000-0000-0000-0000-000000000001', '1.0', '1.0', '{"assessment_id":"30000000-0000-0000-0000-000000000001","findings":[]}', '{"finding_count":0}'),
    ('30000000-0000-0000-0000-000000000002', '20000000-0000-0000-0000-000000000002', '1.0', '1.0', '{"assessment_id":"30000000-0000-0000-0000-000000000002","findings":[]}', '{"finding_count":0}');

INSERT INTO assessment_findings (
    assessment_id, finding_id, algorithm, variant, role, status, confidence,
    file_path, risk_kind, risk_level, risk_score, finding_json, risk_json
) VALUES (
    '30000000-0000-0000-0000-000000000001', 'CRYPTO-001', 'RSA', 'RSA-2048',
    'key-establishment', 'confirmed', 'high', 'src/crypto.py',
    'classical-weakness', 'high', 75.0,
    '{"finding_id":"CRYPTO-001","algorithm":"RSA"}',
    '{"risk_level":"high","risk_score":75.0}'
);

INSERT INTO migration_plans (migration_plan_id, assessment_id, recommendation_policy_version, plan_json, summary_json)
VALUES (
    '40000000-0000-0000-0000-000000000001',
    '30000000-0000-0000-0000-000000000001', '1.0',
    '{"migration_plan_id":"40000000-0000-0000-0000-000000000001","tasks":[]}', '{}'
);

INSERT INTO compliance_reports (report_id, assessment_id, migration_plan_id, as_of, report_json, summary_json)
VALUES (
    '50000000-0000-0000-0000-000000000001',
    '30000000-0000-0000-0000-000000000001',
    '40000000-0000-0000-0000-000000000001', DATE '2026-10-26',
    '{"assessment_id":"30000000-0000-0000-0000-000000000001","results":[]}', '{}'
);

INSERT INTO scan_diffs (diff_id, baseline_assessment_id, current_assessment_id, diff_json, summary_json)
VALUES (
    '60000000-0000-0000-0000-000000000001',
    '30000000-0000-0000-0000-000000000001',
    '30000000-0000-0000-0000-000000000002',
    '{"added":[],"removed":[]}', '{"added":0,"removed":0,"changed":0,"unchanged":0}'
);

DO $$
BEGIN
    BEGIN
        INSERT INTO scan_runs (scan_run_id, project_id, input_kind, status)
        VALUES ('20000000-0000-0000-0000-000000000003', '10000000-0000-0000-0000-000000000001', 'local_directory', 'invalid-status');
        RAISE EXCEPTION 'Status constraint failed to reject an invalid scan status';
    EXCEPTION WHEN check_violation THEN
        NULL;
    END;

    BEGIN
        INSERT INTO scan_runs (scan_run_id, project_id, input_kind, status)
        VALUES ('20000000-0000-0000-0000-000000000004', '90000000-0000-0000-0000-000000000099', 'local_directory', 'queued');
        RAISE EXCEPTION 'Foreign key failed to reject a missing project';
    EXCEPTION WHEN foreign_key_violation THEN
        NULL;
    END;
END $$;

ROLLBACK;

SELECT 'database smoke tests passed' AS result;
