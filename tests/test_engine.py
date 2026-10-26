from __future__ import annotations

import json

import pytest

from quantumshield.common.models import AssessmentResult
from quantumshield.engine import (
    BadTargetError,
    InvalidAssessmentError,
    InvalidContextError,
    comply,
    diff,
    plan,
    scan,
)


def test_scan_returns_assessment_and_round_trips_json(tmp_path):
    assessment = scan(tmp_path)

    assert isinstance(assessment, AssessmentResult)
    assert assessment.target == str(tmp_path.resolve())
    assert assessment.project_context.project_name == tmp_path.name

    payload = assessment.model_dump(mode="json")
    restored = AssessmentResult.model_validate(json.loads(json.dumps(payload)))
    assert restored.model_dump(mode="json") == payload

    # Scanning returns data; it must not generate assessment or inventory files.
    assert list(tmp_path.iterdir()) == []


def test_facade_plan_compliance_and_diff_use_existing_outputs(tmp_path):
    assessment = scan(tmp_path)

    migration_plan = plan(assessment)
    assert migration_plan["source_assessment_id"] == assessment.assessment_id
    assert migration_plan["schema_version"] == "1.0"
    assert json.loads(json.dumps(migration_plan)) == migration_plan

    compliance_report = comply(
        assessment,
        migration_plan,
        as_of="2026-10-26",
    )
    assert compliance_report["assessment_id"] == assessment.assessment_id
    assert compliance_report["migration_plan_id"] == migration_plan["migration_plan_id"]
    assert "results" in compliance_report
    assert json.loads(json.dumps(compliance_report)) == compliance_report

    difference = diff(assessment, assessment)
    assert difference["baseline_assessment_id"] == assessment.assessment_id
    assert difference["current_assessment_id"] == assessment.assessment_id
    assert difference["summary"] == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "unchanged": 0,
    }
    assert json.loads(json.dumps(difference)) == difference


def test_scan_requires_absolute_existing_target(tmp_path):
    with pytest.raises(BadTargetError, match="absolute path"):
        scan("relative/project")

    with pytest.raises(BadTargetError, match="existing directory"):
        scan(tmp_path / "missing")


def test_scan_rejects_invalid_context(tmp_path):
    invalid_context = {
        "project_name": "demo",
        "asset_contexts": "not-a-list",
    }

    with pytest.raises(
        InvalidContextError,
        match="Project context is invalid",
    ):
        scan(tmp_path, context=invalid_context)


def test_plan_requires_assessment_model():
    with pytest.raises(InvalidAssessmentError, match="AssessmentResult"):
        plan({})  # type: ignore[arg-type]


def test_diff_requires_assessment_models(tmp_path):
    assessment = scan(tmp_path)
    with pytest.raises(
        InvalidAssessmentError, match="baseline must be an AssessmentResult"
    ):
        diff({}, assessment)  # type: ignore[arg-type]


def test_diff_matches_same_project_across_temporary_workspaces(tmp_path):
    first_root = tmp_path / "first" / "project"
    second_root = tmp_path / "second" / "project"

    first_root.mkdir(parents=True)
    second_root.mkdir(parents=True)

    source = "RSA.generate(2048)\n"
    (first_root / "crypto.py").write_text(source)
    (second_root / "crypto.py").write_text(source)

    baseline = scan(first_root)
    current = scan(second_root)

    assert baseline.target != current.target
    assert baseline.findings
    assert current.findings

    result = diff(baseline, current)

    assert result["summary"]["added"] == 0
    assert result["summary"]["removed"] == 0
    assert result["summary"]["changed"] == 0
    assert result["summary"]["unchanged"] > 0


def test_scan_uses_durable_project_name_and_context_provenance(tmp_path):
    workspace = tmp_path / "temporary-random-workspace-id"
    workspace.mkdir()

    assessment = scan(
        workspace,
        project_name="stable-project-name",
        context_loaded=False,
    )

    assert assessment.schema_version == "1.0"
    assert assessment.project_context.project_name == "stable-project-name"
    assert assessment.target == str(workspace.resolve())
    assert any(
        "No project-context YAML was loaded" in limitation
        for limitation in assessment.limitations
    )


def test_scan_project_name_overrides_context_name_but_preserves_context_fields(
    tmp_path,
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    context = {
        "project_name": "temporary-folder-name",
        "asset_contexts": [],
        "data_sensitivity": 5,
    }

    assessment = scan(workspace, project_name="stored-project-name", context=context)

    assert assessment.project_context.project_name == "stored-project-name"
    assert assessment.project_context.data_sensitivity == 5
