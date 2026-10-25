import json
from datetime import datetime, timezone

import pytest

from quantumshield.common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FileOutcome,
    FileRecord,
    FindingStatus,
    ProjectContext,
    ScanResult,
    CoverageReport,
    StageStatus,
)
from quantumshield.scoring.assessment_writer import (
    build_assessment,
    load_project_context,
    write_assessment,
)


def make_scan():
    finding = CryptoFinding(
        finding_id="CRYPTO-001",
        algorithm="RSA",
        variant="RSA-2048",
        key_size=2048,
        role=CryptoRole.KEY_ESTABLISHMENT,
        status=FindingStatus.CONFIRMED,
        evidence=[
            Evidence(
                finding_id="CRYPTO-001",
                file_path="src/keys.py",
                line_start=12,
                evidence_type=EvidenceType.API_CALL,
                detection_method=DetectionMethod.REGEX,
                rule_id="PY-RSA-001",
                excerpt="RSA.generate(2048)",
                confidence=Confidence.HIGH,
            )
        ],
    )
    record = FileRecord(
        path="src/keys.py",
        outcome=FileOutcome.ANALYZED,
        stages={"source": StageStatus.SUCCESS},
    )
    return ScanResult(findings=[finding], coverage=CoverageReport.from_records([record]))


def test_missing_context_file_returns_empty_context_with_target_name(tmp_path):
    context, loaded = load_project_context(tmp_path / "missing.yaml", target_name="test-service")
    assert loaded is False
    assert context.project_name == "test-service"
    assert context.data_sensitivity is None


def test_context_yaml_is_loaded_and_validated(tmp_path):
    path = tmp_path / "project-context.yaml"
    path.write_text(
        "project_name: payments\ndata_sensitivity: 4\nconfidentiality_years: 12\n"
        "exposure: 3\nsystem_criticality: 5\nmigration_years: 2\nthreat_horizon_year: 2035\n",
        encoding="utf-8",
    )
    context, loaded = load_project_context(path, target_name="ignored")
    assert loaded is True
    assert context.project_name == "payments"
    assert context.confidentiality_years == 12


def test_non_mapping_yaml_is_rejected(tmp_path):
    path = tmp_path / "project-context.yaml"
    path.write_text("- not\n- a\n- mapping\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a mapping"):
        load_project_context(path, target_name="test-service")


def test_build_assessment_links_findings_risks_and_coverage(tmp_path):
    report = build_assessment(
        make_scan(),
        target=tmp_path,
        context=ProjectContext(project_name="payments", data_sensitivity=4,
                               confidentiality_years=10, exposure=4,
                               system_criticality=5, migration_years=3,
                               threat_horizon_year=2035),
        assessment_id="ASSESS-TEST",
        scan_timestamp=datetime(2026, 10, 11, tzinfo=timezone.utc),
        assessment_year=2026,
    )
    assert report.assessment_id == "ASSESS-TEST"
    assert report.findings[0].finding_id == report.risks[0].finding_id
    assert report.coverage.file_coverage_percent == 100
    assert report.risks[0].risk_score is not None
    assert report.policy_version == "1.1"


def test_write_assessment_serializes_enums_and_computed_confidence(tmp_path):
    report = build_assessment(
        make_scan(),
        target=tmp_path,
        context=ProjectContext(project_name="payments"),
        context_loaded=False,
        assessment_id="ASSESS-TEST",
        scan_timestamp=datetime(2026, 10, 11, tzinfo=timezone.utc),
        assessment_year=2026,
    )
    path = write_assessment(report, tmp_path / "out" / "assessment.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["assessment_id"] == "ASSESS-TEST"
    assert data["findings"][0]["confidence"] == "high"
    assert data["risks"][0]["risk_kind"] == "hndl-confidentiality"
    assert data["risks"][0]["risk_score"] is not None
    assert any("No project-context YAML" in item for item in data["limitations"])
