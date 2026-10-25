import pytest
from pydantic import ValidationError

from quantumshield.common.models import (
    AssessmentResult,
    Confidence,
    CoverageReport,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FileOutcome,
    FileRecord,
    FileStageResult,
    FindingStatus,
    ProjectContext,
    RiskAssessment,
    RiskKind,
    RiskLevel,
    StageStatus,
    assign_ids,
)


def ev(conf=Confidence.HIGH, etype=EvidenceType.API_CALL, path="a.py", line=3, **kw):
    return Evidence(
        file_path=path,
        line_start=line,
        evidence_type=etype,
        detection_method=DetectionMethod.REGEX,
        rule_id="PY-RSA-001",
        excerpt="rsa.generate_private_key(...)",
        confidence=conf,
        **kw,
    )


def finding(status=FindingStatus.CONFIRMED, evidence=None, **kw):
    return CryptoFinding(
        algorithm="RSA",
        status=status,
        evidence=[ev()] if evidence is None else evidence,
        **kw,
    )


# ---- Evidence ---------------------------------------------------------------


def test_excerpt_is_single_line_and_bounded():
    e = Evidence(
        file_path="a.py",
        evidence_type=EvidenceType.KEYWORD,
        detection_method=DetectionMethod.REGEX,
        rule_id="r",
        excerpt="line one\n   line two " + "x" * 500,
        confidence=Confidence.LOW,
    )
    assert "\n" not in e.excerpt
    assert len(e.excerpt) <= 200


def test_line_end_defaults_and_is_validated():
    assert ev(line=7).line_end == 7
    with pytest.raises(ValidationError):
        Evidence(
            file_path="a.py",
            line_start=9,
            line_end=4,
            evidence_type=EvidenceType.KEYWORD,
            detection_method=DetectionMethod.REGEX,
            rule_id="r",
            confidence=Confidence.LOW,
        )


# ---- Findings ---------------------------------------------------------------


def test_confidence_is_derived_from_strongest_evidence():
    f = finding(
        status=FindingStatus.POTENTIAL,
        evidence=[ev(Confidence.LOW), ev(Confidence.MEDIUM, line=9)],
    )
    assert f.confidence == Confidence.MEDIUM


def test_confirmed_needs_strong_non_comment_evidence():
    with pytest.raises(ValidationError):
        finding(evidence=[ev(Confidence.MEDIUM)])
    with pytest.raises(ValidationError):
        finding(evidence=[ev(Confidence.HIGH, etype=EvidenceType.COMMENT_MENTION)])
    assert finding().status == FindingStatus.CONFIRMED


def test_finding_without_evidence_needs_a_reason():
    with pytest.raises(ValidationError):
        finding(status=FindingStatus.POTENTIAL, evidence=[])
    f = finding(
        status=FindingStatus.UNABLE_TO_ANALYZE,
        evidence=[],
        evidence_gap_reason="file is empty",
    )
    assert f.confidence == Confidence.UNKNOWN


def test_unable_to_analyze_requires_reason_even_with_evidence():
    with pytest.raises(ValidationError):
        finding(status=FindingStatus.UNABLE_TO_ANALYZE)


def test_assign_ids_is_deterministic_and_links_evidence():
    a = finding(evidence=[ev(path="b.py", line=2)])
    b = finding(evidence=[ev(path="a.py", line=5), ev(path="a.py", line=8)])
    ordered = assign_ids([a, b])
    assert [f.finding_id for f in ordered] == ["CRYPTO-001", "CRYPTO-002"]
    assert ordered[0].evidence[0].file_path == "a.py"
    assert ordered[0].evidence[1].evidence_id == "CRYPTO-001-E2"
    assert ordered[0].evidence[1].finding_id == "CRYPTO-001"


def test_finding_json_round_trip_with_computed_confidence():
    f = assign_ids([finding(role=CryptoRole.KEY_ESTABLISHMENT)])[0]
    data = f.model_dump(mode="json")
    assert data["confidence"] == "high"
    assert CryptoFinding.model_validate(data) == f


# ---- Coverage ---------------------------------------------------------------


def stage(path, name, ok=True, reason=None):
    return FileStageResult(
        path=path,
        stage=name,
        status=StageStatus.SUCCESS if ok else StageStatus.FAILED,
        reason=reason,
    )


def test_outcome_derivation():
    ok = FileRecord.from_stage_results("a.py", [stage("a.py", "source")])
    assert ok.outcome == FileOutcome.ANALYZED

    failed = FileRecord.from_stage_results(
        "b.py", [stage("b.py", "source", ok=False, reason="not valid UTF-8")]
    )
    assert failed.outcome == FileOutcome.FAILED
    assert "UTF-8" in failed.reason

    partial = FileRecord.from_stage_results(
        "c.pem",
        [stage("c.pem", "artifact"), stage("c.pem", "x509", ok=False, reason="empty file")],
    )
    assert partial.outcome == FileOutcome.PARTIAL

    unsupported = FileRecord.from_stage_results("notes.txt", [])
    assert unsupported.outcome == FileOutcome.UNSUPPORTED
    assert ".txt" in unsupported.reason

    skipped = FileRecord.from_stage_results(
        ".git/config", [], skip_reason="excluded by policy (.git)"
    )
    assert skipped.outcome == FileOutcome.SKIPPED


def test_coverage_accounts_for_every_file_and_cannot_hide_failures():
    records = [
        FileRecord.from_stage_results("a.py", [stage("a.py", "source")]),
        FileRecord.from_stage_results("b.py", [stage("b.py", "source", ok=False, reason="x")]),
        FileRecord.from_stage_results("c.pem", [stage("c.pem", "artifact"), stage("c.pem", "x509", ok=False, reason="y")]),
        FileRecord.from_stage_results("n.txt", []),
        FileRecord.from_stage_results(".git/HEAD", [], skip_reason="policy"),
    ]
    rep = CoverageReport.from_records(records)
    assert rep.files_discovered == 5
    assert (rep.files_analyzed, rep.files_failed, rep.files_partial) == (1, 1, 1)
    assert (rep.files_unsupported, rep.files_skipped) == (1, 1)
    assert rep.files_eligible == 3
    assert rep.file_coverage_percent == 20.0  # only fully analyzed files count
    assert rep.unsupported_extensions == {".txt": 1}
    assert rep.stage_counts["x509"] == {"success": 0, "failed": 1}


def test_coverage_validator_rejects_inconsistent_counts():
    rep = CoverageReport.from_records([FileRecord.from_stage_results("a.py", [stage("a.py", "source")])])
    data = rep.model_dump(mode="json")
    data["files_failed"] = 4
    with pytest.raises(ValidationError):
        CoverageReport.model_validate(data)


def test_empty_project_does_not_divide_by_zero():
    assert CoverageReport.from_records([]).file_coverage_percent == 0.0


# ---- Project context --------------------------------------------------------


def test_missing_inputs_are_reported_not_assumed():
    ctx = ProjectContext(data_sensitivity=4, exposure=3)
    assert ctx.missing_inputs() == ["confidentiality_years", "system_criticality"]
    with pytest.raises(ValidationError):
        ProjectContext(data_sensitivity=9)


# ---- Risk and assessment ----------------------------------------------------


def test_risk_kind_must_match_score_presence():
    base = dict(finding_id="CRYPTO-001", confidence=Confidence.HIGH, policy_version="1.0")
    RiskAssessment(risk_kind=RiskKind.NOT_ASSESSED, **base)
    RiskAssessment(
        risk_kind=RiskKind.HNDL_CONFIDENTIALITY,
        risk_score=95,
        risk_level=RiskLevel.CRITICAL,
        **base,
    )
    with pytest.raises(ValidationError):
        RiskAssessment(risk_kind=RiskKind.HNDL_CONFIDENTIALITY, **base)
    with pytest.raises(ValidationError):
        RiskAssessment(risk_kind=RiskKind.NOT_ASSESSED, risk_score=10, risk_level=RiskLevel.LOW, **base)


def test_assessment_references_must_resolve():
    findings = assign_ids([finding()])
    cov = CoverageReport.from_records([])
    common = dict(
        assessment_id="A-1",
        scan_timestamp="2026-10-11T10:00:00Z",
        target="samples/test-repo",
        policy_version="1.0",
        project_context=ProjectContext(),
        coverage=cov,
        findings=findings,
    )
    AssessmentResult(**common)
    bad = RiskAssessment(
        finding_id="CRYPTO-999",
        risk_kind=RiskKind.NOT_ASSESSED,
        confidence=Confidence.LOW,
        policy_version="1.0",
    )
    with pytest.raises(ValidationError):
        AssessmentResult(risks=[bad], **common)
    with pytest.raises(ValidationError):  # findings must have ids
        AssessmentResult(**{**common, "findings": [finding()]})
