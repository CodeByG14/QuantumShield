from datetime import datetime, timezone

import pytest

from quantumshield.monitor.diff import AssessmentFormatError, diff_assessments


def _finding(
    finding_id="CRYPTO-001",
    *,
    algorithm="RSA",
    variant="RSA-2048",
    curve=None,
    role="key-establishment",
    status="confirmed",
    confidence="high",
    line=10,
    file_path="src/keys.py",
    fingerprint=None,
):
    metadata = {"fingerprint_sha256": fingerprint} if fingerprint else {}
    return {
        "finding_id": finding_id,
        "algorithm": algorithm,
        "variant": variant,
        "curve": curve,
        "role": role,
        "status": status,
        "confidence": confidence,
        "evidence": [
            {
                "file_path": file_path,
                "line_start": line,
                "line_end": line,
                "evidence_type": "certificate",
                "detection_method": "x509",
                "rule_id": "X509-001",
                "excerpt": "public key",
                "confidence": confidence,
                "metadata": metadata,
            }
        ],
    }


def _assessment(
    assessment_id,
    findings,
    *,
    coverage=100.0,
    risks=None,
    files_discovered=10,
    files_analyzed=10,
):
    return {
        "assessment_id": assessment_id,
        "target": "/work/project",
        "findings": findings,
        "risks": risks or [],
        "coverage": {
            "files_discovered": files_discovered,
            "files_eligible": files_discovered,
            "files_analyzed": files_analyzed,
            "files_partial": 0,
            "files_failed": files_discovered - files_analyzed,
            "files_unsupported": 0,
            "files_skipped": 0,
            "file_coverage_percent": coverage,
        },
    }


def _risk(finding_id, score=80.0, level="very-high", kind="hndl-confidentiality"):
    return {
        "finding_id": finding_id,
        "risk_score": score,
        "risk_level": level,
        "risk_kind": kind,
    }


def test_line_shifts_and_ordinal_finding_ids_do_not_create_change():
    baseline = _assessment("baseline", [_finding("CRYPTO-001", line=10)])
    current = _assessment("current", [_finding("CRYPTO-042", line=100)])
    result = diff_assessments(baseline, current, generated_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    assert result["summary"] == {"added": 0, "removed": 0, "changed": 0, "unchanged": 1}
    assert result["coverage"]["delta_percentage_points"] == 0


def test_added_and_removed_findings_are_reported():
    old = _finding("CRYPTO-001")
    added = _finding("CRYPTO-002", algorithm="ECDSA", variant="P-256", role="signature")
    result = diff_assessments(_assessment("b", [old]), _assessment("c", [added]))
    assert result["summary"]["added"] == 1
    assert result["summary"]["removed"] == 1
    assert result["added"][0]["algorithm"] == "ECDSA"
    assert result["removed"][0]["algorithm"] == "RSA"


def test_status_confidence_role_variant_and_risk_changes_are_detected():
    old = _finding("CRYPTO-001", status="potential", confidence="medium")
    new = _finding("CRYPTO-091", status="confirmed", confidence="high")
    baseline = _assessment("b", [old], risks=[_risk("CRYPTO-001", score=55.0, level="high")])
    current = _assessment("c", [new], risks=[_risk("CRYPTO-091", score=91.0, level="critical")])
    result = diff_assessments(baseline, current)
    assert result["summary"]["changed"] == 1
    changes = result["changed"][0]["changes"]
    assert set(changes) == {"status", "confidence", "risk_score", "risk_level"}
    assert changes["risk_score"] == {"before": 55.0, "after": 91.0}


def test_variant_changes_are_reported_as_changes_when_unambiguous():
    baseline = _assessment("b", [_finding("CRYPTO-001", variant="RSA-2048")])
    current = _assessment("c", [_finding("CRYPTO-009", variant="RSA-3072")])
    result = diff_assessments(baseline, current)
    assert result["summary"]["added"] == 0
    assert result["summary"]["removed"] == 0
    assert result["summary"]["changed"] == 1
    assert result["changed"][0]["changes"]["variant"] == {"before": "RSA-2048", "after": "RSA-3072"}


def test_role_changes_are_reported_as_changes_when_unambiguous():
    baseline = _assessment("b", [_finding("CRYPTO-001", role="key-establishment")])
    current = _assessment("c", [_finding("CRYPTO-009", role="signature")])
    result = diff_assessments(baseline, current)
    assert result["summary"]["changed"] == 1
    assert result["changed"][0]["changes"]["role"] == {"before": "key-establishment", "after": "signature"}


def test_multiple_certificates_in_one_file_remain_distinct():
    first = _finding("CRYPTO-001", file_path="bundle.pem", fingerprint="aa")
    second = _finding("CRYPTO-002", file_path="bundle.pem", fingerprint="bb")
    shifted = [
        _finding("CRYPTO-010", file_path="bundle.pem", fingerprint="aa", line=100),
        _finding("CRYPTO-011", file_path="bundle.pem", fingerprint="bb", line=200),
    ]
    result = diff_assessments(_assessment("b", [first, second]), _assessment("c", shifted))
    assert result["summary"] == {"added": 0, "removed": 0, "changed": 0, "unchanged": 2}


def test_coverage_delta_uses_percentage_points_and_file_count_deltas():
    baseline = _assessment("b", [], coverage=90.0, files_discovered=10, files_analyzed=9)
    current = _assessment("c", [], coverage=75.0, files_discovered=12, files_analyzed=9)
    result = diff_assessments(baseline, current)
    assert result["coverage"]["delta_percentage_points"] == -15.0
    assert result["coverage"]["counts"]["files_discovered"]["delta"] == 2


def test_bad_assessment_shape_fails_loudly():
    with pytest.raises(AssessmentFormatError, match="file_coverage_percent"):
        diff_assessments(_assessment("b", []), {"assessment_id": "c", "findings": [], "coverage": {}})
