import json

from quantumshield.monitor.check import (
    EXIT_INPUT_ERROR,
    EXIT_OK,
    EXIT_THRESHOLD_BREACHED,
    _parse_fail_on,
    evaluate_failures,
    main,
)
from quantumshield.monitor.diff import diff_assessments


def assessment(assessment_id, findings, coverage=100.0, risks=None):
    return {
        "assessment_id": assessment_id,
        "target": "/project",
        "findings": findings,
        "risks": risks or [],
        "coverage": {
            "file_coverage_percent": coverage,
            "files_discovered": 10,
            "files_eligible": 10,
            "files_analyzed": int(coverage / 10),
            "files_partial": 0,
            "files_failed": 0,
            "files_unsupported": 0,
            "files_skipped": 0,
        },
    }


def finding(fid, *, algorithm="RSA", status="confirmed", file="key.py"):
    return {
        "finding_id": fid,
        "algorithm": algorithm,
        "variant": "RSA-2048",
        "curve": None,
        "role": "key-establishment",
        "status": status,
        "confidence": "high",
        "evidence": [{"file_path": file, "line_start": 1, "rule_id": "TEST", "evidence_type": "api-call", "metadata": {}}],
    }


def test_parse_fail_on_rules_accept_repeated_and_comma_separated():
    assert _parse_fail_on(["new-high,new-critical", "coverage-drop:5", "new-unable"]) == [
        ("new-high", None),
        ("new-critical", None),
        ("coverage-drop", 5.0),
        ("new-unable", None),
    ]


def test_invalid_fail_on_is_rejected():
    try:
        _parse_fail_on(["coverage-drop:-1"])
    except ValueError as exc:
        assert "between 0 and 100" in str(exc)
    else:
        raise AssertionError("negative coverage-drop should be rejected")


def test_fail_rules_detect_new_high_critical_unable_and_coverage_drop():
    before = assessment("b", [finding("CRYPTO-001", algorithm="ECDSA")], coverage=95.0)
    after = assessment(
        "c",
        [
            finding("CRYPTO-101", algorithm="ECDSA"),
            finding("CRYPTO-102", algorithm="RSA", status="unable-to-analyze", file="bad.pem"),
        ],
        coverage=80.0,
        risks=[
            {"finding_id": "CRYPTO-102", "risk_level": "critical", "risk_score": 99.0, "risk_kind": "not-assessed"}
        ],
    )
    result = diff_assessments(before, after)
    rules = _parse_fail_on(["new-high", "new-critical", "new-unable", "coverage-drop:10"])
    failures = evaluate_failures(result, rules)
    assert any("new-high" in failure for failure in failures)
    assert any("new-unable" in failure for failure in failures)
    assert any("coverage-drop" in failure for failure in failures)


def test_cli_writes_diff_and_returns_threshold_exit_code(tmp_path):
    before = assessment("b", [finding("CRYPTO-001", algorithm="ECDSA")], coverage=100.0)
    after = assessment("c", [finding("CRYPTO-002", algorithm="ECDSA"), finding("CRYPTO-003", algorithm="RSA")], coverage=70.0,
        risks=[{"finding_id": "CRYPTO-003", "risk_level": "critical", "risk_score": 99.0, "risk_kind": "hndl-confidentiality"}])
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output_path = tmp_path / "diff.json"
    baseline_path.write_text(json.dumps(before))
    current_path.write_text(json.dumps(after))

    exit_code = main([
        "--baseline", str(baseline_path), "--current", str(current_path),
        "--output", str(output_path), "--fail-on", "new-critical",
    ])
    assert exit_code == EXIT_THRESHOLD_BREACHED
    assert json.loads(output_path.read_text())["summary"]["added"] == 1


def test_cli_invalid_json_returns_input_error(tmp_path):
    bad_path = tmp_path / "bad.json"
    bad_path.write_text("not json")
    good_path = tmp_path / "good.json"
    good_path.write_text(json.dumps(assessment("g", [])))
    assert main(["--baseline", str(bad_path), "--current", str(good_path), "--output", str(tmp_path / "out.json")]) == EXIT_INPUT_ERROR
