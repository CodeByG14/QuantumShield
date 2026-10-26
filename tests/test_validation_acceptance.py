from pathlib import Path

from validation.acceptance import (
    check_file_labels,
    evaluate_acceptance_diff,
    evaluate_compliance_artifacts,
    load_spec,
    split_cases,
)


def test_split_cases_separates_rootfs_labels():
    project, rootfs = split_cases([
        {"path": "src/a.py", "label": "negative", "expected_findings": []},
        {"path": "rootfs/usr/lib/libssl.so.3", "label": "rootfs-positive", "expected_findings": [{"algorithm": "library:openssl"}]},
    ])
    assert [case["path"] for case in project] == ["src/a.py"]
    assert [case["path"] for case in rootfs] == ["rootfs/usr/lib/libssl.so.3"]


def test_check_file_labels_detects_unlabelled_project_and_rootfs_files(tmp_path: Path):
    project = tmp_path / "project"
    rootfs = tmp_path / "rootfs"
    (project / "src").mkdir(parents=True)
    (project / "src" / "a.py").write_text("x=1\n")
    (project / "src" / "extra.py").write_text("x=2\n")
    (rootfs / "usr" / "lib").mkdir(parents=True)
    (rootfs / "usr" / "lib" / "libssl.so.3").write_bytes(b"")
    (rootfs / "usr" / "lib" / "unknown.so").write_bytes(b"")
    cases = [
        {"path": "src/a.py", "label": "negative", "expected_findings": []},
        {"path": "rootfs/usr/lib/libssl.so.3", "label": "rootfs-positive", "expected_findings": [{"algorithm": "library:openssl"}]},
    ]
    issues = check_file_labels(project, rootfs, cases)
    assert any("src/extra.py" in item for item in issues)
    assert any("rootfs/usr/lib/unknown.so" in item for item in issues)


def test_load_spec_rejects_duplicate_paths(tmp_path: Path):
    spec = tmp_path / "spec.yaml"
    spec.write_text(
        "schema_version: 1\ncorpus:\n  target: p\n  rootfs: r\ncases:\n"
        "  - path: src/a.py\n    label: negative\n    expected_findings: []\n"
        "  - path: src/a.py\n    label: negative\n    expected_findings: []\n",
        encoding="utf-8",
    )
    try:
        load_spec(spec)
    except ValueError as exc:
        assert "duplicate" in str(exc)
    else:
        raise AssertionError("duplicate paths should be rejected")


def test_diff_evaluation_accepts_exact_expected_change():
    result = evaluate_acceptance_diff({
        "summary": {"added": 1, "removed": 0, "changed": 0, "unchanged": 12},
        "added": [{"algorithm": "SHA-256", "variant": "SHA-256", "status": "confirmed"}],
        "removed": [], "changed": [],
    })
    assert result["valid"] is True
    assert result["issues"] == []


def test_diff_evaluation_rejects_wrong_counts_or_algorithm():
    result = evaluate_acceptance_diff({
        "summary": {"added": 1, "removed": 1, "changed": 0, "unchanged": 11},
        "added": [{"algorithm": "MD5", "variant": "MD5", "status": "confirmed"}],
        "removed": [{}], "changed": [],
    })
    assert result["valid"] is False
    assert any("removed=0" in issue for issue in result["issues"])
    assert any("SHA-256" in issue for issue in result["issues"])


def test_compliance_artifact_evaluator_checks_assessment_id_and_source():
    good = evaluate_compliance_artifacts(
        {"assessment_id": "a", "results": [{"rule_id": "x", "status": "not assessed"}]},
        "# QuantumShield Compliance Assessment\n\nhttps://csrc.nist.gov/pubs/ir/8547/ipd\n",
        expected_assessment_id="a",
    )
    assert good["valid"] is True
    bad = evaluate_compliance_artifacts(
        {"assessment_id": "wrong", "results": []}, "# bad\n", expected_assessment_id="a"
    )
    assert bad["valid"] is False
    assert len(bad["issues"]) >= 3
