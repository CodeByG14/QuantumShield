import os

import pytest

from common.models import FileOutcome, FindingStatus
from discovery import pipeline
from discovery.pipeline import run_scan


def outcomes(result):
    return {r.path: r.outcome for r in result.coverage.files}


def test_every_file_is_accounted_for_with_the_right_outcome(sample_project):
    res = run_scan(sample_project)
    assert outcomes(res) == {
        "Demo.java": FileOutcome.ANALYZED,
        "app.py": FileOutcome.ANALYZED,
        "bad.py": FileOutcome.FAILED,
        "empty.pem": FileOutcome.FAILED,
        "enc.key": FileOutcome.FAILED,
        "node_modules/dep.py": FileOutcome.SKIPPED,
        "notes.txt": FileOutcome.UNSUPPORTED,
        "requirements.txt": FileOutcome.ANALYZED,
        "server.pem": FileOutcome.ANALYZED,
        "store.p12": FileOutcome.UNSUPPORTED,
    }
    c = res.coverage
    assert c.files_discovered == 10
    assert (c.files_analyzed, c.files_failed, c.files_unsupported, c.files_skipped) == (4, 3, 2, 1)
    assert c.file_coverage_percent == 40.0  # failures are not counted as analyzed
    assert c.files_eligible == 7
    assert c.unsupported_extensions == {".txt": 1, ".p12": 1}


def test_every_non_analyzed_file_has_a_reason(sample_project):
    res = run_scan(sample_project)
    for r in res.coverage.files:
        if r.outcome != FileOutcome.ANALYZED:
            assert r.reason, r.path
    reasons = {r.path: r.reason for r in res.coverage.files}
    assert "UTF-8" in reasons["bad.py"]
    assert "empty" in reasons["empty.pem"]
    assert "passphrase" in reasons["enc.key"]
    assert "node_modules" in reasons["node_modules/dep.py"]


def test_skipped_and_failed_files_produce_no_misleading_findings(sample_project):
    res = run_scan(sample_project)
    files = {f.evidence[0].file_path for f in res.findings}
    assert "node_modules/dep.py" not in files  # skipped: never scanned
    assert "bad.py" not in files  # undecodable: no findings invented
    # ...but unreadable crypto files stay visible as unable-to-analyze
    unable = {f.evidence[0].file_path for f in res.findings if f.status == FindingStatus.UNABLE_TO_ANALYZE}
    assert unable == {"empty.pem", "enc.key"}


def test_unsupported_container_still_yields_a_potential_finding(sample_project):
    res = run_scan(sample_project)
    (f,) = [f for f in res.findings if f.evidence[0].file_path == "store.p12"]
    assert f.status == FindingStatus.POTENTIAL and f.algorithm == "unknown"


def test_ids_are_deterministic(sample_project):
    root = sample_project
    a, b = run_scan(root), run_scan(root)
    assert [f.finding_id for f in a.findings] == [f.finding_id for f in b.findings]
    assert a.model_dump(mode="json") == b.model_dump(mode="json")
    assert a.findings[0].finding_id == "CRYPTO-001"


def test_scanner_bug_is_reported_as_failure_not_a_crash(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("RSA.generate(2048)\n")

    def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(pipeline, "scan_source", boom)
    res = run_scan(tmp_path)
    (rec,) = res.coverage.files
    assert rec.outcome == FileOutcome.FAILED and "internal error" in rec.reason


def test_size_cap_skips_large_files(tmp_path):
    (tmp_path / "big.py").write_text("RSA.generate(2048)\n" * 50)
    res = run_scan(tmp_path, max_file_bytes=100)
    (rec,) = res.coverage.files
    assert rec.outcome == FileOutcome.SKIPPED and "larger than 100" in rec.reason
    assert res.findings == []


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlink support")
def test_symlinks_are_not_followed(tmp_path):
    (tmp_path / "real.py").write_text("x = 1\n")
    try:
        (tmp_path / "link.py").symlink_to(tmp_path / "real.py")
        (tmp_path / "linkdir").symlink_to(tmp_path, target_is_directory=True)
    except OSError:
        pytest.skip("cannot create symlinks here")
    res = run_scan(tmp_path)
    got = outcomes(res)
    assert got["link.py"] == FileOutcome.SKIPPED and got["linkdir"] == FileOutcome.SKIPPED
    assert got["real.py"] == FileOutcome.ANALYZED


def test_clean_project_reports_full_coverage_and_no_findings(tmp_path):
    (tmp_path / "a.py").write_text("def f():\n    return 1\n")
    res = run_scan(tmp_path)
    assert res.findings == [] and res.coverage.file_coverage_percent == 100.0


def test_empty_project(tmp_path):
    res = run_scan(tmp_path)
    assert res.coverage.files_discovered == 0 and res.coverage.file_coverage_percent == 0.0


def test_target_must_be_a_directory(tmp_path):
    f = tmp_path / "x.py"
    f.write_text("")
    with pytest.raises(NotADirectoryError):
        run_scan(f)
