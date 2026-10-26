from validation.run import _write_markdown


def test_markdown_report_includes_new_workflow_results(tmp_path):
    report = {
        "acceptance": {"passed": True, "checks": []},
        "run": {"started_at_utc": "2026-10-26T00:00:00+00:00", "duration_seconds": 1, "corpus_path": "validation/corpus"},
        "detection": {},
        "coverage": {"available": True, "sections": {}, "issues": []},
        "migration_plan": {"valid": True, "task_count": 1, "action_counts": {}, "issues": []},
        "change_detection": {"valid": True, "summary": {"added": 1, "removed": 0, "changed": 0}, "added_algorithms": ["MD5"], "issues": []},
        "compliance": {"valid": True, "expected_rule_id": "NIST-IR8547-PUBLICKEY-112", "observed_status": "deprecated-soon", "plan_completion_date": "2033-01-01", "plan_finishes_before_deadline": True, "markdown_has_source_link": True, "issues": []},
    }
    output = tmp_path / "report.md"
    _write_markdown(output, report)
    rendered = output.read_text(encoding="utf-8")
    assert "## Change-detection workflow" in rendered
    assert "## Compliance workflow" in rendered
    assert "NIST-IR8547-PUBLICKEY-112" in rendered
    assert "2033-01-01" in rendered
