from __future__ import annotations

import json
from argparse import Namespace

from quantumshield.__main__ import diff_command


def _assessment(assessment_id: str) -> dict:
    return {
        "assessment_id": assessment_id,
        "target": "/validation/demo",
        "findings": [],
        "risks": [],
        "coverage": {
            "files_discovered": 1,
            "files_eligible": 1,
            "files_analyzed": 1,
            "files_partial": 0,
            "files_failed": 0,
            "files_unsupported": 0,
            "files_skipped": 0,
            "file_coverage_percent": 100.0,
        },
    }


def test_diff_command_accepts_json_assessment_objects(tmp_path):
    baseline_path = tmp_path / "baseline.json"
    current_path = tmp_path / "current.json"
    output_path = tmp_path / "diff.json"
    baseline_path.write_text(json.dumps(_assessment("baseline")), encoding="utf-8")
    current_path.write_text(json.dumps(_assessment("current")), encoding="utf-8")

    exit_code = diff_command(Namespace(
        baseline=str(baseline_path),
        current=str(current_path),
        output=str(output_path),
    ))

    assert exit_code == 0
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert result["summary"] == {"added": 0, "removed": 0, "changed": 0, "unchanged": 0}
