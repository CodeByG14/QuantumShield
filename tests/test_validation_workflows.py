from __future__ import annotations

import json
from pathlib import Path

from validation.workflows import (
    evaluate_change_diff,
    evaluate_compliance_report,
    run_change_detection,
    run_compliance,
)


def test_change_diff_accepts_one_added_md5_finding():
    result = evaluate_change_diff({
        "summary": {"added": 1, "removed": 0, "changed": 0, "unchanged": 0},
        "added": [{"algorithm": "MD5", "variant": "MD5"}],
        "removed": [],
        "changed": [],
    })
    assert result["valid"] is True
    assert result["added_algorithms"] == ["MD5"]
    assert result["issues"] == []


def test_change_diff_rejects_missing_expected_change():
    result = evaluate_change_diff({
        "summary": {"added": 0, "removed": 0, "changed": 0, "unchanged": 0},
        "added": [],
        "removed": [],
        "changed": [],
    })
    assert result["valid"] is False
    assert any("added=1" in issue for issue in result["issues"])
    assert any("added MD5" in issue for issue in result["issues"])


def test_compliance_evaluation_requires_expected_status_and_plan_date():
    report = {
        "assessment_id": "phase7-compliance-fixture",
        "results": [{
            "finding_id": "CRYPTO-001",
            "framework": "NIST IR 8547",
            "rule_id": "NIST-IR8547-PUBLICKEY-112",
            "status": "deprecated-soon",
            "plan_completion_date": "2033-01-01",
            "plan_finishes_before_deadline": True,
        }],
    }
    markdown = "# QuantumShield Compliance Assessment\n\nhttps://csrc.nist.gov/pubs/ir/8547/ipd\n"
    result = evaluate_compliance_report(report, markdown)
    assert result["valid"] is True
    assert result["observed_status"] == "deprecated-soon"
    assert result["plan_completion_date"] == "2033-01-01"


def test_compliance_evaluation_rejects_wrong_status_or_missing_source():
    report = {
        "assessment_id": "phase7-compliance-fixture",
        "results": [{
            "finding_id": "CRYPTO-001",
            "framework": "NIST IR 8547",
            "rule_id": "NIST-IR8547-PUBLICKEY-112",
            "status": "compliant",
            "plan_completion_date": None,
            "plan_finishes_before_deadline": None,
        }],
    }
    result = evaluate_compliance_report(report, "# QuantumShield Compliance Assessment\n")
    assert result["valid"] is False
    assert any("deprecated-soon" in issue for issue in result["issues"])
    assert any("source link" in issue for issue in result["issues"])


def test_change_detection_workflow_invokes_scans_and_diff(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "out"
    commands = []

    def fake_runner(command, *, cwd, timeout_seconds=120):
        command = list(command)
        if "scan" in command:
            output_path = Path(command[command.index("--output") + 1])
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps({"findings": []}), encoding="utf-8")
        elif "diff" in command:
            output_path = Path(command[command.index("--output") + 1])
            output_path.write_text(json.dumps({
                "summary": {"added": 1, "removed": 0, "changed": 0, "unchanged": 0},
                "added": [{"algorithm": "MD5", "variant": "MD5"}],
                "removed": [],
                "changed": [],
            }), encoding="utf-8")
        return {"command": command, "return_code": 0, "stdout": "", "stderr": ""}

    result = run_change_detection(repo, output, fake_runner, commands)
    assert result["valid"] is True
    assert len(commands) == 3
    assert (output / "change_detection" / "diff.json").is_file()


def test_compliance_workflow_invokes_cli_and_checks_written_reports(tmp_path: Path):
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "out"
    commands = []

    def fake_runner(command, *, cwd, timeout_seconds=120):
        command = list(command)
        report_path = Path(command[command.index("--output") + 1])
        markdown_path = Path(command[command.index("--markdown-output") + 1])
        report_path.write_text(json.dumps({
            "assessment_id": "phase7-compliance-fixture",
            "results": [{
                "finding_id": "CRYPTO-001",
                "framework": "NIST IR 8547",
                "rule_id": "NIST-IR8547-PUBLICKEY-112",
                "status": "deprecated-soon",
                "plan_completion_date": "2033-01-01",
                "plan_finishes_before_deadline": True,
            }],
        }), encoding="utf-8")
        markdown_path.write_text(
            "# QuantumShield Compliance Assessment\nhttps://csrc.nist.gov/pubs/ir/8547/ipd\n",
            encoding="utf-8",
        )
        return {"command": command, "return_code": 0, "stdout": "", "stderr": ""}

    result = run_compliance(repo, output, fake_runner, commands)
    assert result["valid"] is True
    assert len(commands) == 1
    assert Path(result["json_report"]).is_file()
    assert Path(result["markdown_report"]).is_file()
