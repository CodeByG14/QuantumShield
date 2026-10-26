from __future__ import annotations

import json
from argparse import Namespace

from quantumshield.__main__ import compliance_command


def test_cli_writes_json_and_markdown_without_revalidating_historical_risk_enums(tmp_path, monkeypatch, capsys):
    assessment = {
        "assessment_id": "legacy-assessment",
        "project_context": {"project_name": "test"},
        "findings": [{
            "finding_id": "CRYPTO-001", "algorithm": "RSA", "variant": "RSA-2048",
            "key_size": 2048, "curve": None, "role": "signature", "status": "confirmed",
            "evidence": [{"file_path": "src/auth.py", "line_start": 9, "metadata": {}}],
        }],
        # An older value from an earlier schema is irrelevant to compliance matching.
        "risks": [{"finding_id": "CRYPTO-001", "risk_kind": "authenticity"}],
    }
    assessment_path = tmp_path / "assessment.json"
    assessment_path.write_text(json.dumps(assessment), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = compliance_command(Namespace(
        assessment=str(assessment_path), plan=None, rules=None, as_of="2026-10-25",
        output="compliance_report.json", markdown_output="compliance_report.md",
    ))
    assert code == 0
    report = json.loads((tmp_path / "compliance_report.json").read_text(encoding="utf-8"))
    assert report["assessment_id"] == "legacy-assessment"
    assert (tmp_path / "compliance_report.md").exists()
    assert "Wrote compliance_report.json" in capsys.readouterr().out


def test_cli_returns_error_for_bad_date_and_does_not_write_report(tmp_path, monkeypatch, capsys):
    assessment = {"assessment_id": "bad-date", "project_context": {}, "findings": []}
    assessment_path = tmp_path / "assessment.json"
    assessment_path.write_text(json.dumps(assessment), encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    code = compliance_command(Namespace(
        assessment=str(assessment_path), plan=None, rules=None, as_of="25-10-2026",
        output="report.json", markdown_output="report.md",
    ))
    assert code == 2
    assert not (tmp_path / "report.json").exists()
    assert "ISO date" in capsys.readouterr().err
