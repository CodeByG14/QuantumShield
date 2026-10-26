from __future__ import annotations

import json

from quantumshield.compliance.checker import check_compliance
from quantumshield.compliance.report import render_markdown, write_reports


def test_report_has_source_links_and_draft_status():
    assessment = {
        "assessment_id": "report-test",
        "project_context": {},
        "findings": [{
            "finding_id": "CRYPTO-001", "algorithm": "RSA", "variant": "RSA-2048",
            "key_size": 2048, "curve": None, "role": "signature", "status": "confirmed",
            "evidence": [{"file_path": "src/auth.py", "line_start": 9, "metadata": {}}],
        }],
    }
    report = check_compliance(assessment, as_of="2026-10-25")
    markdown = render_markdown(report)
    assert "Initial Public Draft" in " ".join(report["warnings"])
    assert "https://csrc.nist.gov/pubs/ir/8547/ipd" in markdown
    assert "(draft)" in markdown
    assert "not assessed" in markdown


def test_report_writer_writes_both_json_and_markdown(tmp_path):
    report = check_compliance({"assessment_id": "empty", "project_context": {}, "findings": []}, as_of="2026-10-25")
    json_path, markdown_path = write_reports(report, tmp_path / "report.json", tmp_path / "report.md")
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["assessment_id"] == "empty"
    assert markdown_path.read_text(encoding="utf-8").startswith("# QuantumShield Compliance Assessment")
