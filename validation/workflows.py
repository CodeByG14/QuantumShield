"""Controlled change-detection and compliance workflows for Phase 7 validation.

These workflows invoke QuantumShield's public command-line interfaces using
small, deterministic fixtures. They do not scan a live host or make network
connections. Their results validate selected regression-backed behaviors, not
real-world accuracy across arbitrary projects.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path
from typing import Any, Callable, Mapping

CommandRunner = Callable[..., dict[str, Any]]


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def evaluate_change_diff(diff: Mapping[str, Any]) -> dict[str, Any]:
    """Check that adding one MD5 use is reported as a single added finding."""
    issues: list[str] = []
    summary = diff.get("summary")
    if not isinstance(summary, Mapping):
        summary = {}
        issues.append("diff report has no summary object")

    added = diff.get("added")
    if not isinstance(added, list):
        added = []
        issues.append("diff report has no added-finding list")
    added_algorithms = sorted({str(item.get("algorithm", "")).strip().upper() for item in added if isinstance(item, Mapping)})

    expected_counts = {"added": 1, "removed": 0, "changed": 0}
    observed_counts: dict[str, Any] = {}
    for key, expected in expected_counts.items():
        observed = summary.get(key)
        observed_counts[key] = observed
        if observed != expected:
            issues.append(f"expected diff summary {key}={expected}, observed {observed!r}")

    if "MD5" not in added_algorithms:
        issues.append(f"expected an added MD5 finding; observed added algorithms: {added_algorithms}")

    return {
        "valid": not issues,
        "summary": observed_counts,
        "added_algorithms": added_algorithms,
        "expected_scenario": "a clean project gains one hashlib.md5 call",
        "issues": issues,
    }


def run_change_detection(
    repo_root: Path,
    output_dir: Path,
    run_command: CommandRunner,
    command_log: list[dict[str, Any]],
) -> dict[str, Any]:
    """Scan before/after synthetic projects and evaluate the CLI diff output."""
    workflow_dir = output_dir / "change_detection"
    if workflow_dir.exists():
        shutil.rmtree(workflow_dir)
    baseline_root = workflow_dir / "baseline_project"
    current_root = workflow_dir / "current_project"
    baseline_root.mkdir(parents=True)
    current_root.mkdir(parents=True)

    # Identical clean app in both states; only the current state gains a known
    # cryptographic API call. These files are inspected as text, never executed.
    (baseline_root / "app.py").write_text("def main():\n    return 'ok'\n", encoding="utf-8")
    (current_root / "app.py").write_text("def main():\n    return 'ok'\n", encoding="utf-8")
    (current_root / "legacy_crypto.py").write_text(
        "import hashlib\n\nlegacy_digest = hashlib.md5(b'phase7-validation')\n",
        encoding="utf-8",
    )

    context_path = workflow_dir / "context-that-does-not-exist.yaml"
    baseline_assessment = workflow_dir / "baseline_assessment.json"
    current_assessment = workflow_dir / "current_assessment.json"
    diff_path = workflow_dir / "diff.json"
    commands = [
        [sys.executable, "-m", "quantumshield", "scan", str(baseline_root), "--context", str(context_path),
         "--output", str(baseline_assessment), "--assessment-id", "phase7-change-baseline"],
        [sys.executable, "-m", "quantumshield", "scan", str(current_root), "--context", str(context_path),
         "--output", str(current_assessment), "--assessment-id", "phase7-change-current"],
    ]
    results: list[dict[str, Any]] = []
    for command in commands:
        result = run_command(command, cwd=repo_root)
        command_log.append(result)
        results.append(result)

    diff_result: dict[str, Any] | None = None
    if all(result.get("return_code") == 0 for result in results) and baseline_assessment.is_file() and current_assessment.is_file():
        command = [sys.executable, "-m", "quantumshield", "diff", str(baseline_assessment), str(current_assessment), "--output", str(diff_path)]
        diff_result = run_command(command, cwd=repo_root)
        command_log.append(diff_result)
    else:
        diff_result = {"return_code": None, "stderr": "one or both scan commands failed or omitted their assessment output"}

    issues: list[str] = []
    evaluated: dict[str, Any] = {"valid": False, "summary": {}, "added_algorithms": [], "issues": []}
    if diff_result.get("return_code") != 0 or not diff_path.is_file():
        issues.append("diff CLI failed or did not write diff.json")
        if diff_result.get("stderr"):
            issues.append(str(diff_result["stderr"]))
    else:
        try:
            evaluated = evaluate_change_diff(_read_object(diff_path))
            issues.extend(evaluated["issues"])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            issues.append(f"could not read or evaluate diff output: {exc}")

    return {
        "valid": not issues and all(result.get("return_code") == 0 for result in results),
        "expected_scenario": "a clean project gains one hashlib.md5 call",
        "baseline_assessment": str(baseline_assessment),
        "current_assessment": str(current_assessment),
        "diff_report": str(diff_path),
        "scan_commands_succeeded": all(result.get("return_code") == 0 for result in results),
        "diff_command_succeeded": diff_result.get("return_code") == 0 and diff_path.is_file(),
        "summary": evaluated.get("summary", {}),
        "added_algorithms": evaluated.get("added_algorithms", []),
        "issues": issues,
    }


def evaluate_compliance_report(
    report: Mapping[str, Any],
    markdown: str,
    *,
    expected_assessment_id: str = "phase7-compliance-fixture",
) -> dict[str, Any]:
    """Check a known RSA-2048 compliance boundary and linked plan estimate."""
    issues: list[str] = []
    if report.get("assessment_id") != expected_assessment_id:
        issues.append(f"unexpected compliance assessment_id: {report.get('assessment_id')!r}")

    rows = report.get("results")
    if not isinstance(rows, list):
        rows = []
        issues.append("compliance report has no results list")

    row = next((
        item for item in rows
        if isinstance(item, Mapping)
        and item.get("finding_id") == "CRYPTO-001"
        and item.get("framework") == "NIST IR 8547"
        and item.get("rule_id") == "NIST-IR8547-PUBLICKEY-112"
    ), None)
    if row is None:
        issues.append("expected NIST IR 8547 public-key 112-bit rule result was not found")
        observed_status = None
        plan_completion_date = None
        plan_finishes_before_deadline = None
    else:
        observed_status = row.get("status")
        plan_completion_date = row.get("plan_completion_date")
        plan_finishes_before_deadline = row.get("plan_finishes_before_deadline")
        if observed_status != "deprecated-soon":
            issues.append(f"expected RSA-2048 status 'deprecated-soon' on 2031-01-01, observed {observed_status!r}")
        if plan_completion_date != "2033-01-01":
            issues.append(f"expected the 24-month migration completion date 2033-01-01, observed {plan_completion_date!r}")
        if plan_finishes_before_deadline is not True:
            issues.append("expected the linked migration plan to finish before the compliance deadline")

    if "https://csrc.nist.gov/pubs/ir/8547/ipd" not in markdown:
        issues.append("compliance Markdown report is missing the expected NIST IR 8547 source link")
    if not markdown.startswith("# QuantumShield Compliance Assessment"):
        issues.append("compliance Markdown report does not have the expected report heading")

    return {
        "valid": not issues,
        "assessment_id": report.get("assessment_id"),
        "result_count": len(rows),
        "expected_rule_id": "NIST-IR8547-PUBLICKEY-112",
        "observed_status": observed_status,
        "plan_completion_date": plan_completion_date,
        "plan_finishes_before_deadline": plan_finishes_before_deadline,
        "markdown_has_source_link": "https://csrc.nist.gov/pubs/ir/8547/ipd" in markdown,
        "issues": issues,
    }


def run_compliance(
    repo_root: Path,
    output_dir: Path,
    run_command: CommandRunner,
    command_log: list[dict[str, Any]],
) -> dict[str, Any]:
    """Run compliance CLI on a labelled fixture with a matching migration plan."""
    workflow_dir = output_dir / "compliance"
    if workflow_dir.exists():
        shutil.rmtree(workflow_dir)
    workflow_dir.mkdir(parents=True)

    assessment_id = "phase7-compliance-fixture"
    assessment_path = workflow_dir / "assessment.json"
    plan_path = workflow_dir / "migration_plan.json"
    report_path = workflow_dir / "compliance_report.json"
    markdown_path = workflow_dir / "compliance_report.md"

    assessment = {
        "assessment_id": assessment_id,
        "target": "validation/compliance-fixture",
        "project_context": {},
        "findings": [{
            "finding_id": "CRYPTO-001",
            "algorithm": "RSA",
            "variant": "RSA-2048",
            "key_size": 2048,
            "curve": None,
            "role": "signature",
            "purpose": "synthetic compliance regression fixture",
            "status": "confirmed",
            "evidence": [{
                "file_path": "src/signing.py",
                "line_start": 1,
                "line_end": 1,
                "metadata": {},
            }],
        }],
    }
    plan = {
        "migration_plan_id": "phase7-compliance-plan",
        "source_assessment_id": assessment_id,
        "generated_at": "2031-01-01T00:00:00+00:00",
        "tasks": [{"finding_id": "CRYPTO-001", "timeline_months": 24}],
    }
    assessment_path.write_text(json.dumps(assessment, indent=2) + "\n", encoding="utf-8")
    plan_path.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")

    command = [
        sys.executable, "-m", "quantumshield", "compliance", str(assessment_path),
        "--plan", str(plan_path), "--as-of", "2031-01-01",
        "--output", str(report_path), "--markdown-output", str(markdown_path),
    ]
    result = run_command(command, cwd=repo_root)
    command_log.append(result)

    issues: list[str] = []
    evaluated: dict[str, Any] = {"valid": False, "issues": ["compliance CLI did not produce reports"]}
    if result.get("return_code") != 0 or not report_path.is_file() or not markdown_path.is_file():
        issues.append("compliance CLI failed or did not write both JSON and Markdown reports")
        if result.get("stderr"):
            issues.append(str(result["stderr"]))
    else:
        try:
            evaluated = evaluate_compliance_report(
                _read_object(report_path),
                markdown_path.read_text(encoding="utf-8"),
                expected_assessment_id=assessment_id,
            )
            issues.extend(evaluated["issues"])
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            issues.append(f"could not read or evaluate compliance outputs: {exc}")

    return {
        "valid": not issues and result.get("return_code") == 0 and report_path.is_file() and markdown_path.is_file(),
        "command_succeeded": result.get("return_code") == 0,
        "json_report": str(report_path),
        "markdown_report": str(markdown_path),
        "assessment_fixture": str(assessment_path),
        "migration_plan_fixture": str(plan_path),
        "assessment_id": evaluated.get("assessment_id"),
        "result_count": evaluated.get("result_count"),
        "expected_rule_id": evaluated.get("expected_rule_id"),
        "observed_status": evaluated.get("observed_status"),
        "plan_completion_date": evaluated.get("plan_completion_date"),
        "plan_finishes_before_deadline": evaluated.get("plan_finishes_before_deadline"),
        "markdown_has_source_link": evaluated.get("markdown_has_source_link", False),
        "issues": issues,
    }
