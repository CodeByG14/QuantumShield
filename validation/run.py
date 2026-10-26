"""Run QuantumShield against the controlled Phase 7 synthetic corpus.

From the repository root:
    uv run python -m validation.run

This initial corpus is a harness smoke test, not a statistically meaningful
claim about real-world cryptographic detection accuracy. See README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import yaml

from validation.metrics import evaluate_findings, extract_actual_findings, inspect_coverage, inspect_migration_plan
from validation.workflows import run_change_detection, run_compliance

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_SPEC = Path(__file__).resolve().with_name("expected.yaml")
_DEFAULT_OUTPUT = Path(__file__).resolve().with_name("out")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def _write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _write_markdown(path: Path, report: Mapping[str, Any]) -> None:
    detection = report.get("detection", {})
    coverage = report.get("coverage", {})
    plan = report.get("migration_plan", {})
    change_detection = report.get("change_detection", {})
    compliance = report.get("compliance", {})
    acceptance = report.get("acceptance", {})
    run_info = report.get("run", {})

    lines = [
        "# QuantumShield Phase 7 Validation Report",
        "",
        f"- **Result:** {'PASS' if acceptance.get('passed') else 'FAIL'}",
        f"- **Started (UTC):** {run_info.get('started_at_utc', 'unknown')}",
        f"- **Duration:** {run_info.get('duration_seconds', 'unknown')} seconds",
        f"- **Corpus:** `{run_info.get('corpus_path', 'unknown')}`",
        "",
        "> **Scope limitation:** the controlled corpus covers selected regression-backed cases across source code, static configuration, certificate parsing, extension indicators, and extracted-root-filesystem library-name discovery. Separate deterministic fixtures exercise change detection and compliance. These are conformance results for selected cases, not an estimate of accuracy across real repositories; compliance applicability still requires expert review.",
        "",
        "## Detection metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Expected findings | {detection.get('expected_findings', 0)} |",
        f"| Predicted findings (scorable) | {detection.get('scorable_findings', 0)} |",
        f"| True positives | {detection.get('true_positives', 0)} |",
        f"| False positives | {detection.get('false_positives', 0)} |",
        f"| False negatives | {detection.get('false_negatives', 0)} |",
        f"| Precision | {detection.get('precision', 'n/a')} |",
        f"| Recall | {detection.get('recall', 'n/a')} |",
        f"| F1 score | {detection.get('f1', 'n/a')} |",
        f"| Inconclusive findings | {detection.get('inconclusive_count', 0)} |",
        "",
        "## Per-algorithm metrics",
        "",
        "| Algorithm key | TP | FP | FN | Precision | Recall | F1 |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    by_algorithm = detection.get("by_algorithm", {})
    if by_algorithm:
        for algorithm, metrics in sorted(by_algorithm.items()):
            lines.append(
                f"| {algorithm} | {metrics.get('true_positives', 0)} | {metrics.get('false_positives', 0)} | "
                f"{metrics.get('false_negatives', 0)} | {metrics.get('precision', 'n/a')} | "
                f"{metrics.get('recall', 'n/a')} | {metrics.get('f1', 'n/a')} |"
            )
    else:
        lines.append("| _No labelled findings_ | 0 | 0 | 0 | n/a | n/a | n/a |")

    lines.extend([
        "",
        "## Coverage checks",
        "",
        f"- Available: {coverage.get('available', False)}",
        f"- Counts (first section): `{json.dumps(coverage.get('counts', {}), sort_keys=True)}`",
        f"- File coverage percentage (first section): {coverage.get('file_coverage_percent', 'n/a')}",
        "",
        "| Coverage section | Counts | File coverage (%) | Issues |",
        "|---|---|---:|---|",
    ])
    sections = coverage.get("sections", {})
    if sections:
        for section_name, section in sorted(sections.items()):
            lines.append(
                f"| {section_name} | `{json.dumps(section.get('counts', {}), sort_keys=True)}` | "
                f"{section.get('file_coverage_percent', 'n/a')} | "
                f"`{json.dumps(section.get('issues', []), ensure_ascii=False)}` |"
            )
    else:
        lines.append("| _No section detail available_ | `{}` | n/a | `[]` |")
    lines.extend([
        f"- Combined issues: `{json.dumps(coverage.get('issues', []), ensure_ascii=False)}`",
        "",
        "## Migration plan checks",
        "",
        f"- Valid: {plan.get('valid', False)}",
        f"- Task count: {plan.get('task_count', 'n/a')}",
        f"- Action counts: `{json.dumps(plan.get('action_counts', {}), sort_keys=True)}`",
        f"- Summary action counts consistent: {plan.get('summary_action_counts_consistent', 'not exposed')}",
        f"- Issues: `{json.dumps(plan.get('issues', []), ensure_ascii=False)}`",
        "",
        "## Change-detection workflow",
        "",
        f"- Valid: {change_detection.get('valid', False)}",
        f"- Summary: `{json.dumps(change_detection.get('summary', {}), sort_keys=True)}`",
        f"- Added algorithms: `{json.dumps(change_detection.get('added_algorithms', []))}`",
        f"- Issues: `{json.dumps(change_detection.get('issues', []), ensure_ascii=False)}`",
        "",
        "## Compliance workflow",
        "",
        f"- Valid: {compliance.get('valid', False)}",
        f"- Expected rule: {compliance.get('expected_rule_id', 'n/a')}",
        f"- Observed status: {compliance.get('observed_status', 'n/a')}",
        f"- Migration plan completion: {compliance.get('plan_completion_date', 'n/a')}",
        f"- Plan finishes before deadline: {compliance.get('plan_finishes_before_deadline', 'n/a')}",
        f"- Markdown contains source link: {compliance.get('markdown_has_source_link', False)}",
        f"- Issues: `{json.dumps(compliance.get('issues', []), ensure_ascii=False)}`",
        "",
        "## Acceptance checks",
        "",
    ])
    for check in acceptance.get("checks", []):
        lines.append(f"- [{'x' if check.get('passed') else ' '}] {check.get('name')}: {check.get('detail', '')}")

    false_positives = detection.get("false_positive_findings", [])
    if false_positives:
        lines.extend(["", "## False-positive findings", "", "```json", json.dumps(false_positives, indent=2), "```"])
    false_negatives = detection.get("false_negatives", 0)
    if false_negatives:
        lines.extend(["", "## Expected findings missed", "", "The JSON report contains metric totals; compare `expected.yaml` with the actual finding records to diagnose missed labels."])
    inconclusive = detection.get("inconclusive_findings", [])
    if inconclusive:
        lines.extend(["", "## Inconclusive findings", "", "```json", json.dumps(inconclusive, indent=2), "```"])

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run_command(command: list[str], *, cwd: Path, timeout_seconds: int = 120) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        result = subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds,
            check=False,
            env={**os.environ, "PYTHONUTF8": "1"},
        )
        return {
            "command": command,
            "return_code": result.returncode,
            "duration_seconds": round(time.perf_counter() - started, 4),
            "stdout": result.stdout[-8000:],
            "stderr": result.stderr[-8000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": command,
            "return_code": None,
            "duration_seconds": round(time.perf_counter() - started, 4),
            "stdout": str(exc.stdout or "")[-8000:],
            "stderr": f"Command timed out after {timeout_seconds} seconds: {exc}",
        }


def _load_spec(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Validation spec must be a YAML object: {path}")
    if payload.get("schema_version") != 1:
        raise ValueError("expected.yaml must have schema_version: 1")
    if not isinstance(payload.get("cases"), list) or not payload["cases"]:
        raise ValueError("expected.yaml must define a non-empty cases list")
    seen: set[str] = set()
    for section in ("cases", "rootfs_cases"):
        section_cases = payload.get(section, [])
        if not isinstance(section_cases, list):
            raise ValueError(f"{section} must be a list")
        for case in section_cases:
            if not isinstance(case, dict) or not case.get("path"):
                raise ValueError(f"each case in {section} needs a path")
            normalized = str(Path(str(case["path"])).as_posix())
            if normalized in seen:
                raise ValueError(f"duplicate case path: {normalized}")
            seen.add(normalized)
            if not isinstance(case.get("expected_findings", []), list):
                raise ValueError(f"expected_findings must be a list for {normalized}")
            for expected in case.get("expected_findings", []):
                if not isinstance(expected, dict) or not expected.get("algorithm"):
                    raise ValueError(f"each expected finding for {normalized} needs an algorithm")
    return payload


def _check_corpus_labels(corpus: Path, cases: list[dict[str, Any]]) -> list[str]:
    """Check that every source-project file has one explicit ground-truth case."""
    issues: list[str] = []
    if not corpus.is_dir():
        return [f"corpus target directory does not exist: {corpus}"]
    actual_files = {
        path.relative_to(corpus).as_posix()
        for path in corpus.rglob("*")
        if path.is_file()
        and not path.name.startswith(".")
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    expected_files = {str(Path(case["path"]).as_posix()) for case in cases}
    for path in sorted(actual_files - expected_files):
        issues.append(f"corpus file has no ground-truth label: {path}")
    for path in sorted(expected_files - actual_files):
        issues.append(f"ground-truth case references missing corpus file: {path}")
    return issues


def _check_rootfs_labels(rootfs: Path | None, cases: list[dict[str, Any]]) -> list[str]:
    """Check rootfs ground truth separately from the project-source corpus."""
    if not cases:
        return []
    if rootfs is None:
        return ["rootfs_cases are present but corpus.rootfs is not configured"]
    if not rootfs.is_dir():
        return [f"rootfs corpus directory does not exist: {rootfs}"]
    actual_files = {
        path.relative_to(rootfs).as_posix()
        for path in rootfs.rglob("*")
        if path.is_file()
        and not path.name.startswith(".")
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    expected_files: set[str] = set()
    for case in cases:
        raw = str(Path(case["path"]).as_posix())
        if raw.startswith("rootfs/"):
            raw = raw[len("rootfs/"):]
        expected_files.add(raw)
    issues: list[str] = []
    for path in sorted(actual_files - expected_files):
        issues.append(f"rootfs corpus file has no ground-truth label: {path}")
    for path in sorted(expected_files - actual_files):
        issues.append(f"rootfs ground-truth case references missing corpus file: {path}")
    return issues


def run(spec_path: Path, output_dir: Path) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc)
    start_timer = time.perf_counter()
    spec = _load_spec(spec_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    corpus_config = spec.get("corpus", {})
    corpus_value = corpus_config.get("target", "corpus/synthetic_project")
    corpus_path = (spec_path.parent / corpus_value).resolve()
    rootfs_value = corpus_config.get("rootfs")
    rootfs_path = (spec_path.parent / rootfs_value).resolve() if rootfs_value else None
    project_cases = spec["cases"]
    rootfs_cases = spec.get("rootfs_cases", [])
    # Metrics are computed across both labels, while file-label checks remain
    # correctly scoped to the separate source-project and rootfs trees.
    cases = project_cases + rootfs_cases
    corpus_issues = _check_corpus_labels(corpus_path, project_cases)
    corpus_issues.extend(_check_rootfs_labels(rootfs_path, rootfs_cases))

    assessment_path = output_dir / "assessment.json"
    plan_path = output_dir / "migration_plan.json"
    context_path = output_dir / "context-that-does-not-exist.yaml"
    scan_command = [
        sys.executable, "-m", "quantumshield", "scan", str(corpus_path),
        "--context", str(context_path), "--output", str(assessment_path),
        "--assessment-id", "phase7-synthetic-validation",
    ]
    if rootfs_path is not None:
        if not rootfs_path.is_dir():
            corpus_issues.append(f"configured rootfs directory does not exist: {rootfs_path}")
        else:
            scan_command.extend(["--rootfs", str(rootfs_path)])

    commands: list[dict[str, Any]] = []
    scan_result = _run_command(scan_command, cwd=_REPO_ROOT)
    commands.append(scan_result)
    report: dict[str, Any] = {
        "schema_version": 1,
        "run": {
            "started_at_utc": started_at.isoformat(),
            "corpus_path": corpus_path.relative_to(_REPO_ROOT).as_posix() if corpus_path.is_relative_to(_REPO_ROOT) else str(corpus_path),
            "rootfs_path": rootfs_path.relative_to(_REPO_ROOT).as_posix() if rootfs_path is not None and rootfs_path.is_relative_to(_REPO_ROOT) else (str(rootfs_path) if rootfs_path is not None else None),
            "spec_path": spec_path.relative_to(_REPO_ROOT).as_posix() if spec_path.is_relative_to(_REPO_ROOT) else str(spec_path),
            "output_dir": output_dir.relative_to(_REPO_ROOT).as_posix() if output_dir.is_relative_to(_REPO_ROOT) else str(output_dir),
        },
        "scope_note": "Controlled regression-backed corpus plus deterministic compliance and change-detection fixtures. Results are conformance checks for selected behaviors, not a statistically representative estimate of real-world detection accuracy.",
        "commands": commands,
        "corpus_label_issues": corpus_issues,
        "detection": {},
        "coverage": {"available": False, "issues": ["scan has not completed successfully"]},
        "migration_plan": {"valid": False, "task_count": None, "action_counts": {}, "issues": ["plan has not been generated"]},
        "change_detection": {"valid": False, "issues": ["change-detection workflow has not run"]},
        "compliance": {"valid": False, "issues": ["compliance workflow has not run"]},
        "acceptance": {"passed": False, "checks": []},
    }

    if scan_result["return_code"] == 0 and assessment_path.is_file():
        try:
            assessment = _read_json(assessment_path)
            actual = extract_actual_findings(assessment, project_root=corpus_path, rootfs_root=rootfs_path)
            detection = evaluate_findings(cases, actual)
            coverage = inspect_coverage(assessment)
            report["detection"] = detection
            report["coverage"] = coverage

            plan_result = _run_command(
                [sys.executable, "-m", "quantumshield", "plan", str(assessment_path), "--output", str(plan_path)],
                cwd=_REPO_ROOT,
            )
            commands.append(plan_result)
            if plan_result["return_code"] == 0 and plan_path.is_file():
                report["migration_plan"] = inspect_migration_plan(_read_json(plan_path))
            else:
                report["migration_plan"] = {
                    "valid": False,
                    "task_count": None,
                    "action_counts": {},
                    "issues": ["migration plan command failed or did not produce a JSON file"],
                }
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            report["execution_error"] = f"could not evaluate scan outputs: {exc}"
    else:
        report["execution_error"] = "scan command failed or did not produce assessment.json"

    # Exercise public diff and compliance commands with separate, controlled fixtures.
    # These run independently of the corpus scan so their results remain visible
    # even if source discovery fails.
    try:
        report["change_detection"] = run_change_detection(_REPO_ROOT, output_dir, _run_command, commands)
    except Exception as exc:  # validation must surface the workflow failure in its report
        report["change_detection"] = {"valid": False, "issues": [f"change-detection workflow raised {type(exc).__name__}: {exc}"]}
    try:
        report["compliance"] = run_compliance(_REPO_ROOT, output_dir, _run_command, commands)
    except Exception as exc:  # validation must surface the workflow failure in its report
        report["compliance"] = {"valid": False, "issues": [f"compliance workflow raised {type(exc).__name__}: {exc}"]}

    thresholds = spec.get("acceptance", {})
    detection = report.get("detection", {})
    coverage = report.get("coverage", {})
    migration_plan = report.get("migration_plan", {})
    checks: list[dict[str, Any]] = []

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    add_check("all_corpus_files_labelled", not corpus_issues, "; ".join(corpus_issues) or "every source-project and rootfs corpus file has a ground-truth case")
    add_check("scan_command_succeeded", scan_result["return_code"] == 0 and assessment_path.is_file(), f"return code={scan_result['return_code']}")
    if detection:
        add_check(
            "minimum_precision",
            float(detection.get("precision", 0)) >= float(thresholds.get("min_precision", 1.0)),
            f"observed={detection.get('precision')}, required>={thresholds.get('min_precision', 1.0)}",
        )
        add_check(
            "minimum_recall",
            float(detection.get("recall", 0)) >= float(thresholds.get("min_recall", 1.0)),
            f"observed={detection.get('recall')}, required>={thresholds.get('min_recall', 1.0)}",
        )
        add_check(
            "minimum_f1",
            float(detection.get("f1", 0)) >= float(thresholds.get("min_f1", 1.0)),
            f"observed={detection.get('f1')}, required>={thresholds.get('min_f1', 1.0)}",
        )
        add_check(
            "no_unlabelled_findings",
            not detection.get("unlabelled_findings"),
            f"unlabelled findings={len(detection.get('unlabelled_findings', []))}",
        )
    else:
        add_check("detection_metrics_available", False, "no metrics were calculated")
    add_check("coverage_invariants", bool(coverage.get("available")) and not coverage.get("issues"), "; ".join(coverage.get("issues", [])) or "coverage counts and file explanations are consistent")
    add_check("migration_plan_invariants", bool(migration_plan.get("valid")), "; ".join(migration_plan.get("issues", [])) or "migration tasks and exposed summaries are consistent")
    change_detection = report.get("change_detection", {})
    add_check("change_detection_workflow", bool(change_detection.get("valid")), "; ".join(change_detection.get("issues", [])) or "adding one MD5 call is reported as one added finding")
    compliance = report.get("compliance", {})
    add_check("compliance_workflow", bool(compliance.get("valid")), "; ".join(compliance.get("issues", [])) or "known RSA-2048 compliance status, source link, and plan estimate match expected values")
    report["acceptance"] = {"passed": all(check["passed"] for check in checks), "checks": checks, "thresholds": thresholds}
    report["run"]["duration_seconds"] = round(time.perf_counter() - start_timer, 4)
    report["run"]["finished_at_utc"] = datetime.now(timezone.utc).isoformat()

    report_json = output_dir / "validation_report.json"
    report_md = output_dir / "validation_report.md"
    _write_json(report_json, report)
    _write_markdown(report_md, report)
    report["run"]["report_json"] = str(report_json.relative_to(_REPO_ROOT)) if report_json.is_relative_to(_REPO_ROOT) else str(report_json)
    report["run"]["report_markdown"] = str(report_md.relative_to(_REPO_ROOT)) if report_md.is_relative_to(_REPO_ROOT) else str(report_md)
    # Rewrite JSON once with its own report paths included; markdown remains valid.
    _write_json(report_json, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate QuantumShield against its controlled Phase 7 corpus")
    parser.add_argument("--spec", type=Path, default=_DEFAULT_SPEC, help="Ground-truth YAML file (default: validation/expected.yaml)")
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT, help="Directory for scan artifacts and reports")
    args = parser.parse_args(argv)

    spec_path = args.spec.resolve()
    output_dir = args.output_dir.resolve()
    try:
        report = run(spec_path, output_dir)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Validation failed before execution: {exc}", file=sys.stderr)
        return 2

    detection = report.get("detection", {})
    print(f"Phase 7 validation: {'PASS' if report['acceptance']['passed'] else 'FAIL'}")
    print(
        "Detection: TP={tp} FP={fp} FN={fn} precision={precision} recall={recall} F1={f1}".format(
            tp=detection.get("true_positives", 0),
            fp=detection.get("false_positives", 0),
            fn=detection.get("false_negatives", 0),
            precision=detection.get("precision", "n/a"),
            recall=detection.get("recall", "n/a"),
            f1=detection.get("f1", "n/a"),
        )
    )
    print(f"JSON report: {report['run']['report_json']}")
    print(f"Markdown report: {report['run']['report_markdown']}")
    for check in report["acceptance"]["checks"]:
        print(f"{'PASS' if check['passed'] else 'FAIL'}: {check['name']} — {check['detail']}")
    return 0 if report["acceptance"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
