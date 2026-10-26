"""Run QuantumShield's separate Phase 7 independent acceptance scenario.

Usage from the repository root:
    uv run python -m validation.acceptance

The project is inspected as data; its code is never executed. Rootfs scanning
is limited to the separately supplied, already-extracted fixture directory.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Mapping, Sequence

import yaml

from validation.metrics import evaluate_findings, extract_actual_findings, inspect_coverage, inspect_migration_plan

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_SPEC = Path(__file__).resolve().with_name("acceptance_expected.yaml")
_DEFAULT_OUTPUT = _REPO_ROOT / "validation" / "out" / "acceptance_e2e"
_SOURCE_LINK = "https://csrc.nist.gov/pubs/ir/8547/ipd"


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def _visible_files(root: Path) -> set[str]:
    if not root.is_dir():
        return set()
    return {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file()
        and not path.name.startswith(".")
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }


def load_spec(path: Path) -> dict[str, Any]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("acceptance specification must be a YAML object with schema_version: 1")
    corpus = payload.get("corpus")
    if not isinstance(corpus, dict) or not corpus.get("target") or not corpus.get("rootfs"):
        raise ValueError("acceptance specification must define corpus.target and corpus.rootfs")
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("acceptance specification must contain non-empty cases")

    seen: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("path"), str) or not case["path"].strip():
            raise ValueError("each acceptance case requires a path")
        case_path = PurePosixPath(case["path"].replace("\\", "/")).as_posix()
        if case_path in seen:
            raise ValueError(f"duplicate acceptance case path: {case_path}")
        seen.add(case_path)
        if case.get("label") not in {"positive", "negative", "conservative-triage", "rootfs-positive"}:
            raise ValueError(f"unsupported label for {case_path}: {case.get('label')!r}")
        expected = case.get("expected_findings", [])
        if not isinstance(expected, list):
            raise ValueError(f"expected_findings must be a list for {case_path}")
        for finding in expected:
            if not isinstance(finding, dict) or not finding.get("algorithm"):
                raise ValueError(f"expected findings for {case_path} must each specify algorithm")
    return payload


def split_cases(cases: Sequence[Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Separate paths labelled as rootfs entries from project-relative paths."""
    project_cases: list[dict[str, Any]] = []
    rootfs_cases: list[dict[str, Any]] = []
    for raw in cases:
        case = dict(raw)
        path = PurePosixPath(str(case["path"]).replace("\\", "/")).as_posix()
        if path.startswith("rootfs/"):
            case["path"] = path
            rootfs_cases.append(case)
        else:
            case["path"] = path
            project_cases.append(case)
    return project_cases, rootfs_cases


def check_file_labels(project_root: Path, rootfs_root: Path, cases: Sequence[Mapping[str, Any]]) -> list[str]:
    """Ensure every acceptance input file has exactly one expected-result case."""
    project_cases, rootfs_cases = split_cases(cases)
    issues: list[str] = []
    project_actual = _visible_files(project_root)
    project_expected = {str(case["path"]) for case in project_cases}
    for path in sorted(project_actual - project_expected):
        issues.append(f"acceptance project file has no ground-truth label: {path}")
    for path in sorted(project_expected - project_actual):
        issues.append(f"acceptance case references missing project file: {path}")

    rootfs_actual = _visible_files(rootfs_root)
    rootfs_expected = {str(case["path"])[len("rootfs/"):] for case in rootfs_cases}
    for path in sorted(rootfs_actual - rootfs_expected):
        issues.append(f"acceptance rootfs file has no ground-truth label: rootfs/{path}")
    for path in sorted(rootfs_expected - rootfs_actual):
        issues.append(f"acceptance case references missing rootfs file: rootfs/{path}")
    return issues


def evaluate_acceptance_diff(diff: Mapping[str, Any]) -> dict[str, Any]:
    """Require one added SHA-256 finding and twelve unchanged baseline findings."""
    issues: list[str] = []
    summary = diff.get("summary")
    if not isinstance(summary, Mapping):
        summary = {}
        issues.append("diff output has no summary object")

    expected_counts = {"added": 1, "removed": 0, "changed": 0, "unchanged": 12}
    observed: dict[str, Any] = {}
    for field, expected in expected_counts.items():
        observed[field] = summary.get(field)
        if observed[field] != expected:
            issues.append(f"expected diff summary {field}={expected}, observed {observed[field]!r}")

    added = diff.get("added")
    if not isinstance(added, list):
        added = []
        issues.append("diff output has no added-finding list")
    if len(added) != 1:
        issues.append(f"expected exactly one added finding, observed {len(added)}")
    added_algorithms = [str(item.get("algorithm", "")) for item in added if isinstance(item, Mapping)]
    if added_algorithms != ["SHA-256"]:
        issues.append(f"expected only an added SHA-256 finding, observed {added_algorithms!r}")
    elif added[0].get("variant") != "SHA-256" or added[0].get("status") != "confirmed":
        issues.append("added SHA-256 finding does not have the expected variant and confirmed status")

    return {"valid": not issues, "summary": observed, "added_algorithms": added_algorithms, "issues": issues}


def evaluate_compliance_artifacts(
    report: Mapping[str, Any], markdown: str, *, expected_assessment_id: str
) -> dict[str, Any]:
    """Check report identity, non-empty results, source references, and Markdown output."""
    issues: list[str] = []
    if report.get("assessment_id") != expected_assessment_id:
        issues.append(
            f"compliance assessment ID mismatch: expected {expected_assessment_id!r}, "
            f"observed {report.get('assessment_id')!r}"
        )
    results = report.get("results")
    if not isinstance(results, list) or not results:
        issues.append("compliance report has no rule results")
        result_count = 0
    else:
        result_count = len(results)
        malformed = [index for index, result in enumerate(results) if not isinstance(result, Mapping)]
        if malformed:
            issues.append(f"compliance report contains non-object results at indices {malformed}")
    has_source = _SOURCE_LINK in markdown
    if not has_source:
        issues.append("compliance Markdown does not contain the expected NIST IR 8547 source link")
    if not markdown.startswith("# QuantumShield Compliance Assessment"):
        issues.append("compliance Markdown has an unexpected report heading")
    return {
        "valid": not issues,
        "assessment_id": report.get("assessment_id"),
        "result_count": result_count,
        "markdown_has_source_link": has_source,
        "issues": issues,
    }


def _run_command(command: Sequence[str | Path], *, cwd: Path, timeout_seconds: int = 120) -> dict[str, Any]:
    rendered = [str(part) for part in command]
    try:
        completed = subprocess.run(
            rendered,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        return {
            "command": rendered,
            "return_code": completed.returncode,
            "stdout": completed.stdout[-12000:],
            "stderr": completed.stderr[-12000:],
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "command": rendered,
            "return_code": None,
            "stdout": (exc.stdout or "")[-12000:] if isinstance(exc.stdout, str) else "",
            "stderr": f"command timed out after {timeout_seconds} seconds",
        }
    except OSError as exc:
        return {"command": rendered, "return_code": None, "stdout": "", "stderr": str(exc)}


def _coverage_records(assessment: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    coverage = assessment.get("coverage")
    if not isinstance(coverage, Mapping):
        return {}
    records = coverage.get("files")
    if not isinstance(records, list):
        return {}
    return {
        str(record.get("path")): record
        for record in records
        if isinstance(record, Mapping) and record.get("path")
    }


def _negative_control_summary(assessment: Mapping[str, Any], cases: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    records = _coverage_records(assessment)
    findings = assessment.get("findings", [])
    paths_with_findings: set[str] = set()
    if isinstance(findings, list):
        for finding in findings:
            if not isinstance(finding, Mapping):
                continue
            evidence = finding.get("evidence")
            if isinstance(evidence, list):
                for item in evidence:
                    if isinstance(item, Mapping) and item.get("file_path"):
                        paths_with_findings.add(str(item["file_path"]))

    expected_negative = [str(case["path"]) for case in cases if case.get("label") == "negative"]
    details: list[dict[str, Any]] = []
    for path in expected_negative:
        outcome = records.get(path, {}).get("outcome")
        details.append({
            "path": path,
            "outcome": outcome,
            "has_finding": path in paths_with_findings,
            "contents_analyzed": outcome == "analyzed",
            "note": None if outcome == "analyzed" else "No-content-negative conclusion is not established because this file was not analyzed.",
        })
    return {
        "details": details,
        "analyzed_negative_controls": sum(item["contents_analyzed"] for item in details),
        "unverified_negative_controls": [item["path"] for item in details if not item["contents_analyzed"]],
        "issues": [f"negative control {item['path']} produced a finding" for item in details if item["has_finding"]],
    }


def _markdown_report(path: Path, report: Mapping[str, Any]) -> None:
    detection = report.get("detection", {})
    coverage = report.get("coverage", {})
    plan = report.get("migration_plan", {})
    compliance = report.get("compliance", {})
    change = report.get("change_detection", {})
    negative = report.get("negative_controls", {})
    acceptance = report.get("acceptance", {})
    lines = [
        "# QuantumShield Independent Acceptance Report",
        "",
        f"- **Result:** {'PASS' if acceptance.get('passed') else 'FAIL'}",
        f"- **Started (UTC):** {report.get('run', {}).get('started_at_utc', 'unknown')}",
        f"- **Duration:** {report.get('run', {}).get('duration_seconds', 'unknown')} seconds",
        f"- **Project:** `{report.get('run', {}).get('project_path', 'unknown')}`",
        f"- **Extracted root filesystem:** `{report.get('run', {}).get('rootfs_path', 'unknown')}`",
        "",
        "> This is a labelled, independent acceptance exercise, not a statistically representative estimate of detection accuracy. It scans files as data, never executes project code, and inventories only a separately extracted root-filesystem fixture.",
        "",
        "## Detection metrics",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| Expected findings | {detection.get('expected_findings', 'n/a')} |",
        f"| Predicted findings | {detection.get('scorable_findings', detection.get('predicted_findings', 'n/a'))} |",
        f"| True positives | {detection.get('true_positives', 'n/a')} |",
        f"| False positives | {detection.get('false_positives', 'n/a')} |",
        f"| False negatives | {detection.get('false_negatives', 'n/a')} |",
        f"| Precision | {detection.get('precision', 'n/a')} |",
        f"| Recall | {detection.get('recall', 'n/a')} |",
        f"| F1 | {detection.get('f1', 'n/a')} |",
        f"| Inconclusive | {detection.get('inconclusive_count', 0)} |",
        "",
        "## Coverage",
        "",
        f"- Coverage invariant result: {not coverage.get('issues') and coverage.get('available', False)}",
        f"- Coverage issues: `{json.dumps(coverage.get('issues', []), ensure_ascii=False)}`",
        "- Coverage sections:",
    ]
    for key, section in sorted(coverage.get("sections", {}).items()):
        lines.append(
            f"  - `{key}`: {section.get('file_coverage_percent', 'n/a')}% "
            f"({json.dumps(section.get('counts', {}), sort_keys=True)})"
        )
    lines.extend([
        "",
        "## Negative controls",
        "",
        f"- Analyzed negative controls: {negative.get('analyzed_negative_controls', 0)}",
        f"- Negative controls not analyzed: `{json.dumps(negative.get('unverified_negative_controls', []))}`",
        "",
        "| Path | Coverage outcome | Finding observed | Content analyzed |",
        "|---|---|---:|---:|",
    ])
    for item in negative.get("details", []):
        lines.append(f"| `{item['path']}` | {item.get('outcome', 'unknown')} | {item.get('has_finding')} | {item.get('contents_analyzed')} |")
    lines.extend([
        "",
        "## Migration plan",
        "",
        f"- Valid: {plan.get('valid', False)}",
        f"- Task count: {plan.get('task_count', 'n/a')}",
        f"- Action summary consistent: {plan.get('summary_action_counts_consistent', 'not exposed')}",
        f"- Issues: `{json.dumps(plan.get('issues', []), ensure_ascii=False)}`",
        "",
        "## Compliance report",
        "",
        f"- Valid: {compliance.get('valid', False)}",
        f"- Rule results: {compliance.get('result_count', 0)}",
        f"- Source link present: {compliance.get('markdown_has_source_link', False)}",
        f"- Issues: `{json.dumps(compliance.get('issues', []), ensure_ascii=False)}`",
        "",
        "## Change detection",
        "",
        f"- Valid: {change.get('valid', False)}",
        f"- Diff summary: `{json.dumps(change.get('summary', {}), sort_keys=True)}`",
        f"- Added algorithms: `{json.dumps(change.get('added_algorithms', []))}`",
        f"- Issues: `{json.dumps(change.get('issues', []), ensure_ascii=False)}`",
        "",
        "## Acceptance checks",
        "",
    ])
    for check in acceptance.get("checks", []):
        lines.append(f"- [{'x' if check.get('passed') else ' '}] {check.get('name')}: {check.get('detail', '')}")
    lines.extend(["", "## Unsupported or inconclusive inputs", "", "File coverage measures the amount of input processed, not completeness of cryptographic discovery. Unsupported labelled files are listed above and are not treated as analyzed negative controls."])
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(spec_path: Path, output_dir: Path, *, as_of: str = "2026-10-26") -> dict[str, Any]:
    started = datetime.now(timezone.utc)
    timer = time.perf_counter()
    spec_path = spec_path.resolve()
    spec = load_spec(spec_path)
    base_dir = spec_path.parent
    corpus = spec["corpus"]
    project_root = (base_dir / str(corpus["target"])).resolve()
    rootfs_root = (base_dir / str(corpus["rootfs"])).resolve()
    context_value = str(corpus.get("context", "acceptance_context.yaml"))
    context_path = (base_dir / context_value).resolve()
    output_dir = output_dir.resolve()

    # Never allow cleanup to remove the repository, corpus, rootfs, or a parent
    # of any of those locations. Also keep output outside either scanned tree.
    if output_dir == _REPO_ROOT or _REPO_ROOT.is_relative_to(output_dir):
        raise ValueError("output directory cannot be the repository root or one of its parents")
    if (
        output_dir == project_root
        or output_dir == rootfs_root
        or project_root.is_relative_to(output_dir)
        or rootfs_root.is_relative_to(output_dir)
        or output_dir.is_relative_to(project_root)
        or output_dir.is_relative_to(rootfs_root)
    ):
        raise ValueError("output directory must be separate from both acceptance input trees")
    if output_dir.exists():
        shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    cases = spec["cases"]
    project_cases, rootfs_cases = split_cases(cases)
    label_issues = check_file_labels(project_root, rootfs_root, cases)
    commands: list[dict[str, Any]] = []
    checks: list[dict[str, Any]] = []

    def add_check(name: str, passed: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(passed), "detail": detail})

    add_check("acceptance_files_labelled", not label_issues, "; ".join(label_issues) or "every project and rootfs fixture has ground-truth labels")
    add_check("inputs_exist", project_root.is_dir() and rootfs_root.is_dir() and context_path.is_file(), f"project={project_root.is_dir()}, rootfs={rootfs_root.is_dir()}, context={context_path.is_file()}")

    if not project_root.is_dir() or not rootfs_root.is_dir() or not context_path.is_file():
        report = {
            "schema_version": 1,
            "run": {"started_at_utc": started.isoformat(), "duration_seconds": round(time.perf_counter() - timer, 4), "project_path": str(project_root), "rootfs_path": str(rootfs_root), "spec_path": str(spec_path), "output_dir": str(output_dir)},
            "corpus_label_issues": label_issues,
            "commands": commands,
            "acceptance": {"passed": False, "checks": checks},
        }
        _write_json(output_dir / "acceptance_report.json", report)
        _markdown_report(output_dir / "acceptance_report.md", report)
        return report

    baseline_path = output_dir / "acceptance_assessment.json"
    plan_path = output_dir / "acceptance_plan.json"
    compliance_path = output_dir / "acceptance_compliance.json"
    compliance_md_path = output_dir / "acceptance_compliance.md"

    scan_cmd = [
        sys.executable, "-m", "quantumshield", "scan", str(project_root),
        "--context", str(context_path), "--rootfs", str(rootfs_root),
        "--assessment-id", "phase7-independent-acceptance", "--output", str(baseline_path),
    ]
    scan_result = _run_command(scan_cmd, cwd=_REPO_ROOT)
    commands.append(scan_result)

    report: dict[str, Any] = {
        "schema_version": 1,
        "run": {
            "started_at_utc": started.isoformat(),
            "project_path": project_root.relative_to(_REPO_ROOT).as_posix() if project_root.is_relative_to(_REPO_ROOT) else str(project_root),
            "rootfs_path": rootfs_root.relative_to(_REPO_ROOT).as_posix() if rootfs_root.is_relative_to(_REPO_ROOT) else str(rootfs_root),
            "spec_path": spec_path.relative_to(_REPO_ROOT).as_posix() if spec_path.is_relative_to(_REPO_ROOT) else str(spec_path),
            "output_dir": output_dir.relative_to(_REPO_ROOT).as_posix() if output_dir.is_relative_to(_REPO_ROOT) else str(output_dir),
            "as_of": as_of,
        },
        "scope_note": "Independent labelled acceptance project; conformance against this specification is not a statistical estimate of real-world accuracy. Project code is scanned as data and never executed; rootfs scanning is limited to the supplied extracted fixture.",
        "commands": commands,
        "corpus_label_issues": label_issues,
        "detection": {},
        "coverage": {"available": False, "issues": ["scan did not complete successfully"]},
        "negative_controls": {},
        "migration_plan": {"valid": False, "issues": ["migration plan not generated"]},
        "compliance": {"valid": False, "issues": ["compliance reports not generated"]},
        "change_detection": {"valid": False, "issues": ["acceptance change scenario not run"]},
    }

    assessment: dict[str, Any] | None = None
    if scan_result["return_code"] == 0 and baseline_path.is_file():
        try:
            assessment = _read_object(baseline_path)
            actual = extract_actual_findings(assessment, project_root=project_root, rootfs_root=rootfs_root)
            detection = evaluate_findings(cases, actual)
            report["detection"] = detection
            report["coverage"] = inspect_coverage(assessment)
            report["negative_controls"] = _negative_control_summary(assessment, project_cases)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            report["execution_error"] = f"could not evaluate assessment output: {type(exc).__name__}: {exc}"
    add_check("baseline_scan_succeeded", scan_result["return_code"] == 0 and baseline_path.is_file(), f"return code={scan_result['return_code']}")

    if assessment is not None:
        plan_cmd = [sys.executable, "-m", "quantumshield", "plan", str(baseline_path), "--output", str(plan_path)]
        plan_result = _run_command(plan_cmd, cwd=_REPO_ROOT)
        commands.append(plan_result)
        if plan_result["return_code"] == 0 and plan_path.is_file():
            try:
                report["migration_plan"] = inspect_migration_plan(_read_object(plan_path))
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                report["migration_plan"] = {"valid": False, "issues": [f"could not evaluate plan: {exc}"]}

        compliance_cmd = [
            sys.executable, "-m", "quantumshield", "compliance", str(baseline_path),
            "--plan", str(plan_path), "--as-of", as_of,
            "--output", str(compliance_path), "--markdown-output", str(compliance_md_path),
        ]
        compliance_result = _run_command(compliance_cmd, cwd=_REPO_ROOT)
        commands.append(compliance_result)
        if compliance_result["return_code"] == 0 and compliance_path.is_file() and compliance_md_path.is_file():
            try:
                compliance_data = _read_object(compliance_path)
                markdown = compliance_md_path.read_text(encoding="utf-8")
                report["compliance"] = evaluate_compliance_artifacts(
                    compliance_data, markdown, expected_assessment_id=str(assessment.get("assessment_id", ""))
                )
                report["compliance"].update({"json_report": str(compliance_path), "markdown_report": str(compliance_md_path)})
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                report["compliance"] = {"valid": False, "issues": [f"could not evaluate compliance reports: {exc}"]}
        else:
            report["compliance"] = {"valid": False, "issues": ["compliance command failed or omitted JSON/Markdown report", compliance_result.get("stderr", "")[-4000:]]}

        # Build a separate copy with exactly one added SHA-256 API call.
        change_dir = output_dir / "change_detection"
        baseline_copy = change_dir / "baseline_project"
        current_copy = change_dir / "current_project"
        change_dir.mkdir(parents=True, exist_ok=True)
        shutil.copytree(project_root, baseline_copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copytree(project_root, current_copy, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        crypto_file = current_copy / "src" / "legacy_crypto.py"
        if not crypto_file.is_file():
            report["change_detection"] = {"valid": False, "issues": ["acceptance change scenario requires src/legacy_crypto.py"]}
        else:
            text = crypto_file.read_text(encoding="utf-8")
            if "hashlib.sha256" in text:
                report["change_detection"] = {"valid": False, "issues": ["baseline already contains hashlib.sha256; cannot assert a single new SHA-256 finding"]}
            else:
                crypto_file.write_text(text.rstrip() + '\n\nhashlib.sha256(b"phase7-acceptance-change")\n', encoding="utf-8")
                baseline_change_assessment = change_dir / "baseline_assessment.json"
                current_change_assessment = change_dir / "current_assessment.json"
                diff_path = change_dir / "diff.json"
                change_scan_results = []
                for target, assessment_output, assessment_id in (
                    (baseline_copy, baseline_change_assessment, "phase7-independent-change-baseline"),
                    (current_copy, current_change_assessment, "phase7-independent-change-current"),
                ):
                    cmd = [
                        sys.executable, "-m", "quantumshield", "scan", str(target),
                        "--context", str(context_path), "--rootfs", str(rootfs_root),
                        "--assessment-id", assessment_id, "--output", str(assessment_output),
                    ]
                    result = _run_command(cmd, cwd=_REPO_ROOT)
                    commands.append(result)
                    change_scan_results.append(result)
                diff_result: dict[str, Any] = {"return_code": None, "stderr": "baseline/current scan failed"}
                if all(item["return_code"] == 0 for item in change_scan_results) and baseline_change_assessment.is_file() and current_change_assessment.is_file():
                    diff_result = _run_command([
                        sys.executable, "-m", "quantumshield", "diff", str(baseline_change_assessment),
                        str(current_change_assessment), "--output", str(diff_path),
                    ], cwd=_REPO_ROOT)
                    commands.append(diff_result)
                if diff_result.get("return_code") == 0 and diff_path.is_file():
                    try:
                        change_summary = evaluate_acceptance_diff(_read_object(diff_path))
                        change_summary.update({"diff_report": str(diff_path), "issues": change_summary["issues"]})
                        report["change_detection"] = change_summary
                    except (OSError, ValueError, json.JSONDecodeError) as exc:
                        report["change_detection"] = {"valid": False, "issues": [f"could not evaluate diff output: {exc}"]}
                else:
                    report["change_detection"] = {"valid": False, "issues": ["change-detection CLI failed or did not write diff output", str(diff_result.get("stderr", ""))[-4000:]]}

    detection = report.get("detection", {})
    thresholds = spec.get("acceptance", {})
    if not detection:
        add_check("detection_metrics_available", False, "no detection metrics were calculated")
    else:
        add_check("acceptance_findings_match", detection.get("expected_findings") == 12 and detection.get("true_positives") == 12, f"expected=12, observed TP={detection.get('true_positives')} of {detection.get('expected_findings')}")
        for key, default in (("precision", 1.0), ("recall", 1.0), ("f1", 1.0)):
            observed = float(detection.get(key, 0) or 0)
            required = float(thresholds.get(f"min_{key}", default))
            add_check(f"minimum_{key}", observed >= required, f"observed={observed}, required>={required}")
        add_check("no_unlabelled_findings", not detection.get("unlabelled_findings"), f"unlabelled findings={len(detection.get('unlabelled_findings', []))}")
        add_check("no_false_positives_or_negatives", detection.get("false_positives") == 0 and detection.get("false_negatives") == 0, f"FP={detection.get('false_positives')}, FN={detection.get('false_negatives')}")

    coverage = report.get("coverage", {})
    add_check("coverage_invariants", bool(coverage.get("available")) and not coverage.get("issues"), "; ".join(coverage.get("issues", [])) or "project and rootfs coverage counts and explanations are consistent")
    plan = report.get("migration_plan", {})
    add_check("migration_plan_invariants", bool(plan.get("valid")), "; ".join(plan.get("issues", [])) or "migration tasks and summary counts are consistent")
    compliance = report.get("compliance", {})
    add_check("compliance_reports", bool(compliance.get("valid")), "; ".join(compliance.get("issues", [])) or f"{compliance.get('result_count')} compliance rule results and expected source link verified")
    change = report.get("change_detection", {})
    add_check("independent_change_detection", bool(change.get("valid")), "; ".join(change.get("issues", [])) or "one SHA-256 addition detected; baseline findings unchanged")
    negative = report.get("negative_controls", {})
    add_check("analyzed_clean_negative_control", any(item.get("path") == "src/clean.py" and item.get("outcome") == "analyzed" and not item.get("has_finding") for item in negative.get("details", [])), "src/clean.py must be analyzed and produce no finding")
    add_check("no_findings_on_negative_controls", not negative.get("issues"), "; ".join(negative.get("issues", [])) or "no findings on labelled negative controls")

    report["acceptance"] = {"passed": all(item["passed"] for item in checks), "checks": checks, "thresholds": thresholds}
    report["run"]["duration_seconds"] = round(time.perf_counter() - timer, 4)
    report["run"]["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
    json_path = output_dir / "acceptance_report.json"
    markdown_path = output_dir / "acceptance_report.md"
    _write_json(json_path, report)
    _markdown_report(markdown_path, report)
    report["run"]["report_json"] = str(json_path.relative_to(_REPO_ROOT)) if json_path.is_relative_to(_REPO_ROOT) else str(json_path)
    report["run"]["report_markdown"] = str(markdown_path.relative_to(_REPO_ROOT)) if markdown_path.is_relative_to(_REPO_ROOT) else str(markdown_path)
    _write_json(json_path, report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run QuantumShield's independent Phase 7 acceptance scenario")
    parser.add_argument("--spec", type=Path, default=_DEFAULT_SPEC, help="Acceptance ground-truth YAML")
    parser.add_argument("--output-dir", type=Path, default=_DEFAULT_OUTPUT, help="Output directory; existing output is replaced")
    parser.add_argument("--as-of", default="2026-10-26", help="Compliance evaluation date in YYYY-MM-DD format")
    args = parser.parse_args(argv)
    try:
        report = run(args.spec, args.output_dir, as_of=args.as_of)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        print(f"Acceptance run could not start: {exc}", file=sys.stderr)
        return 2

    acceptance = report.get("acceptance", {})
    print(f"Independent acceptance: {'PASS' if acceptance.get('passed') else 'FAIL'}")
    detection = report.get("detection", {})
    if detection:
        print(
            "Detection: TP={tp} FP={fp} FN={fn} precision={precision} recall={recall} F1={f1}".format(
                tp=detection.get("true_positives", 0), fp=detection.get("false_positives", 0),
                fn=detection.get("false_negatives", 0), precision=detection.get("precision", "n/a"),
                recall=detection.get("recall", "n/a"), f1=detection.get("f1", "n/a"),
            )
        )
    run_info = report.get("run", {})
    print(f"JSON report: {run_info.get('report_json', str(args.output_dir / 'acceptance_report.json'))}")
    print(f"Markdown report: {run_info.get('report_markdown', str(args.output_dir / 'acceptance_report.md'))}")
    for check in acceptance.get("checks", []):
        print(f"{'PASS' if check['passed'] else 'FAIL'}: {check['name']} — {check['detail']}")
    return 0 if acceptance.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
