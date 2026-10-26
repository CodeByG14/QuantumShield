"""Deterministic finding matching and evaluation metrics for Phase 7.

Ground truth is supplied separately from scanner output. Findings that could not
be analyzed are recorded as inconclusive and excluded from precision/recall.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping


_INCONCLUSIVE_STATUSES = {
    "unable-to-analyze",
    "unanalyzable",
    "inconclusive",
}


def normalize_algorithm(value: Any) -> str:
    """Normalize superficial punctuation/case differences, not semantics."""
    return re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())


def normalize_status(value: Any) -> str:
    return str(value or "").strip().casefold().replace("_", "-").replace(" ", "-")


def normalize_path(value: Any, *, project_root: Path | None = None, rootfs_root: Path | None = None) -> str:
    """Return a stable POSIX relative path for matching against expected.yaml."""
    raw = str(value or "").strip()
    if not raw:
        return "<unknown-path>"

    candidate = Path(raw).expanduser()
    if candidate.is_absolute():
        try:
            if rootfs_root is not None:
                return "rootfs:" + candidate.resolve().relative_to(rootfs_root.resolve()).as_posix()
        except (OSError, ValueError):
            pass
        try:
            if project_root is not None:
                return candidate.resolve().relative_to(project_root.resolve()).as_posix()
        except (OSError, ValueError):
            pass
        # Absolute paths outside the corpus cannot match a relative ground-truth label.
        return candidate.name or "<unknown-path>"

    normalized = PurePosixPath(raw.replace("\\", "/")).as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized == ".":
        return "<unknown-path>"
    return normalized


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return [value]


def finding_paths(finding: Mapping[str, Any], *, project_root: Path | None = None, rootfs_root: Path | None = None) -> list[str]:
    evidence = _as_list(finding.get("evidence"))
    paths: list[str] = []
    for item in evidence:
        if isinstance(item, Mapping):
            path = item.get("file_path") or item.get("path") or item.get("source_path")
            if path:
                paths.append(normalize_path(path, project_root=project_root, rootfs_root=rootfs_root))
    if not paths:
        path = finding.get("file_path") or finding.get("path") or finding.get("source_path")
        if path:
            paths.append(normalize_path(path, project_root=project_root, rootfs_root=rootfs_root))
    # A finding can have multiple evidence rows in one file. Count it once per file.
    return sorted(set(paths)) or ["<unknown-path>"]


def extract_actual_findings(
    assessment: Mapping[str, Any], *, project_root: Path | None = None, rootfs_root: Path | None = None
) -> list[dict[str, Any]]:
    """Flatten assessment findings to stable path/algorithm/status records."""
    raw_findings = assessment.get("findings", [])
    if not isinstance(raw_findings, list):
        raise ValueError("assessment 'findings' must be a list")

    actual: list[dict[str, Any]] = []
    for index, finding in enumerate(raw_findings):
        if not isinstance(finding, Mapping):
            raise ValueError(f"assessment finding at index {index} is not an object")
        algorithm = str(finding.get("algorithm") or "unknown")
        status = normalize_status(finding.get("status"))
        category = str(finding.get("category") or finding.get("risk_kind") or "")
        for path in finding_paths(finding, project_root=project_root, rootfs_root=rootfs_root):
            actual.append(
                {
                    "path": path,
                    "algorithm": algorithm,
                    "algorithm_key": normalize_algorithm(algorithm),
                    "status": status,
                    "variant": str(finding.get("variant") or ""),
                    "variant_key": normalize_algorithm(finding.get("variant")),
                    "category": category,
                    "finding_id": str(finding.get("finding_id") or ""),
                    "inconclusive": status in _INCONCLUSIVE_STATUSES,
                }
            )
    return actual


def _ratio(numerator: int, denominator: int, *, empty_value: float) -> float:
    return numerator / denominator if denominator else empty_value


def _score_records(expected: list[dict[str, Any]], actual: list[dict[str, Any]]) -> dict[str, Any]:
    """Score already-normalized expected and actual records with one-to-one matching."""
    expected_remaining = list(range(len(expected)))
    actual_matched: set[int] = set()
    expected_matched: set[int] = set()

    # Exact path and normalized algorithm are the primary identity. If expected
    # status is specified, it is also part of the match.
    for ai, prediction in enumerate(actual):
        for ei in expected_remaining:
            truth = expected[ei]
            if prediction["path"] != truth["path"]:
                continue
            if prediction["algorithm_key"] != truth["algorithm_key"]:
                continue
            if truth.get("status") and prediction["status"] != truth["status"]:
                continue
            if truth.get("category") and normalize_algorithm(prediction.get("category")) != normalize_algorithm(truth["category"]):
                continue
            if truth.get("variant_key") and normalize_algorithm(prediction.get("variant")) != truth["variant_key"]:
                continue
            actual_matched.add(ai)
            expected_matched.add(ei)
            expected_remaining.remove(ei)
            break

    tp = len(actual_matched)
    fn = len(expected) - tp
    fp_indices = [i for i in range(len(actual)) if i not in actual_matched]
    fp = len(fp_indices)
    precision = _ratio(tp, tp + fp, empty_value=(1.0 if not expected else 0.0))
    recall = _ratio(tp, tp + fn, empty_value=1.0)
    f1 = _ratio(2 * precision * recall, precision + recall, empty_value=0.0)

    return {
        "expected_findings": len(expected),
        "predicted_findings": len(actual),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(f1, 6),
        "matched_indices": sorted(actual_matched),
        "false_positive_indices": fp_indices,
    }


def evaluate_findings(
    expected_cases: Iterable[Mapping[str, Any]],
    actual_findings: Iterable[Mapping[str, Any]],
) -> dict[str, Any]:
    """Evaluate predictions against labelled paths in expected.yaml.

    Each case contains ``path`` and ``expected_findings``. All files in the
    controlled corpus must be labelled, including negative/decoy files.
    ``UNABLE_TO_ANALYZE`` findings are reported separately, never silently
    turned into true positives or false positives.
    """
    cases = list(expected_cases)
    labelled_paths = {normalize_path(case.get("path")) for case in cases}
    expected: list[dict[str, Any]] = []
    for case in cases:
        path = normalize_path(case.get("path"))
        expected_findings = case.get("expected_findings", [])
        if not isinstance(expected_findings, list):
            raise ValueError(f"expected_findings for {path!r} must be a list")
        for item in expected_findings:
            if not isinstance(item, Mapping) or not item.get("algorithm"):
                raise ValueError(f"every expected finding for {path!r} needs an algorithm")
            expected.append(
                {
                    "path": path,
                    "algorithm": str(item["algorithm"]),
                    "algorithm_key": normalize_algorithm(item["algorithm"]),
                    "status": normalize_status(item.get("status")) if item.get("status") else "",
                    "variant": str(item.get("variant") or ""),
                    "variant_key": normalize_algorithm(item.get("variant")),
                    "category": str(item.get("category") or ""),
                }
            )

    actual_all = [dict(item) for item in actual_findings]
    inconclusive = [item for item in actual_all if item.get("inconclusive") or normalize_status(item.get("status")) in _INCONCLUSIVE_STATUSES]
    scorable: list[dict[str, Any]] = []
    unlabelled: list[dict[str, Any]] = []
    for item in actual_all:
        if item in inconclusive:
            continue
        normalized = dict(item)
        normalized["path"] = normalize_path(normalized.get("path"))
        normalized["algorithm"] = str(normalized.get("algorithm") or "unknown")
        normalized["algorithm_key"] = normalize_algorithm(normalized["algorithm"])
        normalized["status"] = normalize_status(normalized.get("status"))
        normalized["variant"] = str(normalized.get("variant") or "")
        normalized["variant_key"] = normalize_algorithm(normalized.get("variant"))
        if normalized["path"] not in labelled_paths:
            unlabelled.append(normalized)
        scorable.append(normalized)

    overall = _score_records(expected, scorable)
    # Make the report's false-positive list useful without requiring callers to
    # infer it from array positions in an opaque scanner report.
    overall["false_positive_findings"] = [
        {k: v for k, v in scorable[index].items() if k not in {"inconclusive"}}
        for index in overall.pop("false_positive_indices")
    ]
    overall.pop("matched_indices", None)
    overall["inconclusive_findings"] = [
        {k: v for k, v in item.items() if k != "inconclusive"} for item in inconclusive
    ]
    overall["unlabelled_findings"] = unlabelled
    overall["labelled_paths"] = sorted(labelled_paths)

    # Per-algorithm scores include both misses and unexpected predictions.
    algorithm_keys = sorted({item["algorithm_key"] for item in expected + scorable})
    by_algorithm: dict[str, Any] = {}
    for key in algorithm_keys:
        exp_for_key = [item for item in expected if item["algorithm_key"] == key]
        act_for_key = [item for item in scorable if item["algorithm_key"] == key]
        scored = _score_records(exp_for_key, act_for_key)
        scored.pop("matched_indices", None)
        scored.pop("false_positive_indices", None)
        by_algorithm[key or "unknown"] = scored
    overall["by_algorithm"] = by_algorithm
    overall["scorable_findings"] = len(scorable)
    overall["inconclusive_count"] = len(inconclusive)
    overall["metrics_meaningful"] = bool(expected or scorable)
    return overall


def inspect_coverage(assessment: Mapping[str, Any]) -> dict[str, Any]:
    """Validate source-project and optional rootfs coverage independently."""
    issues: list[str] = []
    found: list[tuple[str, Mapping[str, Any]]] = []

    def walk(value: Any, path: str = "$", ancestors: frozenset[int] = frozenset()) -> None:
        if isinstance(value, Mapping):
            if id(value) in ancestors:
                return
            nested_ancestors = ancestors | {id(value)}
            if "files_discovered" in value and ("files_analyzed" in value or "files" in value):
                found.append((path, value))
            for key, child in value.items():
                walk(child, f"{path}.{key}", nested_ancestors)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]", ancestors)

    walk(assessment)
    if not found:
        return {"available": False, "issues": ["assessment does not contain a recognizable coverage report"], "sections": {}}

    def check_one(section_path: str, coverage: Mapping[str, Any]) -> dict[str, Any]:
        section_issues: list[str] = []
        count_names = ("files_discovered", "files_analyzed", "files_failed", "files_unsupported", "files_skipped")
        counts = {key: coverage.get(key) for key in count_names if key in coverage}
        if all(isinstance(coverage.get(key), int) for key in count_names):
            accounted = sum(int(coverage[key]) for key in count_names[1:])
            if int(coverage["files_discovered"]) != accounted:
                section_issues.append(
                    "coverage counts do not reconcile: files_discovered != analyzed + failed + unsupported + skipped"
                )

        records = coverage.get("files")
        checked_records = 0
        if isinstance(records, list):
            seen_paths: set[str] = set()
            for record in records:
                if not isinstance(record, Mapping):
                    section_issues.append("coverage contains a non-object file record")
                    continue
                path = str(record.get("path") or record.get("file_path") or "<unknown>")
                if path in seen_paths:
                    section_issues.append(f"coverage contains duplicate file record: {path}")
                seen_paths.add(path)
                checked_records += 1
                outcome = normalize_status(record.get("outcome"))
                if outcome and outcome != "analyzed" and not record.get("reason"):
                    section_issues.append(f"non-analyzed file {path!r} has no explanation")
            if isinstance(coverage.get("files_discovered"), int) and len(records) != coverage["files_discovered"]:
                section_issues.append("coverage file-record count differs from files_discovered")

        return {
            "available": True,
            "counts": counts,
            "file_coverage_percent": coverage.get("file_coverage_percent"),
            "file_records_checked": checked_records,
            "issues": section_issues,
            "source_path": section_path,
        }

    sections: dict[str, Any] = {}
    for section_path, coverage in found:
        key = section_path.removeprefix("$. ").removeprefix("$").lstrip(".") or "coverage"
        # Prefer simple field names, e.g. coverage and rootfs_coverage.
        key = key.replace("[", "_").replace("]", "")
        sections[key] = check_one(section_path, coverage)
        issues.extend(f"{key}: {issue}" for issue in sections[key]["issues"])

    first = next(iter(sections.values()))
    return {
        "available": True,
        "counts": first.get("counts", {}),
        "file_coverage_percent": first.get("file_coverage_percent"),
        "file_records_checked": first.get("file_records_checked", 0),
        "issues": issues,
        "sections": sections,
    }


def inspect_migration_plan(plan: Mapping[str, Any]) -> dict[str, Any]:
    """Check that a generated migration plan has tasks and coherent summaries."""
    issues: list[str] = []

    def task_list(value: Any) -> list[Mapping[str, Any]] | None:
        if isinstance(value, Mapping):
            for task_key in ("tasks", "migration_tasks"):
                preferred = value.get(task_key)
                if task_key in value and isinstance(preferred, list) and all(isinstance(item, Mapping) for item in preferred):
                    return preferred
            for child in value.values():
                found = task_list(child)
                if found is not None:
                    return found
        elif isinstance(value, list):
            for child in value:
                found = task_list(child)
                if found is not None:
                    return found
        return None

    tasks = task_list(plan)
    if tasks is None:
        return {"valid": False, "task_count": None, "action_counts": {}, "issues": ["migration plan has no task list"]}

    action_counts: Counter[str] = Counter()
    for index, task in enumerate(tasks):
        action = task.get("action_type") or task.get("action") or task.get("by_action")
        if action is not None:
            action_counts[str(action)] += 1
        elif tasks:
            issues.append(f"migration task at index {index} has no action_type/action field")

    # Compare summaries only when the plan exposes an identifiable action-count map.
    summary_maps: list[tuple[str, Mapping[str, Any]]] = []
    def collect_summaries(value: Any, path: str = "$") -> None:
        if isinstance(value, Mapping):
            for key, child in value.items():
                key_norm = str(key).casefold().replace("-", "_")
                child_path = f"{path}.{key}"
                if key_norm in {"by_action", "action_counts", "tasks_by_action", "count_by_action"} and isinstance(child, Mapping):
                    summary_maps.append((child_path, child))
                collect_summaries(child, child_path)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                collect_summaries(child, f"{path}[{index}]")
    collect_summaries(plan)

    summary_consistent: bool | None = None
    if summary_maps and action_counts:
        _, raw_summary = summary_maps[0]
        normalized_summary = {str(k): int(v) for k, v in raw_summary.items() if isinstance(v, (int, float))}
        normalized_actual = dict(action_counts)
        summary_consistent = normalized_summary == normalized_actual
        if not summary_consistent:
            issues.append(f"migration action summary differs from task-derived counts: summary={normalized_summary}, tasks={normalized_actual}")

    # Check explicit total-task summaries if present.
    for key in ("total_tasks", "task_count", "tasks_count"):
        if isinstance(plan.get(key), int) and plan[key] != len(tasks):
            issues.append(f"migration plan {key}={plan[key]} but task list contains {len(tasks)}")

    return {
        "valid": not issues,
        "task_count": len(tasks),
        "action_counts": dict(sorted(action_counts.items())),
        "summary_action_counts_consistent": summary_consistent,
        "issues": issues,
    }
