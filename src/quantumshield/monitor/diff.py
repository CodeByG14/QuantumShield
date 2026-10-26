"""Compare two QuantumShield assessment reports without rescanning a project."""

from __future__ import annotations

from datetime import datetime, timezone
import math
from typing import Any, Mapping

from .identity import assign_stable_keys, stable_finding_anchor


_CHANGE_FIELDS = ("status", "confidence", "role", "variant")
_COVERAGE_FIELDS = (
    "files_discovered",
    "files_eligible",
    "files_analyzed",
    "files_partial",
    "files_failed",
    "files_unsupported",
    "files_skipped",
)


class AssessmentFormatError(ValueError):
    """An assessment is missing fields required for safe comparison."""


def _validate_assessment(report: Mapping[str, Any], label: str) -> None:
    if not isinstance(report, Mapping):
        raise AssessmentFormatError(f"{label} assessment must be a JSON object")
    for key in ("assessment_id", "findings", "coverage"):
        if key not in report:
            raise AssessmentFormatError(f"{label} assessment is missing required field '{key}'")
    if not isinstance(report["assessment_id"], str) or not report["assessment_id"].strip():
        raise AssessmentFormatError(f"{label} assessment has an invalid assessment_id")
    if not isinstance(report["findings"], list):
        raise AssessmentFormatError(f"{label} assessment field 'findings' must be a list")
    coverage = report["coverage"]
    if not isinstance(coverage, Mapping):
        raise AssessmentFormatError(f"{label} assessment field 'coverage' must be an object")
    coverage_percent = coverage.get("file_coverage_percent")
    if isinstance(coverage_percent, bool) or not isinstance(coverage_percent, (int, float)):
        raise AssessmentFormatError(f"{label} coverage.file_coverage_percent must be numeric")
    if not math.isfinite(float(coverage_percent)) or not 0 <= float(coverage_percent) <= 100:
        raise AssessmentFormatError(f"{label} coverage.file_coverage_percent must be between 0 and 100")

    seen_ids: set[str] = set()
    for index, finding in enumerate(report["findings"]):
        if not isinstance(finding, Mapping):
            raise AssessmentFormatError(f"{label} findings[{index}] must be an object")
        for key in ("finding_id", "algorithm", "role", "status"):
            if key not in finding:
                raise AssessmentFormatError(f"{label} findings[{index}] is missing '{key}'")
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id.strip():
            raise AssessmentFormatError(f"{label} findings[{index}] has an invalid finding_id")
        if finding_id in seen_ids:
            raise AssessmentFormatError(f"{label} assessment has duplicate finding_id '{finding_id}'")
        seen_ids.add(finding_id)
        evidence = finding.get("evidence", [])
        if not isinstance(evidence, list):
            raise AssessmentFormatError(f"{label} findings[{index}].evidence must be a list")
        for evid_index, item in enumerate(evidence):
            if not isinstance(item, Mapping):
                raise AssessmentFormatError(
                    f"{label} findings[{index}].evidence[{evid_index}] must be an object"
                )

    risks = report.get("risks", [])
    if not isinstance(risks, list):
        raise AssessmentFormatError(f"{label} assessment field 'risks' must be a list")
    risk_ids: set[str] = set()
    for index, risk in enumerate(risks):
        if not isinstance(risk, Mapping) or not isinstance(risk.get("finding_id"), str):
            raise AssessmentFormatError(f"{label} risks[{index}] must have a string finding_id")
        risk_id = risk["finding_id"]
        if risk_id in risk_ids:
            raise AssessmentFormatError(f"{label} assessment has duplicate risk for '{risk_id}'")
        risk_ids.add(risk_id)


def _risk_index(report: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    return {risk["finding_id"]: risk for risk in report.get("risks", [])}


def _risk_for(finding: Mapping[str, Any], risks: Mapping[str, Mapping[str, Any]]) -> Mapping[str, Any]:
    return risks.get(str(finding.get("finding_id", "")), {})


def _summary(
    finding: Mapping[str, Any], risks: Mapping[str, Mapping[str, Any]], key: str
) -> dict[str, Any]:
    risk = _risk_for(finding, risks)
    evidence = finding.get("evidence") or []
    normalized_evidence = []
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
        fingerprint = next(
            (metadata[name] for name in ("fingerprint_sha256", "sha256_fingerprint", "fingerprint", "certificate_fingerprint") if metadata.get(name)),
            None,
        )
        normalized_evidence.append(
            {
                "file": item.get("file_path"),
                "fingerprint": fingerprint,
                "rule_id": item.get("rule_id"),
                "evidence_type": item.get("evidence_type"),
            }
        )
    return {
        "key": key,
        "finding_id": finding.get("finding_id"),
        "algorithm": finding.get("algorithm"),
        "variant": finding.get("variant"),
        "curve": finding.get("curve"),
        "role": finding.get("role"),
        "status": finding.get("status"),
        "confidence": finding.get("confidence", "unknown"),
        "risk_level": risk.get("risk_level"),
        "risk_score": risk.get("risk_score"),
        "risk_kind": risk.get("risk_kind"),
        "evidence": normalized_evidence,
    }


def _tracked_changes(before: Mapping[str, Any], after: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    changes: dict[str, dict[str, Any]] = {}
    for field in _CHANGE_FIELDS:
        old = before.get(field)
        new = after.get(field)
        if old != new:
            changes[field] = {"before": old, "after": new}
    for field in ("risk_level", "risk_score"):
        old = before.get(field)
        new = after.get(field)
        if field == "risk_score" and old is not None and new is not None:
            if isinstance(old, (int, float)) and isinstance(new, (int, float)) and math.isclose(float(old), float(new), rel_tol=0, abs_tol=1e-9):
                continue
        if old != new:
            changes[field] = {"before": old, "after": new}
    return changes


def _coverage_delta(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> dict[str, Any]:
    before = baseline["coverage"]
    after = current["coverage"]
    coverage: dict[str, Any] = {
        "baseline_percent": float(before["file_coverage_percent"]),
        "current_percent": float(after["file_coverage_percent"]),
        "delta_percentage_points": round(
            float(after["file_coverage_percent"]) - float(before["file_coverage_percent"]), 4
        ),
        "counts": {},
    }
    for field in _COVERAGE_FIELDS:
        old = before.get(field)
        new = after.get(field)
        if old is not None or new is not None:
            coverage["counts"][field] = {
                "baseline": old,
                "current": new,
                "delta": (new - old) if isinstance(old, int) and isinstance(new, int) else None,
            }
    return coverage


def diff_assessments(
    baseline: Mapping[str, Any],
    current: Mapping[str, Any],
    *,
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Return added, removed, changed findings and coverage deltas.

    Matching is based on stable finding identity rather than CRYPTO-### IDs or
    source line numbers. Only the documented risk/status attributes are treated
    as finding changes; changes to arbitrary evidence excerpts do not by
    themselves mark an asset as changed.
    """
    _validate_assessment(baseline, "baseline")
    _validate_assessment(current, "current")

    baseline_target = str(baseline.get("target", "")) or None
    current_target = str(current.get("target", "")) or None
    old_keyed = assign_stable_keys(baseline["findings"], target=baseline_target)
    new_keyed = assign_stable_keys(current["findings"], target=current_target)
    old_map = {key: finding for key, finding in old_keyed}
    new_map = {key: finding for key, finding in new_keyed}
    old_risks = _risk_index(baseline)
    new_risks = _risk_index(current)

    old_summaries = {key: _summary(item, old_risks, key) for key, item in old_map.items()}
    new_summaries = {key: _summary(item, new_risks, key) for key, item in new_map.items()}

    old_keys, new_keys = set(old_map), set(new_map)
    exact_shared = sorted(old_keys & new_keys)
    matched_pairs: list[tuple[str, str]] = [(key, key) for key in exact_shared]
    used_old = set(exact_shared)
    used_new = set(exact_shared)

    # The prescribed key includes variant and role, but the specification also
    # requires those fields to be reported as changes. For unmatched findings,
    # correlate only unique pairs sharing algorithm + curve + file + fingerprint.
    old_anchor_groups: dict[str, list[str]] = {}
    new_anchor_groups: dict[str, list[str]] = {}
    for key, finding in old_map.items():
        if key not in used_old:
            anchor = stable_finding_anchor(finding, target=baseline_target)
            old_anchor_groups.setdefault(anchor, []).append(key)
    for key, finding in new_map.items():
        if key not in used_new:
            anchor = stable_finding_anchor(finding, target=current_target)
            new_anchor_groups.setdefault(anchor, []).append(key)
    for anchor in sorted(set(old_anchor_groups) & set(new_anchor_groups)):
        old_candidates = old_anchor_groups[anchor]
        new_candidates = new_anchor_groups[anchor]
        if len(old_candidates) == 1 and len(new_candidates) == 1:
            old_key, new_key = old_candidates[0], new_candidates[0]
            matched_pairs.append((old_key, new_key))
            used_old.add(old_key)
            used_new.add(new_key)

    added_keys = sorted(new_keys - used_new)
    removed_keys = sorted(old_keys - used_old)

    added = [new_summaries[key] for key in added_keys]
    removed = [old_summaries[key] for key in removed_keys]
    changed: list[dict[str, Any]] = []
    for old_key, new_key in sorted(matched_pairs):
        changes = _tracked_changes(old_summaries[old_key], new_summaries[new_key])
        if changes:
            item = {
                "key": old_key,
                "changes": changes,
                "baseline": old_summaries[old_key],
                "current": new_summaries[new_key],
            }
            if old_key != new_key:
                item["current_key"] = new_key
            changed.append(item)

    coverage = _coverage_delta(baseline, current)
    timestamp = generated_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    return {
        "schema_version": "1.0",
        "generated_at": timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "baseline_assessment_id": baseline["assessment_id"],
        "current_assessment_id": current["assessment_id"],
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "unchanged": len(matched_pairs) - len(changed),
        },
        "added": added,
        "removed": removed,
        "changed": changed,
        "coverage": coverage,
    }
