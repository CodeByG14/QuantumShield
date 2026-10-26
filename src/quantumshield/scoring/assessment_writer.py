"""Build and write QuantumShield's Week 5 assessment.json report."""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from quantumshield.common.models import (
    AssessmentResult,
    ProjectContext,
    ScanResult,
)
from quantumshield.scoring.hndl_engine import assess_scan
from quantumshield.scoring.policy import (
    DEFAULT_MIGRATION_YEARS,
    DEFAULT_THREAT_HORIZON_YEAR,
    POLICY_VERSION,
)


def load_project_context(
    context_path: str | Path | None,
    *,
    target_name: str,
) -> tuple[ProjectContext, bool]:
    """Load an optional YAML context file and return (context, was_loaded).

    Missing files intentionally produce an empty context. Risk scoring applies
    documented provisional defaults and records the missing inputs instead of
    pretending that the project context was supplied.
    """
    if context_path is None:
        return ProjectContext(project_name=target_name), False

    path = Path(context_path)
    if not path.is_file():
        return ProjectContext(project_name=target_name), False

    try:
        raw: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"cannot read project context {path}: {exc}") from exc

    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ValueError("project context YAML must contain a mapping of fields")
    raw = dict(raw)
    if not raw.get("project_name"):
        raw["project_name"] = target_name

    try:
        return ProjectContext.model_validate(raw), True
    except ValidationError as exc:
        raise ValueError(f"invalid project context in {path}: {exc}") from exc


def _limitations(
    scan_result: ScanResult,
    context: ProjectContext,
    *,
    context_loaded: bool,
) -> list[str]:
    limitations = [
        scan_result.coverage.metric_note,
        "Discovery is static and pattern-based; it does not execute project code or perform runtime/network scanning.",
        "Indirect calls, dynamic dispatch, generated code, unsupported languages, and crypto hidden in binary or packaged dependencies may not be fully identified.",
        f"Risk policy {POLICY_VERSION} is an initial, unvalidated prioritization policy; scores are not probabilities of an attack succeeding.",
        "Potential and low-confidence findings require review of their evidence before remediation decisions.",
    ]
    if not context_loaded:
        limitations.append(
            "No project-context YAML was loaded; missing context values use explicit provisional defaults and are listed per risk assessment."
        )
    
    # Week 6: Asset-level context information
    if context.asset_contexts:
        limitations.append(
            f"Asset-level context overrides are configured for {len(context.asset_contexts)} asset(s). "
            "Check context_provenance in each risk assessment to see which context layer was used."
        )
    
    if context.data_sensitivity is None or context.confidentiality_years is None or context.exposure is None or context.system_criticality is None:
        limitations.append(
            "One or more project risk attributes were not supplied; affected factor scores use the documented 3/5 provisional assumption."
        )
    if context.migration_years is None:
        limitations.append(
            f"Migration duration is not configured; Mosca timing uses the policy default of {DEFAULT_MIGRATION_YEARS:g} years where applicable."
        )
    if context.threat_horizon_year is None:
        limitations.append(
            f"Threat horizon is not configured; Mosca timing uses the policy default year {DEFAULT_THREAT_HORIZON_YEAR} where applicable."
        )

    coverage = scan_result.coverage
    if scan_result.rootfs_coverage is not None:
        limitations.append(
            "An extracted-rootfs library inventory was requested. Its capability labels describe sourced upstream version/API availability, "
            "not proof that the installed build, provider, policy, or application actually enables or uses post-quantum algorithms."
        )
        rootfs_coverage = scan_result.rootfs_coverage
        if rootfs_coverage.files_partial or rootfs_coverage.files_failed or rootfs_coverage.files_unsupported or rootfs_coverage.files_skipped:
            limitations.append(
                "The extracted-rootfs inventory has incomplete coverage: "
                f"{rootfs_coverage.files_partial} partial, {rootfs_coverage.files_failed} failed, "
                f"{rootfs_coverage.files_unsupported} unsupported, and {rootfs_coverage.files_skipped} skipped entry/entries."
            )
    if coverage.files_partial or coverage.files_failed or coverage.files_unsupported or coverage.files_skipped:
        limitations.append(
            "The assessment has incomplete file coverage: "
            f"{coverage.files_partial} partial, {coverage.files_failed} failed, "
            f"{coverage.files_unsupported} unsupported, and {coverage.files_skipped} skipped file(s). "
            "Review the coverage report before interpreting absence of findings."
        )
    return limitations


def build_assessment(
    scan_result: ScanResult,
    *,
    target: str | Path,
    context: ProjectContext,
    context_loaded: bool = True,
    assessment_id: str | None = None,
    scan_timestamp: datetime | None = None,
    assessment_year: int | None = None,
    agility_config: Any | None = None,
) -> AssessmentResult:
    """Combine discovery, coverage, context, and per-finding risk results."""
    timestamp = scan_timestamp or datetime.now(timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)

    risks = assess_scan(scan_result, context, assessment_year=assessment_year)
    from quantumshield.agility.scoring import score_agility
    scoring_defaults = (agility_config.defaults.get("agility_scoring", {})
                        if agility_config is not None else {})
    agility = score_agility(
        scan_result.findings,
        configurable_weight=float(scoring_defaults.get("configurable_weight", 1.0)),
        static_weight=float(scoring_defaults.get("static_weight", 1.0)),
    )
    return AssessmentResult(
        assessment_id=assessment_id or str(uuid.uuid4()),
        scan_timestamp=timestamp,
        target=str(Path(target).resolve()),
        policy_version=POLICY_VERSION,
        project_context=context,
        coverage=scan_result.coverage,
        findings=scan_result.findings,
        rootfs_coverage=scan_result.rootfs_coverage,
        risks=risks,
        limitations=_limitations(scan_result, context, context_loaded=context_loaded),
        agility=agility,
    )


def write_assessment(
    assessment: AssessmentResult,
    output_path: str | Path = "assessment.json",
) -> Path:
    """Serialize the assessment model as JSON without modifying cbom.json."""
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = assessment.model_dump(mode="json", exclude_none=False)
    destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return destination


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        description="Run QuantumShield discovery and generate assessment.json."
    )
    parser.add_argument("target", nargs="?", default="samples/test-repo")
    parser.add_argument("--context", default="project-context.yaml")
    parser.add_argument("-o", "--output", default="assessment.json")
    args = parser.parse_args(argv)

    target = Path(args.target)
    if not target.is_dir():
        parser.error(f"target is not a directory: {target}")

    try:
        context, context_loaded = load_project_context(args.context, target_name=target.name)
    except ValueError as exc:
        parser.error(str(exc))

    # Delayed import keeps the policy and writer functions independently
    # testable without importing the filesystem discovery pipeline.
    from quantumshield.discovery.pipeline import run_scan

    try:
        scan_result = run_scan(target)
    except (OSError, NotADirectoryError, ValueError) as exc:
        parser.error(str(exc))

    report = build_assessment(
        scan_result,
        target=target,
        context=context,
        context_loaded=context_loaded,
    )
    destination = write_assessment(report, args.output)

    level_counts: dict[str, int] = {}
    not_scored = 0
    for risk in report.risks:
        if risk.risk_level is None:
            not_scored += 1
        else:
            level_counts[risk.risk_level.value] = level_counts.get(risk.risk_level.value, 0) + 1

    cov = report.coverage
    print(f"Wrote {destination}: {len(report.findings)} findings, {len(report.risks)} risk assessments")
    print(
        f"  coverage: {cov.file_coverage_percent}% of {cov.files_discovered} files fully analyzed "
        f"(analyzed={cov.files_analyzed}, partial={cov.files_partial}, failed={cov.files_failed}, "
        f"unsupported={cov.files_unsupported}, skipped={cov.files_skipped})"
    )
    print("  risk levels:", ", ".join(f"{k}={v}" for k, v in sorted(level_counts.items())) or "none")
    print(f"  not scored / not HNDL-applicable: {not_scored}")
    print(f"  policy: {report.policy_version}; assessment: {report.assessment_id}")


if __name__ == "__main__":
    main()
