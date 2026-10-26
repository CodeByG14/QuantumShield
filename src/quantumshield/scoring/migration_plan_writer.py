"""Migration plan writer for QuantumShield Week 6 Track 2.

Generates migration_plan.json containing ordered, explainable migration tasks.
"""

from __future__ import annotations

import argparse
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from quantumshield.common.models import AssessmentResult
from quantumshield.scoring.migration_engine import (
    MigrationRecommendationRegistry,
    MigrationTask,
    generate_migration_tasks,
)


def _rootfs_inventory(assessment: AssessmentResult) -> list[dict[str, Any]]:
    """Extract rootfs library facts without inferring application linkage."""
    inventory: list[dict[str, Any]] = []
    for finding in assessment.findings:
        if not finding.algorithm.lower().startswith("library:"):
            continue
        rootfs_evidence = [e for e in finding.evidence if e.metadata.get("inventory_source") == "rootfs"]
        if not rootfs_evidence:
            continue
        metadata = rootfs_evidence[0].metadata
        inventory.append({
            "library": metadata.get("library_name", finding.algorithm.split(":", 1)[1]),
            "version": metadata.get("library_version", "unknown"),
            "pqc_capability": metadata.get("pqc_capability", "unknown"),
            "capability_reason": metadata.get("pqc_capability_reason", "No capability rationale supplied."),
            "capability_source": metadata.get("pqc_capability_source", ""),
            "evidence_paths": sorted({e.file_path for e in rootfs_evidence}),
        })
    return sorted(inventory, key=lambda item: (item["library"], item["version"], item["evidence_paths"]))


def _rootfs_prerequisite(item: dict[str, Any]) -> str:
    library = item["library"].replace("_", " ")
    version = item["version"] or "unknown version"
    capability = item["pqc_capability"]
    if capability == "yes":
        return (
            f"Verify that the application uses the inventoried {library} {version} build and that the required PQC algorithms, providers, "
            "and protocol settings are enabled; version-level capability does not prove application use."
        )
    if capability == "no":
        return (
            f"Assess upgrading or replacing the inventoried {library} {version} before integrating PQC APIs, because the sourced upstream "
            "capability table does not identify standardized PQC support for this version."
        )
    return (
        f"Verify PQC API and provider support for the inventoried {library} {version} in the deployed build before selecting migration "
        "targets; available rootfs metadata is inconclusive."
    )


def build_migration_plan(
    assessment: AssessmentResult,
    *,
    plan_id: str | None = None,
    registry: MigrationRecommendationRegistry | None = None,
) -> dict[str, Any]:
    """Build migration plan from an assessment.

    Args:
        assessment: The assessment containing findings
        plan_id: Optional plan identifier
        registry: Optional migration recommendation registry

    Returns:
        Migration plan as dictionary ready for JSON serialization
    """
    if registry is None:
        registry = MigrationRecommendationRegistry()

    # Generate tasks
    tasks = generate_migration_tasks(assessment.findings, registry=registry)
    rootfs_libraries = _rootfs_inventory(assessment) if assessment.rootfs_coverage is not None else []
    rootfs_prerequisites = [_rootfs_prerequisite(item) for item in rootfs_libraries]
    for task in tasks:
        task.prerequisites = list(dict.fromkeys([*task.prerequisites, *rootfs_prerequisites]))

    # Build plan structure
    plan = {
        "migration_plan_id": plan_id or str(uuid.uuid4()),
        "plan_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source_assessment_id": assessment.assessment_id,
        "recommendation_policy_version": registry.version,
        "schema_version": "1.0",

        "summary": {
            "total_tasks": len(tasks),
            "by_priority": _count_by_priority(tasks),
            "by_action": _count_by_action(tasks),
            "by_effort": _count_by_effort(tasks),
            "by_confidence": _count_by_confidence(tasks),
        },

        "tasks": [_task_to_dict(task) for task in tasks],

        "metadata": {
            "project_name": assessment.project_context.project_name,
            "target": assessment.target,
            "policy_version": assessment.policy_version,
            "findings_count": len(assessment.findings),
        },

        "advisory_notice": (
            "This migration plan is advisory only. All recommendations require "
            "compatibility testing, application changes, and verification in your "
            "specific environment. Do not apply changes automatically without review."
        ),
    }

    if assessment.rootfs_coverage is not None:
        capability_summary = {"yes": 0, "no": 0, "unknown": 0}
        for item in rootfs_libraries:
            status = item["pqc_capability"]
            capability_summary[status if status in capability_summary else "unknown"] += 1
        plan["metadata"]["rootfs_inventory"] = {
            "scanned": True,
            "files_discovered": assessment.rootfs_coverage.files_discovered,
            "files_analyzed": assessment.rootfs_coverage.files_analyzed,
            "files_failed": assessment.rootfs_coverage.files_failed,
            "files_skipped": assessment.rootfs_coverage.files_skipped,
            "file_coverage_percent": assessment.rootfs_coverage.file_coverage_percent,
            "library_findings": rootfs_libraries,
            "pqc_capability_counts": capability_summary,
            "scope_note": "Filename/package-metadata inventory only; does not establish which libraries applications load or whether PQC is enabled.",
        }

    return plan


def _task_to_dict(task: MigrationTask) -> dict[str, Any]:
    """Convert a MigrationTask to a dictionary for JSON serialization."""
    return {
        "task_id": task.task_id,
        "finding_id": task.finding_id,
        "affected_component": task.affected_component,
        "source": {
            "algorithm": task.source_algorithm,
            "role": task.source_role,
            "location": task.source_location,
        },
        "recommendation": {
            "algorithm": task.recommended_algorithm,
            "standard": task.recommendation_standard,
            "rationale": task.rationale,
        },
        "compatibility_notes": task.compatibility_notes,
        "prerequisites": task.prerequisites,
        "verification_steps": task.verification_steps,
        "effort_band": task.effort_band,
        "priority": task.priority,
        "confidence": task.confidence,
        "action_type": task.action_type,
        "status": task.status,
        "depends_on": task.depends_on,
        # Phase 2 additions
        "category": task.category,
        "wave": task.wave,
        "timeline_months": task.timeline_months,
        "strategy_rule": task.strategy_rule,
        "kb_sources": task.kb_sources,
    }


def _count_by_priority(tasks: list[MigrationTask]) -> dict[str, int]:
    """Count tasks by priority band."""
    counts = {
        "urgent": 0,  # priority <= 15
        "high": 0,    # priority 16-35
        "medium": 0,  # priority 36-60
        "low": 0,     # priority > 60
    }

    for task in tasks:
        if task.priority <= 15:
            counts["urgent"] += 1
        elif task.priority <= 35:
            counts["high"] += 1
        elif task.priority <= 60:
            counts["medium"] += 1
        else:
            counts["low"] += 1

    return counts


def _count_by_action(tasks: list[MigrationTask]) -> dict[str, int]:
    """Count tasks by action type (from the recommendation's explicit action type)."""
    counts: dict[str, int] = {}

    for task in tasks:
        # Use the recommendation's explicit action type; do not infer from
        # priority or from whether a target algorithm exists.
        action = task.action_type or "migrate"
        counts[action] = counts.get(action, 0) + 1

    return counts


def _count_by_effort(tasks: list[MigrationTask]) -> dict[str, int]:
    """Count tasks by effort band."""
    counts: dict[str, int] = {}

    for task in tasks:
        band = task.effort_band or "unknown"
        counts[band] = counts.get(band, 0) + 1

    return counts


def _count_by_confidence(tasks: list[MigrationTask]) -> dict[str, int]:
    """Count tasks by confidence level."""
    counts: dict[str, int] = {}

    for task in tasks:
        conf = task.confidence
        counts[conf] = counts.get(conf, 0) + 1

    return counts


def write_migration_plan(
    plan: dict[str, Any],
    output_path: str | Path = "migration_plan.json",
) -> Path:
    """Write migration plan to JSON file.

    Args:
        plan: Migration plan dictionary
        output_path: Output file path

    Returns:
        Path to written file
    """
    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with open(destination, "w", encoding="utf-8") as f:
        json.dump(plan, f, indent=2, ensure_ascii=False)
        f.write("\n")

    return destination


def main(argv: list[str] | None = None) -> None:
    """Generate migration plan from an existing assessment."""
    parser = argparse.ArgumentParser(
        description="Generate migration_plan.json from assessment.json"
    )
    parser.add_argument("assessment", nargs="?", default="assessment.json",
                        help="Path to assessment.json")
    parser.add_argument("-o", "--output", default="migration_plan.json",
                        help="Output path for migration_plan.json")
    args = parser.parse_args(argv)

    # Load assessment
    assessment_path = Path(args.assessment)
    if not assessment_path.exists():
        parser.error(f"Assessment file not found: {assessment_path}")

    with open(assessment_path, "r", encoding="utf-8") as f:
        assessment_data = json.load(f)

    # Reconstruct AssessmentResult from JSON
    from quantumshield.common.models import AssessmentResult
    assessment = AssessmentResult.model_validate(assessment_data)

    # Build migration plan
    plan = build_migration_plan(assessment)

    # Write to file
    output_path = write_migration_plan(plan, args.output)

    # Print summary
    summary = plan["summary"]
    print(f"Wrote {output_path}: {summary['total_tasks']} migration tasks")
    print(f"  Priority: {dict(summary['by_priority'])}")
    print(f"  Effort: {dict(summary['by_effort'])}")
    print(f"  Confidence: {dict(summary['by_confidence'])}")
    print(f"  Plan ID: {plan['migration_plan_id']}")


if __name__ == "__main__":
    main()
