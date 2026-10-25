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
