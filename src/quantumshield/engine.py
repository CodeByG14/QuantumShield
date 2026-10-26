"""Small, importable interface to the existing QuantumShield engine.

The facade deliberately delegates to the existing discovery, scoring,
migration-planning, compliance, and diff implementations. It does not write
output files or invoke the command-line interface.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from quantumshield.common.models import AssessmentResult, ProjectContext
from quantumshield.compliance.checker import (
    ComplianceAssessmentError,
    check_compliance,
)
from quantumshield.compliance.rules import ComplianceRulesError
from quantumshield.discovery.pipeline import run_scan
from quantumshield.monitor.diff import diff_assessments
from quantumshield.scoring.assessment_writer import build_assessment
from quantumshield.scoring.migration_plan_writer import build_migration_plan


class EngineError(RuntimeError):
    """Base class for expected, user-safe engine errors."""


class BadTargetError(EngineError):
    """The scan target or extracted root filesystem is invalid."""


class InvalidContextError(EngineError):
    """The supplied project context cannot be validated."""


class InvalidAssessmentError(EngineError):
    """An operation received an unsupported assessment input."""


def _require_directory(value: str | Path, label: str) -> Path:
    """Return an existing absolute directory without consulting the CWD."""
    try:
        path = Path(value).expanduser()
    except (TypeError, ValueError) as exc:
        raise BadTargetError(f"{label} must be a valid filesystem path.") from exc

    if not path.is_absolute():
        raise BadTargetError(f"{label} must be an absolute path.")

    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise BadTargetError(f"{label} must refer to an existing directory.") from exc

    if not resolved.is_dir():
        raise BadTargetError(f"{label} must refer to an existing directory.")

    return resolved


def _resolve_context(
    context: ProjectContext | Mapping[str, Any] | None,
    target: Path,
) -> tuple[ProjectContext, bool]:
    if context is None:
        # A no-context scan remains usable, but the assessment records that no
        # explicit project context was supplied.
        return (
            ProjectContext(
                project_name=target.name or "unnamed-project",
                asset_contexts=[],
            ),
            False,
        )

    if isinstance(context, ProjectContext):
        return context, True

    try:
        return ProjectContext.model_validate(context), True
    except (ValidationError, TypeError, ValueError) as exc:
        raise InvalidContextError(
            "Project context is invalid; check its fields and values."
        ) from exc


def _require_assessment(value: AssessmentResult, argument: str = "assessment") -> AssessmentResult:
    if not isinstance(value, AssessmentResult):
        raise InvalidAssessmentError(f"{argument} must be an AssessmentResult model.")
    return value


def scan(
    target: str | Path,
    *,
    rootfs: str | Path | None = None,
    context: ProjectContext | Mapping[str, Any] | None = None,
) -> AssessmentResult:
    """Scan an absolute project directory and return its risk assessment.

    ``rootfs`` optionally names an existing, already-extracted root filesystem
    directory. Live TLS endpoint scanning is intentionally not part of this
    minimal public interface.

    The function performs no output-file writes. Relative paths are rejected
    so callers, including future backend workers, must resolve paths explicitly.
    """
    target_path = _require_directory(target, "target")
    rootfs_path = _require_directory(rootfs, "rootfs") if rootfs is not None else None
    project_context, context_loaded = _resolve_context(context, target_path)

    try:
        scan_result = run_scan(target_path, rootfs=rootfs_path)
        return build_assessment(
            scan_result,
            target=target_path,
            context=project_context,
            context_loaded=context_loaded,
        )
    except OSError as exc:
        raise EngineError(
            "The scan could not complete because an input file or scanner resource could not be read."
        ) from exc


def plan(assessment: AssessmentResult) -> dict[str, Any]:
    """Build a migration plan from a validated assessment model."""
    assessment = _require_assessment(assessment)
    try:
        return build_migration_plan(assessment)
    except OSError as exc:
        raise EngineError("Migration-planning resources could not be read.") from exc


def comply(
    assessment: AssessmentResult,
    plan: Mapping[str, Any] | None = None,
    *,
    as_of: str | date | None = None,
) -> dict[str, Any]:
    """Evaluate a validated assessment against the configured compliance rules."""
    assessment = _require_assessment(assessment)
    if plan is not None and not isinstance(plan, Mapping):
        raise InvalidAssessmentError("plan must be a mapping returned by the plan function.")

    try:
        return check_compliance(
            assessment.model_dump(mode="json"),
            migration_plan=plan,
            as_of=as_of,
        )
    except ComplianceAssessmentError as exc:
        raise InvalidAssessmentError(
            "The assessment or migration plan could not be used for compliance evaluation."
        ) from exc
    except ComplianceRulesError as exc:
        raise EngineError("Compliance rules could not be loaded.") from exc
    except ValueError as exc:
        raise EngineError("The compliance evaluation input, including as_of, is invalid.") from exc


def diff(
    baseline: AssessmentResult,
    current: AssessmentResult,
) -> dict[str, Any]:
    """Compare two validated assessment models using stable finding identity."""
    baseline = _require_assessment(baseline, "baseline")
    current = _require_assessment(current, "current")
    return diff_assessments(
        baseline.model_dump(mode="json"),
        current.model_dump(mode="json"),
    )


__all__ = [
    "BadTargetError",
    "EngineError",
    "InvalidAssessmentError",
    "InvalidContextError",
    "comply",
    "diff",
    "plan",
    "scan",
]
