"""Engine orchestration and transactional persistence for API requests."""
from __future__ import annotations

import logging
import os
import shutil
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from quantumshield.api.source_adapters import (
    SourceInputError,
    extract_zip_safely,
    load_bom_json,
    parse_bom_scan_result,
    prepare_github_repository,
)
from quantumshield.common.models import AssessmentResult, ProjectContext
from quantumshield.source_contracts import ScanInputKind
from quantumshield.storage_contracts import assessment_snapshot_for_storage

logger = logging.getLogger(__name__)


def workspace_root() -> Path:
    root = Path(os.getenv("QUANTUMSHIELD_WORKSPACE_ROOT", "/tmp/quantumshield-workspaces")).expanduser()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink():
        raise ValueError("Workspace root must not be a symbolic link.")
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError("Workspace root must be a directory.")
    return resolved


def assessment_summary(snapshot: dict[str, Any]) -> dict[str, Any]:
    findings = snapshot.get("findings", [])
    risks = snapshot.get("risks", [])
    levels = Counter((risk.get("risk_level") or "not-scored") for risk in risks)
    coverage = snapshot.get("coverage") or {}
    return {
        "finding_count": len(findings),
        "risk_count": len(risks),
        "risk_levels": dict(sorted(levels.items())),
        "files_discovered": coverage.get("files_discovered", 0),
        "files_analyzed": coverage.get("files_analyzed", 0),
        "files_failed": coverage.get("files_failed", 0),
        "file_coverage_percent": coverage.get("file_coverage_percent", 0),
    }


def load_dashboard_summary(pool: Any, session_id: UUID) -> dict[str, Any]:
    with pool.connection() as conn:
        project_count = conn.execute(
            """SELECT count(*) AS count FROM projects
               WHERE session_id = %s AND archived = FALSE""",
            (session_id,),
        ).fetchone()["count"]
        status_rows = conn.execute(
            """SELECT sr.status, count(*) AS count
               FROM scan_runs sr
               JOIN projects p ON p.project_id = sr.project_id
               WHERE p.session_id = %s AND p.archived = FALSE
               GROUP BY sr.status""",
            (session_id,),
        ).fetchall()
        latest_assessments = conn.execute(
            """SELECT latest.summary_json
               FROM (
                   SELECT a.summary_json,
                          row_number() OVER (
                              PARTITION BY p.project_id
                              ORDER BY sr.completed_at DESC, sr.started_at DESC, a.created_at DESC
                          ) AS assessment_rank
                   FROM projects p
                   JOIN scan_runs sr ON sr.project_id = p.project_id
                   JOIN assessments a ON a.scan_run_id = sr.scan_run_id
                   WHERE p.session_id = %s AND p.archived = FALSE
                     AND sr.status = 'completed'
               ) AS latest
               WHERE latest.assessment_rank = 1""",
            (session_id,),
        ).fetchall()

    scans_by_status = {
        row["status"]: row["count"]
        for row in status_rows
    }
    risk_levels: Counter[str] = Counter()
    for row in latest_assessments:
        summary = row["summary_json"]
        if not isinstance(summary, dict) or not isinstance(summary.get("risk_levels"), dict):
            raise ValueError("Stored assessment summary is missing its risk-level counts.")
        for level, count in summary["risk_levels"].items():
            if not isinstance(level, str) or isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("Stored assessment summary contains invalid risk-level counts.")
            risk_levels[level] += count

    high_priority_risk_count = sum(
        risk_levels.get(level, 0)
        for level in ("high", "very-high", "critical")
    )
    active_scan_count = scans_by_status.get("queued", 0) + scans_by_status.get("running", 0)
    return {
        "project_count": project_count,
        "scan_count": sum(scans_by_status.values()),
        "scans_by_status": scans_by_status,
        "active_scan_count": active_scan_count,
        "latest_assessment_count": len(latest_assessments),
        "latest_assessment_risk_levels": dict(sorted(risk_levels.items())),
        "high_priority_risk_count": high_priority_risk_count,
    }


def _jsonb(value: Any) -> Any:
    from psycopg.types.json import Jsonb

    return Jsonb(value)


def _context_for_run(context_data: dict[str, Any] | None, project_name: str) -> tuple[ProjectContext, bool]:
    if context_data is None:
        return ProjectContext(project_name=project_name), False
    data = dict(context_data)
    data["project_name"] = project_name
    try:
        context = ProjectContext.model_validate(data)
    except (ValidationError, TypeError, ValueError) as exc:
        raise SourceInputError("Project risk context was invalid.") from exc
    # A project display name alone does not count as user-provided risk context.
    risk_fields = (
        "data_sensitivity", "confidentiality_years", "exposure", "system_criticality",
        "migration_years", "threat_horizon_year",
    )
    context_loaded = any(getattr(context, name) is not None for name in risk_fields) or bool(context.asset_contexts)
    return context, context_loaded


def _write_assessment_transaction(
    pool: Any,
    *,
    scan_run_id: UUID,
    project_id: UUID,
    assessment: AssessmentResult,
) -> dict[str, Any]:
    snapshot = assessment_snapshot_for_storage(assessment, project_id)
    summary = assessment_summary(snapshot)
    risks = {item["finding_id"]: item for item in snapshot.get("risks", [])}

    with pool.connection() as conn:
        conn.execute(
            """INSERT INTO assessments (
                   assessment_id, scan_run_id, policy_version, assessment_schema_version,
                   assessment_json, summary_json
               ) VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                snapshot["assessment_id"], scan_run_id, snapshot["policy_version"],
                snapshot.get("schema_version", "1.0"), _jsonb(snapshot), _jsonb(summary),
            ),
        )
        for finding in snapshot.get("findings", []):
            fid = finding["finding_id"]
            risk = risks.get(fid)
            evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
            file_path = next((item.get("file_path") for item in evidence if isinstance(item, dict) and item.get("file_path")), None)
            conn.execute(
                """INSERT INTO assessment_findings (
                       assessment_id, finding_id, algorithm, variant, role, status, confidence,
                       file_path, risk_kind, risk_level, risk_score, finding_json, risk_json
                   ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                (
                    snapshot["assessment_id"], fid, str(finding.get("algorithm", "unknown"))[:100],
                    (str(finding["variant"])[:150] if finding.get("variant") is not None else None),
                    str(finding.get("role", "undetermined"))[:80],
                    str(finding.get("status", "potential"))[:40], str(finding.get("confidence", "unknown"))[:30],
                    file_path, (str(risk.get("risk_kind"))[:80] if risk and risk.get("risk_kind") is not None else None),
                    (str(risk.get("risk_level"))[:40] if risk and risk.get("risk_level") is not None else None),
                    risk.get("risk_score") if risk else None,
                    _jsonb(finding), _jsonb(risk) if risk else None,
                ),
            )
        conn.execute(
            """UPDATE scan_runs SET status = 'completed', completed_at = now(), error_message = NULL
               WHERE scan_run_id = %s""",
            (scan_run_id,),
        )
        conn.execute(
            "UPDATE projects SET updated_at = now() WHERE project_id = %s",
            (project_id,),
        )
    return snapshot


def _mark_scan_failed(pool: Any, scan_run_id: UUID, exc: Exception) -> None:
    if isinstance(exc, SourceInputError):
        message = str(exc)
    elif type(exc).__name__ in {"EngineError", "BadTargetError", "InvalidContextError", "InvalidAssessmentError"}:
        message = str(exc)
    elif isinstance(exc, ValidationError):
        message = "Scan output did not match the expected assessment schema."
    else:
        message = f"Scan failed during preparation or analysis ({type(exc).__name__})."
    try:
        with pool.connection() as conn:
            conn.execute(
                """UPDATE scan_runs SET status = 'failed', completed_at = now(), error_message = %s
                   WHERE scan_run_id = %s""",
                (message[:2000], scan_run_id),
            )
    except Exception:
        logger.exception("Could not persist failed scan status for run %s", scan_run_id)


def run_scan_job(
    pool: Any,
    *,
    scan_run_id: str,
    project_id: str,
    workspace_id: str,
    input_kind: str,
    input_name: str,
    source_reference: str | None,
    project_name: str,
    context_data: dict[str, Any] | None,
) -> None:
    """Run one scan, persist its result atomically, and remove its workspace."""
    from quantumshield import engine

    scan_uuid = UUID(scan_run_id)
    project_uuid = UUID(project_id)
    workspace_uuid = UUID(workspace_id)
    workspace: Path | None = None
    try:
        root = workspace_root()
        workspace = (root / str(workspace_uuid)).resolve()
        if root not in workspace.parents:
            raise SourceInputError("Workspace identifier was invalid.")

        with pool.connection() as conn:
            row = conn.execute(
                """UPDATE scan_runs SET status = 'running', started_at = now()
                   WHERE scan_run_id = %s AND status = 'queued'
                   RETURNING scan_run_id""",
                (scan_uuid,),
            ).fetchone()
        if not row:
            return

        context, context_loaded = _context_for_run(context_data, project_name)
        kind = ScanInputKind(input_kind)
        source_revision: str | None = None
        additional_limitations: list[str] = []

        if kind == ScanInputKind.GITHUB_REPOSITORY:
            if not source_reference:
                raise SourceInputError("GitHub repository URL is missing.")
            target, _, source_revision = prepare_github_repository(source_reference, workspace)
            assessment = engine.scan(
                target,
                context=context,
                project_name=project_name,
                context_loaded=context_loaded,
            )
        elif kind == ScanInputKind.ZIP_ARCHIVE:
            upload_path = workspace / "upload.bin"
            target = extract_zip_safely(upload_path, workspace)
            assessment = engine.scan(
                target,
                context=context,
                project_name=project_name,
                context_loaded=context_loaded,
            )
        elif kind in {ScanInputKind.SBOM, ScanInputKind.CBOM}:
            from quantumshield.scoring.assessment_writer import build_assessment

            upload_path = workspace / "upload.bin"
            payload = load_bom_json(upload_path)
            scan_result, additional_limitations = parse_bom_scan_result(payload, kind=kind, input_name=input_name)
            assessment = build_assessment(
                scan_result,
                target=workspace,
                context=context,
                context_loaded=context_loaded,
            )
            assessment = assessment.model_copy(update={
                "limitations": list(assessment.limitations) + additional_limitations + [
                    f"Input provenance: imported from {kind.value}; source code was not rescanned."
                ]
            })
        else:
            raise SourceInputError("This input type is not supported by the public API.")

        if source_revision is not None:
            with pool.connection() as conn:
                conn.execute(
                    "UPDATE scan_runs SET source_revision = %s WHERE scan_run_id = %s",
                    (source_revision, scan_uuid),
                )
        _write_assessment_transaction(pool, scan_run_id=scan_uuid, project_id=project_uuid, assessment=assessment)
    except Exception as exc:
        logger.exception("Scan run failed: %s", scan_uuid)
        _mark_scan_failed(pool, scan_uuid, exc)
    finally:
        if workspace is not None:
            shutil.rmtree(workspace, ignore_errors=True)


def load_assessment_for_session(pool: Any, assessment_id: str, session_id: UUID) -> dict[str, Any] | None:
    with pool.connection() as conn:
        return conn.execute(
            """SELECT a.assessment_id, a.scan_run_id, a.policy_version,
                      a.assessment_schema_version, a.assessment_json, a.summary_json, a.created_at,
                      sr.project_id
               FROM assessments a
               JOIN scan_runs sr ON sr.scan_run_id = a.scan_run_id
               JOIN projects p ON p.project_id = sr.project_id
               WHERE a.assessment_id = %s AND p.session_id = %s AND p.archived = FALSE""",
            (assessment_id, session_id),
        ).fetchone()


def load_owned_assessment_model(pool: Any, assessment_id: str, session_id: UUID) -> AssessmentResult | None:
    row = load_assessment_for_session(pool, assessment_id, session_id)
    if row is None:
        return None
    return AssessmentResult.model_validate(row["assessment_json"])


def plan_summary(plan: dict[str, Any]) -> dict[str, Any]:
    summary = plan.get("summary")
    if isinstance(summary, dict):
        return summary
    tasks = plan.get("tasks", [])
    return {"total_tasks": len(tasks) if isinstance(tasks, list) else 0}


def compliance_summary(report: dict[str, Any]) -> dict[str, Any]:
    results = report.get("results", [])
    counts = Counter((str(row.get("status", "unknown")) if isinstance(row, dict) else "unknown") for row in results)
    return {"result_count": len(results) if isinstance(results, list) else 0, "by_status": dict(sorted(counts.items()))}


def utc_now() -> datetime:
    return datetime.now(timezone.utc)
