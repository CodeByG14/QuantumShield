"""FastAPI routes for QuantumShield.

Run locally only:
    uv run uvicorn quantumshield.api.app:app --host 127.0.0.1 --port 8000 --env-file .env
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Literal
from uuid import UUID
from quantumshield.common.models import AssessmentResult
from fastapi import (
    BackgroundTasks,
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import ValidationError

from quantumshield.api.db import get_pool, open_pool
from quantumshield.api.schemas import (
    ComplianceOut,
    ComplianceRequest,
    DashboardSummaryOut,
    DiffOut,
    DiffRequest,
    FindingsOut,
    PlanOut,
    PlanRequest,
    ProjectCreate,
    ProjectOut,
    ScanAccepted,
    ScanListOut,
    ScanStatusOut,
    SessionOut,
    SessionUpdate,
)
from quantumshield.api.service import (
    assessment_summary,
    compliance_summary,
    load_dashboard_summary,
    load_assessment_for_session,
    plan_summary,
    run_scan_job,
    workspace_root,
)
from quantumshield.api.sessions import get_local_session
from quantumshield.api.source_adapters import (
    MAX_UPLOAD_BYTES,
    SourceInputError,
    canonical_github_url,
    safe_upload_name,
)
from quantumshield.common.models import ProjectContext
from quantumshield.source_contracts import ScanInputKind, ScanSourceMetadata

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    pool_factory = getattr(app.state, "pool_factory", None)
    if pool_factory:
        app.state.db_pool = pool_factory()
    else:
        try:
            app.state.db_pool = open_pool()
        except Exception as exc:
            logger.exception("Could not open PostgreSQL connection pool")
            raise RuntimeError("QuantumShield API could not connect to PostgreSQL; check .env and container health.") from exc
    try:
        yield
    finally:
        pool = getattr(app.state, "db_pool", None)
        if pool is not None and hasattr(pool, "close"):
            pool.close()


def create_app(*, pool_factory=None) -> FastAPI:
    app = FastAPI(
        title="QuantumShield API",
        description="Local API for cryptographic inventory, risk assessment, migration planning, compliance and comparison.",
        version="1.0",
        lifespan=lifespan,
    )
    # Test-only injection point; production uses environment-configured PostgreSQL.
    app.state.pool_factory = pool_factory
    cors_origins = [
        origin.strip()
        for origin in os.getenv(
            "QUANTUMSHIELD_CORS_ORIGINS",
            "http://127.0.0.1:5173,http://localhost:5173",
        ).split(",")
        if origin.strip()
    ]
    if "*" in cors_origins:
        raise ValueError("QUANTUMSHIELD_CORS_ORIGINS must list explicit local origins; wildcard CORS is not allowed.")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Content-Type"],
    )

    @app.get("/health", tags=["system"])
    def health(pool: Any = Depends(get_pool)) -> dict[str, str]:
        try:
            with pool.connection() as conn:
                conn.execute("SELECT 1").fetchone()
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Database is unavailable.") from exc
        return {"status": "ok", "database": "ok"}

    @app.get("/dashboard/summary", response_model=DashboardSummaryOut, tags=["dashboard"])
    def get_dashboard_summary(
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        return load_dashboard_summary(pool, session["session_id"])

    @app.get("/session", response_model=SessionOut, tags=["session"])
    def get_session(session: dict[str, Any] = Depends(get_local_session)) -> dict[str, Any]:
        return session

    @app.patch("/session", response_model=SessionOut, tags=["session"])
    def update_session(
        body: SessionUpdate,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        if "display_name" not in body.model_fields_set:
            return session
        with pool.connection() as conn:
            row = conn.execute(
                """UPDATE local_sessions SET display_name = %s, last_seen_at = now()
                   WHERE session_id = %s
                   RETURNING session_id, display_name, created_at, last_seen_at, expires_at""",
                (body.display_name, session["session_id"]),
            ).fetchone()
        return row

    @app.get("/projects", response_model=list[ProjectOut], tags=["projects"])
    def list_projects(
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> list[dict[str, Any]]:
        with pool.connection() as conn:
            rows = conn.execute(
                """SELECT project_id, project_name, description, created_at, updated_at, archived
                   FROM projects WHERE session_id = %s AND archived = FALSE
                   ORDER BY updated_at DESC, created_at DESC""",
                (session["session_id"],),
            ).fetchall()
        return rows

    @app.post("/projects", response_model=ProjectOut, status_code=status.HTTP_201_CREATED, tags=["projects"])
    def create_project(
        body: ProjectCreate,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            row = conn.execute(
                """INSERT INTO projects (session_id, project_name, description)
                   VALUES (%s, %s, %s)
                   RETURNING project_id, project_name, description, created_at, updated_at, archived""",
                (session["session_id"], body.project_name, body.description),
            ).fetchone()
        return row

    @app.get("/projects/{project_id}", response_model=ProjectOut, tags=["projects"])
    def get_project(
        project_id: UUID,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            row = conn.execute(
                """SELECT project_id, project_name, description, created_at, updated_at, archived
                   FROM projects WHERE project_id = %s AND session_id = %s AND archived = FALSE""",
                (project_id, session["session_id"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Project was not found in this local session.")
        return row

    @app.delete(
        "/projects/{project_id}",
        status_code=status.HTTP_204_NO_CONTENT,
        tags=["projects"],
    )
    def delete_project(
        project_id: UUID,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> None:
        with pool.connection() as conn:
            project = conn.execute(
                """SELECT project_id FROM projects
                   WHERE project_id = %s AND session_id = %s AND archived = FALSE
                   FOR UPDATE""",
                (project_id, session["session_id"]),
            ).fetchone()
            if project is None:
                raise HTTPException(status_code=404, detail="Project was not found in this local session.")

            active_scan = conn.execute(
                """SELECT EXISTS (
                       SELECT 1 FROM scan_runs
                       WHERE project_id = %s AND status IN ('queued', 'running')
                   ) AS exists""",
                (project_id,),
            ).fetchone()["exists"]
            if active_scan:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A project with queued or running scans cannot be deleted.",
                )

            conn.execute(
                "DELETE FROM projects WHERE project_id = %s AND session_id = %s",
                (project_id, session["session_id"]),
            )

    @app.post("/scan", response_model=ScanAccepted, status_code=status.HTTP_202_ACCEPTED, tags=["scans"])
    async def start_scan(
        background_tasks: BackgroundTasks,
        source_type: Literal["github_repository", "zip_archive", "sbom", "cbom"] = Form(...),
        project_id: UUID | None = Form(default=None),
        project_name: str | None = Form(default=None, max_length=255),
        description: str | None = Form(default=None, max_length=5000),
        repository_url: str | None = Form(default=None),
        context_json: str | None = Form(default=None, max_length=100_000),
        file: UploadFile | None = File(default=None),
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        kind = ScanInputKind(source_type)
        source_reference: str | None = None
        upload_name: str | None = None
        inferred_project_name: str

        if kind == ScanInputKind.GITHUB_REPOSITORY:
            if file is not None:
                raise HTTPException(status_code=422, detail="GitHub input must use repository_url, not file.")
            try:
                source_reference, inferred_project_name = canonical_github_url(repository_url or "")
            except SourceInputError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            input_name = inferred_project_name
        else:
            if file is None:
                raise HTTPException(status_code=422, detail="Upload one file for ZIP, SBOM, or CBOM input.")
            if repository_url:
                raise HTTPException(status_code=422, detail="repository_url is only valid for GitHub input.")
            upload_name = safe_upload_name(file.filename, "upload.zip" if kind == ScanInputKind.ZIP_ARCHIVE else "bom.json")
            if kind == ScanInputKind.ZIP_ARCHIVE and not upload_name.casefold().endswith(".zip"):
                raise HTTPException(status_code=422, detail="ZIP input must have a .zip filename.")
            if kind in {ScanInputKind.SBOM, ScanInputKind.CBOM} and not upload_name.casefold().endswith(".json"):
                raise HTTPException(status_code=422, detail="SBOM and CBOM input currently require a .json filename.")
            input_name = upload_name
            inferred_project_name = Path(upload_name).stem[:255] or "quantumshield-project"

        requested_name = (project_name or inferred_project_name).strip()
        if not requested_name or "\x00" in requested_name:
            raise HTTPException(status_code=422, detail="project_name must be non-empty and contain no null byte.")
        if len(requested_name) > 255:
            raise HTTPException(status_code=422, detail="project_name must not exceed 255 characters.")

        context_data: dict[str, Any] | None = None
        if context_json is not None:
            try:
                decoded = json.loads(context_json)
                if not isinstance(decoded, dict):
                    raise ValueError("Project context must be a JSON object.")
                checked = ProjectContext.model_validate(decoded)
                context_data = checked.model_dump(mode="json")
            except (json.JSONDecodeError, ValidationError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="context_json must be a valid QuantumShield project-context object.") from exc

        workspace_id = uuid.uuid4()
        root = workspace_root()
        workspace = root / str(workspace_id)
        workspace.mkdir(parents=True, mode=0o700, exist_ok=False)
        source_fingerprint: str | None = None
        try:
            if file is not None:
                upload_path = workspace / "upload.bin"
                digest = hashlib.sha256()
                total = 0
                with upload_path.open("xb") as output:
                    while True:
                        chunk = await file.read(1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > MAX_UPLOAD_BYTES:
                            raise HTTPException(status_code=413, detail=f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit.")
                        digest.update(chunk)
                        output.write(chunk)
                if total == 0:
                    raise HTTPException(status_code=422, detail="Uploaded file is empty.")
                source_fingerprint = digest.hexdigest()
                await file.close()

            metadata = ScanSourceMetadata(
                input_kind=kind,
                input_name=input_name,
                workspace_id=workspace_id,
                source_reference=source_reference,
                source_fingerprint=source_fingerprint,
            )

            with pool.connection() as conn:
                if project_id is not None:
                    project = conn.execute(
                        """SELECT project_id, project_name FROM projects
                           WHERE project_id = %s AND session_id = %s AND archived = FALSE""",
                        (project_id, session["session_id"]),
                    ).fetchone()
                    if project is None:
                        raise HTTPException(status_code=404, detail="Project was not found in this local session.")
                    chosen_project_id = project["project_id"]
                    chosen_project_name = project["project_name"]
                else:
                    project = conn.execute(
                        """INSERT INTO projects (session_id, project_name, description)
                           VALUES (%s, %s, %s)
                           RETURNING project_id, project_name""",
                        (session["session_id"], requested_name, description),
                    ).fetchone()
                    chosen_project_id = project["project_id"]
                    chosen_project_name = project["project_name"]

                scan_row = conn.execute(
                    """INSERT INTO scan_runs (
                           project_id, workspace_id, input_kind, input_name, source_revision,
                           source_fingerprint, source_reference, status
                       ) VALUES (%s, %s, %s, %s, NULL, %s, %s, 'queued')
                       RETURNING scan_run_id, started_at""",
                    (
                        chosen_project_id, metadata.workspace_id, metadata.input_kind.value,
                        metadata.input_name, metadata.source_fingerprint, metadata.source_reference,
                    ),
                ).fetchone()
                conn.execute("UPDATE projects SET updated_at = now() WHERE project_id = %s", (chosen_project_id,))

            background_tasks.add_task(
                run_scan_job,
                pool,
                scan_run_id=str(scan_row["scan_run_id"]),
                project_id=str(chosen_project_id),
                workspace_id=str(workspace_id),
                input_kind=kind.value,
                input_name=input_name,
                source_reference=source_reference,
                project_name=chosen_project_name,
                context_data=context_data,
            )
            return {
                "scan_run_id": scan_row["scan_run_id"],
                "project_id": chosen_project_id,
                "workspace_id": workspace_id,
                "status": "queued",
                "input_kind": kind.value,
                "input_name": input_name,
                "status_url": f"/scans/{scan_row['scan_run_id']}",
            }
        except HTTPException:
            shutil.rmtree(workspace, ignore_errors=True)
            raise
        except (ValidationError, ValueError) as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            raise HTTPException(status_code=422, detail="Scan source metadata was invalid.") from exc
        except Exception as exc:
            shutil.rmtree(workspace, ignore_errors=True)
            logger.exception("Could not enqueue scan")
            raise HTTPException(status_code=503, detail="Could not enqueue scan; check database availability.") from exc

    @app.get("/projects/{project_id}/scans", response_model=ScanListOut, tags=["scans"])
    def list_project_scans(
        project_id: UUID,
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            project = conn.execute(
                "SELECT project_id FROM projects WHERE project_id = %s AND session_id = %s AND archived = FALSE",
                (project_id, session["session_id"]),
            ).fetchone()
            if project is None:
                raise HTTPException(status_code=404, detail="Project was not found in this local session.")
            total = conn.execute("SELECT count(*) AS count FROM scan_runs WHERE project_id = %s", (project_id,)).fetchone()["count"]
            rows = conn.execute(
                """SELECT sr.scan_run_id, sr.project_id, sr.input_kind, sr.input_name,
                          sr.source_revision, sr.status, sr.started_at, sr.completed_at, sr.error_message,
                          a.assessment_id, a.summary_json AS assessment_summary
                   FROM scan_runs sr LEFT JOIN assessments a ON a.scan_run_id = sr.scan_run_id
                   WHERE sr.project_id = %s ORDER BY sr.started_at DESC LIMIT %s OFFSET %s""",
                (project_id, limit, offset),
            ).fetchall()
        return {"items": rows, "count": total}

    @app.get("/scans/{scan_run_id}", response_model=ScanStatusOut, tags=["scans"])
    def get_scan_status(
        scan_run_id: UUID,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            row = conn.execute(
                """SELECT sr.scan_run_id, sr.project_id, sr.input_kind, sr.input_name,
                          sr.source_revision, sr.status, sr.started_at, sr.completed_at, sr.error_message,
                          a.assessment_id, a.summary_json AS assessment_summary
                   FROM scan_runs sr JOIN projects p ON p.project_id = sr.project_id
                   LEFT JOIN assessments a ON a.scan_run_id = sr.scan_run_id
                   WHERE sr.scan_run_id = %s AND p.session_id = %s AND p.archived = FALSE""",
                (scan_run_id, session["session_id"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Scan was not found in this local session.")
        return row

    @app.get("/scans/{scan_run_id}/assessment", tags=["assessments"])
    def get_scan_assessment(
        scan_run_id: UUID,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            row = conn.execute(
                """SELECT a.assessment_json FROM assessments a
                   JOIN scan_runs sr ON sr.scan_run_id = a.scan_run_id
                   JOIN projects p ON p.project_id = sr.project_id
                   WHERE sr.scan_run_id = %s AND p.session_id = %s AND p.archived = FALSE""",
                (scan_run_id, session["session_id"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Assessment was not found for this scan in the current session.")
        return row["assessment_json"]

    @app.get("/assessments/{assessment_id}", tags=["assessments"])
    def get_assessment(
        assessment_id: str,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        row = load_assessment_for_session(pool, assessment_id, session["session_id"])
        if row is None:
            raise HTTPException(status_code=404, detail="Assessment was not found in this local session.")
        return row["assessment_json"]

    @app.get("/assessments/{assessment_id}/findings", response_model=FindingsOut, tags=["assessments"])
    def get_findings(
        assessment_id: str,
        algorithm: str | None = Query(default=None, max_length=100),
        role: str | None = Query(default=None, max_length=80),
        finding_status: str | None = Query(default=None, alias="status", max_length=40),
        risk_level: str | None = Query(default=None, max_length=40),
        limit: int = Query(default=50, ge=1, le=100),
        offset: int = Query(default=0, ge=0),
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        if load_assessment_for_session(pool, assessment_id, session["session_id"]) is None:
            raise HTTPException(status_code=404, detail="Assessment was not found in this local session.")
        clauses = ["assessment_id = %s"]
        params: list[Any] = [assessment_id]
        for column, value in (("algorithm", algorithm), ("role", role), ("status", finding_status), ("risk_level", risk_level)):
            if value is not None:
                clauses.append(f"{column} = %s")
                params.append(value)
        where = " AND ".join(clauses)
        with pool.connection() as conn:
            total = conn.execute(f"SELECT count(*) AS count FROM assessment_findings WHERE {where}", tuple(params)).fetchone()["count"]
            rows = conn.execute(
                f"""SELECT finding_json, risk_json FROM assessment_findings WHERE {where}
                    ORDER BY finding_id LIMIT %s OFFSET %s""",
                tuple(params + [limit, offset]),
            ).fetchall()
        items = []
        for row in rows:
            item = dict(row["finding_json"])
            item["risk"] = row["risk_json"]
            items.append(item)
        return {"assessment_id": assessment_id, "items": items, "count": total, "limit": limit, "offset": offset}

    @app.post("/plan", response_model=PlanOut, status_code=status.HTTP_201_CREATED, tags=["migration"])
    def create_plan(
        body: PlanRequest,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        row = load_assessment_for_session(pool, body.assessment_id, session["session_id"])
        if row is None:
            raise HTTPException(status_code=404, detail="Assessment was not found in this local session.")
        assessment = AssessmentResult.model_validate(row["assessment_json"])
        from quantumshield import engine
        try:
            plan = engine.plan(assessment)
        except engine.InvalidAssessmentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except engine.EngineError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        summary = plan_summary(plan)
        try:
            from psycopg.types.json import Jsonb
            with pool.connection() as conn:
                saved = conn.execute(
                    """INSERT INTO migration_plans (
                           migration_plan_id, assessment_id, recommendation_policy_version,
                           plan_json, summary_json
                       ) VALUES (%s, %s, %s, %s, %s)
                       RETURNING generated_at""",
                    (plan["migration_plan_id"], body.assessment_id, plan.get("recommendation_policy_version"), Jsonb(plan), Jsonb(summary)),
                ).fetchone()
        except Exception as exc:
            logger.exception("Could not persist migration plan")
            raise HTTPException(status_code=503, detail="Could not save migration plan.") from exc
        return {
            "migration_plan_id": plan["migration_plan_id"],
            "assessment_id": body.assessment_id,
            "plan": plan,
            "summary": summary,
            "generated_at": saved["generated_at"],
        }

    @app.get("/plans/{plan_id}", response_model=PlanOut, tags=["migration"])
    def get_plan(
        plan_id: str,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            row = conn.execute(
                """SELECT mp.migration_plan_id, mp.assessment_id, mp.plan_json, mp.summary_json, mp.generated_at
                   FROM migration_plans mp JOIN assessments a ON a.assessment_id = mp.assessment_id
                   JOIN scan_runs sr ON sr.scan_run_id = a.scan_run_id
                   JOIN projects p ON p.project_id = sr.project_id
                   WHERE mp.migration_plan_id = %s AND p.session_id = %s AND p.archived = FALSE""",
                (plan_id, session["session_id"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Migration plan was not found in this local session.")
        return {"migration_plan_id": row["migration_plan_id"], "assessment_id": row["assessment_id"], "plan": row["plan_json"], "summary": row["summary_json"], "generated_at": row["generated_at"]}

    @app.post("/compliance", response_model=ComplianceOut, status_code=status.HTTP_201_CREATED, tags=["compliance"])
    def create_compliance_report(
        body: ComplianceRequest,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        row = load_assessment_for_session(pool, body.assessment_id, session["session_id"])
        if row is None:
            raise HTTPException(status_code=404, detail="Assessment was not found in this local session.")
        assessment = AssessmentResult.model_validate(row["assessment_json"])
        plan_json = None
        if body.migration_plan_id:
            with pool.connection() as conn:
                plan_row = conn.execute(
                    """SELECT mp.plan_json FROM migration_plans mp
                       JOIN assessments a ON a.assessment_id = mp.assessment_id
                       JOIN scan_runs sr ON sr.scan_run_id = a.scan_run_id
                       JOIN projects p ON p.project_id = sr.project_id
                       WHERE mp.migration_plan_id = %s AND mp.assessment_id = %s
                         AND p.session_id = %s AND p.archived = FALSE""",
                    (body.migration_plan_id, body.assessment_id, session["session_id"]),
                ).fetchone()
            if plan_row is None:
                raise HTTPException(status_code=422, detail="Migration plan must belong to the selected assessment and local session.")
            plan_json = plan_row["plan_json"]
        from quantumshield import engine
        try:
            report = engine.comply(assessment, plan_json, as_of=body.as_of.isoformat() if body.as_of else None)
        except engine.InvalidAssessmentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except engine.EngineError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc
        summary = compliance_summary(report)
        report_id = uuid.uuid4()
        try:
            from psycopg.types.json import Jsonb
            with pool.connection() as conn:
                saved = conn.execute(
                    """INSERT INTO compliance_reports (
                           report_id, assessment_id, migration_plan_id, as_of, report_json, summary_json
                       ) VALUES (%s, %s, %s, %s, %s, %s)
                       RETURNING generated_at""",
                    (report_id, body.assessment_id, body.migration_plan_id, body.as_of, Jsonb(report), Jsonb(summary)),
                ).fetchone()
        except Exception as exc:
            logger.exception("Could not persist compliance report")
            raise HTTPException(status_code=503, detail="Could not save compliance report.") from exc
        return {"report_id": report_id, "assessment_id": body.assessment_id, "migration_plan_id": body.migration_plan_id, "as_of": body.as_of, "report": report, "summary": summary, "generated_at": saved["generated_at"]}

    @app.get("/compliance/{report_id}", response_model=ComplianceOut, tags=["compliance"])
    def get_compliance_report(
        report_id: UUID,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            row = conn.execute(
                """SELECT cr.report_id, cr.assessment_id, cr.migration_plan_id, cr.as_of,
                          cr.report_json, cr.summary_json, cr.generated_at
                   FROM compliance_reports cr JOIN assessments a ON a.assessment_id = cr.assessment_id
                   JOIN scan_runs sr ON sr.scan_run_id = a.scan_run_id
                   JOIN projects p ON p.project_id = sr.project_id
                   WHERE cr.report_id = %s AND p.session_id = %s AND p.archived = FALSE""",
                (report_id, session["session_id"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Compliance report was not found in this local session.")
        return {"report_id": row["report_id"], "assessment_id": row["assessment_id"], "migration_plan_id": row["migration_plan_id"], "as_of": row["as_of"], "report": row["report_json"], "summary": row["summary_json"], "generated_at": row["generated_at"]}

    @app.post("/diff", response_model=DiffOut, status_code=status.HTTP_201_CREATED, tags=["comparison"])
    def create_diff(
        body: DiffRequest,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        if body.baseline_assessment_id == body.current_assessment_id:
            raise HTTPException(status_code=422, detail="Baseline and current assessment IDs must be different.")
        baseline_row = load_assessment_for_session(pool, body.baseline_assessment_id, session["session_id"])
        current_row = load_assessment_for_session(pool, body.current_assessment_id, session["session_id"])
        if baseline_row is None or current_row is None:
            raise HTTPException(status_code=404, detail="Both assessments must belong to this local session.")
        if baseline_row["project_id"] != current_row["project_id"]:
            raise HTTPException(status_code=422, detail="Assessments must belong to the same project to be compared.")
        baseline = AssessmentResult.model_validate(baseline_row["assessment_json"])
        current = AssessmentResult.model_validate(current_row["assessment_json"])
        from quantumshield import engine
        try:
            difference = engine.diff(baseline, current)
        except engine.InvalidAssessmentError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except engine.EngineError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        summary = difference.get("summary", {})
        diff_id = uuid.uuid4()
        try:
            from psycopg.types.json import Jsonb
            with pool.connection() as conn:
                saved = conn.execute(
                    """INSERT INTO scan_diffs (
                           diff_id, baseline_assessment_id, current_assessment_id, diff_json, summary_json
                       ) VALUES (%s, %s, %s, %s, %s)
                       RETURNING generated_at""",
                    (diff_id, body.baseline_assessment_id, body.current_assessment_id, Jsonb(difference), Jsonb(summary)),
                ).fetchone()
        except Exception as exc:
            logger.exception("Could not persist assessment comparison")
            raise HTTPException(status_code=503, detail="Could not save assessment comparison.") from exc
        return {"diff_id": diff_id, "baseline_assessment_id": body.baseline_assessment_id, "current_assessment_id": body.current_assessment_id, "diff": difference, "summary": summary, "generated_at": saved["generated_at"]}

    @app.get("/diffs/{diff_id}", response_model=DiffOut, tags=["comparison"])
    def get_diff(
        diff_id: UUID,
        pool: Any = Depends(get_pool),
        session: dict[str, Any] = Depends(get_local_session),
    ) -> dict[str, Any]:
        with pool.connection() as conn:
            row = conn.execute(
                """SELECT d.diff_id, d.baseline_assessment_id, d.current_assessment_id,
                          d.diff_json, d.summary_json, d.generated_at
                   FROM scan_diffs d
                   JOIN assessments ba ON ba.assessment_id = d.baseline_assessment_id
                   JOIN scan_runs bsr ON bsr.scan_run_id = ba.scan_run_id
                   JOIN projects bp ON bp.project_id = bsr.project_id
                   JOIN assessments ca ON ca.assessment_id = d.current_assessment_id
                   JOIN scan_runs csr ON csr.scan_run_id = ca.scan_run_id
                   JOIN projects cp ON cp.project_id = csr.project_id
                   WHERE d.diff_id = %s AND bp.session_id = %s AND cp.session_id = %s
                     AND bp.archived = FALSE AND cp.archived = FALSE""",
                (diff_id, session["session_id"], session["session_id"]),
            ).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Comparison was not found in this local session.")
        return {"diff_id": row["diff_id"], "baseline_assessment_id": row["baseline_assessment_id"], "current_assessment_id": row["current_assessment_id"], "diff": row["diff_json"], "summary": row["summary_json"], "generated_at": row["generated_at"]}

    return app


app = create_app()
