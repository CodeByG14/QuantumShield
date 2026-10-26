"""HTTP request/response schemas. Keep external contracts independent of SQL."""
from __future__ import annotations

from datetime import datetime, date
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionOut(BaseModel):
    session_id: UUID
    display_name: str | None = None
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime | None = None


class SessionUpdate(StrictModel):
    display_name: str | None = Field(default=None, max_length=120)

    @field_validator("display_name")
    @classmethod
    def clean_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            raise ValueError("display_name must not be blank; send null to clear it")
        if "\x00" in value:
            raise ValueError("display_name must not contain a null byte")
        return value


class ProjectCreate(StrictModel):
    project_name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=5000)

    @field_validator("project_name")
    @classmethod
    def clean_project_name(cls, value: str) -> str:
        value = value.strip()
        if not value or "\x00" in value:
            raise ValueError("project_name must be non-empty and contain no null byte")
        return value


class ProjectOut(BaseModel):
    project_id: UUID
    project_name: str
    description: str | None = None
    created_at: datetime
    updated_at: datetime
    archived: bool = False


class ScanAccepted(BaseModel):
    scan_run_id: UUID
    project_id: UUID
    workspace_id: UUID
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    input_kind: str
    input_name: str
    status_url: str


class ScanStatusOut(BaseModel):
    scan_run_id: UUID
    project_id: UUID
    input_kind: str
    input_name: str | None = None
    source_revision: str | None = None
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    started_at: datetime
    completed_at: datetime | None = None
    error_message: str | None = None
    assessment_id: str | None = None
    assessment_summary: dict[str, Any] | None = None


class ScanListOut(BaseModel):
    items: list[ScanStatusOut]
    count: int


class AssessmentSummaryOut(BaseModel):
    assessment_id: str
    scan_run_id: UUID
    assessment_schema_version: str
    policy_version: str
    summary: dict[str, Any]
    created_at: datetime


class FindingsOut(BaseModel):
    assessment_id: str
    items: list[dict[str, Any]]
    count: int
    limit: int
    offset: int


class PlanRequest(StrictModel):
    assessment_id: str = Field(min_length=1, max_length=255)


class PlanOut(BaseModel):
    migration_plan_id: str
    assessment_id: str
    plan: dict[str, Any]
    summary: dict[str, Any]
    generated_at: datetime


class ComplianceRequest(StrictModel):
    assessment_id: str = Field(min_length=1, max_length=255)
    migration_plan_id: str | None = Field(default=None, max_length=255)
    as_of: date | None = None


class ComplianceOut(BaseModel):
    report_id: UUID
    assessment_id: str
    migration_plan_id: str | None = None
    as_of: date | None = None
    report: dict[str, Any]
    summary: dict[str, Any]
    generated_at: datetime


class DiffRequest(StrictModel):
    baseline_assessment_id: str = Field(min_length=1, max_length=255)
    current_assessment_id: str = Field(min_length=1, max_length=255)


class DiffOut(BaseModel):
    diff_id: UUID
    baseline_assessment_id: str
    current_assessment_id: str
    diff: dict[str, Any]
    summary: dict[str, Any]
    generated_at: datetime


class ErrorOut(BaseModel):
    detail: str
