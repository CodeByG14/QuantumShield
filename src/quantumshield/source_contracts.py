"""Stable source metadata contracts shared by input adapters and persistence.

This module validates metadata only. It does not download repositories, extract
archives, parse SBOM/CBOM documents, or create workspace directories.
"""

from __future__ import annotations

from enum import Enum
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ScanInputKind(str, Enum):
    """Database-aligned names for supported input sources.

    ``local_directory`` is internal/test-only for the engine. The initial HTTP
    endpoint should expose only github_repository, zip_archive, sbom, and cbom.
    """

    LOCAL_DIRECTORY = "local_directory"
    GITHUB_REPOSITORY = "github_repository"
    ZIP_ARCHIVE = "zip_archive"
    SBOM = "sbom"
    CBOM = "cbom"


class ScanSourceMetadata(BaseModel):
    """Source identity that can be retained without storing source bytes/paths."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    input_kind: ScanInputKind
    input_name: str = Field(min_length=1, max_length=255)
    workspace_id: UUID = Field(default_factory=uuid4)
    source_reference: str | None = Field(default=None, max_length=2048)
    source_revision: str | None = Field(default=None, max_length=255)
    source_fingerprint: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @field_validator("input_name")
    @classmethod
    def normalize_input_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("input_name must not be empty")
        if "\x00" in normalized:
            raise ValueError("input_name must not contain a null byte")
        return normalized

    @field_validator("source_reference")
    @classmethod
    def normalize_source_reference(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("source_reference must be omitted when empty")
        parsed = urlsplit(normalized)
        if parsed.username or parsed.password:
            raise ValueError("source_reference must not contain embedded credentials")
        if parsed.query or parsed.fragment:
            raise ValueError("source_reference must not contain a query string or fragment")
        return normalized

    @model_validator(mode="after")
    def validate_kind_reference(self) -> "ScanSourceMetadata":
        if self.input_kind == ScanInputKind.GITHUB_REPOSITORY:
            if not self.source_reference:
                raise ValueError("GitHub source_reference is required")
            parsed = urlsplit(self.source_reference)
            if parsed.scheme != "https" or parsed.hostname != "github.com":
                raise ValueError("GitHub source_reference must use https://github.com/")
            segments = [part for part in parsed.path.split("/") if part]
            if len(segments) < 2:
                raise ValueError("GitHub source_reference must identify an owner and repository")
        elif self.source_reference is not None:
            raise ValueError("source_reference is only used for GitHub repository inputs")
        return self
