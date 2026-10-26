"""Safe serialization contracts for storing QuantumShield assessments.

These helpers do not connect to PostgreSQL. They prepare model output for a
repository layer while keeping temporary workspace paths out of stored JSON.
"""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Any
from uuid import UUID

from quantumshield.common.models import AssessmentResult

_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[/\\]")


def assessment_snapshot_for_storage(
    assessment: AssessmentResult,
    project_id: UUID | str,
) -> dict[str, Any]:
    """Return a JSON-ready snapshot with a stable logical target.

    The engine model is not mutated. Finding evidence paths must be project-
    relative; rejecting absolute paths is safer than accidentally persisting a
    host or temporary workspace path.
    """
    if not isinstance(assessment, AssessmentResult):
        raise TypeError("assessment must be an AssessmentResult")
    try:
        normalized_project_id = str(UUID(str(project_id)))
    except (TypeError, ValueError, AttributeError) as exc:
        raise ValueError("project_id must be a valid UUID") from exc

    snapshot = assessment.model_dump(mode="json", exclude_none=False)
    for finding_index, finding in enumerate(snapshot.get("findings", [])):
        for evidence_index, evidence in enumerate(finding.get("evidence", [])):
            file_path = evidence.get("file_path")
            if file_path is None:
                continue
            if not isinstance(file_path, str):
                raise ValueError(
                    f"findings[{finding_index}].evidence[{evidence_index}].file_path must be a string"
                )
            normalized_path = file_path.replace("\\", "/")
            path_parts = PurePosixPath(normalized_path).parts
            if (
                PurePosixPath(normalized_path).is_absolute()
                or _WINDOWS_ABSOLUTE_PATH.match(normalized_path)
                or ".." in path_parts
            ):
                raise ValueError(
                    f"findings[{finding_index}].evidence[{evidence_index}] contains an absolute file path or traversal"
                )

    # This is a storage-safe logical target, not the filesystem path used to run the scan.
    snapshot["target"] = f"project:{normalized_project_id}"
    return snapshot
