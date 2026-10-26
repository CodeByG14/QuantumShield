from uuid import UUID

import pytest
from pydantic import ValidationError

from quantumshield.source_contracts import ScanInputKind, ScanSourceMetadata


def test_workspace_id_is_generated_and_different_from_project_identity():
    first = ScanSourceMetadata(input_kind="zip_archive", input_name="project.zip")
    second = ScanSourceMetadata(input_kind="zip_archive", input_name="project.zip")

    assert isinstance(first.workspace_id, UUID)
    assert first.workspace_id != second.workspace_id
    assert first.input_kind is ScanInputKind.ZIP_ARCHIVE


def test_github_source_records_public_repository_and_revision():
    source = ScanSourceMetadata(
        input_kind="github_repository",
        input_name="QuantumShield",
        source_reference="https://github.com/CodeByG14/QuantumShield",
        source_revision="0123456789abcdef",
        source_fingerprint="a" * 64,
    )
    assert source.model_dump(mode="json")["input_kind"] == "github_repository"
    assert source.model_dump(mode="json")["source_reference"] == "https://github.com/CodeByG14/QuantumShield"
    assert source.model_dump(mode="json")["source_fingerprint"] == "a" * 64


@pytest.mark.parametrize(
    "source_reference",
    [
        None,
        "http://github.com/example/repo",
        "https://user:secret@github.com/example/repo",
        "https://github.com/example/repo?token=secret",
        "https://github.com/example/repo#fragment",
        "https://github.com/example",
    ],
)
def test_github_source_rejects_missing_or_unsafe_repository_reference(source_reference):
    with pytest.raises(ValidationError):
        ScanSourceMetadata(
            input_kind="github_repository",
            input_name="repo",
            source_reference=source_reference,
        )


def test_non_github_input_cannot_persist_a_source_reference():
    with pytest.raises(ValidationError, match="only used for GitHub"):
        ScanSourceMetadata(
            input_kind="sbom",
            input_name="bom.json",
            source_reference="https://example.com/bom.json",
        )


def test_fingerprint_must_be_sha256_hex():
    with pytest.raises(ValidationError):
        ScanSourceMetadata(
            input_kind="cbom",
            input_name="cbom.json",
            source_fingerprint="not-a-hash",
        )
