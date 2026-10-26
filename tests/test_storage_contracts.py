import pytest
from quantumshield.common.models import AssessmentResult
from quantumshield.engine import scan
from quantumshield.storage_contracts import assessment_snapshot_for_storage

PROJECT_ID = "10000000-0000-0000-0000-000000000001"


def test_storage_snapshot_uses_project_identity_and_does_not_mutate_assessment(tmp_path):
    source = tmp_path / "source-project"
    source.mkdir()
    (source / "crypto.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    assessment = scan(source, project_name="stable-project", context_loaded=False)

    snapshot = assessment_snapshot_for_storage(assessment, PROJECT_ID)

    assert snapshot["target"] == f"project:{PROJECT_ID}"
    assert snapshot["schema_version"] == "1.0"
    assert assessment.target == str(source.resolve())
    assert snapshot["assessment_id"] == assessment.assessment_id
    for finding in snapshot["findings"]:
        for evidence in finding.get("evidence", []):
            path = evidence.get("file_path")
            assert path is None or not path.startswith("/")


def test_storage_snapshot_rejects_absolute_evidence_paths(tmp_path):
    source = tmp_path / "source-project"
    source.mkdir()
    (source / "crypto.py").write_text(
        "from cryptography.hazmat.primitives.asymmetric import rsa\n"
        "key = rsa.generate_private_key(public_exponent=65537, key_size=2048)\n",
        encoding="utf-8",
    )
    assessment = scan(source, project_name="stable-project", context_loaded=False)
    payload = assessment.model_dump(mode="json")
    assert payload["findings"], "fixture should produce a crypto finding"
    payload["findings"][0]["evidence"][0]["file_path"] = "/tmp/private-workspace/crypto.py"
    unsafe_assessment = AssessmentResult.model_validate(payload)

    with pytest.raises(ValueError, match="absolute file path"):
        assessment_snapshot_for_storage(unsafe_assessment, PROJECT_ID)


def test_storage_snapshot_requires_valid_project_uuid(tmp_path):
    assessment = scan(tmp_path, project_name="stable-project", context_loaded=False)
    with pytest.raises(ValueError, match="project_id must be a valid UUID"):
        assessment_snapshot_for_storage(assessment, "not-a-uuid")
