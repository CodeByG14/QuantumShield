from __future__ import annotations

from copy import deepcopy

import pytest

from common.models import AssetContext as RootAssetContext, ProjectContext as RootProjectContext
from quantumshield.common.models import AssetContext as PackageAssetContext, ProjectContext as PackageProjectContext
from quantumshield.compliance.checker import (
    ComplianceAssessmentError,
    check_compliance,
    infer_security_strength_bits,
)


def finding(algorithm="RSA", *, finding_id="CRYPTO-001", role="signature", key_size=None, variant=None, curve=None, file_path="src/crypto.py", purpose=None):
    return {
        "finding_id": finding_id,
        "algorithm": algorithm,
        "variant": variant,
        "key_size": key_size,
        "curve": curve,
        "role": role,
        "purpose": purpose,
        "status": "confirmed",
        "evidence": [{"file_path": file_path, "line_start": 12, "metadata": {}}],
    }


def assessment(*findings, context=None):
    return {
        "assessment_id": "assessment-test-1",
        "project_context": context or {},
        "findings": list(findings),
    }


def result(report, finding_id, framework="NIST IR 8547"):
    return next(x for x in report["results"] if x["finding_id"] == finding_id and x["framework"] == framework)


@pytest.mark.parametrize(
    ("as_of", "expected"),
    [
        ("2030-12-31", "compliant"),
        ("2031-01-01", "deprecated-soon"),
        ("2035-12-31", "deprecated-soon"),
        ("2036-01-01", "past-deadline"),
    ],
)
def test_public_key_112_bit_status_boundaries(as_of, expected):
    report = check_compliance(assessment(finding(key_size=2048, variant="RSA-2048")), as_of=as_of)
    row = result(report, "CRYPTO-001")
    assert row["rule_id"] == "NIST-IR8547-PUBLICKEY-112"
    assert row["security_strength_bits"] == 112
    assert row["status"] == expected


def test_public_key_128_bit_and_higher_has_no_unsupported_early_deprecation():
    rsa3072 = finding(key_size=3072, variant="RSA-3072")
    before = result(check_compliance(assessment(rsa3072), as_of="2035-12-31"), "CRYPTO-001")
    deadline = result(check_compliance(assessment(rsa3072), as_of="2036-01-01"), "CRYPTO-001")
    assert before["rule_id"] == "NIST-IR8547-PUBLICKEY-128-PLUS"
    assert before["status"] == "compliant"
    assert deadline["status"] == "past-deadline"


def test_strength_inference_uses_common_known_parameters_only():
    assert infer_security_strength_bits(finding(key_size=2048)) == 112
    assert infer_security_strength_bits(finding(key_size=3072)) == 128
    assert infer_security_strength_bits(finding(algorithm="ECDSA", curve="P-256")) == 128
    assert infer_security_strength_bits(finding(key_size=None, variant=None)) is None


def test_symmetric_112_bit_rule_boundary():
    sha224 = finding("SHA-224", role="hash", variant="SHA-224")
    before = result(check_compliance(assessment(sha224), as_of="2029-12-31"), "CRYPTO-001")
    deadline = result(check_compliance(assessment(sha224), as_of="2030-01-01"), "CRYPTO-001")
    assert before["status"] == "compliant"
    assert deadline["status"] == "past-deadline"
    assert before["deadline_year"] == 2030


def test_unknown_algorithm_and_missing_strength_are_not_assessed():
    unknown = result(check_compliance(assessment(finding("made-up-cipher")), as_of="2026-10-25"), "CRYPTO-001")
    no_size = result(check_compliance(assessment(finding("RSA")), as_of="2026-10-25"), "CRYPTO-001")
    assert unknown["status"] == "not assessed"
    assert unknown["rule_id"] is None
    assert no_size["status"] == "not assessed"
    assert no_size["rule_id"] is None
    assert set(no_size["rule_candidate_ids"]) == {
        "NIST-IR8547-PUBLICKEY-112", "NIST-IR8547-PUBLICKEY-128-PLUS"
    }
    assert no_size["sources"][0]["publication_status"] == "draft"


def test_final_nist_pqc_standard_is_recognized():
    mlkem = finding("ML-KEM", role="key-establishment", variant="ML-KEM-1024")
    row = result(check_compliance(assessment(mlkem), as_of="2026-10-25"), "CRYPTO-001")
    assert row["rule_id"] == "NIST-FIPS-PQC-MLKEM"
    assert row["status"] == "compliant"
    assert any(source["publication_status"] == "final" for source in row["sources"])


def test_cnsa_requires_explicit_scope_and_category():
    mlkem = finding("ML-KEM", role="key-establishment", variant="ML-KEM-1024")
    report = check_compliance(assessment(mlkem, context={"system_category": "web"}), as_of="2026-10-25")
    assert result(report, "CRYPTO-001", "CNSA 2.0 / CNSSP No. 15")["status"] == "not assessed"

    report = check_compliance(assessment(mlkem, context={"cnsa_scope_confirmed": True}), as_of="2026-10-25")
    cnsa = result(report, "CRYPTO-001", "CNSA 2.0 / CNSSP No. 15")
    assert cnsa["status"] == "not assessed"
    assert "system_category" in cnsa["reason"]


def test_cnsa_mlkem_uses_parameter_set_and_explicit_nss_scope():
    mlkem = finding("ML-KEM", role="key-establishment", variant="ML-KEM-1024")
    context = {"system_category": "web", "cnsa_scope_confirmed": True}
    row = result(check_compliance(assessment(mlkem, context=context), as_of="2026-10-25"), "CRYPTO-001", "CNSA 2.0 / CNSSP No. 15")
    assert row["rule_id"] == "CNSA2-MLKEM-1024"
    assert row["status"] == "compliant"
    assert any(source["id"] == "nsa_csfc_pqc_addendum_draft" for source in row["sources"])

    wrong = finding("ML-KEM", role="key-establishment", variant="ML-KEM-768")
    row = result(check_compliance(assessment(wrong, context=context), as_of="2026-10-25"), "CRYPTO-001", "CNSA 2.0 / CNSSP No. 15")
    assert row["status"] == "not assessed"
    assert "does not match required set" in row["reason"]


def test_asset_context_overrides_project_category_and_scope():
    lms = finding("LMS", role="signature", file_path="src/firmware/signing.py")
    context = {
        "system_category": "web", "cnsa_scope_confirmed": False,
        "asset_contexts": [{"asset_id": "src/firmware/**", "system_category": "firmware-signing", "cnsa_scope_confirmed": True}],
    }
    row = result(check_compliance(assessment(lms, context=context), as_of="2026-10-25"), "CRYPTO-001", "CNSA 2.0 / CNSSP No. 15")
    assert row["system_category"] == "firmware-signing"
    assert row["cnsa_scope_confirmed"] is True
    assert row["rule_id"] == "CNSA2-LMS-XMSS-SIGNING"
    assert row["status"] == "compliant"


def test_exact_asset_context_without_compliance_fields_does_not_block_path_context():
    rsa = finding(key_size=2048, variant="RSA-2048", file_path="src/firmware/signing.py")
    context = {
        "asset_contexts": [
            {"asset_id": "CRYPTO-001", "data_sensitivity": 5},
            {"asset_id": "src/firmware/**", "system_category": "firmware-signing", "cnsa_scope_confirmed": True},
        ],
    }
    row = result(
        check_compliance(assessment(rsa, context=context), as_of="2026-10-25"),
        "CRYPTO-001", "CNSA 2.0 / CNSSP No. 15",
    )
    assert row["system_category"] == "firmware-signing"
    assert row["cnsa_scope_confirmed"] is True
    assert row["cnsa_scope_source"] == "asset_context:src/firmware/**"


def test_migration_plan_estimate_compares_before_deadline_and_checks_assessment_id():
    rsa = finding(key_size=2048, variant="RSA-2048")
    early_plan = {
        "migration_plan_id": "plan-1", "source_assessment_id": "assessment-test-1",
        "generated_at": "2026-10-25T10:00:00+00:00",
        "tasks": [{"finding_id": "CRYPTO-001", "timeline_months": 36}],
    }
    row = result(check_compliance(assessment(rsa), migration_plan=early_plan, as_of="2026-10-25"), "CRYPTO-001")
    assert row["plan_completion_date"] == "2029-10-25"
    assert row["plan_finishes_before_deadline"] is True

    late_plan = deepcopy(early_plan)
    late_plan["tasks"][0]["timeline_months"] = 120
    row = result(check_compliance(assessment(rsa), migration_plan=late_plan, as_of="2026-10-25"), "CRYPTO-001")
    assert row["plan_finishes_before_deadline"] is False

    late_plan["source_assessment_id"] = "another-assessment"
    row = result(check_compliance(assessment(rsa), migration_plan=late_plan, as_of="2026-10-25"), "CRYPTO-001")
    assert row["plan_completion_date"] is None
    assert "does not match" in row["plan_comparison_note"]


def test_invalid_as_of_is_rejected():
    with pytest.raises(ComplianceAssessmentError, match="ISO date"):
        check_compliance(assessment(finding()), as_of="25-10-2026")


def test_system_category_and_cnsa_scope_fields_exist_in_both_context_model_namespaces():
    root_context = RootProjectContext.model_validate({
        "project_name": "demo", "system_category": "web", "cnsa_scope_confirmed": True,
        "asset_contexts": [{"asset_id": "src/**", "system_category": "firmware-signing", "cnsa_scope_confirmed": True}],
    })
    package_context = PackageProjectContext.model_validate({
        "project_name": "demo", "system_category": "web", "cnsa_scope_confirmed": True,
        "asset_contexts": [{"asset_id": "src/**", "system_category": "firmware-signing", "cnsa_scope_confirmed": True}],
    })
    assert root_context.system_category == package_context.system_category == "web"
    assert isinstance(root_context.asset_contexts[0], RootAssetContext)
    assert isinstance(package_context.asset_contexts[0], PackageAssetContext)
