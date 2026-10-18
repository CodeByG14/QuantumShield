from common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
    ProjectContext,
    RiskKind,
    RiskLevel,
)
from scoring.hndl_engine import assess_finding
from scoring.policy import (
    CLASSICAL_WEAKNESS_WEIGHTS,
    CONFIDENTIALITY_WEIGHTS,
    POLICY_VERSION,
    SIGNATURE_TRANSITION_WEIGHTS,
    confidentiality_lifetime_score,
    quantum_profile,
    risk_level_for_score,
)


def make_finding(
    algorithm="RSA",
    *,
    role=CryptoRole.KEY_ESTABLISHMENT,
    status=FindingStatus.CONFIRMED,
    confidence=Confidence.HIGH,
    variant=None,
    key_size=None,
    curve=None,
    evidence_type=EvidenceType.API_CALL,
    finding_id="CRYPTO-001",
):
    return CryptoFinding(
        finding_id=finding_id,
        algorithm=algorithm,
        variant=variant,
        key_size=key_size,
        curve=curve,
        role=role,
        status=status,
        evidence=[
            Evidence(
                finding_id=finding_id,
                file_path="src/example.py",
                line_start=12,
                evidence_type=evidence_type,
                detection_method=DetectionMethod.REGEX,
                rule_id="TEST-001",
                excerpt="test crypto call",
                confidence=confidence,
            )
        ],
    )


def complete_context(**overrides):
    data = {
        "project_name": "test-project",
        "data_sensitivity": 4,
        "confidentiality_years": 15,
        "exposure": 4,
        "system_criticality": 4,
        "migration_years": 3,
        "threat_horizon_year": 2035,
    }
    data.update(overrides)
    return ProjectContext(**data)


def test_weights_are_normalized():
    assert sum(CONFIDENTIALITY_WEIGHTS.values()) == 1.0
    assert sum(SIGNATURE_TRANSITION_WEIGHTS.values()) == 1.0
    assert sum(CLASSICAL_WEAKNESS_WEIGHTS.values()) == 1.0


def test_lifetime_mapping_is_monotonic_and_bounded():
    values = [confidentiality_lifetime_score(y) for y in (0, 1, 3, 5, 10, 15)]
    assert values == [0, 1, 2, 3, 4, 5]


def test_risk_level_thresholds():
    assert risk_level_for_score(19.9) == RiskLevel.LOW
    assert risk_level_for_score(20) == RiskLevel.MODERATE
    assert risk_level_for_score(40) == RiskLevel.HIGH
    assert risk_level_for_score(60) == RiskLevel.VERY_HIGH
    assert risk_level_for_score(80) == RiskLevel.CRITICAL


def test_shor_vulnerable_confidentiality_role_is_scored_and_mosca_escalates():
    finding = make_finding("RSA", role=CryptoRole.KEY_ESTABLISHMENT)
    result = assess_finding(finding, complete_context(), assessment_year=2026)
    assert result.risk_kind == RiskKind.HNDL_CONFIDENTIALITY
    assert result.risk_score is not None and result.risk_score >= 80
    assert result.risk_level == RiskLevel.CRITICAL
    assert result.escalations
    assert result.policy_version == POLICY_VERSION
    assert len(result.factors) == 5



def test_mosca_escalation_floors_low_sensitivity_confidentiality_risk_at_very_high():
    finding = make_finding("RSA", role=CryptoRole.KEY_ESTABLISHMENT)
    context = complete_context(
        data_sensitivity=2,
        confidentiality_years=1,
        exposure=1,
        system_criticality=1,
        migration_years=3,
        threat_horizon_year=2028,
    )
    result = assess_finding(finding, context, assessment_year=2026)
    assert result.escalations
    assert result.risk_level == RiskLevel.VERY_HIGH
    assert result.risk_score is not None and result.risk_score >= 60


def test_bare_asymmetric_key_with_undetermined_role_is_scored_provisionally():
    finding = make_finding(
        "RSA", role=CryptoRole.UNDETERMINED, evidence_type=EvidenceType.KEY_FILE
    )
    result = assess_finding(finding, complete_context(), assessment_year=2026)
    assert result.risk_kind == RiskKind.HNDL_CONFIDENTIALITY
    assert result.risk_score is not None
    assert result.provisional is True
    assert "cryptographic_role" in result.missing_inputs
    assert any("conservatively assesses" in item for item in result.explanation)


def test_signature_is_authenticity_risk_and_drops_lifetime_factor():
    finding = make_finding("RSA", role=CryptoRole.SIGNATURE)
    result = assess_finding(finding, complete_context(), assessment_year=2026)
    assert result.risk_kind == RiskKind.SIGNATURE_TRANSITION
    assert result.risk_score is not None
    assert len(result.factors) == 4
    assert "confidentiality_lifetime" not in {factor.factor for factor in result.factors}
    assert result.escalations == []
    assert any("not HNDL" in item for item in result.explanation)


def test_hash_is_not_hndl_scored_and_md5_is_not_mislabelled_quantum_risk():
    finding = make_finding("MD5", role=CryptoRole.HASH)
    result = assess_finding(finding, complete_context())
    assert result.risk_kind == RiskKind.CLASSICAL_WEAKNESS
    assert result.risk_score is not None  # Now scored as classical weakness
    assert any("classical" in item.lower() for item in result.explanation)


def test_library_component_is_not_scored_as_crypto_usage():
    finding = make_finding("library:cryptography", role=CryptoRole.UNDETERMINED, evidence_type=EvidenceType.DEPENDENCY)
    result = assess_finding(finding, complete_context())
    assert result.risk_kind == RiskKind.NOT_ASSESSED
    assert result.risk_score is None


def test_unable_to_analyze_has_no_score():
    finding = CryptoFinding(
        finding_id="CRYPTO-022",
        algorithm="unknown",
        role=CryptoRole.UNDETERMINED,
        status=FindingStatus.UNABLE_TO_ANALYZE,
        evidence_gap_reason="file is empty",
        evidence=[Evidence(
            finding_id="CRYPTO-022",
            file_path="server.pem",
            evidence_type=EvidenceType.FILE_EXTENSION,
            detection_method=DetectionMethod.FILE_EXTENSION,
            rule_id="X509-UNREADABLE-001",
            excerpt="empty file",
            confidence=Confidence.LOW,
        )],
    )
    result = assess_finding(finding, complete_context())
    assert result.risk_kind == RiskKind.NOT_ASSESSED
    assert result.risk_score is None
    assert result.provisional is True
    assert any("could not be analyzed" in item for item in result.explanation)


def test_potential_low_confidence_finding_is_scored_but_provisional():
    finding = make_finding(
        "RSA",
        role=CryptoRole.KEY_ESTABLISHMENT,
        status=FindingStatus.POTENTIAL,
        confidence=Confidence.LOW,
        evidence_type=EvidenceType.KEYWORD,
    )
    result = assess_finding(finding, complete_context(), assessment_year=2026)
    assert result.risk_score is not None
    assert result.confidence == Confidence.LOW
    assert result.provisional is True
    assert any("potential, not confirmed" in item for item in result.explanation)


def test_missing_context_is_assumed_explicitly_and_makes_result_provisional():
    finding = make_finding("RSA", role=CryptoRole.KEY_ESTABLISHMENT)
    result = assess_finding(finding, ProjectContext(), assessment_year=2026)
    assert result.risk_score is not None
    assert result.provisional is True
    assert "data_sensitivity" in result.missing_inputs
    assert "confidentiality_years" in result.missing_inputs
    assert "exposure" in result.missing_inputs
    assert "system_criticality" in result.missing_inputs
    assert "migration_years" in result.missing_inputs
    assert "threat_horizon_year" in result.missing_inputs
    assert all(f.basis == "assumed" for f in result.factors if f.factor != "quantum_vulnerability")


def test_missing_mosca_inputs_use_and_record_policy_defaults():
    finding = make_finding("RSA", role=CryptoRole.KEY_ESTABLISHMENT)
    context = complete_context(migration_years=None, threat_horizon_year=None)
    result = assess_finding(finding, context, assessment_year=2026)
    assert "migration_years" in result.missing_inputs
    assert "threat_horizon_year" in result.missing_inputs
    assert any("assumes 3 year(s)" in item for item in result.explanation)
    assert any("assumes 2035" in item for item in result.explanation)


def test_unknown_aes_key_size_uses_explicit_aes128_assumption():
    finding = make_finding("AES", role=CryptoRole.SYMMETRIC_ENCRYPTION)
    profile = quantum_profile(finding)
    result = assess_finding(finding, complete_context())
    qv = next(f for f in result.factors if f.factor == "quantum_vulnerability")
    assert profile is not None and profile.assumed is True
    assert qv.score == 3
    assert qv.assumed is True
    assert "key_size" in result.missing_inputs
    assert result.provisional is True
    assert any("assumes AES-128" in item for item in result.explanation)


def test_aes256_maps_to_quantum_safe_tier():
    finding = make_finding("AES", role=CryptoRole.SYMMETRIC_ENCRYPTION, variant="AES-256", key_size=256)
    profile = quantum_profile(finding)
    assert profile is not None
    assert profile.tier == "quantum-safe"
    assert profile.score == 0
    assert profile.assumed is False


def test_signature_does_not_require_confidentiality_lifetime_input():
    finding = make_finding("ECDSA", role=CryptoRole.SIGNATURE)
    result = assess_finding(finding, ProjectContext(data_sensitivity=3, exposure=2, system_criticality=4))
    assert "confidentiality_years" not in result.missing_inputs
    assert result.risk_kind == RiskKind.SIGNATURE_TRANSITION
