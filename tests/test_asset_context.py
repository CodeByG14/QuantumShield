"""Tests for asset-level context overrides and provenance tracking."""

import pytest

from common.models import (
    AssetContext,
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
    ProjectContext,
    RiskKind,
)
from scoring.hndl_engine import assess_finding


def make_finding(
    algorithm="RSA",
    *,
    role=CryptoRole.KEY_ESTABLISHMENT,
    status=FindingStatus.CONFIRMED,
    confidence=Confidence.HIGH,
    variant=None,
    key_size=None,
    file_path="src/example.py",
    finding_id="CRYPTO-001",
):
    return CryptoFinding(
        finding_id=finding_id,
        algorithm=algorithm,
        variant=variant,
        key_size=key_size,
        role=role,
        status=status,
        evidence=[
            Evidence(
                finding_id=finding_id,
                file_path=file_path,
                line_start=12,
                evidence_type=EvidenceType.API_CALL,
                detection_method=DetectionMethod.REGEX,
                rule_id="TEST-001",
                excerpt="test crypto call",
                confidence=confidence,
            )
        ],
    )


def test_asset_context_overrides_project_context():
    """Asset-specific context should take precedence over project-level context."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        confidentiality_years=5,
        exposure=2,
        system_criticality=2,
    )
    
    # Add asset-specific context with higher sensitivity
    asset = AssetContext(
        asset_id="src/example.py",
        data_sensitivity=5,
        confidentiality_years=20,
    )
    project.asset_contexts = [asset]
    
    finding = make_finding("RSA", role=CryptoRole.KEY_ESTABLISHMENT, file_path="src/example.py")
    result = assess_finding(finding, project, assessment_year=2026)
    
    # Should use asset-level values, not project-level
    data_sens_factor = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data_sens_factor.score == 5.0
    assert data_sens_factor.context_source == "asset_context"
    
    lifetime_factor = next(f for f in result.factors if f.factor == "confidentiality_lifetime")
    assert lifetime_factor.score == 5.0  # 20 years maps to 5
    assert lifetime_factor.context_source == "asset_context"
    
    # exposure and system_criticality should fall through to project
    exposure_factor = next(f for f in result.factors if f.factor == "exposure")
    assert exposure_factor.score == 2.0
    assert exposure_factor.context_source == "project_context"


def test_context_provenance_tracking():
    """All context values should have provenance tracked."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=3,
        confidentiality_years=10,
        exposure=3,
        system_criticality=4,
    )
    
    finding = make_finding("RSA", role=CryptoRole.KEY_ESTABLISHMENT)
    result = assess_finding(finding, project, assessment_year=2026)
    
    # Check provenance is tracked for all context factors
    assert "data_sensitivity" in result.context_provenance
    assert result.context_provenance["data_sensitivity"] == "project_context"
    
    assert "confidentiality_years" in result.context_provenance
    assert result.context_provenance["confidentiality_years"] == "project_context"
    
    assert "exposure" in result.context_provenance
    assert result.context_provenance["exposure"] == "project_context"
    
    assert "system_criticality" in result.context_provenance
    assert result.context_provenance["system_criticality"] == "project_context"


def test_missing_context_shows_policy_default_provenance():
    """Missing context values should show policy_default as source."""
    project = ProjectContext(project_name="test-project")
    
    finding = make_finding("RSA", role=CryptoRole.KEY_ESTABLISHMENT)
    result = assess_finding(finding, project, assessment_year=2026)
    
    # All context factors should show policy_default as source
    data_sens_factor = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data_sens_factor.context_source == "policy_default"
    assert data_sens_factor.assumed is True
    
    assert result.context_provenance["data_sensitivity"] == "policy_default"
    assert result.provisional is True


def test_asset_context_matched_by_finding_id():
    """Asset context can be matched by exact finding_id."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        exposure=2,
        system_criticality=2,
    )
    
    # Add asset context for specific finding ID
    asset = AssetContext(
        asset_id="CRYPTO-001",
        data_sensitivity=5,
    )
    project.asset_contexts = [asset]
    
    finding = make_finding("RSA", role=CryptoRole.SIGNATURE, finding_id="CRYPTO-001")
    result = assess_finding(finding, project, assessment_year=2026)
    
    # Should use asset-level data_sensitivity
    data_sens_factor = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data_sens_factor.score == 5.0
    assert data_sens_factor.context_source == "asset_context"
    
    # Others fall through to project
    exposure_factor = next(f for f in result.factors if f.factor == "exposure")
    assert exposure_factor.context_source == "project_context"


def test_asset_context_matched_by_file_path():
    """Asset context can be matched by file path."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        exposure=2,
        system_criticality=2,
    )
    
    # Add asset context for file path
    asset = AssetContext(
        asset_id="src/critical/payment.py",
        data_sensitivity=5,
        system_criticality=5,
    )
    project.asset_contexts = [asset]
    
    finding = make_finding(
        "RSA",
        role=CryptoRole.KEY_ESTABLISHMENT,
        file_path="src/critical/payment.py",
        finding_id="CRYPTO-005"
    )
    result = assess_finding(finding, project, assessment_year=2026)
    
    data_sens_factor = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data_sens_factor.score == 5.0
    assert data_sens_factor.context_source == "asset_context"
    
    crit_factor = next(f for f in result.factors if f.factor == "system_criticality")
    assert crit_factor.score == 5.0
    assert crit_factor.context_source == "asset_context"


def test_multiple_asset_contexts_first_match_wins():
    """When multiple asset contexts could match, first match by finding_id wins."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=1,
        exposure=1,
        system_criticality=1,
    )
    
    # Multiple asset contexts
    asset1 = AssetContext(
        asset_id="CRYPTO-002",
        data_sensitivity=5,
    )
    asset2 = AssetContext(
        asset_id="src/example.py",
        data_sensitivity=3,
    )
    project.asset_contexts = [asset1, asset2]
    
    # Finding matches both (by ID and by file path)
    finding = make_finding("RSA", finding_id="CRYPTO-002", file_path="src/example.py")
    result = assess_finding(finding, project, assessment_year=2026)
    
    # Should use asset1 (exact finding_id match takes precedence)
    data_sens_factor = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data_sens_factor.score == 5.0


def test_asset_context_for_signature_no_lifetime_needed():
    """Signature findings don't need confidentiality_years even with asset context."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        exposure=2,
        system_criticality=2,
    )
    
    asset = AssetContext(
        asset_id="src/auth.py",
        data_sensitivity=4,
        # No confidentiality_years specified
    )
    project.asset_contexts = [asset]
    
    finding = make_finding("ECDSA", role=CryptoRole.SIGNATURE, file_path="src/auth.py")
    result = assess_finding(finding, project)
    
    assert result.risk_kind == RiskKind.SIGNATURE_TRANSITION
    assert "confidentiality_years" not in result.missing_inputs
    assert "confidentiality_lifetime" not in [f.factor for f in result.factors]


def test_asset_context_enables_mosca_escalation():
    """Asset-specific long confidentiality lifetime can trigger Mosca escalation."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        confidentiality_years=3,  # Short project-level lifetime
        exposure=2,
        system_criticality=2,
        migration_years=3,
        threat_horizon_year=2028,
    )
    
    # Critical asset with long confidentiality requirement
    asset = AssetContext(
        asset_id="src/archive.py",
        data_sensitivity=5,
        confidentiality_years=20,  # Long lifetime for this asset
    )
    project.asset_contexts = [asset]
    
    finding = make_finding(
        "RSA",
        role=CryptoRole.KEY_ESTABLISHMENT,
        file_path="src/archive.py"
    )
    result = assess_finding(finding, project, assessment_year=2026)
    
    # Should trigger Mosca escalation due to asset-level long lifetime
    assert result.escalations
    assert any("Mosca escalation" in e for e in result.escalations)
    assert result.risk_level.value in ("very-high", "critical")


def test_different_assets_get_different_scores():
    """Two identical findings in different files should get different scores with asset context."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        confidentiality_years=5,
        exposure=2,
        system_criticality=2,
    )
    
    # Critical payment processing
    critical_asset = AssetContext(
        asset_id="src/payment.py",
        data_sensitivity=5,
        confidentiality_years=15,
        exposure=5,
        system_criticality=5,
    )
    
    # Non-critical test code
    test_asset = AssetContext(
        asset_id="tests/test_crypto.py",
        data_sensitivity=1,
        confidentiality_years=1,
        exposure=1,
        system_criticality=1,
    )
    
    project.asset_contexts = [critical_asset, test_asset]
    
    # Same RSA finding in both files
    critical_finding = make_finding(
        "RSA",
        role=CryptoRole.KEY_ESTABLISHMENT,
        file_path="src/payment.py",
        finding_id="CRYPTO-001"
    )
    test_finding = make_finding(
        "RSA",
        role=CryptoRole.KEY_ESTABLISHMENT,
        file_path="tests/test_crypto.py",
        finding_id="CRYPTO-002"
    )
    
    critical_result = assess_finding(critical_finding, project, assessment_year=2026)
    test_result = assess_finding(test_finding, project, assessment_year=2026)
    
    # Critical finding should have much higher score
    assert critical_result.risk_score is not None
    assert test_result.risk_score is not None
    assert critical_result.risk_score > test_result.risk_score
    
    # Verify provenance shows asset_context was used
    assert critical_result.context_provenance["data_sensitivity"] == "asset_context"
    assert test_result.context_provenance["data_sensitivity"] == "asset_context"


def test_classical_weakness_uses_asset_context():
    """Classical weakness risk category should also support asset context."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=1,
        exposure=1,
        system_criticality=1,
    )
    
    asset = AssetContext(
        asset_id="src/legacy.py",
        data_sensitivity=4,
        exposure=5,
    )
    project.asset_contexts = [asset]
    
    finding = make_finding("MD5", role=CryptoRole.HASH, file_path="src/legacy.py")
    result = assess_finding(finding, project)
    
    assert result.risk_kind == RiskKind.CLASSICAL_WEAKNESS
    
    # Should use asset-level context
    data_sens_factor = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data_sens_factor.score == 4.0
    assert data_sens_factor.context_source == "asset_context"
    
    exposure_factor = next(f for f in result.factors if f.factor == "exposure")
    assert exposure_factor.score == 5.0
    assert exposure_factor.context_source == "asset_context"


def test_asset_context_partial_override():
    """Asset context can override only some fields, others fall through."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        confidentiality_years=5,
        exposure=3,
        system_criticality=2,
    )
    
    # Override only data_sensitivity
    asset = AssetContext(
        asset_id="CRYPTO-001",
        data_sensitivity=5,
        # exposure and system_criticality not specified
    )
    project.asset_contexts = [asset]
    
    finding = make_finding("RSA", finding_id="CRYPTO-001")
    result = assess_finding(finding, project, assessment_year=2026)
    
    # data_sensitivity from asset
    data_sens_factor = next(f for f in result.factors if f.factor == "data_sensitivity")
    assert data_sens_factor.score == 5.0
    assert data_sens_factor.context_source == "asset_context"
    
    # exposure from project (not overridden)
    exposure_factor = next(f for f in result.factors if f.factor == "exposure")
    assert exposure_factor.score == 3.0
    assert exposure_factor.context_source == "project_context"
    
    # system_criticality from project
    crit_factor = next(f for f in result.factors if f.factor == "system_criticality")
    assert crit_factor.score == 2.0
    assert crit_factor.context_source == "project_context"
    
    # confidentiality_years from project
    lifetime_factor = next(f for f in result.factors if f.factor == "confidentiality_lifetime")
    lifetime_score = lifetime_factor.score
    # 5 years maps to score 3.0
    assert lifetime_factor.context_source == "project_context"


def test_get_asset_context_no_match_returns_none():
    """get_asset_context should return None when no match found."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
    )
    
    asset = AssetContext(
        asset_id="src/other.py",
        data_sensitivity=5,
    )
    project.asset_contexts = [asset]
    
    finding = make_finding("RSA", file_path="src/example.py", finding_id="CRYPTO-001")
    
    # No match by finding_id or file path
    result = project.get_asset_context(finding)
    assert result is None


def test_explanation_mentions_asset_context_usage():
    """When asset context is used, explanation should mention it."""
    project = ProjectContext(
        project_name="test-project",
        data_sensitivity=2,
        exposure=2,
        system_criticality=2,
    )
    
    asset = AssetContext(
        asset_id="CRYPTO-001",
        data_sensitivity=5,
    )
    project.asset_contexts = [asset]
    
    finding = make_finding("RSA", finding_id="CRYPTO-001")
    result = assess_finding(finding, project, assessment_year=2026)
    
    # Explanation should mention asset-specific context
    explanation_text = " ".join(result.explanation)
    assert "asset-specific context" in explanation_text.lower()
