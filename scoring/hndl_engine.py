"""Role-aware, explainable HNDL risk assessment for QuantumShield.

The engine consumes the normalized findings produced by discovery. It never
scans files and never mutates the CycloneDX CBOM.
"""

from __future__ import annotations

from datetime import date

from common.models import (
    AssetContext,
    Confidence,
    CryptoFinding,
    CryptoRole,
    FactorScore,
    FindingStatus,
    ProjectContext,
    RiskAssessment,
    RiskKind,
    RiskLevel,
    ScanResult,
)
from scoring.policy import (
    CLASSICAL_WEAKNESS_WEIGHTS,
    CLASSICALLY_WEAK_HASHES,
    CONFIDENTIALITY_WEIGHTS,
    DEFAULT_MIGRATION_YEARS,
    DEFAULT_THREAT_HORIZON_YEAR,
    MISSING_CONTEXT_SCORE,
    POLICY_VERSION,
    SHOR_VULNERABLE_FAMILIES,
    SIGNATURE_TRANSITION_WEIGHTS,
    confidentiality_lifetime_score,
    quantum_profile,
    risk_floor_for_level,
    risk_level_for_score,
)


def _add_missing(missing: list[str], field: str) -> None:
    if field not in missing:
        missing.append(field)


def _get_context_value_with_source(
    *,
    field_name: str,
    finding: CryptoFinding,
    asset_context: AssetContext | None,
    project_context: ProjectContext,
) -> tuple[int | float | None, str]:
    """Get context value with explicit precedence and source tracking.
    
    Precedence: finding override (future) > asset context > project context > None (policy default)
    Returns: (value, source) where source is one of:
        "asset_context", "project_context", "policy_default"
    """
    # Check asset-level context first
    if asset_context is not None:
        asset_value = getattr(asset_context, field_name, None)
        if asset_value is not None:
            return asset_value, "asset_context"
    
    # Fall through to project-level context
    project_value = getattr(project_context, field_name, None)
    if project_value is not None:
        return project_value, "project_context"
    
    # No value at any level
    return None, "policy_default"


def _context_factor(
    *,
    name: str,
    value: int | float | None,
    weight: float,
    missing: list[str],
    explanation: list[str],
    context_source: str = "policy_default",
) -> FactorScore:
    if value is None:
        _add_missing(missing, name)
        explanation.append(
            f"{name} was not supplied; the policy uses the provisional default score {MISSING_CONTEXT_SCORE:g}/5."
        )
        score = MISSING_CONTEXT_SCORE
        basis = "assumed"
        assumed = True
    else:
        score = float(value)
        basis = "supplied" if context_source != "policy_default" else "assumed"
        assumed = (context_source == "policy_default")
    return FactorScore(
        factor=name,
        score=score,
        weight=weight,
        contribution=round(score / 5.0 * weight * 100.0, 4),
        basis=basis,
        assumed=assumed,
        context_source=context_source,
    )


def _quantum_factor(finding: CryptoFinding, weight: float, explanation: list[str]) -> FactorScore:
    profile = quantum_profile(finding)
    # Called only after an algorithm has been checked as scoreable.
    assert profile is not None and profile.score is not None
    explanation.append(profile.rationale)
    explanation.append(f"Quantum-vulnerability factor: {profile.score:g}/5 ({profile.tier}).")
    if profile.assumed:
        explanation.append("This factor uses a documented conservative assumption.")
    return FactorScore(
        factor="quantum_vulnerability",
        score=profile.score,
        weight=weight,
        contribution=round(profile.score / 5.0 * weight * 100.0, 4),
        basis="assumed" if profile.assumed else "observed",
        assumed=profile.assumed,
        context_source="observed",  # Quantum vulnerability comes from algorithm detection
    )


def _classical_weakness_factor(finding: CryptoFinding, weight: float, explanation: list[str]) -> FactorScore:
    """Classical cryptographic weakness factor (independent of quantum computing)."""
    algorithm = finding.algorithm.strip().upper().replace("_", "-")
    
    # High vulnerability for known-broken algorithms
    if algorithm in CLASSICALLY_WEAK_HASHES:
        score = 5.0
        explanation.append(f"{algorithm} is classically cryptographically broken.")
    else:
        # Other classical weaknesses could be added here
        score = 4.0
        explanation.append(f"{algorithm} has classical cryptographic weaknesses.")
    
    return FactorScore(
        factor="classical_vulnerability",
        score=score,
        weight=weight,
        contribution=round(score / 5.0 * weight * 100.0, 4),
        basis="observed",
        assumed=False,
        context_source="observed",
    )


def _is_asymmetric_family(finding: CryptoFinding) -> bool:
    algorithm = finding.algorithm.strip().upper().replace("_", "-")
    if algorithm in SHOR_VULNERABLE_FAMILIES:
        return True
    if finding.curve:
        return algorithm == "EC"
    variant = (finding.variant or "").upper()
    return variant.startswith(("RSA-", "ECDSA-", "ECDH-", "DH-", "DSA-"))


def _empty_assessment(
    finding: CryptoFinding,
    kind: RiskKind,
    explanation: list[str],
    *,
    missing: list[str] | None = None,
    provisional: bool = False,
) -> RiskAssessment:
    return RiskAssessment(
        finding_id=finding.finding_id or "",
        risk_kind=kind,
        risk_score=None,
        risk_level=None,
        factors=[],
        escalations=[],
        explanation=explanation,
        missing_inputs=missing or [],
        provisional=provisional,
        confidence=finding.confidence,
        policy_version=POLICY_VERSION,
    )


def assess_finding(
    finding: CryptoFinding,
    context: ProjectContext,
    *,
    assessment_year: int | None = None,
) -> RiskAssessment:
    """Assess one finding; potential and low-confidence evidence stays visible.

    An undetermined asymmetric key is conservatively treated as a possible
    confidentiality/key-establishment risk and the resulting assessment is
    provisional. Unknown algorithm families and unreadable artifacts are not
    scored because no defensible quantum-vulnerability factor can be assigned.
    
    Uses explicit context precedence: asset context > project context > policy default.
    Context provenance is tracked for transparency.
    """

    explanation: list[str] = []
    missing: list[str] = []
    context_provenance: dict[str, str] = {}
    profile = quantum_profile(finding)
    algorithm = finding.algorithm.strip().upper().replace("_", "-")
    
    # Get asset-specific context if available
    asset_context = context.get_asset_context(finding)
    if asset_context:
        explanation.append(f"Using asset-specific context for asset '{asset_context.asset_id}'.")

    if finding.status == FindingStatus.UNABLE_TO_ANALYZE:
        explanation.append(
            "This material could not be analyzed; no risk score is assigned until it can be examined."
        )
        if finding.evidence_gap_reason:
            explanation.append(f"Analysis gap: {finding.evidence_gap_reason}")
        return _empty_assessment(
            finding, RiskKind.NOT_ASSESSED, explanation, provisional=True
        )

    # Classical cryptographic weakness (e.g., MD5, SHA-1): not a quantum issue
    if algorithm in CLASSICALLY_WEAK_HASHES and finding.role == CryptoRole.HASH:
        explanation.append(
            f"{algorithm} is flagged as a classical cryptographic weakness, independent of quantum computing."
        )
        explanation.append("This is assessed as classical-weakness risk, not HNDL or quantum-related risk.")
        weights = CLASSICAL_WEAKNESS_WEIGHTS
        risk_kind = RiskKind.CLASSICAL_WEAKNESS
        
        factor_scores: list[FactorScore] = []
        
        # Classical vulnerability factor
        factor_scores.append(_classical_weakness_factor(finding, weights["classical_vulnerability"], explanation))
        
        # Context factors with provenance
        data_sens_val, data_sens_src = _get_context_value_with_source(
            field_name="data_sensitivity",
            finding=finding,
            asset_context=asset_context,
            project_context=context,
        )
        context_provenance["data_sensitivity"] = data_sens_src
        factor_scores.append(
            _context_factor(
                name="data_sensitivity",
                value=data_sens_val,
                weight=weights["data_sensitivity"],
                missing=missing,
                explanation=explanation,
                context_source=data_sens_src,
            )
        )
        
        exposure_val, exposure_src = _get_context_value_with_source(
            field_name="exposure",
            finding=finding,
            asset_context=asset_context,
            project_context=context,
        )
        context_provenance["exposure"] = exposure_src
        factor_scores.append(
            _context_factor(
                name="exposure",
                value=exposure_val,
                weight=weights["exposure"],
                missing=missing,
                explanation=explanation,
                context_source=exposure_src,
            )
        )
        
        crit_val, crit_src = _get_context_value_with_source(
            field_name="system_criticality",
            finding=finding,
            asset_context=asset_context,
            project_context=context,
        )
        context_provenance["system_criticality"] = crit_src
        factor_scores.append(
            _context_factor(
                name="system_criticality",
                value=crit_val,
                weight=weights["system_criticality"],
                missing=missing,
                explanation=explanation,
                context_source=crit_src,
            )
        )
        
        baseline_score = round(sum(f.contribution for f in factor_scores), 2)
        risk_score = baseline_score
        risk_level = risk_level_for_score(risk_score)
        explanation.append(
            f"The weighted base score is {baseline_score:.2f}/100; the reported score is {risk_score:.2f}/100 ({risk_level.value})."
        )
        
        provisional = bool(missing) or finding.status == FindingStatus.POTENTIAL or finding.confidence in (Confidence.LOW, Confidence.UNKNOWN)
        
        return RiskAssessment(
            finding_id=finding.finding_id or "",
            risk_kind=risk_kind,
            risk_score=risk_score,
            risk_level=risk_level,
            factors=factor_scores,
            escalations=[],
            explanation=explanation,
            missing_inputs=sorted(missing),
            provisional=provisional,
            confidence=finding.confidence,
            policy_version=POLICY_VERSION,
            context_provenance=context_provenance,
        )

    # Strong hashes (not classically weak): not HNDL-applicable
    if algorithm in {"SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512", "SHA-3", "SHA3"} and finding.role == CryptoRole.HASH:
        explanation.append(
            "Hash findings are marked not HNDL-applicable by policy; review their separate integrity and collision-resistance properties where needed."
        )
        return _empty_assessment(finding, RiskKind.NOT_HNDL_APPLICABLE, explanation)

    if finding.role == CryptoRole.MAC:
        explanation.append(
            "Message-authentication-code findings are outside the current HNDL confidentiality score; assess the construction and key strength separately."
        )
        return _empty_assessment(finding, RiskKind.NOT_HNDL_APPLICABLE, explanation)

    if algorithm in {"UNKNOWN", "", "UNIDENTIFIED CRYPTOGRAPHIC MATERIAL"} or algorithm.startswith("LIBRARY:") or profile is None or profile.score is None:
        explanation.append(
            "The algorithm family or its quantum-vulnerability tier is not sufficiently identified for a defensible risk score."
        )
        return _empty_assessment(
            finding, RiskKind.NOT_ASSESSED, explanation, provisional=True
        )

    conservative_role_assumption = False
    if finding.role == CryptoRole.SIGNATURE:
        risk_kind = RiskKind.SIGNATURE_TRANSITION
        weights = SIGNATURE_TRANSITION_WEIGHTS
        explanation.append("This is assessed as signature-transition priority risk, not HNDL confidentiality risk.")
    elif finding.role in (CryptoRole.KEY_ESTABLISHMENT, CryptoRole.SYMMETRIC_ENCRYPTION):
        risk_kind = RiskKind.HNDL_CONFIDENTIALITY
        weights = CONFIDENTIALITY_WEIGHTS
    elif finding.role == CryptoRole.UNDETERMINED and _is_asymmetric_family(finding):
        risk_kind = RiskKind.HNDL_CONFIDENTIALITY
        weights = CONFIDENTIALITY_WEIGHTS
        conservative_role_assumption = True
        explanation.append(
            "The cryptographic role is undetermined. Policy conservatively assesses this asymmetric asset as a potential confidentiality/key-establishment risk; validate its actual use."
        )
    else:
        explanation.append(
            f"Role '{finding.role.value}' is not covered by the current HNDL/signature-transition scoring policy."
        )
        return _empty_assessment(
            finding, RiskKind.NOT_ASSESSED, explanation, provisional=True
        )

    if profile.assumed:
        _add_missing(missing, "key_size")
        explanation.append("The algorithm parameter needed for a more precise quantum factor was not resolved.")

    factor_scores: list[FactorScore] = []
    quantum_weight = weights["quantum_vulnerability"]
    factor_scores.append(_quantum_factor(finding, quantum_weight, explanation))

    # Context factors with asset-level precedence and provenance tracking
    data_sens_val, data_sens_src = _get_context_value_with_source(
        field_name="data_sensitivity",
        finding=finding,
        asset_context=asset_context,
        project_context=context,
    )
    context_provenance["data_sensitivity"] = data_sens_src
    factor_scores.append(
        _context_factor(
            name="data_sensitivity",
            value=data_sens_val,
            weight=weights["data_sensitivity"],
            missing=missing,
            explanation=explanation,
            context_source=data_sens_src,
        )
    )

    if risk_kind == RiskKind.HNDL_CONFIDENTIALITY:
        lifetime_weight = weights["confidentiality_lifetime"]
        lifetime_val, lifetime_src = _get_context_value_with_source(
            field_name="confidentiality_years",
            finding=finding,
            asset_context=asset_context,
            project_context=context,
        )
        context_provenance["confidentiality_years"] = lifetime_src
        
        if lifetime_val is None:
            lifetime_score = MISSING_CONTEXT_SCORE
            _add_missing(missing, "confidentiality_years")
            explanation.append(
                f"confidentiality_years was not supplied; the policy uses the provisional default score {MISSING_CONTEXT_SCORE:g}/5."
            )
            lifetime_basis, lifetime_assumed = "assumed", True
        else:
            lifetime_score = confidentiality_lifetime_score(lifetime_val)
            lifetime_basis = "supplied" if lifetime_src != "policy_default" else "assumed"
            lifetime_assumed = (lifetime_src == "policy_default")
            explanation.append(
                f"A confidentiality lifetime of {lifetime_val:g} year(s) maps to {lifetime_score:g}/5 under the v{POLICY_VERSION} lifetime bands."
            )
        factor_scores.append(
            FactorScore(
                factor="confidentiality_lifetime",
                score=lifetime_score,
                weight=lifetime_weight,
                contribution=round(lifetime_score / 5.0 * lifetime_weight * 100.0, 4),
                basis=lifetime_basis,
                assumed=lifetime_assumed,
                context_source=lifetime_src,
            )
        )

    exposure_val, exposure_src = _get_context_value_with_source(
        field_name="exposure",
        finding=finding,
        asset_context=asset_context,
        project_context=context,
    )
    context_provenance["exposure"] = exposure_src
    factor_scores.append(
        _context_factor(
            name="exposure",
            value=exposure_val,
            weight=weights["exposure"],
            missing=missing,
            explanation=explanation,
            context_source=exposure_src,
        )
    )
    
    crit_val, crit_src = _get_context_value_with_source(
        field_name="system_criticality",
        finding=finding,
        asset_context=asset_context,
        project_context=context,
    )
    context_provenance["system_criticality"] = crit_src
    factor_scores.append(
        _context_factor(
            name="system_criticality",
            value=crit_val,
            weight=weights["system_criticality"],
            missing=missing,
            explanation=explanation,
            context_source=crit_src,
        )
    )

    baseline_score = round(sum(f.contribution for f in factor_scores), 2)
    risk_score = baseline_score
    escalations: list[str] = []

    # Mosca timing applies only to Shor-vulnerable confidentiality roles. Use
    # a duration remaining until the horizon (year - assessment year), rather
    # than comparing years directly to a calendar year.
    if risk_kind == RiskKind.HNDL_CONFIDENTIALITY and profile.tier == "shor-vulnerable":
        # Get migration_years and threat_horizon_year with asset precedence
        migration_val, migration_src = _get_context_value_with_source(
            field_name="migration_years",
            finding=finding,
            asset_context=asset_context,
            project_context=context,
        )
        context_provenance["migration_years"] = migration_src
        
        if migration_val is None:
            migration_years = DEFAULT_MIGRATION_YEARS
            _add_missing(missing, "migration_years")
            explanation.append(
                f"migration_years was not supplied; Mosca timing assumes {DEFAULT_MIGRATION_YEARS:g} year(s)."
            )
        else:
            migration_years = migration_val
        
        horizon_val, horizon_src = _get_context_value_with_source(
            field_name="threat_horizon_year",
            finding=finding,
            asset_context=asset_context,
            project_context=context,
        )
        context_provenance["threat_horizon_year"] = horizon_src
        
        if horizon_val is None:
            threat_horizon_year = DEFAULT_THREAT_HORIZON_YEAR
            _add_missing(missing, "threat_horizon_year")
            explanation.append(
                f"threat_horizon_year was not supplied; policy assumes {DEFAULT_THREAT_HORIZON_YEAR}."
            )
        else:
            threat_horizon_year = int(horizon_val)

        if lifetime_val is not None:
            current = assessment_year if assessment_year is not None else date.today().year
            years_to_horizon = max(0, threat_horizon_year - current)
            total_required = lifetime_val + migration_years
            if total_required > years_to_horizon:
                sensitivity = data_sens_val if data_sens_val is not None else MISSING_CONTEXT_SCORE
                if sensitivity >= 4:
                    floor = RiskLevel.CRITICAL
                    reason = (
                        f"Mosca escalation: confidentiality lifetime ({lifetime_val:g} years) + "
                        f"migration time ({migration_years:g} years) exceeds {years_to_horizon:g} year(s) until "
                        f"the {threat_horizon_year} threat horizon; data sensitivity is at least 4/5."
                    )
                else:
                    floor = RiskLevel.VERY_HIGH
                    reason = (
                        f"Mosca escalation: confidentiality lifetime ({lifetime_val:g} years) + "
                        f"migration time ({migration_years:g} years) exceeds {years_to_horizon:g} year(s) until "
                        f"the {threat_horizon_year} threat horizon."
                    )
                escalations.append(reason)
                risk_score = max(risk_score, risk_floor_for_level(floor))
                explanation.append(reason)
        else:
            explanation.append(
                "Mosca timing was not evaluated because confidentiality_years was not supplied."
            )

    risk_level = risk_level_for_score(risk_score)
    explanation.append(
        f"The weighted base score is {baseline_score:.2f}/100; the reported score is {risk_score:.2f}/100 ({risk_level.value})."
    )

    if finding.status == FindingStatus.POTENTIAL:
        explanation.append("The underlying discovery is potential, not confirmed; validate the evidence before acting on this score.")
    if finding.confidence in (Confidence.LOW, Confidence.UNKNOWN):
        explanation.append(f"Finding confidence is {finding.confidence.value}; the score should be treated cautiously.")

    if conservative_role_assumption:
        _add_missing(missing, "cryptographic_role")
    provisional = bool(missing) or conservative_role_assumption or finding.status == FindingStatus.POTENTIAL or finding.confidence in (Confidence.LOW, Confidence.UNKNOWN)

    # Deterministic order makes JSON diffs and tests stable.
    missing = sorted(missing)
    return RiskAssessment(
        finding_id=finding.finding_id or "",
        risk_kind=risk_kind,
        risk_score=risk_score,
        risk_level=risk_level,
        factors=factor_scores,
        escalations=escalations,
        explanation=explanation,
        missing_inputs=missing,
        provisional=provisional,
        confidence=finding.confidence,
        policy_version=POLICY_VERSION,
        context_provenance=context_provenance,
    )


def assess_scan(
    scan_result: ScanResult,
    context: ProjectContext,
    *,
    assessment_year: int | None = None,
) -> list[RiskAssessment]:
    """Generate one role-aware risk result for every discovered finding."""
    return [
        assess_finding(finding, context, assessment_year=assessment_year)
        for finding in scan_result.findings
    ]
