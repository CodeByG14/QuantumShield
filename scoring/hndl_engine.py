"""Role-aware, explainable HNDL risk assessment for QuantumShield.

The engine consumes the normalized findings produced by discovery. It never
scans files and never mutates the CycloneDX CBOM.
"""

from __future__ import annotations

from datetime import date

from common.models import (
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
    AUTHENTICITY_WEIGHTS,
    CLASSICALLY_WEAK_HASHES,
    CONFIDENTIALITY_WEIGHTS,
    DEFAULT_MIGRATION_YEARS,
    DEFAULT_THREAT_HORIZON_YEAR,
    MISSING_CONTEXT_SCORE,
    POLICY_VERSION,
    SHOR_VULNERABLE_FAMILIES,
    confidentiality_lifetime_score,
    quantum_profile,
    risk_floor_for_level,
    risk_level_for_score,
)


def _add_missing(missing: list[str], field: str) -> None:
    if field not in missing:
        missing.append(field)


def _context_factor(
    *,
    name: str,
    value: int | float | None,
    weight: float,
    missing: list[str],
    explanation: list[str],
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
        basis = "supplied"
        assumed = False
    return FactorScore(
        factor=name,
        score=score,
        weight=weight,
        contribution=round(score / 5.0 * weight * 100.0, 4),
        basis=basis,
        assumed=assumed,
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
    """

    explanation: list[str] = []
    missing: list[str] = []
    profile = quantum_profile(finding)
    algorithm = finding.algorithm.strip().upper().replace("_", "-")

    if finding.status == FindingStatus.UNABLE_TO_ANALYZE:
        explanation.append(
            "This material could not be analyzed; no risk score is assigned until it can be examined."
        )
        if finding.evidence_gap_reason:
            explanation.append(f"Analysis gap: {finding.evidence_gap_reason}")
        return _empty_assessment(
            finding, RiskKind.NOT_ASSESSED, explanation, provisional=True
        )

    if algorithm in {"MD5", "SHA-1", "SHA1", "SHA-256", "SHA256", "SHA-384", "SHA384", "SHA-512", "SHA512", "SHA-3", "SHA3"} and finding.role == CryptoRole.HASH:
        if algorithm in CLASSICALLY_WEAK_HASHES:
            explanation.append(
                f"{algorithm} is flagged as classically weak regardless of quantum computing; this report does not mislabel that as HNDL risk."
            )
        else:
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
        risk_kind = RiskKind.AUTHENTICITY
        weights = AUTHENTICITY_WEIGHTS
        explanation.append("This is assessed as authenticity risk, not HNDL confidentiality risk.")
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
            f"Role '{finding.role.value}' is not covered by the current HNDL/authenticity scoring policy."
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

    factor_scores.append(
        _context_factor(
            name="data_sensitivity",
            value=context.data_sensitivity,
            weight=weights["data_sensitivity"],
            missing=missing,
            explanation=explanation,
        )
    )

    if risk_kind == RiskKind.HNDL_CONFIDENTIALITY:
        lifetime_weight = weights["confidentiality_lifetime"]
        if context.confidentiality_years is None:
            lifetime_score = MISSING_CONTEXT_SCORE
            _add_missing(missing, "confidentiality_years")
            explanation.append(
                f"confidentiality_years was not supplied; the policy uses the provisional default score {MISSING_CONTEXT_SCORE:g}/5."
            )
            lifetime_basis, lifetime_assumed = "assumed", True
        else:
            lifetime_score = confidentiality_lifetime_score(context.confidentiality_years)
            lifetime_basis, lifetime_assumed = "supplied", False
            explanation.append(
                f"A confidentiality lifetime of {context.confidentiality_years:g} year(s) maps to {lifetime_score:g}/5 under the v{POLICY_VERSION} lifetime bands."
            )
        factor_scores.append(
            FactorScore(
                factor="confidentiality_lifetime",
                score=lifetime_score,
                weight=lifetime_weight,
                contribution=round(lifetime_score / 5.0 * lifetime_weight * 100.0, 4),
                basis=lifetime_basis,
                assumed=lifetime_assumed,
            )
        )

    factor_scores.append(
        _context_factor(
            name="exposure",
            value=context.exposure,
            weight=weights["exposure"],
            missing=missing,
            explanation=explanation,
        )
    )
    factor_scores.append(
        _context_factor(
            name="system_criticality",
            value=context.system_criticality,
            weight=weights["system_criticality"],
            missing=missing,
            explanation=explanation,
        )
    )

    baseline_score = round(sum(f.contribution for f in factor_scores), 2)
    risk_score = baseline_score
    escalations: list[str] = []

    # Mosca timing applies only to Shor-vulnerable confidentiality roles. Use
    # a duration remaining until the horizon (year - assessment year), rather
    # than comparing years directly to a calendar year.
    if risk_kind == RiskKind.HNDL_CONFIDENTIALITY and profile.tier == "shor-vulnerable":
        # These are policy defaults for Mosca timing. List the fields as missing
        # even when confidentiality lifetime is absent and escalation cannot run.
        if context.migration_years is None:
            migration_years = DEFAULT_MIGRATION_YEARS
            _add_missing(missing, "migration_years")
            explanation.append(
                f"migration_years was not supplied; Mosca timing assumes {DEFAULT_MIGRATION_YEARS:g} year(s)."
            )
        else:
            migration_years = context.migration_years
        if context.threat_horizon_year is None:
            threat_horizon_year = DEFAULT_THREAT_HORIZON_YEAR
            _add_missing(missing, "threat_horizon_year")
            explanation.append(
                f"threat_horizon_year was not supplied; policy assumes {DEFAULT_THREAT_HORIZON_YEAR}."
            )
        else:
            threat_horizon_year = context.threat_horizon_year

        if context.confidentiality_years is not None:
            current = assessment_year if assessment_year is not None else date.today().year
            years_to_horizon = max(0, threat_horizon_year - current)
            total_required = context.confidentiality_years + migration_years
            if total_required > years_to_horizon:
                sensitivity = (
                    context.data_sensitivity
                    if context.data_sensitivity is not None
                    else MISSING_CONTEXT_SCORE
                )
                if sensitivity >= 4:
                    floor = RiskLevel.CRITICAL
                    reason = (
                        f"Mosca escalation: confidentiality lifetime ({context.confidentiality_years:g} years) + "
                        f"migration time ({migration_years:g} years) exceeds {years_to_horizon:g} year(s) until "
                        f"the {threat_horizon_year} threat horizon; data sensitivity is at least 4/5."
                    )
                else:
                    floor = RiskLevel.VERY_HIGH
                    reason = (
                        f"Mosca escalation: confidentiality lifetime ({context.confidentiality_years:g} years) + "
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
