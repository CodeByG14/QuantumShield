"""Versioned, explainable risk policy for QuantumShield Week 5.

This module contains policy constants and deterministic mappings only. It does
not scan files or read project context. The score factors are 0..5 and weights
are normalized fractions which sum to 1.0.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from common.models import CryptoFinding, RiskLevel, Tier
from scoring.scoring_map import get_quantum_factor

POLICY_VERSION = "1.0"

# HNDL confidentiality risk: vulnerability + data/context impact.
CONFIDENTIALITY_WEIGHTS: Mapping[str, float] = {
    "quantum_vulnerability": 0.30,
    "data_sensitivity": 0.25,
    "confidentiality_lifetime": 0.20,
    "exposure": 0.15,
    "system_criticality": 0.10,
}

# Signature transition priority: authenticity/integrity concerns, not HNDL.
# Remove lifetime's 0.20 weight and renormalize the remaining weights to sum to 1.0.
SIGNATURE_TRANSITION_WEIGHTS: Mapping[str, float] = {
    "quantum_vulnerability": 0.375,
    "data_sensitivity": 0.3125,
    "exposure": 0.1875,
    "system_criticality": 0.125,
}

# Classical cryptographic weakness (e.g., MD5, broken ciphers): independent of quantum computing.
CLASSICAL_WEAKNESS_WEIGHTS: Mapping[str, float] = {
    "classical_vulnerability": 0.40,
    "data_sensitivity": 0.30,
    "exposure": 0.20,
    "system_criticality": 0.10,
}

# For backward compatibility during migration
AUTHENTICITY_WEIGHTS = SIGNATURE_TRANSITION_WEIGHTS

RISK_THRESHOLDS: tuple[tuple[float, RiskLevel], ...] = (
    (80.0, RiskLevel.CRITICAL),
    (60.0, RiskLevel.VERY_HIGH),
    (40.0, RiskLevel.HIGH),
    (20.0, RiskLevel.MODERATE),
    (0.0, RiskLevel.LOW),
)

MISSING_CONTEXT_SCORE = 3.0
DEFAULT_MIGRATION_YEARS = 3.0
DEFAULT_THREAT_HORIZON_YEAR = 2035

# The five-point quantum-vulnerability factor is a policy mapping from the
# Week 3 tier table. These are risk-engine scores, not NIST security categories.
# The composite score is a priority index, not a probability of successful attack.
TIER_TO_VULNERABILITY_SCORE: Mapping[str, float] = {
    Tier.SHOR_VULNERABLE.value: 5.0,
    Tier.GROVER_AFFECTED.value: 3.0,
    Tier.QUANTUM_SAFE.value: 0.0,
}

SHOR_VULNERABLE_FAMILIES = {
    "RSA", "DSA", "DH", "ECDH", "ECDSA", "EC", "ED25519", "ED448",
    "X25519", "X448",
}

CLASSICALLY_WEAK_HASHES = {"MD5", "SHA-1", "SHA1"}
KNOWN_UNKNOWN_NAMES = {"", "UNKNOWN", "UNIDENTIFIED CRYPTOGRAPHIC MATERIAL"}


@dataclass(frozen=True)
class QuantumProfile:
    """Policy interpretation of the detected algorithm for risk scoring."""

    score: float | None
    tier: str
    assumed: bool = False
    rationale: str = ""


def _normalise_algorithm(value: str | None) -> str:
    return (value or "").strip().upper().replace("_", "-")


def _aes_bits(finding: CryptoFinding) -> int | None:
    if finding.key_size:
        return finding.key_size
    candidate = (finding.variant or "").upper().replace("_", "-")
    # Accept AES-256 and strings such as AES-256-GCM; do not infer a size from
    # an unrelated occurrence of the digits 128/192/256.
    import re

    match = re.search(r"\bAES[- ]?(128|192|256)\b", candidate)
    return int(match.group(1)) if match else None


def quantum_profile(finding: CryptoFinding) -> QuantumProfile | None:
    """Return the quantum-vulnerability factor and tier for a finding.

    None means the algorithm is not mapped well enough to assign a factor.
    Unresolved AES size follows the documented conservative AES-128 assumption.
    MD5/SHA-1 are deliberately not assigned an inflated quantum tier here: their
    primary weakness is classical and hash findings are not HNDL-scored.
    """

    algorithm = _normalise_algorithm(finding.algorithm)
    if algorithm in KNOWN_UNKNOWN_NAMES or algorithm.startswith("LIBRARY:"):
        return None

    if algorithm in CLASSICALLY_WEAK_HASHES:
        return QuantumProfile(
            score=None,
            tier="classically-weak",
            rationale=f"{algorithm} is classically weak; this policy does not treat that as an HNDL quantum factor.",
        )

    if algorithm in SHOR_VULNERABLE_FAMILIES:
        subject = f"EC with curve {finding.curve}" if algorithm == "EC" and finding.curve else algorithm
        return QuantumProfile(
            score=TIER_TO_VULNERABILITY_SCORE[Tier.SHOR_VULNERABLE.value],
            tier=Tier.SHOR_VULNERABLE.value,
            rationale=f"{subject} belongs to a public-key construction vulnerable to Shor-type attacks.",
        )

    if algorithm == "AES":
        bits = _aes_bits(finding)
        if bits is None:
            return QuantumProfile(
                score=TIER_TO_VULNERABILITY_SCORE[Tier.GROVER_AFFECTED.value],
                tier=Tier.GROVER_AFFECTED.value,
                assumed=True,
                rationale="AES key size was unresolved; policy conservatively assumes AES-128.",
            )
        if bits == 256:
            data = get_quantum_factor("AES-256")
        elif bits in (128, 192):
            data = get_quantum_factor(f"AES-{bits}")
        else:
            # Unsupported sizes are not silently treated as safe. Use the
            # conservative AES-128 tier and make the assumption explicit.
            return QuantumProfile(
                score=TIER_TO_VULNERABILITY_SCORE[Tier.GROVER_AFFECTED.value],
                tier=Tier.GROVER_AFFECTED.value,
                assumed=True,
                rationale=f"AES key size {bits} is not covered by policy; conservatively treated as Grover-affected pending review.",
            )
        if data is None:
            return None
        tier = data["tier"]
        return QuantumProfile(
            score=TIER_TO_VULNERABILITY_SCORE[tier],
            tier=tier,
            rationale=f"AES-{bits} was mapped using the Week 3 quantum-factor table.",
        )

    # EC findings use algorithm='EC' and curve='P-256' etc. The family itself
    # is Shor-vulnerable even when its precise curve is unresolved.
    lookup_name = finding.curve if algorithm == "EC" and finding.curve else algorithm
    factor_data = get_quantum_factor(lookup_name)
    if factor_data is None:
        # Newer/alias names that are still known Shor-vulnerable families.
        if lookup_name in {"P-256", "P-384", "P-521", "SECP256K1"}:
            return QuantumProfile(
                score=TIER_TO_VULNERABILITY_SCORE[Tier.SHOR_VULNERABLE.value],
                tier=Tier.SHOR_VULNERABLE.value,
                rationale=f"Elliptic curve {lookup_name} uses a discrete-log construction vulnerable to Shor-type attacks.",
            )
        return None

    tier = factor_data["tier"]
    score = TIER_TO_VULNERABILITY_SCORE.get(tier)
    if score is None:
        return None
    return QuantumProfile(
        score=score,
        tier=tier,
        rationale=f"{lookup_name} was mapped using the Week 3 quantum-factor table.",
    )


def risk_level_for_score(score: float) -> RiskLevel:
    """Convert a 0..100 score into the v1 policy severity band."""
    bounded = max(0.0, min(100.0, score))
    for threshold, level in RISK_THRESHOLDS:
        if bounded >= threshold:
            return level
    return RiskLevel.LOW


def risk_floor_for_level(level: RiskLevel) -> float:
    """Lowest numeric score belonging to a level; used for policy escalations."""
    floors = {
        RiskLevel.LOW: 0.0,
        RiskLevel.MODERATE: 20.0,
        RiskLevel.HIGH: 40.0,
        RiskLevel.VERY_HIGH: 60.0,
        RiskLevel.CRITICAL: 80.0,
    }
    return floors[level]


def confidentiality_lifetime_score(years: float) -> float:
    """Map required confidentiality duration to an explainable 0..5 score."""
    if years <= 0:
        return 0.0
    if years <= 1:
        return 1.0
    if years <= 3:
        return 2.0
    if years <= 5:
        return 3.0
    if years <= 10:
        return 4.0
    return 5.0
