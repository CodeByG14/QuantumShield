"""Heuristic crypto-agility scoring, explicitly not a security certification."""
from __future__ import annotations
from collections import defaultdict
from typing import Any
from quantumshield.common.models import CryptoFinding, EvidenceType


def score_agility(findings: list[CryptoFinding], *, configurable_weight: float = 1.0,
                  static_weight: float = 1.0) -> dict[str, Any]:
    """Return a 0..100 score; dynamic-selection evidence raises score monotonically.

    Each finding is counted once, and grouped by evidence file path. Weight inputs
    must be positive. A scan with no relevant evidence receives a neutral 50, not 100.
    """
    if configurable_weight <= 0 or static_weight <= 0:
        raise ValueError("scoring weights must be greater than zero")
    assets: dict[str, dict[str, int]] = defaultdict(lambda: {"dynamic_selection": 0, "static_crypto_use": 0})
    dynamic = static = 0
    for finding in findings:
        paths = sorted({e.file_path for e in finding.evidence}) or ["unknown"]
        is_dynamic = any(e.evidence_type == EvidenceType.DYNAMIC_SELECTION for e in finding.evidence)
        if is_dynamic:
            dynamic += 1
            for path in paths: assets[path]["dynamic_selection"] += 1
        elif finding.evidence:
            static += 1
            for path in paths: assets[path]["static_crypto_use"] += 1
    denom = dynamic * configurable_weight + static * static_weight
    score = 50 if denom == 0 else round(100 * dynamic * configurable_weight / denom)
    return {
        "score": max(0, min(100, score)), "scale": {"minimum": 0, "maximum": 100},
        "method": "weighted ratio of findings with dynamic-selection evidence to relevant crypto findings",
        "counts": {"dynamic_selection": dynamic, "static_crypto_use": static, "relevant_findings": dynamic + static},
        "per_asset": {path: {**counts, "score": _asset_score(counts, configurable_weight, static_weight)} for path, counts in sorted(assets.items())},
        "weights": {"configurable": configurable_weight, "static": static_weight},
        "limitations": [
            "Heuristic indicator of observed dynamic selection, not proof that algorithm changes are safe or operationally supported.",
            "Static pattern matching can miss indirect dispatch, generated code, reflection, and unsupported languages.",
            "A score of 100 means all detected relevant findings were dynamic-selection findings; it does not mean the system is secure.",
            "No relevant evidence yields a neutral score of 50 because absence of evidence is not proof of agility.",
        ],
    }

def _asset_score(counts: dict[str, int], configurable_weight: float, static_weight: float) -> int:
    dynamic, static = counts["dynamic_selection"], counts["static_crypto_use"]
    denom = dynamic * configurable_weight + static * static_weight
    return 50 if denom == 0 else max(0, min(100, round(100 * dynamic * configurable_weight / denom)))
