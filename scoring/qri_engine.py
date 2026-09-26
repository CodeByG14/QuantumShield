"""
QuantumShield QRI (Quantum Risk Index) Scoring Engine

Reads cbom.json, calculates Algorithm_Risk_Score = Quantum_Factor × Confidence,
produces scored_output.json sorted by descending risk.

Date: 2026-09-27
Formula: v1 (scoring-formula-finalization.md)
"""

import json
from pathlib import Path
from scoring_map import get_quantum_factor, get_algorithm_family


def load_cbom(cbom_path="cbom.json"):
    """Load CycloneDX CBOM file."""
    with open(cbom_path) as f:
        return json.load(f)


def score_component(component):
    """
    Calculate risk score for a single CBOM component.
    
    Args:
        component: CBOM cryptographic-asset component dict
    
    Returns:
        dict with scoring fields, or None if component cannot be scored
    """
    # Extract component name/variant
    name = component.get("name", "")
    bom_ref = component.get("bom-ref", "")
    
    # Extract confidence from evidence
    evidence = component.get("evidence", {})
    confidence = evidence.get("confidence")
    
    if confidence is None:
        print(f"Warning: No confidence found for {name} ({bom_ref}), skipping")
        return None
    
    # Extract location and line from first occurrence
    occurrences = evidence.get("occurrences", [])
    location = occurrences[0].get("location", "") if occurrences else ""
    line = occurrences[0].get("line", 0) if occurrences else 0
    
    # Get algorithm family and look up quantum factor
    algorithm_family = get_algorithm_family(name)
    factor_data = get_quantum_factor(algorithm_family)
    
    if factor_data is None:
        print(f"Warning: No quantum factor found for {algorithm_family} (from {name}), skipping")
        return None
    
    quantum_factor = factor_data["factor"]
    tier = factor_data["tier"]
    
    # Calculate risk score: Quantum_Factor × Confidence
    algorithm_risk_score = quantum_factor * confidence
    
    return {
        "bom-ref": bom_ref,
        "name": name,
        "quantum_factor": quantum_factor,
        "confidence": confidence,
        "algorithm_risk_score": round(algorithm_risk_score, 3),
        "tier": tier,
        "location": location,
        "line": line,
    }


def generate_scored_output(cbom_path="cbom.json", output_path="scored_output.json"):
    """
    Generate scored output from CBOM.
    
    Args:
        cbom_path: Path to input CBOM file
        output_path: Path to output scored results file
    
    Returns:
        dict with scored findings
    """
    cbom = load_cbom(cbom_path)
    
    # Score each component
    findings = []
    for component in cbom.get("components", []):
        if component.get("type") == "cryptographic-asset":
            scored = score_component(component)
            if scored:
                findings.append(scored)
    
    # Sort by algorithm_risk_score descending (highest risk first)
    findings.sort(key=lambda x: x["algorithm_risk_score"], reverse=True)
    
    # Build output structure per scoring-formula-finalization.md
    scored_output = {
        "generated_from": str(Path(cbom_path).name),
        "scoring_formula_version": "v1",
        "findings": findings,
    }
    
    # Write to file
    with open(output_path, "w") as f:
        json.dump(scored_output, f, indent=2)
    
    print(f"Generated {output_path} with {len(findings)} scored findings")
    print(f"Risk score range: {findings[0]['algorithm_risk_score']} (highest) to {findings[-1]['algorithm_risk_score']} (lowest)")
    
    return scored_output


if __name__ == "__main__":
    generate_scored_output()
