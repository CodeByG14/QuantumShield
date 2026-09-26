"""
QuantumShield Dashboard Console View

Reads scored_output.json and displays a formatted risk table.
This is the Week 3 minimum bar — a working script that proves
the full pipeline connects end-to-end.

Date: 2026-09-27
"""

import json
from pathlib import Path
from tabulate import tabulate


def load_scored_output(scored_path="scored_output.json"):
    """Load scored output file."""
    with open(scored_path) as f:
        return json.load(f)


def display_risk_table(scored_output):
    """
    Display scored findings as a formatted console table.
    
    Columns: name, tier, score, location, line
    Sorted by score descending (already sorted in scored_output.json)
    """
    findings = scored_output.get("findings", [])
    
    if not findings:
        print("No findings to display.")
        return
    
    # Build table rows
    table_data = []
    for finding in findings:
        table_data.append([
            finding["name"],
            finding["tier"],
            f"{finding['algorithm_risk_score']:.3f}",
            Path(finding["location"]).name,  # Just filename for cleaner display
            finding["line"],
        ])
    
    # Print header info
    print(f"\n{'=' * 80}")
    print(f"QuantumShield Risk Assessment")
    print(f"{'=' * 80}")
    print(f"Formula version: {scored_output.get('scoring_formula_version', 'unknown')}")
    print(f"Generated from: {scored_output.get('generated_from', 'unknown')}")
    print(f"Total findings: {len(findings)}")
    print(f"{'=' * 80}\n")
    
    # Print table
    headers = ["Algorithm", "Tier", "Risk Score", "File", "Line"]
    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    
    # Print summary statistics
    print(f"\n{'=' * 80}")
    print("Risk Distribution:")
    tier_counts = {}
    for finding in findings:
        tier = finding["tier"]
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
    
    for tier, count in sorted(tier_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {tier}: {count} findings")
    
    print(f"{'=' * 80}\n")


def main(scored_path="scored_output.json"):
    """Main entry point."""
    if not Path(scored_path).exists():
        print(f"Error: {scored_path} not found.")
        print("Run scoring/qri_engine.py first to generate scored output.")
        return
    
    scored_output = load_scored_output(scored_path)
    display_risk_table(scored_output)


if __name__ == "__main__":
    main()
