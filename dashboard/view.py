"""Console dashboard for QuantumShield's Week 5 assessment.json report."""

import argparse
import json
from pathlib import Path

from tabulate import tabulate


def load_assessment(assessment_path: str | Path = "assessment.json") -> dict:
    """Load a generated assessment report."""
    with open(assessment_path, encoding="utf-8") as stream:
        return json.load(stream)


def _asset_name(finding: dict) -> str:
    name = finding.get("variant") or finding.get("algorithm", "unknown")
    curve = finding.get("curve")
    if curve and curve not in name:
        name = f"{name} ({curve})"
    elif finding.get("key_size") and not finding.get("variant"):
        name = f"{name}-{finding['key_size']}"
    return name


def _location(finding: dict) -> str:
    evidence = finding.get("evidence") or []
    if not evidence:
        return "—"
    first = evidence[0]
    path = first.get("file_path", "unknown")
    line = first.get("line_start")
    return f"{path}:{line}" if line else path


def display_assessment(report: dict) -> None:
    """Print coverage, finding/risk table, missing inputs, and limitations."""
    findings = report.get("findings", [])
    risks_by_id = {risk.get("finding_id"): risk for risk in report.get("risks", [])}
    coverage = report.get("coverage", {})
    context = report.get("project_context", {})

    print("\n" + "=" * 120)
    print("QuantumShield — Assessment Overview")
    print("=" * 120)
    print(f"Project: {context.get('project_name', 'unknown')}")
    print(f"Target: {report.get('target', 'unknown')}")
    print(f"Assessment ID: {report.get('assessment_id', 'unknown')}")
    print(f"Scanned at: {report.get('scan_timestamp', 'unknown')}")
    print(f"Policy version: {report.get('policy_version', 'unknown')}")
    print(
        "Coverage: {percent}% ({analyzed}/{discovered} fully analyzed; "
        "partial={partial}, failed={failed}, unsupported={unsupported}, skipped={skipped})".format(
            percent=coverage.get("file_coverage_percent", 0),
            analyzed=coverage.get("files_analyzed", 0),
            discovered=coverage.get("files_discovered", 0),
            partial=coverage.get("files_partial", 0),
            failed=coverage.get("files_failed", 0),
            unsupported=coverage.get("files_unsupported", 0),
            skipped=coverage.get("files_skipped", 0),
        )
    )
    print(f"Cryptographic findings: {len(findings)}")
    print("=" * 120 + "\n")

    if not findings:
        print("No cryptographic findings were produced.")
    else:
        rows = []
        for finding in findings:
            risk = risks_by_id.get(finding.get("finding_id"), {})
            score = risk.get("risk_score")
            rows.append(
                [
                    finding.get("finding_id", "—"),
                    _asset_name(finding),
                    finding.get("role", "undetermined"),
                    finding.get("status", "unknown"),
                    finding.get("confidence", "unknown"),
                    risk.get("risk_kind", "not-assessed"),
                    f"{score:.1f}" if isinstance(score, (int, float)) else "—",
                    risk.get("risk_level") or "not scored",
                    "yes" if risk.get("provisional") else "no",
                    _location(finding),
                ]
            )
        print(
            tabulate(
                rows,
                headers=[
                    "ID", "Asset", "Role", "Finding", "Confidence", "Risk kind",
                    "Score", "Level", "Provisional", "Evidence location",
                ],
                tablefmt="grid",
            )
        )

    missing = sorted(
        {
            field
            for risk in report.get("risks", [])
            for field in risk.get("missing_inputs", [])
        }
    )
    print("\nMissing inputs requiring attention:")
    if missing:
        for field in missing:
            print(f"  - {field}")
    else:
        print("  None reported")

    limitations = report.get("limitations", [])
    print("\nAssessment limitations:")
    for item in limitations:
        print(f"  - {item}")
    print()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Display QuantumShield assessment.json")
    parser.add_argument("assessment", nargs="?", default="assessment.json")
    args = parser.parse_args(argv)

    path = Path(args.assessment)
    if not path.is_file():
        parser.error(
            f"{path} not found. Generate it with: "
            "uv run quantumshield scan samples/test-repo -o assessment.json"
        )
    display_assessment(load_assessment(path))


if __name__ == "__main__":
    main()
