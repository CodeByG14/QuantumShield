"""CLI for comparing baseline and current QuantumShield assessments."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys
from typing import Any

from .diff import AssessmentFormatError, diff_assessments


EXIT_OK = 0
EXIT_THRESHOLD_BREACHED = 1
EXIT_INPUT_ERROR = 2


def _read_json(path: str | Path) -> dict[str, Any]:
    input_path = Path(path)
    try:
        with input_path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except OSError as exc:
        raise ValueError(f"cannot read {input_path}: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"invalid JSON in {input_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{input_path} must contain a JSON object")
    return data


def _parse_fail_on(values: list[str]) -> list[tuple[str, float | None]]:
    parsed: list[tuple[str, float | None]] = []
    supported_simple = {"new-high", "new-critical", "new-unable"}
    for raw in values:
        # Accept both repeated flags and comma-separated rules.
        for item in raw.split(","):
            item = item.strip().casefold()
            if not item:
                continue
            if item in supported_simple:
                parsed.append((item, None))
            elif item.startswith("coverage-drop:"):
                token = item.split(":", 1)[1]
                try:
                    threshold = float(token)
                except ValueError as exc:
                    raise ValueError(f"invalid coverage-drop threshold: {token!r}") from exc
                if not math.isfinite(threshold) or threshold < 0 or threshold > 100:
                    raise ValueError("coverage-drop threshold must be between 0 and 100 percentage points")
                parsed.append(("coverage-drop", threshold))
            else:
                raise ValueError(
                    f"unsupported --fail-on rule {item!r}; expected new-high, new-critical, "
                    "new-unable, or coverage-drop:N"
                )
    # Repeated equivalent rules need only be evaluated once.
    seen: set[tuple[str, float | None]] = set()
    output = []
    for rule in parsed:
        if rule not in seen:
            seen.add(rule)
            output.append(rule)
    return output


def evaluate_failures(report: dict[str, Any], rules: list[tuple[str, float | None]]) -> list[str]:
    breaches: list[str] = []
    if not rules:
        return breaches

    added = report["added"]
    for rule, threshold in rules:
        if rule == "new-high":
            matching = [item for item in added if str(item.get("risk_level") or "").casefold() in {"high", "very-high", "critical"}]
            if matching:
                breaches.append(f"new-high: {len(matching)} new finding(s) at high risk or above")
        elif rule == "new-critical":
            matching = [item for item in added if str(item.get("risk_level") or "").casefold() == "critical"]
            if matching:
                breaches.append(f"new-critical: {len(matching)} new critical finding(s)")
        elif rule == "new-unable":
            matching = [item for item in added if str(item.get("status") or "").casefold() == "unable-to-analyze"]
            if matching:
                breaches.append(f"new-unable: {len(matching)} new unable-to-analyze finding(s)")
        elif rule == "coverage-drop":
            delta = float(report["coverage"]["delta_percentage_points"])
            assert threshold is not None
            if delta < 0 and abs(delta) >= threshold:
                breaches.append(
                    f"coverage-drop:{threshold:g}: coverage fell by {abs(delta):g} percentage point(s)"
                )
            elif threshold == 0 and delta < 0:
                breaches.append("coverage-drop:0: any coverage decrease is a failure")
    return breaches


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare two QuantumShield assessment reports and optionally fail on regressions."
    )
    parser.add_argument("--baseline", required=True, help="Path to baseline assessment JSON")
    parser.add_argument("--current", required=True, help="Path to current assessment JSON")
    parser.add_argument("--output", "-o", default="diff.json", help="Diff report path (default: diff.json)")
    parser.add_argument(
        "--fail-on",
        action="append",
        default=[],
        metavar="RULE",
        help="Fail on new-high, new-critical, new-unable, or coverage-drop:N (repeatable; comma lists supported)",
    )
    args = parser.parse_args(argv)

    try:
        rules = _parse_fail_on(args.fail_on)
        baseline = _read_json(args.baseline)
        current = _read_json(args.current)
        report = diff_assessments(baseline, current)
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (ValueError, AssessmentFormatError) as exc:
        print(f"monitor.check: error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except OSError as exc:
        print(f"monitor.check: error writing report: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    summary = report["summary"]
    coverage = report["coverage"]
    print(
        f"Assessment diff: added={summary['added']}, removed={summary['removed']}, "
        f"changed={summary['changed']}, unchanged={summary['unchanged']}"
    )
    print(
        f"Coverage: {coverage['baseline_percent']:g}% -> {coverage['current_percent']:g}% "
        f"({coverage['delta_percentage_points']:+g} percentage points)"
    )
    print(f"Wrote {output_path}")

    breaches = evaluate_failures(report, rules)
    for breach in breaches:
        print(f"FAIL: {breach}", file=sys.stderr)
    if breaches:
        print("Monitoring threshold(s) breached.", file=sys.stderr)
        return EXIT_THRESHOLD_BREACHED
    if rules:
        print("Monitoring thresholds passed.")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
