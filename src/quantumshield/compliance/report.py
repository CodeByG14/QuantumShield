"""JSON and Markdown writers for compliance reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


def _cell(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_markdown(report: Mapping[str, Any]) -> str:
    summary = report.get("summary", {})
    counts = summary.get("by_status", {})
    lines = [
        "# QuantumShield Compliance Assessment",
        "",
        f"- **As of:** `{report.get('as_of', 'unknown')}`",
        f"- **Assessment ID:** `{report.get('assessment_id', 'unknown')}`",
        f"- **Ruleset:** `{report.get('ruleset_version', 'unknown')}` (updated `{report.get('ruleset_updated_on', 'unknown')}`)",
        f"- **Findings evaluated:** {summary.get('findings', 0)}",
        f"- **Rule results:** {summary.get('results', 0)}",
        "",
        "## Status summary",
        "",
        "| Status | Total | NIST IR 8547 | CNSA 2.0 / CNSSP No. 15 |",
        "|---|---:|---:|---:|",
    ]
    framework_counts = summary.get("by_framework", {})
    nist_counts = framework_counts.get("NIST IR 8547", {})
    cnsa_counts = framework_counts.get("CNSA 2.0 / CNSSP No. 15", {})
    for status in ("compliant", "deprecated-soon", "past-deadline", "not assessed"):
        lines.append(f"| {status} | {counts.get(status, 0)} | {nist_counts.get(status, 0)} | {cnsa_counts.get(status, 0)} |")
    lines += [
        "",
        "## Findings and rule results",
        "",
        "| Finding | Algorithm / variant | Role | Framework | Rule | Status | Deadline year | Estimated plan completion | Before deadline? | Sources |",
        "|---|---|---|---|---|---|---:|---|---|---|",
    ]
    for item in report.get("results", []):
        algo = str(item.get("algorithm") or "unknown")
        variant = item.get("variant")
        if variant:
            algo += f" / {variant}"
        source_links = ", ".join(
            f"[{src.get('id')}]({src.get('url')}) ({src.get('publication_status')})"
            for src in item.get("sources", [])
        ) or "—"
        lines.append("| " + " | ".join(_cell(v) for v in (
            item.get("finding_id"), algo, item.get("role"), item.get("framework"),
            item.get("rule_id"), item.get("status"), item.get("deadline_year"),
            item.get("plan_completion_date"), item.get("plan_finishes_before_deadline"), source_links,
        )) + " |")
        if item.get("reason"):
            lines.append(f"\n> **{_cell(item.get('finding_id'))} — {_cell(item.get('framework'))}:** {_cell(item.get('reason'))}\n")
    lines += ["", "## Source register", ""]
    for source in report.get("sources", []):
        lines.append(
            f"- [{source.get('title')}]({source.get('url')}) — **{source.get('publication_status')}**, "
            f"published {source.get('published_on')}. Scope: {source.get('scope')}"
        )
    lines += ["", "## Scope and limitations", ""]
    for warning in report.get("warnings", []):
        lines.append(f"- {warning}")
    return "\n".join(lines).rstrip() + "\n"


def write_reports(
    report: Mapping[str, Any],
    json_path: str | Path = "compliance_report.json",
    markdown_path: str | Path = "compliance_report.md",
) -> tuple[Path, Path]:
    json_target, markdown_target = Path(json_path), Path(markdown_path)
    json_target.parent.mkdir(parents=True, exist_ok=True)
    markdown_target.parent.mkdir(parents=True, exist_ok=True)
    json_target.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    markdown_target.write_text(render_markdown(report), encoding="utf-8")
    return json_target, markdown_target
