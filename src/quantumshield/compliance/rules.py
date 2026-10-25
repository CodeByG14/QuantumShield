"""Load and validate the versioned, source-backed compliance ruleset."""

from __future__ import annotations

from datetime import date
import re
from pathlib import Path
from typing import Any, Mapping

import yaml


class ComplianceRulesError(ValueError):
    """The compliance rules or their source provenance are invalid."""


DEFAULT_RULES_PATH = Path(__file__).with_name("rules.yaml")
_SOURCE_STATUSES = {"draft", "final", "official-announcement", "approved-guidance", "proposed"}


def normalize_algorithm(value: Any) -> str:
    """Normalize algorithm names for exact alias matching, not fuzzy guessing."""
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())


def validate_ruleset(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ComplianceRulesError("rules YAML must contain a mapping")
    if not isinstance(data.get("ruleset_version"), str) or not data["ruleset_version"].strip():
        raise ComplianceRulesError("ruleset_version is required")
    try:
        date.fromisoformat(str(data.get("updated_on", "")))
    except ValueError as exc:
        raise ComplianceRulesError("updated_on must be an ISO date (YYYY-MM-DD)") from exc

    sources_raw = data.get("sources")
    rules_raw = data.get("rules")
    if not isinstance(sources_raw, list) or not sources_raw:
        raise ComplianceRulesError("ruleset must declare at least one source")
    if not isinstance(rules_raw, list) or not rules_raw:
        raise ComplianceRulesError("ruleset must declare at least one rule")

    sources: dict[str, dict[str, Any]] = {}
    for index, source in enumerate(sources_raw):
        if not isinstance(source, dict):
            raise ComplianceRulesError(f"sources[{index}] must be a mapping")
        required = ("id", "title", "published_on", "publication_status", "url", "scope")
        missing = [field for field in required if not str(source.get(field, "")).strip()]
        if missing:
            raise ComplianceRulesError(
                f"sources[{index}] is missing required provenance field(s): {', '.join(missing)}"
            )
        source_id = str(source["id"])
        if source_id in sources:
            raise ComplianceRulesError(f"duplicate source id: {source_id}")
        if source["publication_status"] not in _SOURCE_STATUSES:
            raise ComplianceRulesError(
                f"source {source_id} has unsupported publication_status {source['publication_status']!r}"
            )
        if not str(source["url"]).startswith("https://"):
            raise ComplianceRulesError(f"source {source_id} must have an HTTPS URL")
        try:
            date.fromisoformat(str(source["published_on"]))
        except ValueError as exc:
            raise ComplianceRulesError(
                f"source {source_id} published_on must be an ISO date (YYYY-MM-DD)"
            ) from exc
        sources[source_id] = dict(source)

    seen_rule_ids: set[str] = set()
    for index, rule in enumerate(rules_raw):
        if not isinstance(rule, dict):
            raise ComplianceRulesError(f"rules[{index}] must be a mapping")
        required = ("id", "framework", "kind", "source_ids", "status_note")
        missing = [field for field in required if field not in rule]
        if missing:
            raise ComplianceRulesError(
                f"rules[{index}] is missing required field(s): {', '.join(missing)}"
            )
        rule_id = str(rule["id"])
        if rule_id in seen_rule_ids:
            raise ComplianceRulesError(f"duplicate rule id: {rule_id}")
        seen_rule_ids.add(rule_id)
        if not isinstance(rule["source_ids"], list) or not rule["source_ids"]:
            raise ComplianceRulesError(f"rule {rule_id} must reference at least one source")
        unknown_sources = set(rule["source_ids"]) - set(sources)
        if unknown_sources:
            raise ComplianceRulesError(
                f"rule {rule_id} references unknown source(s): {', '.join(sorted(unknown_sources))}"
            )
        if rule["kind"] not in {
            "public_key_strength",
            "named_algorithms",
            "approved_pqc",
            "cnsa_legacy_public_key",
            "cnsa_approved_parameterized_pqc",
            "cnsa_approved_pqc",
        }:
            raise ComplianceRulesError(f"rule {rule_id} has unknown kind {rule['kind']!r}")
        if "algorithms" in rule and (not isinstance(rule["algorithms"], list) or not rule["algorithms"]):
            raise ComplianceRulesError(f"rule {rule_id} algorithms must be a non-empty list when supplied")
        for field in ("deadline_effective_date", "deprecated_effective_date", "warning_start_date"):
            value = rule.get(field)
            if value is not None:
                try:
                    date.fromisoformat(str(value))
                except ValueError as exc:
                    raise ComplianceRulesError(
                        f"rule {rule_id} {field} must be an ISO date (YYYY-MM-DD)"
                    ) from exc
        deadline_year = rule.get("deadline_year")
        if deadline_year is not None and (isinstance(deadline_year, bool) or not isinstance(deadline_year, int)):
            raise ComplianceRulesError(f"rule {rule_id} deadline_year must be an integer or null")
        if rule["kind"] in {"public_key_strength", "named_algorithms", "approved_pqc", "cnsa_legacy_public_key", "cnsa_approved_parameterized_pqc", "cnsa_approved_pqc"} and not rule.get("algorithms"):
            raise ComplianceRulesError(f"rule {rule_id} needs algorithm aliases")

    category_map = data.get("system_category_mapping", {})
    if not isinstance(category_map, dict):
        raise ComplianceRulesError("system_category_mapping must be a mapping")
    expected_categories = {"web", "networking", "os", "firmware-signing", "other"}
    for category, mapping in category_map.items():
        if category not in expected_categories:
            raise ComplianceRulesError(f"unsupported system category {category!r}")
        if not isinstance(mapping, dict) or not str(mapping.get("description", "")).strip():
            raise ComplianceRulesError(f"system_category_mapping.{category} needs a description")
        source_ids = mapping.get("source_ids")
        if not isinstance(source_ids, list) or not source_ids:
            raise ComplianceRulesError(f"system_category_mapping.{category} must reference source(s)")
        if set(source_ids) - set(sources):
            raise ComplianceRulesError(
                f"system_category_mapping.{category} references unknown source(s): "
                f"{', '.join(sorted(set(source_ids) - set(sources)))}"
            )

    return {
        **data,
        "sources_by_id": sources,
        "rules": [dict(rule) for rule in rules_raw],
    }


def load_rules(path: str | Path | None = None) -> dict[str, Any]:
    rules_path = Path(path) if path is not None else DEFAULT_RULES_PATH
    try:
        raw = yaml.safe_load(rules_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ComplianceRulesError(f"cannot read compliance rules {rules_path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ComplianceRulesError(f"invalid YAML in compliance rules {rules_path}: {exc}") from exc
    return validate_ruleset(raw)
