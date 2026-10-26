"""Source-backed, date-aware compliance assessment for QuantumShield findings.

The output is advisory transition planning, not a legal certification. NIST IR
8547 remains a draft in the cited source; its proposed dates are labelled as
such. CNSA/NSS findings are assessed only after the user explicitly confirms
that scope in project/asset context.
"""

from __future__ import annotations

import calendar
from datetime import date, datetime, timezone
import fnmatch
import re
from typing import Any, Mapping

from .rules import load_rules, normalize_algorithm

FRAMEWORK_NIST = "NIST IR 8547"
FRAMEWORK_CNSA = "CNSA 2.0 / CNSSP No. 15"
_ALLOWED_CATEGORIES = {"web", "networking", "os", "firmware-signing", "other"}
_EC_ALGORITHMS = {"ec", "ecdsa", "eddsa", "ecdh", "ecmqv", "mqv", "x25519", "x448"}
_PUBLIC_KEY_ALGORITHMS = {"rsa", "ecdsa", "eddsa", "ec", "dh", "diffiehellman", "ecdh", "mqv", "ecmqv", "dsa"}


class ComplianceAssessmentError(ValueError):
    """Invalid assessment, migration plan, or compliance input."""


def _plain(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    return value


def _as_date(value: str | date | None) -> date:
    if value is None:
        return date.today()
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value))
    except (TypeError, ValueError) as exc:
        raise ComplianceAssessmentError("as_of must be an ISO date (YYYY-MM-DD)") from exc


def _norm_role(value: Any) -> str:
    return str(value or "undetermined").casefold().replace("_", "-")


def _norm_path(value: Any) -> str:
    text = str(value or "").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _context_fields(context: Mapping[str, Any] | None) -> tuple[str | None, str | None, bool | None, str | None]:
    if not isinstance(context, Mapping):
        return None, None, None, None
    category = context.get("system_category")
    scope = context.get("cnsa_scope_confirmed")
    valid_category = category if isinstance(category, str) and category in _ALLOWED_CATEGORIES else None
    return (
        valid_category,
        "project_context" if valid_category is not None else None,
        scope if isinstance(scope, bool) else None,
        "project_context" if isinstance(scope, bool) else None,
    )


def _resolve_asset_context(
    project_context: Mapping[str, Any], finding: Mapping[str, Any]
) -> tuple[str | None, str | None, bool | None, str | None]:
    """Resolve explicit category/scope using finding-ID then most-specific path."""
    category, category_source, scope, scope_source = _context_fields(project_context)
    assets = project_context.get("asset_contexts", [])
    if not isinstance(assets, list):
        return category, category_source, scope, scope_source
    finding_id = str(finding.get("finding_id") or "")
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    paths = [_norm_path(e.get("file_path")) for e in evidence if isinstance(e, Mapping) and e.get("file_path")]

    # Exact finding-ID context wins per field, but an unrelated exact context
    # must not block path-level compliance metadata from filling missing fields.
    category_locked = False
    scope_locked = False
    for asset in assets:
        if isinstance(asset, Mapping) and finding_id and asset.get("asset_id") == finding_id:
            if isinstance(asset.get("system_category"), str) and asset.get("system_category") in _ALLOWED_CATEGORIES:
                category, category_source = asset["system_category"], f"asset_context:{finding_id}"
                category_locked = True
            if isinstance(asset.get("cnsa_scope_confirmed"), bool):
                scope, scope_source = asset["cnsa_scope_confirmed"], f"asset_context:{finding_id}"
                scope_locked = True
            break

    path_matches: list[tuple[int, int, Mapping[str, Any], str]] = []
    for index, asset in enumerate(assets):
        if not isinstance(asset, Mapping):
            continue
        pattern = _norm_path(asset.get("asset_id"))
        if not pattern or pattern == finding_id:
            continue
        for path in paths:
            if fnmatch.fnmatchcase(path, pattern):
                literal_prefix = len(pattern.split("*")[0].split("?")[0])
                path_matches.append((literal_prefix, -index, asset, pattern))
                break
    if path_matches:
        _, _, asset, pattern = max(path_matches, key=lambda entry: (entry[0], entry[1]))
        if not category_locked and isinstance(asset.get("system_category"), str) and asset.get("system_category") in _ALLOWED_CATEGORIES:
            category, category_source = asset["system_category"], f"asset_context:{pattern}"
        if not scope_locked and isinstance(asset.get("cnsa_scope_confirmed"), bool):
            scope, scope_source = asset["cnsa_scope_confirmed"], f"asset_context:{pattern}"
    return category, category_source, scope, scope_source


def _algorithm_values(finding: Mapping[str, Any]) -> tuple[str, set[str]]:
    algorithm = normalize_algorithm(finding.get("algorithm"))
    values = {algorithm}
    for field in ("variant", "purpose"):
        value = normalize_algorithm(finding.get(field))
        if value:
            values.add(value)
    return algorithm, values


def _alias_match(finding: Mapping[str, Any], aliases: list[Any]) -> bool:
    _, values = _algorithm_values(finding)
    normalized_aliases = {normalize_algorithm(alias) for alias in aliases}
    if values & normalized_aliases:
        return True
    # Permit canonical names followed by a numeric parameter/size only.
    for value in values:
        for alias in normalized_aliases:
            if alias and value.startswith(alias) and value[len(alias):].isdigit():
                return True
    return False


def infer_security_strength_bits(finding: Mapping[str, Any]) -> int | None:
    """Infer only known/common strengths; never guess when parameters are missing."""
    algorithm, values = _algorithm_values(finding)
    curve_values = {normalize_algorithm(finding.get("curve")), *values}
    curve_map = {
        "p224": 112, "secp224r1": 112, "prime224v1": 112,
        "p256": 128, "secp256r1": 128, "prime256v1": 128,
        "x25519": 128, "ed25519": 128, "curve25519": 128,
        "p384": 192, "secp384r1": 192,
        "p521": 256, "secp521r1": 256,
        "x448": 224, "ed448": 224,
    }
    for value in curve_values:
        if value in curve_map:
            return curve_map[value]

    raw_size = finding.get("key_size")
    if raw_size is None:
        for value in values:
            match = re.fullmatch(r"(?:rsa|dh|dsa)(\d{3,5})", value)
            if match:
                raw_size = int(match.group(1))
                break
    try:
        key_size = int(raw_size) if raw_size is not None else None
    except (TypeError, ValueError):
        key_size = None
    if key_size is None:
        return None
    if algorithm in _EC_ALGORITHMS:
        return {224: 112, 255: 128, 256: 128, 384: 192, 448: 224, 521: 256}.get(key_size)
    if algorithm in {"rsa", "dh", "diffiehellman", "dsa"}:
        if key_size >= 15360:
            return 256
        if key_size >= 7680:
            return 192
        if key_size >= 3072:
            return 128
        if key_size >= 2048:
            return 112
        if key_size >= 1024:
            return 80
    return None


def _parameter(finding: Mapping[str, Any]) -> str | None:
    text = " ".join(str(finding.get(field) or "") for field in ("algorithm", "variant", "purpose"))
    normalized = normalize_algorithm(text)
    if "mlkem" in normalized:
        for candidate in ("1024", "768", "512"):
            if candidate in normalized:
                return candidate
    if "mldsa" in normalized:
        for candidate in ("87", "65", "44"):
            if candidate in normalized:
                return candidate
    return None


def _role_matches(finding: Mapping[str, Any], rule: Mapping[str, Any]) -> bool:
    roles = rule.get("roles")
    return not roles or _norm_role(finding.get("role")) in {_norm_role(x) for x in roles}


def _rule_match(finding: Mapping[str, Any], rule: Mapping[str, Any]) -> tuple[bool, str | None, int | None]:
    """Return (candidate, unresolved reason, strength); candidate may be unresolved."""
    if not _alias_match(finding, rule.get("algorithms", [])) or not _role_matches(finding, rule):
        return False, None, None
    kind = rule.get("kind")
    if kind == "public_key_strength":
        strength = infer_security_strength_bits(finding)
        if strength is None:
            return True, "Algorithm family matched, but key size or curve is insufficient to infer security strength.", None
        minimum = rule.get("min_strength_bits")
        maximum = rule.get("max_strength_bits")
        in_range = (minimum is None or strength >= int(minimum)) and (maximum is None or strength <= int(maximum))
        return in_range, None if in_range else "Determined security strength is outside this rule's range.", strength
    if kind == "cnsa_approved_parameterized_pqc":
        parameter = _parameter(finding)
        required = str(rule.get("required_parameter"))
        if parameter is None:
            return True, "Algorithm family matched, but parameter set is not explicit.", None
        if parameter != required:
            return True, f"Parameter set {parameter} does not match required set {required}.", None
    return True, None, None


def _transition_status(rule: Mapping[str, Any], as_of: date) -> str:
    deadline = rule.get("deadline_effective_date")
    if deadline and as_of >= date.fromisoformat(str(deadline)):
        return "past-deadline"
    deprecated = rule.get("deprecated_effective_date")
    if deprecated and as_of >= date.fromisoformat(str(deprecated)):
        return "deprecated-soon"
    warning = rule.get("warning_start_date")
    if warning and as_of >= date.fromisoformat(str(warning)):
        return "deprecated-soon"
    return "compliant"


def _add_months(value: date, months: int) -> date:
    year = value.year + (value.month - 1 + months) // 12
    month = (value.month - 1 + months) % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return date(year, month, day)


def _plan_estimate(
    finding_id: str, plan: Mapping[str, Any] | None, assessment_id: str, deadline_effective_date: str | None
) -> tuple[str | None, bool | None, str | None]:
    if plan is None:
        return None, None, "No migration plan supplied."
    source_id = plan.get("source_assessment_id")
    if source_id and source_id != assessment_id:
        return None, None, "Migration plan source_assessment_id does not match this assessment."
    tasks = plan.get("tasks")
    if not isinstance(tasks, list):
        return None, None, "Migration plan has no valid tasks list."
    matching = [task for task in tasks if isinstance(task, Mapping) and task.get("finding_id") == finding_id]
    if not matching:
        return None, None, "No migration task matches this finding_id."
    months = [task.get("timeline_months") for task in matching if isinstance(task.get("timeline_months"), int) and not isinstance(task.get("timeline_months"), bool) and task.get("timeline_months") >= 0]
    if not months:
        return None, None, "Matching migration task has no estimated timeline_months."
    try:
        generated = datetime.fromisoformat(str(plan.get("generated_at")).replace("Z", "+00:00")).date()
    except (ValueError, TypeError):
        return None, None, "Migration plan generated_at is missing or invalid."
    completion = _add_months(generated, max(months))
    if not deadline_effective_date:
        return completion.isoformat(), None, "Rule has no deadline to compare against."
    deadline = date.fromisoformat(str(deadline_effective_date))
    return completion.isoformat(), completion < deadline, "Estimated from the maximum timeline_months among matching tasks; advisory, not an actual completion date."


def _sources_for(rule: Mapping[str, Any] | None, source_index: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    if not rule:
        return []
    return [{
        "id": source_index[source_id]["id"],
        "title": source_index[source_id]["title"],
        "url": source_index[source_id]["url"],
        "published_on": source_index[source_id]["published_on"],
        "publication_status": source_index[source_id]["publication_status"],
        "scope": source_index[source_id]["scope"],
    } for source_id in rule.get("source_ids", [])]


def _result_base(finding: Mapping[str, Any], framework: str, category: str | None, category_source: str | None, scope: bool | None, scope_source: str | None) -> dict[str, Any]:
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), list) else []
    files = sorted({str(item.get("file_path")) for item in evidence if isinstance(item, Mapping) and item.get("file_path")})
    return {
        "finding_id": str(finding.get("finding_id") or "(missing finding_id)"),
        "algorithm": str(finding.get("algorithm") or "unknown"),
        "variant": finding.get("variant"), "curve": finding.get("curve"),
        "key_size": finding.get("key_size"), "role": _norm_role(finding.get("role")),
        "files": files, "framework": framework, "system_category": category,
        "system_category_source": category_source, "cnsa_scope_confirmed": scope,
        "cnsa_scope_source": scope_source,
    }


def _evaluate_framework(
    finding: Mapping[str, Any], framework: str, ruleset: Mapping[str, Any], as_of: date,
    category: str | None, category_source: str | None, scope: bool | None, scope_source: str | None,
    plan: Mapping[str, Any] | None, assessment_id: str,
) -> dict[str, Any]:
    base = _result_base(finding, framework, category, category_source, scope, scope_source)
    rules = [rule for rule in ruleset["rules"] if rule.get("framework") == framework]
    if framework == FRAMEWORK_CNSA:
        if scope is not True:
            reason = "CNSA/NSS scope was not affirmatively confirmed." if scope is None else "CNSA/NSS scope was explicitly marked not applicable."
            return {**base, "rule_id": None, "status": "not assessed", "deadline_year": None,
                    "deadline_effective_date": None, "deprecated_effective_date": None,
                    "security_strength_bits": None, "status_note": reason, "reason": reason,
                    "plan_completion_date": None, "plan_finishes_before_deadline": None,
                    "plan_comparison_note": "No comparison without an applicable CNSA rule.", "sources": []}
        if category is None:
            reason = "CNSA scope is confirmed, but system_category is not set."
            return {**base, "rule_id": None, "status": "not assessed", "deadline_year": None,
                    "deadline_effective_date": None, "deprecated_effective_date": None,
                    "security_strength_bits": None, "status_note": reason, "reason": reason,
                    "plan_completion_date": None, "plan_finishes_before_deadline": None,
                    "plan_comparison_note": "No comparison without category-specific rules.", "sources": []}

    matched: list[tuple[Mapping[str, Any], int | None]] = []
    unresolved: list[tuple[Mapping[str, Any], str, int | None]] = []
    for rule in rules:
        categories = rule.get("system_categories")
        if categories and category not in categories:
            continue
        is_candidate, reason, strength = _rule_match(finding, rule)
        if reason is not None:
            unresolved.append((rule, reason, strength))
        if is_candidate and reason is None:
            matched.append((rule, strength))

    if matched:
        # Rules are ordered from specific strength/algorithm rules first. Should
        # more than one match, prefer the one with the most explicit parameters.
        matched.sort(key=lambda pair: (0 if pair[0].get("required_parameter") else 1, pair[0].get("id", "")))
        rule, strength = matched[0]
        status = _transition_status(rule, as_of)
        completion, before_deadline, plan_note = _plan_estimate(
            str(finding.get("finding_id") or ""), plan, assessment_id, rule.get("deadline_effective_date")
        )
        source_records = _sources_for(rule, ruleset["sources_by_id"])
        return {
            **base, "rule_id": rule["id"], "status": status,
            "deadline_year": rule.get("deadline_year"),
            "deadline_effective_date": rule.get("deadline_effective_date"),
            "deprecated_effective_date": rule.get("deprecated_effective_date"),
            "warning_start_date": rule.get("warning_start_date"),
            "security_strength_bits": strength, "status_note": rule.get("status_note"), "reason": None,
            "plan_completion_date": completion, "plan_finishes_before_deadline": before_deadline,
            "plan_comparison_note": plan_note, "sources": source_records,
        }

    if unresolved:
        # If parameters are missing and multiple strength rules are candidates,
        # do not imply that the finding belongs to one specific strength band.
        reason_texts = {reason for _, reason, _ in unresolved}
        candidate_rules = [rule for rule, _, _ in unresolved]
        ambiguous = len(candidate_rules) > 1 and len(reason_texts) == 1 and all(
            rule.get("kind") == "public_key_strength" for rule in candidate_rules
        )
        if ambiguous:
            reason = next(iter(reason_texts))
            source_map: dict[str, dict[str, Any]] = {}
            for candidate in candidate_rules:
                for source in _sources_for(candidate, ruleset["sources_by_id"]):
                    source_map[source["id"]] = source
            return {
                **base, "rule_id": None, "rule_candidate_ids": [rule["id"] for rule in candidate_rules],
                "status": "not assessed", "deadline_year": None,
                "deadline_effective_date": None, "deprecated_effective_date": None,
                "warning_start_date": None, "security_strength_bits": None,
                "status_note": "More than one strength-specific rule could apply if parameters were known.",
                "reason": reason, "plan_completion_date": None,
                "plan_finishes_before_deadline": None,
                "plan_comparison_note": "No comparison because security strength is not known.",
                "sources": sorted(source_map.values(), key=lambda source: source["id"]),
            }
        rule, reason, strength = unresolved[0]
        return {
            **base, "rule_id": rule["id"], "rule_candidate_ids": [rule["id"]], "status": "not assessed",
            "deadline_year": rule.get("deadline_year"),
            "deadline_effective_date": rule.get("deadline_effective_date"),
            "deprecated_effective_date": rule.get("deprecated_effective_date"),
            "warning_start_date": rule.get("warning_start_date"),
            "security_strength_bits": strength, "status_note": rule.get("status_note"), "reason": reason,
            "plan_completion_date": None, "plan_finishes_before_deadline": None,
            "plan_comparison_note": "No comparison because the finding could not be matched to the rule parameters.",
            "sources": _sources_for(rule, ruleset["sources_by_id"]),
        }

    reason = "No sourced rule in this framework matched the algorithm, role, and available parameters."
    return {
        **base, "rule_id": None, "status": "not assessed", "deadline_year": None,
        "deadline_effective_date": None, "deprecated_effective_date": None,
        "warning_start_date": None, "security_strength_bits": None,
        "status_note": reason, "reason": reason, "plan_completion_date": None,
        "plan_finishes_before_deadline": None, "plan_comparison_note": "No applicable deadline.", "sources": [],
    }


def check_compliance(
    assessment: Any,
    *,
    migration_plan: Mapping[str, Any] | None = None,
    as_of: str | date | None = None,
    rules_path: str | None = None,
) -> dict[str, Any]:
    """Assess each finding under NIST IR 8547 and CNSA 2.0 rule families."""
    assessment_data = _plain(assessment)
    if not isinstance(assessment_data, Mapping):
        raise ComplianceAssessmentError("assessment must be an object or Pydantic model")
    if not isinstance(assessment_data.get("assessment_id"), str) or not assessment_data["assessment_id"]:
        raise ComplianceAssessmentError("assessment.assessment_id is required")
    findings = assessment_data.get("findings")
    if not isinstance(findings, list):
        raise ComplianceAssessmentError("assessment.findings must be a list")
    project_context = assessment_data.get("project_context", {})
    if not isinstance(project_context, Mapping):
        raise ComplianceAssessmentError("assessment.project_context must be an object")
    plan_data = _plain(migration_plan) if migration_plan is not None else None
    if plan_data is not None and not isinstance(plan_data, Mapping):
        raise ComplianceAssessmentError("migration_plan must be an object")
    when = _as_date(as_of)
    ruleset = load_rules(rules_path)
    results: list[dict[str, Any]] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, Mapping):
            raise ComplianceAssessmentError(f"assessment.findings[{index}] must be an object")
        if not finding.get("finding_id") or not finding.get("algorithm"):
            raise ComplianceAssessmentError(f"assessment.findings[{index}] needs finding_id and algorithm")
        category, category_source, scope, scope_source = _resolve_asset_context(project_context, finding)
        for framework in (FRAMEWORK_NIST, FRAMEWORK_CNSA):
            results.append(_evaluate_framework(
                finding, framework, ruleset, when, category, category_source, scope, scope_source,
                plan_data, str(assessment_data["assessment_id"]),
            ))

    status_names = ("compliant", "deprecated-soon", "past-deadline", "not assessed")
    statuses = {status: sum(result["status"] == status for result in results) for status in status_names}
    framework_summaries = {
        framework: {
            status: sum(result["framework"] == framework and result["status"] == status for result in results)
            for status in status_names
        }
        for framework in (FRAMEWORK_NIST, FRAMEWORK_CNSA)
    }
    # Keep the full versioned source register in every report. Matched rule rows
    # also include just their own sources, so consumers can trace individual claims.
    all_sources = sorted(ruleset["sources_by_id"].values(), key=lambda source: source["id"])
    warnings = [
        "This report is an engineering planning aid, not legal advice, a certification, or proof of system compliance.",
        "NIST IR 8547 is an Initial Public Draft in the cited source; matching dates are proposed draft guidance, not final requirements.",
        "CNSA transition rules apply only when cnsa_scope_confirmed is explicitly true; a system_category alone does not establish NSS applicability.",
        "This version assesses legacy classical-public-key transition rules for CNSA scope. It does not infer whether a system is new or legacy, and it does not verify capability support required for new commercial NSS from 2027 because that capability is not represented in assessment findings.",
        "Migration completion dates are estimates derived from plan timeline_months, not actual completion commitments.",
        "A status of compliant means only that the matched rule did not identify a transition warning/deadline as of the selected date; it does not mean overall system compliance.",
    ]
    return {
        "report_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": when.isoformat(),
        "assessment_id": assessment_data["assessment_id"],
        "migration_plan_id": plan_data.get("migration_plan_id") if isinstance(plan_data, Mapping) else None,
        "ruleset_version": ruleset["ruleset_version"],
        "ruleset_updated_on": ruleset["updated_on"],
        "summary": {
            "findings": len(findings), "results": len(results), "by_status": statuses,
            "by_framework": framework_summaries,
        },
        "scope": {
            "system_category": project_context.get("system_category"),
            "cnsa_scope_confirmed": project_context.get("cnsa_scope_confirmed"),
            "note": "Per-asset context overrides are resolved for each finding and shown on each result.",
        },
        "warnings": warnings,
        "results": results,
        "sources": all_sources,
    }
