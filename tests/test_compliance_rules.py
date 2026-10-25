from __future__ import annotations

from copy import deepcopy

import pytest
import yaml

from quantumshield.compliance.rules import (
    ComplianceRulesError,
    DEFAULT_RULES_PATH,
    load_rules,
    validate_ruleset,
)


def _raw_rules():
    return yaml.safe_load(DEFAULT_RULES_PATH.read_text(encoding="utf-8"))


def test_default_ruleset_loads_with_versioned_sources_and_rules():
    rules = load_rules()
    assert rules["ruleset_version"]
    assert rules["updated_on"]
    assert rules["rules"]
    assert rules["sources_by_id"]
    for rule in rules["rules"]:
        assert rule["source_ids"]
        assert set(rule["source_ids"]).issubset(rules["sources_by_id"])


def test_every_rule_must_cite_at_least_one_known_source():
    data = deepcopy(_raw_rules())
    data["rules"][0]["source_ids"] = []
    with pytest.raises(ComplianceRulesError, match="must reference at least one source"):
        validate_ruleset(data)

    data = deepcopy(_raw_rules())
    data["rules"][0]["source_ids"] = ["unknown-source"]
    with pytest.raises(ComplianceRulesError, match="unknown source"):
        validate_ruleset(data)


def test_sources_require_https_provenance_and_publication_status():
    data = deepcopy(_raw_rules())
    data["sources"][0]["url"] = "http://example.invalid/source"
    with pytest.raises(ComplianceRulesError, match="HTTPS"):
        validate_ruleset(data)

    data = deepcopy(_raw_rules())
    data["sources"][0]["publication_status"] = "final-ish"
    with pytest.raises(ComplianceRulesError, match="publication_status"):
        validate_ruleset(data)


def test_bad_rule_date_is_rejected():
    data = deepcopy(_raw_rules())
    data["rules"][0]["deadline_effective_date"] = "2036/01/01"
    with pytest.raises(ComplianceRulesError, match="ISO date"):
        validate_ruleset(data)


def test_duplicate_rule_ids_are_rejected():
    data = deepcopy(_raw_rules())
    data["rules"].append(deepcopy(data["rules"][0]))
    with pytest.raises(ComplianceRulesError, match="duplicate rule id"):
        validate_ruleset(data)
