import pytest
import yaml
from pydantic import ValidationError

from discovery.pipeline import DEFAULT_RULES
from discovery.rules import Rule, load_rules


def test_shipped_rules_load_and_ids_are_unique():
    rules = load_rules(DEFAULT_RULES)
    ids = [r.rule.id for r in rules]
    assert len(ids) == len(set(ids)) > 20


def base(**kw):
    d = dict(id="X-1", language="python", algorithm="RSA", evidence_type="api-call", regex=r"foo\(")
    d.update(kw)
    return d


def test_bad_regex_is_rejected():
    with pytest.raises(ValidationError):
        Rule(**base(regex="foo("))


def test_size_regex_needs_exactly_one_group():
    with pytest.raises(ValidationError):
        Rule(**base(size_regex=r"\d+"))
    with pytest.raises(ValidationError):
        Rule(**base(size_regex=r"(\d)(\d)"))
    Rule(**base(size_regex=r"(\d+)"))


def test_keyword_rule_cannot_declare_needs():
    with pytest.raises(ValidationError):
        Rule(**base(evidence_type="keyword", needs="size"))


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        Rule(**base(colour="red"))


def test_duplicate_ids_are_rejected(tmp_path):
    p = tmp_path / "r.yaml"
    p.write_text(yaml.safe_dump({"rules": [base(), base()]}))
    with pytest.raises(ValueError, match="duplicate rule id"):
        load_rules(p)


def test_curve_parameter_rule_cannot_require_api_resolution():
    with pytest.raises(ValidationError):
        Rule(**base(evidence_type="curve-parameter", needs="curve"))


def test_curve_parameter_evidence_type_is_supported():
    rule = Rule(**base(evidence_type="curve-parameter"))
    assert rule.evidence_type.value == "curve-parameter"
