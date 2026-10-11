"""
Detection rule loading and validation.

Rules live in patterns.yaml. Loading validates every rule (regexes compile,
capture groups are sane, ids are unique) so a broken rule fails at start-up,
not silently at scan time.
"""

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, model_validator

from common.models import CryptoRole, EvidenceType


class Language(str, Enum):
    PYTHON = "python"
    JAVA = "java"
    ANY = "any"


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    language: Language
    algorithm: str
    role: CryptoRole = CryptoRole.UNDETERMINED
    evidence_type: EvidenceType  # api-call | keyword | curve-parameter
    regex: str
    ignorecase: bool = False
    size_regex: str | None = None  # exactly one group: the key size
    curve_regex: str | None = None  # exactly one group: the curve name
    variant: str | None = None  # fixed variant, e.g. "MD5"
    curve: str | None = None  # fixed curve
    # What an API-call rule is expected to resolve. If it cannot, confidence is MEDIUM.
    needs: Literal["size", "curve"] | None = None

    @model_validator(mode="after")
    def _check(self):
        if self.evidence_type not in (
            EvidenceType.API_CALL,
            EvidenceType.KEYWORD,
            EvidenceType.CURVE_PARAMETER,
        ):
            raise ValueError(
                f"{self.id}: evidence_type must be api-call, keyword, or curve-parameter"
            )
        if self.evidence_type != EvidenceType.API_CALL and self.needs:
            raise ValueError(f"{self.id}: only api-call rules can declare 'needs'")

        flags = re.IGNORECASE if self.ignorecase else 0
        for label, pattern in (
            ("regex", self.regex),
            ("size_regex", self.size_regex),
            ("curve_regex", self.curve_regex),
        ):
            if pattern is None:
                continue
            try:
                compiled = re.compile(pattern, flags)
            except re.error as exc:
                raise ValueError(f"{self.id}: {label} does not compile: {exc}") from exc
            if label != "regex" and compiled.groups != 1:
                raise ValueError(
                    f"{self.id}: {label} must have exactly one capture group"
                )
        return self


@dataclass(frozen=True)
class CompiledRule:
    rule: Rule
    pattern: re.Pattern
    size_pattern: re.Pattern | None
    curve_pattern: re.Pattern | None


def load_rules(path: str | Path) -> list[CompiledRule]:
    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    compiled: list[CompiledRule] = []
    seen: set[str] = set()
    for entry in raw["rules"]:
        rule = Rule.model_validate(entry)
        if rule.id in seen:
            raise ValueError(f"duplicate rule id: {rule.id}")
        seen.add(rule.id)
        flags = re.IGNORECASE if rule.ignorecase else 0
        compiled.append(
            CompiledRule(
                rule=rule,
                pattern=re.compile(rule.regex, flags),
                size_pattern=(
                    re.compile(rule.size_regex, flags) if rule.size_regex else None
                ),
                curve_pattern=(
                    re.compile(rule.curve_regex, flags) if rule.curve_regex else None
                ),
            )
        )
    return compiled
