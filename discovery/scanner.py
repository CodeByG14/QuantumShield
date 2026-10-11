"""
Source-code stage: apply detection rules to one Python or Java file.

Confidence rules (see patterns.yaml):
  api-call, parameters resolved   -> HIGH   (finding CONFIRMED)
  api-call, parameters unresolved -> MEDIUM (finding POTENTIAL)
  curve-parameter configuration   -> LOW    (finding POTENTIAL unless corroborated)
  keyword                         -> LOW    (finding POTENTIAL)
  any match inside a comment      -> LOW comment-mention (finding POTENTIAL)

Known limits (AST analysis is the real fix):
  * Python docstrings spanning several lines are not recognised as comments.
  * Java key size / curve set in a later statement is not linked to the generator.
"""

import re
from bisect import bisect_right
from dataclasses import dataclass

from common.models import (
    Confidence,
    CryptoFinding,
    CryptoRole,
    DetectionMethod,
    Evidence,
    EvidenceType,
    FindingStatus,
)
from discovery.curves import normalize_curve
from discovery.rules import CompiledRule, Language
from discovery.stage import StageOutput

LANGUAGE_BY_SUFFIX = {".py": Language.PYTHON, ".java": Language.JAVA}


# --------------------------------------------------------------------------
# Comment detection
# --------------------------------------------------------------------------


def _python_comment_spans(lines: list[str]) -> list[list[tuple[int, int]]]:
    spans: list[list[tuple[int, int]]] = []
    for line in lines:
        found: list[tuple[int, int]] = []
        in_str: str | None = None
        i = 0
        while i < len(line):
            ch = line[i]
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
            elif ch in "\"'":
                in_str = ch
            elif ch == "#":
                found.append((i, len(line)))
                break
            i += 1
        spans.append(found)
    return spans


def _java_comment_spans(lines: list[str]) -> list[list[tuple[int, int]]]:
    spans: list[list[tuple[int, int]]] = []
    in_block = False
    for line in lines:
        found: list[tuple[int, int]] = []
        start = 0 if in_block else None
        in_str: str | None = None
        i, n = 0, len(line)
        while i < n:
            ch = line[i]
            if in_block:
                if line.startswith("*/", i):
                    found.append((start, i + 2))
                    in_block, start = False, None
                    i += 2
                    continue
                i += 1
                continue
            if in_str:
                if ch == "\\":
                    i += 2
                    continue
                if ch == in_str:
                    in_str = None
                i += 1
                continue
            if ch in "\"'":
                in_str = ch
            elif line.startswith("//", i):
                found.append((i, n))
                break
            elif line.startswith("/*", i):
                in_block, start = True, i
                i += 2
                continue
            i += 1
        if in_block and start is not None:
            found.append((start, n))
        spans.append(found)
    return spans


def _comment_spans(lines: list[str], language: Language):
    return _python_comment_spans(lines) if language == Language.PYTHON else _java_comment_spans(lines)


# --------------------------------------------------------------------------
# Matching
# --------------------------------------------------------------------------


@dataclass
class _Hit:
    rule_id: str
    algorithm: str
    variant: str | None
    key_size: int | None
    curve: str | None
    role: CryptoRole
    evidence: Evidence
    from_call_rule: bool  # produced by an api-call rule (even if it sits in a comment)

    @property
    def is_call(self) -> bool:
        return self.evidence.evidence_type == EvidenceType.API_CALL


def _find_hits(text: str, rel_path: str, language: Language, rules: list[CompiledRule]) -> list[_Hit]:
    lines = text.split("\n")
    starts = [0]
    for line in lines[:-1]:
        starts.append(starts[-1] + len(line) + 1)
    spans = _comment_spans(lines, language)

    hits: list[_Hit] = []
    for cr in rules:
        rule = cr.rule
        if rule.language not in (language, Language.ANY):
            continue
        for m in cr.pattern.finditer(text):
            matched = m.group(0)
            first = bisect_right(starts, m.start()) - 1
            last = bisect_right(starts, max(m.end() - 1, m.start())) - 1
            col = m.start() - starts[first]
            in_comment = any(s <= col < e for s, e in spans[first])

            size = None
            if cr.size_pattern and (sm := cr.size_pattern.search(matched)):
                size = int(sm.group(1))
            curve = rule.curve
            if cr.curve_pattern and (cm := cr.curve_pattern.search(matched)):
                curve = normalize_curve(cm.group(1))

            if rule.variant:
                variant = rule.variant
            elif size:
                variant = f"{rule.algorithm}-{size}"
            else:
                # Curves are parameters of an algorithm family, not algorithm
                # variants. Keep them in CryptoFinding.curve / CBOM properties.
                variant = None

            if in_comment:
                etype, conf = EvidenceType.COMMENT_MENTION, Confidence.LOW
            elif rule.evidence_type == EvidenceType.KEYWORD:
                etype, conf = EvidenceType.KEYWORD, Confidence.LOW
            elif rule.evidence_type == EvidenceType.CURVE_PARAMETER:
                # A named curve is evidence of a parameter/configuration, not
                # proof by itself that a cryptographic operation uses it.
                etype, conf = EvidenceType.CURVE_PARAMETER, Confidence.LOW
            else:
                resolved = (
                    rule.needs is None
                    or (rule.needs == "size" and size is not None)
                    or (rule.needs == "curve" and curve is not None)
                )
                etype = EvidenceType.API_CALL
                conf = Confidence.HIGH if resolved else Confidence.MEDIUM

            hits.append(
                _Hit(
                    rule_id=rule.id,
                    algorithm=rule.algorithm,
                    variant=variant,
                    key_size=size,
                    curve=curve,
                    role=rule.role,
                    from_call_rule=rule.evidence_type == EvidenceType.API_CALL,
                    evidence=Evidence(
                        file_path=rel_path,
                        line_start=first + 1,
                        line_end=last + 1,
                        evidence_type=etype,
                        detection_method=DetectionMethod.REGEX,
                        rule_id=rule.id,
                        excerpt=matched,
                        confidence=conf,
                    ),
                )
            )
    return hits


def scan_source(text: str, rel_path: str, language: Language, rules: list[CompiledRule]) -> StageOutput:
    hits = _find_hits(text, rel_path, language, rules)

    # A keyword hit on a line an api-call rule already matched (same algorithm)
    # adds nothing, whether or not that line is a comment.
    covered = {
        (h.algorithm, line)
        for h in hits
        if h.from_call_rule
        for line in range(h.evidence.line_start, h.evidence.line_end + 1)
    }
    hits = [h for h in hits if h.from_call_rule or (h.algorithm, h.evidence.line_start) not in covered]

    # Weak evidence is redundant where the same file already has a real call
    # for that algorithm.
    called = {h.algorithm for h in hits if h.is_call}
    hits = [
        h for h in hits
        if h.is_call
        or h.evidence.evidence_type == EvidenceType.CURVE_PARAMETER
        or h.algorithm not in called
    ]

    groups: dict[tuple, list[_Hit]] = {}
    for h in hits:
        groups.setdefault((h.algorithm, h.variant, h.curve, h.role), []).append(h)

    findings: list[CryptoFinding] = []
    for (algorithm, variant, curve, role), members in groups.items():
        seen: set[tuple[str, int | None]] = set()
        evidence: list[Evidence] = []
        for h in sorted(members, key=lambda x: (x.evidence.line_start, x.rule_id)):
            key = (h.rule_id, h.evidence.line_start)
            if key not in seen:  # one record per (rule, line)
                seen.add(key)
                evidence.append(h.evidence)
        strong = any(
            e.confidence == Confidence.HIGH and e.evidence_type != EvidenceType.COMMENT_MENTION
            for e in evidence
        )
        findings.append(
            CryptoFinding(
                algorithm=algorithm,
                variant=variant,
                key_size=next((h.key_size for h in members if h.key_size), None),
                curve=curve,
                role=role,
                status=FindingStatus.CONFIRMED if strong else FindingStatus.POTENTIAL,
                evidence=evidence,
            )
        )
    return StageOutput(findings=findings)
