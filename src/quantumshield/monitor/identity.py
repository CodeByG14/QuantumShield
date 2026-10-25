"""Stable identities for cryptographic findings across repeated scans.

Finding IDs such as CRYPTO-001 are ordinal and can change when files or findings
are inserted. Monitoring therefore identifies an asset from algorithm,
variant, curve, role, file path, and (when available) a certificate fingerprint.
Line numbers and transient finding/evidence IDs are deliberately excluded.
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from collections import defaultdict
from pathlib import PurePosixPath
from typing import Any, Mapping


_FINGERPRINT_FIELDS = (
    "fingerprint_sha256",
    "sha256_fingerprint",
    "fingerprint",
    "certificate_fingerprint",
)


def _text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _segment(value: Any, *, case_insensitive: bool = True) -> str:
    text = _text(value)
    if case_insensitive:
        text = text.casefold()
    # A literal separator must not create a structurally ambiguous key.
    return text.replace("%", "%25").replace("|", "%7c")


def _normalise_path(value: Any, target: str | None = None) -> str:
    path = _text(value).replace("\\", "/")
    if not path:
        return "<no-file>"
    path = posixpath.normpath(path)
    target_path = posixpath.normpath((target or "").replace("\\", "/"))
    if target_path and posixpath.isabs(path):
        try:
            common = posixpath.commonpath((path, target_path))
        except ValueError:
            common = ""
        if common == target_path:
            path = posixpath.relpath(path, target_path)
    return path or "."


def _evidence_parts(finding: Mapping[str, Any], target: str | None) -> list[dict[str, Any]]:
    evidence = finding.get("evidence") or []
    parts: list[dict[str, Any]] = []
    for item in evidence:
        if not isinstance(item, Mapping):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), Mapping) else {}
        fingerprint = ""
        for field in _FINGERPRINT_FIELDS:
            if metadata.get(field):
                fingerprint = _text(metadata[field]).casefold().replace(":", "")
                break
        parts.append(
            {
                "file": _normalise_path(item.get("file_path"), target),
                "fingerprint": fingerprint,
                "evidence_type": _text(item.get("evidence_type")),
                "detection_method": _text(item.get("detection_method")),
                "rule_id": _text(item.get("rule_id")),
                "excerpt": " ".join(_text(item.get("excerpt")).split()),
                "metadata": {
                    str(k): str(v)
                    for k, v in sorted(metadata.items(), key=lambda pair: str(pair[0]))
                    if str(k).casefold() not in {"line", "line_start", "line_end"}
                },
                # These are used only to keep an evidence representative stable;
                # they do not appear in the identity key or tie-break digest.
                "_sort_line": item.get("line_start") if isinstance(item.get("line_start"), int) else 0,
            }
        )
    parts.sort(key=lambda e: (e["file"], e["fingerprint"], _evidence_sort_key(e), e["_sort_line"]))
    return parts


def _evidence_sort_key(evidence: Mapping[str, Any]) -> str:
    stable = {
        key: value
        for key, value in evidence.items()
        if not key.startswith("_")
    }
    return json.dumps(stable, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _base_components(finding: Mapping[str, Any], target: str | None = None) -> tuple[str, ...]:
    evidence = _evidence_parts(finding, target)
    primary = evidence[0] if evidence else {"file": "<no-file>", "fingerprint": ""}
    return (
        _segment(finding.get("algorithm", "unknown")),
        _segment(finding.get("variant")),
        _segment(finding.get("curve")),
        _segment(finding.get("role", "undetermined")),
        _segment(primary.get("file", "<no-file>"), case_insensitive=False),
        _segment(primary.get("fingerprint", "")),
    )


def stable_finding_key(finding: Mapping[str, Any], *, target: str | None = None) -> str:
    """Return the prescribed base key, excluding line and generated IDs."""
    return "|".join(_base_components(finding, target))


def stable_finding_anchor(finding: Mapping[str, Any], *, target: str | None = None) -> str:
    """Return a cautious fallback anchor for a unique role/variant change.

    The primary key is the specified six-field key. Since role and variant are
    also fields the diff must classify as changed, a unique unmatched pair may
    be correlated by algorithm, curve, file, and fingerprint. Ambiguous groups
    are intentionally not correlated.
    """
    components = _base_components(finding, target)
    algorithm, _variant, curve, _role, file_path, fingerprint = components
    return "|".join((algorithm, curve, file_path, fingerprint))


def _collision_hint(finding: Mapping[str, Any], target: str | None = None) -> str:
    """Return a deterministic tie-breaker that ignores line and generated IDs."""
    evidence = _evidence_parts(finding, target)
    stable_evidence = []
    for item in evidence:
        stable_evidence.append({key: val for key, val in item.items() if not key.startswith("_")})
    payload = {
        "evidence": stable_evidence,
        "purpose": finding.get("purpose"),
        "key_size": finding.get("key_size"),
        "assumptions": sorted(str(x) for x in (finding.get("assumptions") or [])),
        "evidence_gap_reason": finding.get("evidence_gap_reason"),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def assign_stable_keys(
    findings: list[Mapping[str, Any]], *, target: str | None = None
) -> list[tuple[str, Mapping[str, Any]]]:
    """Pair findings with stable keys and collision suffixes.

    Collisions are ordered by a digest of non-positional evidence. If two
    findings are byte-for-byte equivalent except for generated IDs and line
    numbers, their order is immaterial to the report; an ordinal suffix still
    keeps both occurrences distinct.
    """
    groups: dict[str, list[tuple[str, int, Mapping[str, Any]]]] = defaultdict(list)
    for index, finding in enumerate(findings):
        base = stable_finding_key(finding, target=target)
        groups[base].append((_collision_hint(finding, target), index, finding))

    keyed: list[tuple[str, Mapping[str, Any]] | None] = [None] * len(findings)
    for base, entries in groups.items():
        entries.sort(key=lambda entry: (entry[0], entry[1]))
        for ordinal, (_, original_index, finding) in enumerate(entries, start=1):
            key = f"{base}#{ordinal}" if len(entries) > 1 else base
            keyed[original_index] = (key, finding)

    # Every original element receives exactly one assigned key.
    return [item for item in keyed if item is not None]
