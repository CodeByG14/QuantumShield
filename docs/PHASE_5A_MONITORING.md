# Phase 5A — Assessment monitoring

## Scope

Phase 5A adds file-based comparison of two QuantumShield assessment reports. It does not rescan a target, change risk scores, or require a database.

## CLI

```bash
python -m monitor.check \
  --baseline baseline.json \
  --current current.json \
  --output diff.json \
  --fail-on new-high \
  --fail-on coverage-drop:5
```

`--fail-on` may be repeated or contain comma-separated rules. Supported rules:

- `new-high`: fail when a newly added finding is high, very-high, or critical risk.
- `new-critical`: fail when a newly added finding is critical risk.
- `new-unable`: fail when a newly added finding has status `unable-to-analyze`.
- `coverage-drop:N`: fail when file coverage falls by at least `N` percentage points. `N=0` means any decrease. This is an absolute percentage-point change, not a relative percentage.

Exit codes: `0` means comparison succeeded and no configured threshold was breached; `1` means one or more configured thresholds were breached; `2` means input, validation, or report-writing failed.

Without `--fail-on`, the command writes a diff and exits zero if both reports are valid.

## Stable finding identity

The base key uses `algorithm | variant | curve | role | file | fingerprint`. Generated `finding_id`, `evidence_id`, source line numbers, and assessment timestamps are excluded. Certificate fingerprints are read from evidence metadata (for example, `fingerprint_sha256`) to keep multiple certificates in a bundle distinct. For collisions, a deterministic ordinal suffix is added using stable evidence details; line numbers are not part of the key.

When two otherwise-identical findings have the same prescribed identity fields and no fingerprint or other stable distinguishing evidence, they cannot be identified individually across arbitrary reordering. The ordinal suffix keeps them separate, but the input data provides no perfect cross-scan identity for truly indistinguishable duplicates.

## Comparison semantics

The diff reports added, removed, changed, and unchanged findings. For matched findings, change detection covers `status`, `confidence`, `risk_level`, `risk_score`, `role`, and `variant`. A changed algorithm, curve, file, or fingerprint produces a different identity and appears as a removal plus an addition. Because role and variant are also required change fields, a unique unmatched pair with the same algorithm + curve + file + fingerprint is correlated and reported as changed; ambiguous fallback groups are left as additions/removals. Coverage includes the absolute change in `file_coverage_percent` in percentage points and deltas for available file counts.

Output summaries intentionally omit evidence excerpts to avoid copying source-code snippets into a second report. They retain file paths, fingerprints, and rule identifiers needed to locate findings.

## Validation

Tests cover line shifts, ordinal finding IDs, multiple certificates in one file, key collisions, added/removed/changed findings, coverage changes, threshold handling, invalid input, and CLI exit codes.
