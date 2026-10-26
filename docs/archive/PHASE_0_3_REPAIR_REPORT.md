# QuantumShield Phase 0–3 Repair Report

**Prepared:** 2026-10-25  
**Basis:** Review and modification of the supplied `quantumshield(1).zip` source archive.  
**Scope:** Core package, discovery, risk assessment, migration planning, command-line integration, and Phase 3 cryptographic benchmarking.

## Summary

The canonical implementation is now `src/quantumshield/`. Duplicate top-level copies of the same core packages were removed from this clean source distribution so that tests and command-line entry points target one implementation.

## Changes made

### Phase 0 — Foundations

- Changed pytest's Python path to `src` so tests exercise the packaged implementation.
- Replaced the package `__init__.py` duplicate CLI implementation with package metadata.
- Corrected internal imports in the CBOM writer and assessment writer to use `quantumshield.*` imports.
- Replaced broad path matching with segment-aware glob matching: `*` and `?` do not cross path separators, while `**` can match nested directories.
- Added migration registry validation for duplicate IDs, missing dependency references, and dependency cycles.
- Removed `.git`, local agent settings, Python caches, and generated assessment/report files from the delivered source archive. The original uploaded ZIP was not modified.

### Phase 1 — Discovery and TLS

- Kept certificate parsing and endpoint scanning within the canonical package.
- Removed fallback parsing that labelled a TLS group as inferred from less-specific output. The negotiated group is now either observed from the explicit OpenSSL output pattern or left unknown.
- Made certificate verification the default for the standalone TLS command. Disabling it requires the explicit `--no-verify-cert` option.
- Added endpoint parsing and validation for host/port syntax, port range, and bracketed IPv6 literals.
- Replaced a network-dependent timeout test with a deterministic mocked socket timeout.

### Phase 2 — Risk and migration planning

- Low-confidence or potential findings are downgraded to low-confidence manual review rather than automatic migration.
- Added `action_type` to each serialized migration task.
- Retained summary counts based on explicit action types and verified that task counts reconcile with the summary.
- Added regression coverage for dependency-cycle rejection and low-confidence recommendation handling.

### Phase 3 — Transition and benchmarking

- Repaired the benchmark command to use the canonical `quantumshield.transition` package and pass a selected backend.
- Added backend selection (`auto`, `openssl`, `oqs`, `fake`) and optional TLS benchmarking flags to the main CLI.
- Benchmark output records backend name/version and explicitly labels fake-backend output as simulated test data.
- Implemented the OpenSSL TLS 1.3 handshake benchmark using a temporary local server and certificate. It only accepts loopback hosts and documents that timing includes launching the OpenSSL client process.
- Added a preliminary migration-readiness advisory command. Its output explicitly states that it is **not** a formal NIST or CNSA compliance determination.
- Added assessment-diff support using an evidence-derived heuristic key, with an advisory that location/evidence changes can affect comparisons.

## Verification performed

| Check | Result |
|---|---|
| Automated tests | **263 passed, 4 warnings** |
| Python compile check (`python -m compileall -q src tests`) | Passed |
| Source scan of `samples/test-repo` | Passed; valid assessment JSON generated |
| Migration plan generation | Passed; 20 tasks generated in the sample run |
| Migration action summary | Reconciled to all generated tasks; each task contains `action_type` |
| Assessment diff command | Passed; valid JSON generated |
| Preliminary compliance-advisory command | Passed; valid JSON generated |
| Fake benchmark CLI | Passed; output clearly labelled simulated |
| OpenSSL benchmark CLI with TLS enabled | Passed in this environment using OpenSSL 3.5.5; 36 benchmark records, including TLS 1.3 measurements for `X25519` and `X25519MLKEM768` |
| Clean package installation | **Not verified**: the audit environment could not obtain the declared build backend while offline and did not have the project's Python 3.12 interpreter available |

The four warnings are expected warnings from tests that deliberately match context by positional finding IDs; path-based asset matching is preferred for stable cross-scan results.

## Important limitations that remain

1. The clean package installation path must be verified on a machine with Python 3.12 and the declared build backend available. The passing tests were run directly against `src/` on Python 3.13.5 in the available environment.
2. TLS key-exchange group reporting depends on what the installed OpenSSL version exposes. When the output does not provide a trustworthy group, QuantumShield records it as unknown. TLS 1.2 group discovery is not inferred from the cipher suite.
3. The TLS benchmark measures OpenSSL command-level latency, including process startup; it is not a pure in-process cryptographic microbenchmark.
4. The compliance command is a preliminary advisory only. It does not implement authoritative, applicability-aware NIST IR 8547 or CNSA 2.0 rule evaluation and must not be described as certification.
5. A full web frontend, API service, database persistence, user/authentication model, cryptographic-agility orchestration, and production monitoring are not completed by this core-logic repair.
6. Migration recommendations remain advisory and require validation against the target protocol, libraries, compatibility constraints, and applicable standards.

## Recommended next step

Run `uv sync` and `uv run pytest -q` on the target development machine using Python 3.12. Then perform a local controlled TLS scan and review the generated assessment, CBOM, and migration plan before treating this as a release candidate.
