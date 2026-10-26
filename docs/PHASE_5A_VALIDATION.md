# Phase 5A validation record

## Functional checks

The user-reported local run on the Phase 5A branch completed with:

- Focused Phase 5A tests: **17 passed**.
- Full suite before Phase 5B: **364 passed, 4 warnings**.
- Self-diff of the same assessment: **0 added, 0 removed, 0 changed, 22 unchanged**.
- Coverage delta for that self-diff: **0 percentage points** (90% to 90%).

The four warnings are about asset context selected by ordinal `CRYPTO-###` finding identifiers. They are non-fatal; path-based asset identifiers and glob patterns are more stable.

## Additional independent verification

The isolated validation snapshot also passed the 17 Phase 5A tests. Its full suite had two unrelated environment/baseline failures:

- `tests/test_tls_scanner.py::test_connection_timeout` received `Connection refused` rather than a timeout from the sandbox network.
- `tests/test_transition_benchmark.py::TestRunBenchmarks::test_run_benchmarks_fake_backend` expected 9 classical-signature results, while the isolated snapshot returned 11.

These two failures were also present before the Phase 5B implementation in this snapshot; they are not reported as Phase 5A or Phase 5B regressions.

## Packaging check

A wheel build could not be completed in the isolated environment because `uv_build` was not cached and the environment could not reach the package index. Run `uv build --wheel` in the local development environment and inspect the wheel for `quantumshield/monitor/` before treating wheel packaging as verified.
