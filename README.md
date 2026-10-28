# QuantumShield

QuantumShield is a research and demonstration framework for cryptographic discovery, post-quantum risk assessment, migration planning, and local algorithm benchmarking. It produces advisory outputs; it does not automatically change production cryptography or certify regulatory compliance.

## Current capabilities

- Static source and dependency-manifest discovery.
- X.509 certificate and key metadata analysis without recording private key material.
- Explicit, bounded TLS endpoint checks for supplied `host:port` values only.
- Versioned risk assessment and asset-context overrides.
- Migration recommendations and a JSON migration plan.
- Assessment comparison and a preliminary migration-readiness advisory.
- Post-quantum algorithm round-trip checks and micro-benchmarks through supported OpenSSL or optional `liboqs` backends.
- Optional local TLS 1.3 handshake timing through the OpenSSL backend. This measures command-level latency, including process startup, not pure in-process cryptographic latency.

## Requirements and installation

- Python 3.12 or newer.
- Dependencies declared in `pyproject.toml`.
- For real post-quantum operations, a compatible OpenSSL build (the tested backend requires OpenSSL 3.5 or newer) or an installed `liboqs` Python binding. The fake backend is for tests only and its output is explicitly labelled simulated.

```bash
uv sync
uv run pytest -q
```

## End-to-end commands

```bash
# Scan source and produce assessment.json
uv run quantumshield scan ./samples/test-repo -o assessment.json

# Build a migration plan from that assessment
uv run quantumshield plan assessment.json -o migration_plan.json

# Probe only explicitly supplied TLS endpoints (certificate verification is on by default)
uv run quantumshield tls --endpoints example.com:443 -o tls.json

# Disable certificate verification only for deliberate inspection of a test endpoint
uv run quantumshield tls --endpoints 127.0.0.1:8443 --no-verify-cert

# Compare assessments
uv run quantumshield diff baseline.json assessment.json -o diff.json

# Produce a preliminary migration-readiness advisory; this is not compliance certification
uv run quantumshield compliance assessment.json -o compliance_advisory.json

# Assess a supplied CycloneDX/SPDX SBOM explicitly without treating arbitrary JSON as a project scan
uv run quantumshield sbom ./path/to/sbom.json --context project-context.yaml -o assessment-sbom.json

# Build a migration plan from that assessment
uv run quantumshield plan assessment-sbom.json -o plan-sbom.json

# Evaluate compliance with the generated plan (generate it before compliance)
uv run quantumshield compliance assessment-sbom.json --plan plan-sbom.json -o compliance-sbom.json --markdown-output compliance-sbom.md

# Benchmark real backend if available; fake is useful for tests but not performance claims
uv run quantumshield benchmark --backend auto --iterations 100 --warmup 10 -o benchmark_results.json
uv run quantumshield benchmark --backend fake --iterations 2 --warmup 0 -o simulated_benchmark.json

# Include local TLS handshake measurements when OpenSSL supports the requested groups
uv run quantumshield benchmark --backend openssl --include-tls --iterations 10 -o benchmark_with_tls.json
```

The `scan --tls` option accepts repeatable explicit endpoints. A TLS observation that cannot be obtained reliably remains unknown; the scanner does not infer a TLS 1.3 key-exchange group from the cipher suite.

## Architecture

The canonical application package lives under `src/quantumshield/`:

- `common/`: shared validated data models.
- `discovery/`: source, manifest, X.509, TLS, and inventory pipeline.
- `scoring/`: policy, risk assessment, and migration planning.
- `transition/`: cryptographic backends and benchmarking.
- `monitor/`: assessment comparison.
- `compliance/`: explicitly preliminary migration-readiness advisory.
- `agility/`, `validation/`: reserved extension points; not all planned capabilities in these areas are implemented yet.

## Important limitations

- Static discovery cannot prove that every cryptographic use has been found. “Not detected” is scope-limited.
- No general runtime scanning, port sweeping, or network-range discovery is performed.
- Migration advice is advisory and must be validated against application protocols, interoperability, key lifecycle, and applicable standards.
- Compliance output is not a legal, contractual, or formal NIST/CNSA compliance determination. Applicable requirements and deadlines require separate verification.
- Migration waves and timeline estimates are planning assumptions, not universal deadlines.
- TLS handshake benchmark latency includes launching an OpenSSL client process; do not compare it directly with in-process library benchmarks.
- The fake backend produces simulated test data and must not be used to make performance claims.

## Development

```bash
uv run pytest -q
uv run quantumshield --help
```

## Compliance assessment (Phase 5)

Compliance outputs are sourced planning guidance, not certification. NIST IR 8547 is labelled as draft guidance in the ruleset; CNSA/NSS rules are assessed only when `cnsa_scope_confirmed: true` is explicitly supplied with an applicable `system_category`. See `docs/PHASE_5B_COMPLIANCE.md` for rule provenance and limitations.
