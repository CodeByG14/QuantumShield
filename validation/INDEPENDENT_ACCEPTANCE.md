# Independent Phase 7 acceptance workflow

This workflow runs the separately labelled fictional acceptance project rather than the small regression corpus used by `python -m validation.run`.

## Prerequisites

From the repository root, verify these files exist:

- `validation/acceptance_expected.yaml`
- `validation/acceptance_context.yaml`
- `validation/acceptance_project/`, including `certs/server.pem`
- `validation/acceptance_rootfs/usr/lib/libssl.so.3`
- `validation/acceptance_rootfs/usr/lib/libnss3.so`

## Run

```bash
uv run pytest -q tests/test_validation_acceptance.py
uv run python -m validation.acceptance
```

The evaluation date is fixed to `2026-10-26` by default for repeatability. To use another deliberate date, pass `--as-of YYYY-MM-DD`.

## Outputs

The runner replaces only `validation/out/acceptance_e2e/` and writes:

- `acceptance_report.json` and `acceptance_report.md`
- `acceptance_assessment.json`
- `acceptance_plan.json`
- `acceptance_compliance.json` and `acceptance_compliance.md`
- `change_detection/diff.json`, plus baseline/current assessment files

The baseline scan is compared with a temporary copy of the project that has exactly one new `hashlib.sha256` call. The expected diff is one added SHA-256 finding, zero removed, zero changed, and twelve unchanged findings.

The labelled README text file is unsupported by the scanner. The report therefore marks that negative control as unverified rather than claiming its contents were analyzed. The plain-text `.p12` fixture generates a potential extension-based finding but is not a real keystore and its contents are not parsed.

The acceptance project is scanned as data. Its code is never executed. The root filesystem passed to `--rootfs` is a separate, already-extracted fixture; no live host or network scan is performed. Results are conformance checks for the documented cases and are not a statistical estimate of real-world accuracy.
