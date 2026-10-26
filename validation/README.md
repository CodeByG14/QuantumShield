# QuantumShield Phase 7 validation

Run from the repository root:

```bash
uv run pytest -q tests/test_validation_metrics.py tests/test_validation_spec.py tests/test_validation_workflows.py
uv run python -m validation.run
```

The harness uses the real QuantumShield command-line interface. It performs four controlled activities:

1. Scan the ground-truth synthetic corpus and calculate detection metrics.
2. Validate source-project and already-extracted root-filesystem coverage independently.
3. Generate and inspect a migration plan, including task/action summary consistency.
4. Run two deterministic workflow checks: a clean project gains one `hashlib.md5` call, and a known RSA-2048 compliance assessment is evaluated alongside a 24-month migration task.

JSON and Markdown reports are written beneath `validation/out/`. Controlled workflow artifacts are written to `validation/out/change_detection/` and `validation/out/compliance/`.

## Ground-truth and metric rules

- `validation/expected.yaml` is authored independently of scanner output; do not derive labels from the scan results being evaluated.
- Every non-hidden source-project file and every rootfs file must have a label.
- Findings are matched by normalized evidence path and algorithm; labelled status and variant are also matched when specified.
- `unable-to-analyze` results are inconclusive and are not silently treated as successful detections.
- The report measures selected regression-backed conformance cases, not population-level real-world accuracy.

## Change-detection check

The workflow scans two temporary synthetic projects. Both contain the same clean `app.py`; only the current project includes `legacy_crypto.py` with a known MD5 call. The public `diff` command is expected to report exactly one added MD5 finding, with no removed or changed findings.

## Compliance check

A controlled RSA-2048 fixture is evaluated as of `2031-01-01`. The selected regression boundary expects NIST IR 8547 rule `NIST-IR8547-PUBLICKEY-112` to return `deprecated-soon`. Its linked migration plan has a 24-month timeline, so the expected completion date is `2033-01-01`, before the rule's deadline. The harness also verifies both compliance reports exist and the Markdown includes the expected NIST IR 8547 source link.

These are deterministic regression checks, not a substitute for expert review of compliance applicability or legal interpretation.

## Limitations and remaining acceptance work

This harness is a controlled conformance suite, not a statistically representative estimate of real-world detection accuracy. It does not yet replace the final independent end-to-end acceptance project. The final acceptance project should be independently authored, have expected results defined before scanning, and cover the real pipeline without executing untrusted project code or performing live network scanning. Review all inconclusive and unsupported inputs rather than treating them as passes.
