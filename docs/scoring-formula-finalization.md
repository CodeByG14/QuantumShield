# QuantumShield — Scoring Formula Finalization (Week 3)

**Date:** 2026-09-27
**Status:** Locked for Week 3 implementation

---

## 1. Formula — Confirmed, No Changes

The v1 formula drafted in Week 2 (`qri-formula-draft.md`) stands as-is:

```
Algorithm_Risk_Score = Quantum_Factor × Confidence_Level
```

No refinement needed at this stage — it remains deliberately simple because organisational HNDL context (data retention, sector criticality) is not yet available. See `quantum-factor-lookup-table.md` for the expanded factor table this now plugs into.

---

## 2. Output Format Decision (Required for `qri_engine.py`)

**Decision: separate `scored_output.json` file. Do NOT patch the score back into `cbom.json`.**

### Reasoning

1. **Schema purity.** CycloneDX 1.6's `cryptographic-asset` component has no native field for a custom risk score. Injecting one (e.g. `cryptoProperties.qsRiskScore`) would produce a non-standard, non-portable CBOM that could fail validation against the official schema or confuse other tools (like `cdxgen`) that might later consume it.
2. **Separation of concerns** — this principle is already stated in `architecture.md`: *"discovery never calculates risk; scoring never scans source."* A shared output file blurs that boundary; a separate file enforces it structurally, not just by convention.
3. **Replaceability.** If the scoring engine is later swapped or a second scoring method is added (e.g. once real HNDL/CVSS data exists), a separate output file means `cbom.json` never needs to change. The discovery layer stays untouched no matter how scoring evolves.
4. **Traceability for the report.** Having two distinct files (`cbom.json` → `scored_output.json`) makes the Week 3 report's before/after story clearer: "here is what was found, here is what we scored it."

### Required Shape of `scored_output.json`

Each entry should carry enough back-reference to trace to its original CBOM component:

```json
{
  "generated_from": "cbom.json",
  "scoring_formula_version": "v1",
  "findings": [
    {
      "bom-ref": "crypto/algorithm/rsa-09d02f28",
      "name": "RSA-2048",
      "quantum_factor": 1.5,
      "confidence": 0.85,
      "algorithm_risk_score": 1.275,
      "tier": "shor-vulnerable",
      "location": "samples/test-repo/crypto_demo.py",
      "line": 12
    }
  ]
}
```

Findings array must be **sorted descending by `algorithm_risk_score`** — highest risk first. `bom-ref` links back to the matching component in `cbom.json` so nothing is duplicated unnecessarily; `location`/`line` are carried over for convenience so the dashboard-groundwork step (Week 3, item 4) doesn't need to cross-reference two files.

---

## 3. What Person B Needs From This Doc

- Formula: unchanged, use as-is.
- Output: new file `scored_output.json`, shape as above.
- Do not modify `cbom_writer.py`'s output structure — `cbom.json` stays exactly as Week 2 left it.
