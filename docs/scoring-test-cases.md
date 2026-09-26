# QuantumShield — Scoring Engine Test Cases (Manual Validation)

**Date:** 2026-09-27
**Purpose:** Known-correct expected outputs for Person B to test `qri_engine.py` against. Uses the actual 5 findings from Week 2's `cbom.json` as the base test set.

---

## Test Inputs (from Week 2's `cbom.json`)

All 5 Week 2 findings had `confidence = 0.85`.

| Finding | Quantum_Factor (from lookup table) | Confidence | Expected Score | Expected Tier |
|---|---|---|---|---|
| RSA-2048 | 1.5 | 0.85 | **1.275** | shor-vulnerable |
| ECDSA | 1.5 | 0.85 | **1.275** | shor-vulnerable |
| DH | 1.5 | 0.85 | **1.275** | shor-vulnerable |
| AES-128-GCM | 1.2 | 0.85 | **1.020** | grover-affected |
| MD5 | 1.2 | 0.85 | **1.020** | grover-affected |

Calculation shown for one example: `RSA-2048: 1.5 × 0.85 = 1.275`

---

## Expected Sort Order in `scored_output.json`

Descending by `algorithm_risk_score`. Note RSA/ECDSA/DH are tied at 1.275 and AES/MD5 tied at 1.020 — any internal order among tied entries is acceptable, but the two groups must not interleave:

1. RSA-2048 — 1.275 — shor-vulnerable
2. ECDSA — 1.275 — shor-vulnerable
3. DH — 1.275 — shor-vulnerable
4. AES-128-GCM — 1.020 — grover-affected
5. MD5 — 1.020 — grover-affected

---

## Additional Edge-Case Test (once `patterns.yaml` expanded per Week 3 scope)

If Person B adds AES-256 detection this week, use this to test the key-size split:

| Finding | Quantum_Factor | Confidence | Expected Score | Expected Tier |
|---|---|---|---|---|
| AES-256 | 1.0 | 0.85 | **0.850** | quantum-safe |

This confirms AES-256 correctly scores *lower* than AES-128 (1.020) despite being the "same algorithm family" — validates the key-size-aware lookup logic is wired correctly, not just falling back to a flat AES factor.

---

## How to Use This

Run `qri_engine.py` against Week 2's `cbom.json`, diff the output against the table above. Any mismatch = bug in either the lookup table wiring or the multiplication logic — not a formula design issue (formula itself is confirmed correct in `scoring-formula-finalization.md`).
