# QuantumShield Week 3 Validation Summary

**Date:** 2026-09-26
**Implementer:** Person B
**Status:** ✅ All tasks complete and validated

---

## Pipeline Verification

### Full Pipeline Execution
```
scanner.py → cbom_writer.py → qri_engine.py → view.py
```

All components working correctly:
- 23 total findings detected (5 original + 18 new)
- All findings successfully scored
- Output formatted and displayable

---

## Test Case Validation (Week 2 Original 5 Findings)

| Finding | Expected Score | Actual Score | Status |
|---------|---------------|--------------|--------|
| RSA-2048 | 1.275 | 1.275 | ✅ Match |
| ECDSA | 1.275 | 1.275 | ✅ Match |
| DH | 1.275 | 1.275 | ✅ Match |
| AES-128-GCM | 1.020 | 1.020 | ✅ Match |
| MD5 | 1.020 | 1.020 | ✅ Match |

**Result:** All 5 original Week 2 test cases pass exactly as specified in `docs/scoring-test-cases.md`.

---

## Sort Order Validation

Expected order: Descending by `algorithm_risk_score`
- Shor-vulnerable tier (1.275, 1.05) appears first ✅
- Grover-affected tier (1.020) in middle ✅
- Quantum-safe tier (0.85) appears last ✅

No interleaving between groups detected. Sort order correct.

---

## Key-Size Split Validation (AES-256 Edge Case)

| Finding | Quantum Factor | Confidence | Expected Score | Actual Score | Status |
|---------|---------------|------------|----------------|--------------|--------|
| AES-256 | 1.0 | 0.85 | 0.850 | 0.850 | ✅ Match |

**Critical validation:** AES-256 scores **lower** (0.850) than AES-128 (1.020), confirming:
- Key-size aware lookup logic works correctly
- Quantum-safe tier (factor 1.0) properly differentiated from grover-affected (factor 1.2)
- Pattern expansion for AES-256 detection successful

---

## New Detection Capabilities

Successfully added and validated:

### Hash Functions
- SHA-1: 1.020 (grover-affected) ✅
- SHA-256: 1.020 (grover-affected) ✅

### Key Agreement
- ECDH: 1.275/1.050 (shor-vulnerable, varies by confidence) ✅

### EC Curves
- P-256: 1.275/1.050 (shor-vulnerable) ✅
- P-384: 1.050 (shor-vulnerable) ✅
- secp256k1: 1.050 (shor-vulnerable) ✅

### Symmetric Crypto Key Sizes
- AES-256: 0.850 (quantum-safe) ✅

All new patterns detected correctly in both Python and Java test files.

---

## Risk Distribution

From `scored_output.json` (23 total findings):
- **Shor-vulnerable:** 16 findings (highest priority)
- **Grover-affected:** 6 findings (medium priority)
- **Quantum-safe:** 1 finding (baseline/control)

Distribution reflects realistic crypto usage patterns in test samples.

---

## File Deliverables

All required files created and working:

1. ✅ `discovery/cbom_writer.py` — updated with confidence field
2. ✅ `scoring/scoring_map.py` — quantum factor lookup table
3. ✅ `scoring/qri_engine.py` — scoring engine
4. ✅ `scored_output.json` — generated, validated
5. ✅ `discovery/patterns.yaml` — expanded (13 patterns total, up from 5)
6. ✅ `samples/test-repo/*.java` — 3 new Java test files
7. ✅ `dashboard/view.py` — console table viewer

---

## Known Behaviors & Notes

### Confidence Variation
Scanner assigns confidence based on context:
- `0.85` = high confidence (function call with parentheses detected)
- `0.70` = medium confidence (keyword match without strong context)

This explains why some findings have scores of 1.275 (0.85 × 1.5) and others 1.05 (0.70 × 1.5) within the same tier.

### Pattern Overlap
Some test files trigger multiple patterns (e.g., `crypto_demo.py` line 8 matches both `ECDSA` and `P-256` patterns). This is expected — both are valid detections since `ec.generate_private_key(ec.SECP256R1())` uses both ECDSA signing and the P-256 curve.

### AES Default Behavior
Per `docs/quantum-factor-lookup-table.md` guidance, `AES` without explicit key size defaults to factor 1.2 (AES-128 assumption) — conservative over-flagging preferred for a risk assessment tool. Only explicit `256` in pattern triggers quantum-safe classification.

---

## Deviations from Plan

**None.** All requirements from the task specification were implemented exactly as specified:
- Formula unchanged (v1)
- Separate `scored_output.json` file (not patched into CBOM)
- Descending sort by risk score
- Confidence field added to CBOM evidence
- All expected test cases pass
- Dashboard groundwork complete

---

## Next Steps (Out of Scope for Week 3)

Potential Week 4+ enhancements:
- Web-based dashboard (Flask/FastAPI)
- CVSS integration for classical vulnerability scoring
- HNDL (data retention) factor integration
- Export to PDF/HTML reports
- CI/CD pipeline integration
- Configuration-based pattern loading
- Support for more languages (C++, Go, Rust)

---

**Validation Status: PASSED** ✅

All Week 3 Person B tasks complete and verified against test specifications.
