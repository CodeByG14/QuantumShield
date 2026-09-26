# QuantumShield — Quantum Factor Lookup Table (Week 3 Spec)

**Purpose:** Authoritative algorithm → Quantum_Factor → tier mapping for `scoring/qri_engine.py`.
Person B: implement this table directly as a dict — no interpretation needed.
**Date:** 2026-09-27
**Sources:** NIST PQC FAQ (csrc.nist.gov), NIST PQC Security Strength Categories 1–5, Benitez (2025) "Mapping Quantum Threats"

---

## 1. Core Principle (unchanged from Week 2)

Two quantum algorithms drive the tiering:
- **Shor's algorithm** — solves integer factorization & discrete log (incl. elliptic curve) in polynomial time. Breaks RSA, DH, ECDH, ECDSA, DSA **completely**, regardless of key size.
- **Grover's algorithm** — quadratic speedup on brute-force search. **Halves** effective security of symmetric ciphers and hash functions (128-bit key → 64-bit effective). Does not break them outright.

This is why Shor-vulnerable algorithms get the highest factor (1.5) — no key size increase can fix them, only full algorithm replacement. Grover-affected algorithms (1.2) can often be mitigated by *doubling key/output length*, which is why AES-256 gets treated differently from AES-128 below.

---

## 2. Expanded Lookup Table

| Algorithm / Variant | Quantum_Factor | Tier | Justification |
|---|---|---|---|
| RSA-1024 | **1.5** | shor-vulnerable | Shor-breakable; additionally already classically weak — flag as highest urgency within this tier |
| RSA-2048 | **1.5** | shor-vulnerable | Shor-breakable; current internet baseline (NIST Category 1 equivalent) |
| RSA-3072 / RSA-4096 | **1.5** | shor-vulnerable | Shor-breakable regardless of size — larger keys buy no quantum resistance |
| ECDSA (any curve) | **1.5** | shor-vulnerable | ECDLP broken by Shor |
| ECDH (any curve) | **1.5** | shor-vulnerable | Same ECDLP break |
| EC curve: P-256 | **1.5** | shor-vulnerable | ~NIST Category 1 classical equivalent, still Shor-broken |
| EC curve: P-384 | **1.5** | shor-vulnerable | ~Category 3 classical equivalent, still Shor-broken |
| EC curve: secp256k1 | **1.5** | shor-vulnerable | Same ECDLP structure (used in blockchain/crypto contexts) |
| DH (classic, any modulus size) | **1.5** | shor-vulnerable | Discrete-log broken by Shor |
| DSA | **1.5** | shor-vulnerable | Discrete-log based signature, same break |
| AES-128 | **1.2** | grover-affected | Grover halves to ~64-bit effective — meaningfully weakened, not broken |
| AES-192 | **1.2** | grover-affected | Halves to ~96-bit effective — still flagged, below modern comfort margin |
| AES-256 | **1.0** | quantum-safe | Halves to ~128-bit effective — NIST's own recommended mitigation (double the key) |
| MD5 | **1.2** | grover-affected | Already classically broken (collisions); Grover adds quantum-relevant exposure on top |
| SHA-1 | **1.2** | grover-affected | Already classically broken; same treatment as MD5 |
| SHA-256 | **1.2** | grover-affected | BHT algorithm reduces collision resistance to ~85-bit; NIST still treats it as the Category 2 anchor, but flag legacy usage for review |
| SHA-384 | **1.0** | quantum-safe | Sufficient output length maintains strong post-quantum collision resistance |
| SHA-512 / SHA-3 family | **1.0** | quantum-safe | Same — long output length survives Grover/BHT comfortably |
| ML-KEM (FIPS 203) | **1.0** | quantum-safe | NIST-standardized PQC algorithm — the target, not a risk |
| ML-DSA (FIPS 204) | **1.0** | quantum-safe | NIST-standardized PQC signature |
| SLH-DSA (FIPS 205) | **1.0** | quantum-safe | NIST-standardized PQC signature |

---

## 3. Implementation Note for Person B

Keep the dict keyed by the **family name string** your scanner already emits (`f["name"]` in `scanner.py` — e.g. `"RSA"`, `"AES"`, `"MD5"`), not by full variant string, unless you've also expanded `patterns.yaml` to distinguish AES-128 vs AES-256 specifically. If `patterns.yaml` doesn't yet differentiate AES key sizes, default `"AES"` findings to the **1.2 (AES-128 assumption)** tier — safer to over-flag than under-flag for a risk tool. Only split into 1.0 vs 1.2 once the regex can actually detect key size (e.g. `AES.MODE_GCM` + explicit `256` nearby, or `AES-256` string literal).

## 4. What Changed From Week 2's 3-Algorithm Table

Week 2 only covered RSA / ECDSA / DH / AES / MD5 at the family level. This table adds:
- Key-size differentiation for RSA and AES (where it matters — AES only, since RSA has no safe key size against Shor)
- Named EC curves (P-256, P-384, secp256k1)
- Additional hash functions (SHA-1, SHA-256, SHA-384, SHA-512/3)
- The target PQC algorithms themselves (ML-KEM, ML-DSA, SLH-DSA) at factor 1.0 — useful once the scanner also detects *correct* migrations, not just vulnerable ones
