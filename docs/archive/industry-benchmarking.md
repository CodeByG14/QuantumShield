# QuantumShield — Industry Benchmarking: NIST/CISA Alignment

**Date:** 2026-09-27
**Purpose:** Sanity-check that QuantumShield's scoring approach is directionally compatible with real industry guidance, not a reinvented/incompatible scheme.

---

## 1. NIST SP 1800-38 Series (NCCoE Migration to PQC Practice Guide)

NIST's own migration guidance is split into three volumes directly relevant to QuantumShield's three pillars:

| NIST SP 1800-38 Volume | Focus | Maps to QuantumShield |
|---|---|---|
| **Volume A** — Executive Summary | Why migrate, crypto-agility framing | Overall project motivation |
| **Volume B** — Quantum Readiness: Cryptographic Discovery | Automated discovery tools (source, binary, network, certificate scanning), building a CBOM | **Pillar 1** (our scanner) |
| **Volume C** — Quantum Readiness: Testing Draft Standards | Interoperability/performance testing of PQC algorithms | Future pillar (not yet in scope) |

Key validation point: NIST's own lab demonstration architecture is described as *discovery in three domains (CI/CD pipeline, operational systems, network services) feeding into a central analysis engine, with output normalized/correlated then run through risk assessment to prioritize remediation.* This is structurally the same pipeline QuantumShield already follows: **Discovery Engine → CBOM → Scoring Engine**. We are not inventing an unusual architecture — this matches the reference pattern NIST itself demonstrated.

NIST Volume B also explicitly states most organizations lack visibility into where cryptography is used, and recommends **expanding existing asset inventory processes to include cryptographic components** — directly validating why Week 1–2's discovery/CBOM work was the correct starting point before scoring.

---

## 2. Mosca's Theorem — The Real Prioritization Standard

NIST SP 1800-38B cites **Mosca's Theorem** as the standard reference starting point for PQC migration prioritization:

```
If X + Y > Z, then your data is at risk.
```
Where:
- **X** = confidentiality lifetime of the data (how long it must stay secret)
- **Y** = migration time (how long it will take to move the system to quantum-safe crypto)
- **Z** = threat timeline (time until quantum computers can break today's crypto)

### How this compares to QuantumShield's v1 formula

Our current v1 formula (`Quantum_Factor × Confidence_Level`) is **algorithm-centric only** — it does not yet include X (data lifetime) or Y (migration time) at all. This is an honest gap, not an oversight: it was already anticipated in `qri-formula-draft.md`'s "future extension" section, which sketches a path to incorporate an HNDL term once organisational data is available:

```
QRI = CVSS_base × Quantum_Factor × (1 + HNDL_Score² / 10)
```

**Conclusion:** QuantumShield v1 is a **subset** of Mosca's Theorem — it currently answers "how bad is this algorithm if broken?" but not yet "how urgent is it given data lifetime and migration time?" This is consistent with NIST's own phased approach (discovery first, full risk context later) and is not a departure from industry practice — it's the same sequencing NIST itself used across SP 1800-38's volumes.

---

## 3. CISA Guidance Alignment

CISA's PQC roadmap materials similarly emphasize starting with **cryptographic inventory** before attempting full risk-based prioritization, and stress that inventory should flag both:
- **Confidentiality risk** (HNDL-style, key-exchange/encryption algorithms)
- **Authenticity risk** (signature forgery, once quantum computers can fake signed data)

This confidentiality-vs-authenticity split is already present in our lookup table implicitly — key-exchange/encryption primitives (`pke`, `key-agree`) vs signature primitives (`signature`) are tagged separately in `cryptoProperties.algorithmProperties.primitive`, so the data model already supports this distinction even though the current scoring formula doesn't yet weight them differently. Worth flagging as a Week 4+ refinement.

---

## 4. Summary for the Report

> "QuantumShield's Discovery → CBOM → Scoring pipeline mirrors the reference architecture demonstrated in NIST SP 1800-38B's cryptographic discovery lab. Our v1 scoring formula is intentionally a simplified subset of the industry-standard Mosca's Theorem (X+Y>Z) prioritization model — covering the algorithm-risk term now, with a clearly documented extension path (already drafted in Week 2) to incorporate data-lifetime and migration-time factors once organisational HNDL data is available. This phased approach matches NIST's own volume-by-volume rollout (discovery before full risk-based testing/prioritization) rather than diverging from it."

**Sources referenced:**
- NIST SP 1800-38A/B (NCCoE, Migration to Post-Quantum Cryptography practice guide)
- NIST PQC Security Strength Categories 1–5 (csrc.nist.gov)
- CISA Post-Quantum Cryptography Initiative guidance
