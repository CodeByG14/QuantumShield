# QuantumShield — Week 5 Assessment Design Decisions

**Policy version:** 1.0 (initial; unvalidated)

## Purpose and boundaries

The Week 5 engine estimates cryptographic migration priority and, where relevant,
Harvest Now, Decrypt Later (HNDL) confidentiality concern. A score is a
policy-driven prioritization index, not a probability of attack or a claim that
quantum computers can break the asset today. Discovery remains separate from
risk scoring, and `cbom.json` is not patched with scores. The combined output is
`assessment.json`.

## Factor model

Each factor is scored from 0 to 5. Its contribution is `(score / 5) * weight * 100`.

| Factor | HNDL confidentiality weight |
|---|---:|
| Quantum vulnerability | 30% |
| Data sensitivity | 25% |
| Confidentiality lifetime | 20% |
| Exposure | 15% |
| System criticality | 10% |

Initial severity bands are Low 0–19.99, Moderate 20–39.99, High 40–59.99,
Very High 60–79.99, and Critical 80–100. These weights and thresholds require
review against expert-labelled scenarios; they are not an external standard.

## Quantum-vulnerability factor mapping

| Week 3 tier | Week 5 factor (0–5) |
|---|---:|
| Shor-vulnerable | 5 |
| Grover-affected | 3 |
| Quantum-safe | 0 |

AES with unresolved key size uses the explicit conservative AES-128 assumption
and is marked provisional. MD5 and SHA-1 are described as classically weak; hash
findings are not given an HNDL score merely because they appeared in the old
quantum-factor lookup table.

## Confidentiality lifetime

| Required lifetime | Score |
|---|---:|
| 0 years | 0 |
| More than 0–1 year | 1 |
| More than 1–3 years | 2 |
| More than 3–5 years | 3 |
| More than 5–10 years | 4 |
| More than 10 years | 5 |

Missing context factor values use 3/5, are marked `assumed`, appear in
`missing_inputs`, and make the assessment provisional.

## Role-aware assessment

- Key establishment and symmetric encryption receive the full confidentiality
  factor set and may receive Mosca timing escalation.
- Signature use is reported as `authenticity` risk, not HNDL. Its confidentiality
  lifetime factor is omitted, and remaining weights are renormalized to 100%.
- Hash and MAC findings are marked not HNDL-applicable in this version. MD5 and
  SHA-1 receive an explanation that their principal weakness is classical.
- A known asymmetric algorithm with an undetermined role is conservatively
  treated as a possible confidentiality/key-establishment risk and marked
  provisional. A library dependency alone is not treated as proof of crypto use.
- `UNABLE_TO_ANALYZE` and unknown algorithms are not scored.
- `POTENTIAL` and low-confidence findings remain visible and can be scored, with
  confidence and provisional status kept separate from severity.

## Mosca timing

Defaults: migration duration **Y = 3 years**, threat-horizon calendar year
**Z = 2035**. Since Z is a calendar year, the comparison is:

`confidentiality lifetime X + migration duration Y > (threat horizon year Z - assessment year)`

For Shor-vulnerable confidentiality roles, satisfying the condition floors the
risk at Very High, or Critical when data sensitivity is at least 4/5. This is a
policy escalation, not a prediction that a quantum computer will arrive in 2035.
Mosca timing is not evaluated if confidentiality lifetime is missing; the result
remains provisional.

## Coverage and limitations

File coverage is `files_analyzed / files_discovered * 100`. It describes scanner
processing coverage, not completeness of cryptographic discovery. Static,
pattern-based scans can miss dynamic, generated, unsupported, binary, or indirect
cryptographic usage. Every assessment carries these limitations forward.
