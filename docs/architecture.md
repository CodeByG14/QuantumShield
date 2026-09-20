# QuantumShield — High-Level Architecture

```
┌─────────────────────┐
│   Target Codebase   │  (Python / Java sample repo)
│  /samples/test-repo │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Discovery Engine   │  ← Week 2 PoC (Person B)
│  • scanner.py       │
│  • patterns.yaml    │
│  • cbom_writer.py   │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│   CBOM JSON         │  (CycloneDX 1.6+ cryptographic-asset)
│   schema-valid      │
└──────────┬──────────┘
           │
           ▼  (future)
┌─────────────────────┐
│  Scoring Engine     │  ← Week 3 (qri_engine.py)
│  Algorithm_Risk =   │
│  QF × Confidence    │
└──────────┬──────────┘
           │
           ▼  (future)
┌─────────────────────┐
│     Dashboard       │  ← later phase
│  prioritised view   │
└─────────────────────┘
```

## Pillar Mapping

| Pillar | Component | Status |
|---|---|---|
| 1. Discovery | scanner + CBOM writer | In progress (Week 2) |
| 2. Scoring | QRI / Algorithm Risk Score | Spec ready, code in Week 3 |
| 3. Dashboard | Visualisation & prioritisation | Future |

## Data Flow Summary

1. Scanner walks directory → matches regexes from `patterns.yaml`.
2. Each match becomes a finding (file, line, keyword, confidence).
3. `cbom_writer.py` turns findings into CycloneDX `cryptographic-asset` components following `/docs/cbom-field-reference.md`.
4. Resulting `cbom.json` is the single source of truth for downstream scoring and (later) the dashboard.
5. Scoring engine reads the CBOM, applies the formula from `/docs/qri-formula-draft.md`, and emits prioritised risk records.

## Design Principles

- **Schema-first:** everything downstream consumes valid CBOM.
- **Separation of concerns:** discovery never calculates risk; scoring never scans source.
- **Replaceable detectors:** the regex scanner can later be swapped for sonar-cryptography or cdxgen without changing the scoring or dashboard contracts.
