# Phase 5B — Compliance assessment

## Purpose and scope

Phase 5B adds a file-based compliance assessment over existing QuantumShield assessment findings. It produces a sourced, date-specific planning report for NIST IR 8547 transition guidance and CNSA 2.0 / CNSSP No. 15 guidance. It does not certify a product or establish legal applicability.

NIST IR 8547 is marked **Initial Public Draft** by NIST. Its transition dates must be presented as draft/proposed guidance, not final mandatory requirements: <https://csrc.nist.gov/pubs/ir/8547/ipd>. NIST FIPS 203, 204, and 205 are final standards for ML-KEM, ML-DSA, and SLH-DSA respectively: <https://csrc.nist.gov/projects/post-quantum-cryptography/publications>.

NSA's October 1, 2026 announcement states that, under CNSS Policy 15, new commercial National Security Systems must support quantum-resistant algorithms beginning in 2027 and legacy systems that cannot support them are to be phased out by 2030: <https://www.nsa.gov/Press-Room/Press-Releases-Statements/Press-Release-View/Article/4615285/nsa-announces-post-quantum-cryptography-measures-to-safeguard-national-security/>. That timeline is NSS-specific. The separate CSfC category mapping cited by this ruleset is from a **draft** addendum, and is explicitly marked as draft in the data: <https://www.nsa.gov/Portals/75/documents/resources/everyone/csfc/capability-packages/CSfC%20Post%20Quantum%20Cryptography%20Guidance%20Addendum%201_0%20Draft%20_5.pdf?ver=wCGPoDQXcJKEWTgbH8xsRA%3D%3D>.

## Run it

```bash
uv run quantumshield compliance assessment.json \
  --plan migration_plan.json \
  --as-of 2026-10-25 \
  --output compliance_report.json \
  --markdown-output compliance_report.md
```

`--as-of` defaults to the current local date. If `--plan` is omitted, the command uses `migration_plan.json` from the current directory when that file exists. `--rules` can point to an alternate versioned YAML ruleset; otherwise the packaged `rules.yaml` is used.

## Context

Add `system_category` to project context or an asset-context override using one of `web`, `networking`, `os`, `firmware-signing`, or `other`. Category alone does not prove CNSA/NSS applicability. Set `cnsa_scope_confirmed: true` only when a system owner has established that the asset falls within the relevant CNSA/NSS scope. If scope is unknown or false, CNSA rows are `not assessed` rather than inferred. This version evaluates the legacy classical-public-key phase-out rules; it does not infer new-versus-legacy status or verify the 2027 new-commercial-NSS capability obligation, because neither capability state is present in the current assessment schema.

## Status semantics

- `compliant`: no warning or deadline in the matched rule is active as of the selected date, or the algorithm matches a listed standardized PQC option. This is only a rule-level result, not overall system compliance.
- `deprecated-soon`: the rule's warning/deprecation date has been reached but its modeled disallowance deadline has not.
- `past-deadline`: the modeled effective deadline has been reached.
- `not assessed`: no rule matched, parameters were insufficient, the algorithm is unknown, or contextual scope was not confirmed.

For public-key strength rules, security strength is inferred only from recognized key sizes and curves. Unknown parameters are not guessed. The draft proposes 112-bit public-key deprecation after 2030 and disallowance after 2035; for public-key schemes at 128-bit strength or higher, it specifies disallowance after 2035 but does not assign an earlier deprecation period. The draft says NIST symmetric standards at 112-bit strength will be disallowed in 2030; this ruleset does not invent an earlier deprecation period for that row. Its year-only wording is represented by a date boundary in the rules file, so consumers should read `deadline_year` and the source text together rather than treating the chosen date boundary as a more precise source statement.

Plan completion is estimated by adding the maximum `timeline_months` value among matching tasks to the plan's `generated_at` date. It is compared with the rule's effective deadline and is advisory, not an actual completion commitment. A migration plan tied to a different `source_assessment_id` is not used.

## Validation

The tests cover ruleset versioning/provenance, missing source citations, invalid source URLs, deadline boundaries, unknown algorithms, insufficient key parameters, CNSA scoping/category matching, parameterized PQC algorithms, migration-plan consistency, and JSON/Markdown report writing. Rules and source publication statuses remain in the report to support review and later version updates.
