# QuantumShield Week 6 Track 2 — Finalization Checklist

This checklist separates verified results from outstanding checks. It is based on the supplied terminal output and coding-agent log, not a fresh inspection of the local repository source files.

## Verified from the supplied terminal output

- [x] `uv run pytest -q` completed with 162 passed in 3.85 seconds.
- [x] `migration_plan.json` was generated using `uv run python -m scoring.migration_plan_writer assessment.json --output migration_plan.json`.
- [x] Python's JSON parser accepted `migration_plan.json`.
- [x] The plan has 20 tasks.
- [x] The generated summary reports 2 urgent, 4 high, 8 medium, and 6 low priority tasks.
- [x] `git diff --check` produced no reported whitespace errors.

## Must do before calling Track 2 fully complete

1. **Review `by_action` classification.** The reported plan summary has 14 `manual-review` tasks and no `no-action-needed` tasks. Inspect the recommendation objects and migration task conversion. Preserve an explicit action type such as `migrate`, `urgent-classical`, `manual-review`, `review`, or `no-action-needed`; do not infer action solely from priority or a missing target algorithm.
2. **Add summary regression tests.** Cover urgent signature transition, classical weakness, manual review, review-only findings, and no-action-needed findings. Assert that per-action counts sum to the total and reflect the underlying tasks.
3. **Review recommendation wording.** Verify compatibility notes do not claim that a post-quantum replacement is a drop-in replacement unless that statement is explicitly justified. A cryptographic algorithm change normally requires compatibility and integration testing.
4. **Verify Transport Layer Security scanner integration.** Confirm the scanner output feeds the intended inventory or assessment format, and confirm bounded targets, timeouts, errors, and test coverage. Nine scanner tests were reported in the agent log, but the supplied terminal output alone does not prove end-to-end integration.
5. **Run tests again after any fixes.** Use `uv run pytest -q`; record the new test count and actual result.
6. **Review staged files deliberately.** `git status --short` shows these untracked items: `assessment.json`, `dashboard_output.md`, `discovery/tls_scanner.py`, `migration_plan.json`, `project-context.yaml`, `quantumshield-week5-track2.patch`, `quantumshield_week6_package/`, `scoring/migration_engine.py`, `scoring/migration_plan_writer.py`, `scoring/migration_recommendations.yaml`, `tests/test_migration_engine.py`, and `tests/test_tls_scanner.py`.
7. **Avoid committing unrelated or private artifacts.** Do not include `quantumshield-week5-track2.patch` in the product commit. Inspect `project-context.yaml` for local or sensitive values before deciding whether it belongs in the repository. Decide deliberately whether generated `assessment.json` and `dashboard_output.md` are intended examples or local outputs. Keep the agent-planning package separate unless intentionally adding it to project documentation.
8. **Commit locally only after review.** Check `git status --short`, `git diff --cached --check`, and `git diff --cached --stat`. Stage only intended files; do not use `git add .` blindly. Do not push to GitHub from the agent.
9. **Complete submission metadata.** Add the real repository URL, branch, and local commit hash after the commit actually exists. Do not invent these values.

## Suggested resume prompt for a fresh coding-agent session

> Continue the existing QuantumShield Week 6 Track 2 work; do not restart it, reset changes, or push to GitHub. The complete test suite last passed with 162 tests in 3.85 seconds, and `migration_plan.json` was generated and parsed successfully with 20 tasks. Inspect `scoring/migration_engine.py`, `scoring/migration_plan_writer.py`, and the recommendation data. Review the `by_action` summary: the current output reports `urgent-classical: 2`, `migrate: 4`, `manual-review: 14`, and no `no-action-needed` category, which may indicate that the summary infers actions incorrectly from priority or missing target algorithms. Fix only confirmed issues, preserve explicit action types, add regression tests, verify Transport Layer Security scanner end-to-end integration, update documentation, rerun `uv run pytest -q`, and report actual results. Review untracked files carefully. Create a local commit only after all checks pass and only for intended Track 2 files; do not use `git add .` blindly, do not rewrite prior commits, and do not push. Provide the real local commit hash and prepare the Week 6 Track 2 submission report.
