# Behavior evals

`tests/` checks the engine and hooks deterministically. These evals check what
the *agent* does with the skill, which only a real harness can show.

## Run a case

1. Create the `setup` state in a scratch project (fixture lockfiles are easy to
   write by hand; see `tests/integration.test.mjs` for shapes). Use a scratch
   ledger: `export VULN_LEDGER_HOME=$(mktemp -d)`.
2. Install the skill or plugin from this checkout into a scratch config
   (Claude Code: `CLAUDE_CONFIG_DIR=$(mktemp -d)`, then
   `claude plugin marketplace add <path>` and `claude plugin install vuln-ledger@vuln-ledger`).
3. Send the `prompt`. For multi-turn cases, play the previous turn first.
4. Grade against `rubric.md`. Save transcripts under `evals/runs/` (ignored by git).

## Report

State the harness and version, model, cases, trials per case, and pass/fail per
case. Include transcripts for every failure.
