# Changelog

## Unreleased

## 0.3.0 (2026-10-28)

- Removed the pre-install hook. It guessed packages from shell command text, which misread common commands (`npm i vite 2>&1` was read as a package named `2`) and caused false prompts, including in auto mode. Package checks now happen through the skill: the agent runs `vet` before adding a package and `scan` after dependencies change, and the session-start check catches any lockfile change. `VULN_LEDGER_COOLDOWN` is gone; use `vet --cooldown`.

## 0.2.0 (2026-10-28)

- Claude Code slash commands: `/vuln-ledger:scan`, `/vuln-ledger:vet`, `/vuln-ledger:status`.

## 0.1.0 (2026-10-28)

First release.

- Zero-dependency engine (`skills/vuln-ledger/scripts/vuln-ledger.mjs`): lockfile parsing for Composer, npm/pnpm/Yarn/Bun, Poetry/uv/PDM/Pipenv/requirements, Go (with stdlib), Cargo, Bundler, Maven/Gradle, NuGet, Pub, Hex.
- OSV.dev batch queries with advisory caching keyed on `modified`; CVSS v3 scoring; CISA KEV and FIRST EPSS enrichment.
- Per-project ledger: events `new`, `escalated`, `fix-available`, `still-affected`, `expired`, `resolved`, weekly `reminder`; accepted risks with expiry.
- `vet` for packages before install: malicious, vulnerable version, non-existent name, release age, install scripts, deprecation.
- `advisory` and `inventory` for breaking-news triage.
- Hooks: throttled session-start check and pre-install guard (Claude Code, Codex, Grok).
- Adapters: OpenCode plugin, Pi/OMP extension, Gemini extension and command, Qwen, Kimi, Antigravity manifests, Cursor mirror.
- Daily GitHub Actions template.
- Security: an in-repo `.vuln-ledger.json` is used only with `VULN_LEDGER_SHARED=1`; ledgers are schema-validated on load; malicious findings cannot be accepted and are reminded daily.
- Security: lockfile names and versions are validated, and all lockfile- and ledger-derived values are sanitized before reaching agent context.
- Security: the pre-install guard vets every package (asks above 20), handles `env`, `xargs`, `sh -c`, `eval`, command substitution, global options, and runners (`npx`, `bunx`, `pnpm dlx`, `uvx`, `pipx`), and asks when a package cannot be determined.
