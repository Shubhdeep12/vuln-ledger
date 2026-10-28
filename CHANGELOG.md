# Changelog

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
