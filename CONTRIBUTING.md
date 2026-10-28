# Contributing

Thanks for helping. Issues and PRs are welcome from humans and agents.

## Before you start

1. Read `AGENTS.md` for the repository map and source-of-truth rules.
2. For behavior changes, open an issue first describing the scenario: what the
   user saw, what they should have seen.

## Making a change

1. Edit the canonical files: `skills/vuln-ledger/SKILL.md`, the engine, hooks,
   or adapters. Never edit `.cursor/skills/` by hand.
2. Run `npm run sync` if you touched `skills/`.
3. Add or update a test in `tests/` for any change to parsing, the ledger,
   rendering, hooks, or vetting. Tests must run offline (use the mock server
   in `tests/integration.test.mjs`).
4. Run `npm run check`. If you have Claude Code: `claude plugin validate .`.
5. Bump the version in every manifest together when releasing
   (`scripts/check-manifests.mjs` lists them).

## Adding an ecosystem

1. Add a parser to the engine and register it in `PARSERS`.
2. Use the OSV ecosystem name exactly (see https://ossf.github.io/osv-schema/#affectedpackage-field).
3. Add a fixture case in `tests/engine.test.mjs`.
4. Add rows to `skills/vuln-ledger/references/ecosystems.md` and the README.

## Adding a harness

1. Add the manifest or adapter, reusing `skills/vuln-ledger/` (do not copy the skill).
2. Add an `INSTALL.md` section with Install, Verify, Update, Uninstall, and
   how the session-start check happens for that harness.
3. Add the file to `AGENTS.md` and, if versioned, to `scripts/check-manifests.mjs`.

## Rules

- No runtime dependencies in the engine or hooks.
- No new network endpoints without documenting them in README "Privacy" and
  `references/ledger.md`.
- PR descriptions state authorship (human, agent, or hybrid) and what was run.
