# vuln-ledger

This extension guards the project's dependencies against known vulnerabilities
and malicious packages, and remembers what the user has already been told.

At the start of a session in a project with a lockfile, run once:

```bash
node ~/.gemini/extensions/vuln-ledger/skills/vuln-ledger/scripts/vuln-ledger.mjs scan --quiet --max-age 6h
```

No output means nothing changed since the last check: say nothing about it.
Otherwise follow the rules below. In them, `<skill-dir>` is
`~/.gemini/extensions/vuln-ledger/skills/vuln-ledger`.

@./skills/vuln-ledger/SKILL.md
