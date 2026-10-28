# Security policy

## Reporting a vulnerability in vuln-ledger

Use GitHub's private vulnerability reporting on this repository
(**Security → Report a vulnerability**). Please do not open a public issue.
Expect an acknowledgement within 3 days.

In scope: the engine, hooks, and adapters, for example a crafted lockfile or
advisory that makes the tool write outside its state directory, execute code,
inject instructions into agent context, or report a vulnerable project as clean.

Out of scope: vulnerabilities in the packages the tool reports on. Report
those to the package maintainers or to the advisory database (GitHub
Advisory Database, OSV).

## Design guarantees

- The engine never modifies the scanned project. It writes only its ledger and
  cache under `VULN_LEDGER_HOME` (or a `.vuln-ledger.json` the user created).
- It never executes code from the project or from packages, and never runs
  package-manager install commands.
- Advisory text is sanitized and truncated before it reaches agent context, and
  the skill instructs agents to treat it as data.
- Hooks fail open (exit 0, no output) and can only add a confirmation prompt;
  they never auto-approve anything.
- A failed or partial check is reported as incomplete, never as clean.
