# The ledger

## Where it lives

One JSON file per project:

| Platform | Default path |
|---|---|
| macOS / Linux | `$XDG_STATE_HOME/vuln-ledger/projects/<dir>-<hash>.json` (default `~/.local/state/...`) |
| Windows | `%LOCALAPPDATA%\vuln-ledger\projects\<dir>-<hash>.json` |

Overrides, highest first:

1. `--ledger FILE`
2. `.vuln-ledger.json` in the project root, if it exists. Create it (copy the
   default file there) to share accepted risks with a team through git.
3. `VULN_LEDGER_HOME` moves the whole state directory (useful in CI caches).

Advisory details, the CISA KEV list, and EPSS scores are cached under
`<state>/cache/` (KEV and EPSS for 24 hours; advisories until OSV reports a newer
`modified` time).

## What each finding records

```json
{
  "key": "GHSA-xvch-5gv4-984h|npm|minimist",
  "id": "GHSA-xvch-5gv4-984h",
  "aliases": ["CVE-2021-44906"],
  "package": "minimist", "ecosystem": "npm",
  "installed": "1.2.5", "fixed": "1.2.6", "bump": "patch",
  "level": "CRITICAL", "score": 9.8, "kev": false, "epss": 0.05,
  "status": "open | accepted | resolved",
  "firstSeen": "...", "lastSeen": "...",
  "notifiedAt": "...", "notifiedLevel": "CRITICAL", "notifiedFixed": "1.2.6",
  "remindedAt": "...",
  "decision": { "reason": "internal tool", "at": "...", "until": "...", "by": "user" },
  "resolvedAt": "...", "resolvedHow": "upgraded to 1.2.6"
}
```

The key is advisory + package, not version, so a bump that is still vulnerable
is reported as `still-affected` rather than as a new finding.

## Rules that keep it quiet

- A finding is reported once (`notifiedAt`). After that it is silent unless it
  escalates, a fix appears, the installed version changes, or it resolves.
- Undecided critical/high findings get a one-line reminder at most every
  `--remind-every` (default 7 days).
- Accepted findings are silent until `decision.until` or an escalation.
- A finding resolves only after a complete scan. Failed requests or unparsable
  lockfiles never produce false "resolved" events.
- Republished or re-modified advisories do not count as new: the key already
  exists.

## What leaves the machine

| Request | Data sent | When |
|---|---|---|
| `api.osv.dev` | package names and versions from lockfiles | `scan`, `vet`, `advisory` |
| `cisa.gov` KEV feed | nothing (download) | at most daily, if findings have CVEs |
| `api.first.org` EPSS | CVE IDs | at most daily per CVE |
| npm / PyPI / Packagist / crates.io / RubyGems / Go proxy | the package name being vetted | `vet` and the pre-install hook |

Use `--offline`, `--no-kev`, `--no-epss`, or point `VULN_LEDGER_OSV_URL` at an
internal mirror if that is a concern.
