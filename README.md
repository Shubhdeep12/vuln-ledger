<p align="center">
  <img src="./logo.png" alt="vuln-ledger" width="120" />
</p>
<h1 align="center">vuln-ledger</h1>
<p align="center">
  <strong>Know about vulnerable or malicious dependencies the day the advisory lands. Hear about each one once.</strong>
</p>
<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Shubhdeep12/vuln-ledger?style=flat" alt="License"></a>
  <img src="https://img.shields.io/badge/node-%E2%89%A518.17-339933?style=flat" alt="Node 18.17+">
  <img src="https://img.shields.io/badge/dependencies-0-blue?style=flat" alt="Zero dependencies">
</p>

A skill and plugin for AI coding agents (Claude Code, Codex, Cursor, Gemini CLI,
Copilot, OpenCode, Qwen, Kimi, Grok, Pi, Zed, and any Agent Skills harness) that
checks your lockfiles for known vulnerabilities and malicious packages, keeps a
**ledger** per project, and tells you only what changed.

## Install

Copy/paste into your agent:

```text
Install the vuln-ledger skill/plugin from https://github.com/Shubhdeep12/vuln-ledger, refer to the repo's AGENTS.md for instructions.
```

Or 🔗 [pick your harness in INSTALL.md](INSTALL.md). Claude Code in two lines:

```bash
claude plugin marketplace add Shubhdeep12/vuln-ledger
claude plugin install vuln-ledger@vuln-ledger
```

No agent? It is also a plain CLI:

```bash
npx -y github:Shubhdeep12/vuln-ledger scan
```

## Why another scanner

`npm audit`, `composer audit`, Dependabot and Snyk find vulnerabilities. Agent
skills that wrap them exist too. What none of them do inside an agent session:

| Problem | What vuln-ledger does |
|---|---|
| Every audit dumps the same 40 findings, so people stop reading | A per-project ledger. Each finding is reported **once**. Later checks show only `new`, `escalated`, `fix-available`, `still-affected`, `resolved` |
| A new critical drops on Tuesday; you hear about it at the next weekly CI run | A throttled check at **every session start** (OSV at most every 6h, immediately if a lockfile changed). New advisories are labelled `newly disclosed <date>` |
| "Not now" turns into nagging, or into forgetting forever | `accept --until 30d` records your decision. Silent until it expires **or gets worse** (severity up, CISA KEV, malicious) |
| Agents install packages that are brand new, malicious, or hallucinated | A pre-install hook vets every `npm i` / `composer require` / `pip install` / `cargo add` / `go get` ... and asks you first on a strong signal |
| Severity alone does not say what is urgent | CISA KEV ("exploited in the wild") and FIRST EPSS (exploit probability) on every row |
| Agents "fix" things with `npm audit fix --force` | The skill stops, shows one table, asks, then updates one package at a time to the smallest fixed version, runs tests, and re-scans |

## What it looks like

First session in a project (baseline):

```text
vuln-ledger · shop-api · 312 packages (Packagist 118, npm 194) · OSV.dev · 2026-10-28 09:12 UTC
Since last check (first run): 26 new. Known and unchanged: 0 open, 0 accepted (not repeated).

### Action needed: ask the user before continuing
| Package | Installed | Fix | Severity | Advisory | What changed | Scope |
|---|---|---|---|---|---|---|
| minimist (npm) | 1.2.5 | 1.2.6 (patch) | CRITICAL 9.8 · EPSS 5% | GHSA-xvch-5gv4-984h (CVE-2021-44906) | baseline | transitive |
| laravel/framework (Packagist) | 10.0.0 | 10.48.23 (minor) | HIGH · EPSS 45% | GHSA-gv7v-rgg6-548h (CVE-2024-52301) | baseline | direct |

### Lower severity (baseline): 13 MEDIUM, 1 LOW. Run `status --all` to list them.
```

Next session, nothing changed: **no output at all**.

The day after you bump lodash:

```text
Since last check (2026-10-28 09:12 UTC): 1 still-affected · 3 resolved. Known and unchanged: 20 open, 1 accepted (not repeated).

### Action needed: ask the user before continuing
| lodash (npm) | 4.17.21 | 4.18.0 (minor) | HIGH 8.1 | GHSA-r5fr-rjxr-66jc (CVE-2026-4800) | still affected after change 4.17.15 -> 4.17.21 | direct |

### Resolved since last check
- lodash GHSA-35jh-r3h4-6jhm: upgraded to 4.17.21
```

An agent trying to install a typo-squat:

```text
$ npm install lodahs
vuln-ledger flagged this install:
npm:lodahs@0.0.1-security: MAL-2025-25502: this version is reported as MALICIOUS.
```

## How it works

```
lockfiles ──► inventory ──► OSV.dev querybatch ──► advisory details (cached by `modified`)
                                                         │
                     CISA KEV + FIRST EPSS (daily cache) ┤
                                                         ▼
                 per-project ledger ◄── reconcile ──► events: new · escalated · fix-available
                 (what you were told,                          still-affected · expired · resolved
                  what you decided)                            reminder (weekly, critical/high only)
                                                         ▼
                                 skill: stop + ask on critical/high/KEV/malicious,
                                        one line for the rest, silence for nothing new
```

- **One script, zero dependencies**: `skills/vuln-ledger/scripts/vuln-ledger.mjs`, Node 18+. No scanner to install. Uses `osv-scanner` instead when you ask (`--engine osv-scanner`).
- **Ecosystems**: Composer, npm/pnpm/Yarn/Bun, pip/Poetry/uv/PDM/Pipenv, Go (incl. stdlib), Cargo, Bundler, Maven/Gradle, NuGet, Dart/Flutter, Hex.
- **Read-only** on your project. It writes only its ledger (`~/.local/state/vuln-ledger/`, or a shared in-repo `.vuln-ledger.json` that is used only with `VULN_LEDGER_SHARED=1`).
- **Never claims clean on failure**: a timeout or API error is reported as "check incomplete", and never produces a false "resolved".

## Commands

| Command | Does |
|---|---|
| `scan` | Check and report only changes. `--quiet` prints nothing when nothing changed. `--max-age 6h` reuses a recent result |
| `status [--all]` | Everything in the ledger, no network |
| `vet npm:pkg@1.2.3 composer:vendor/pkg pypi:requests` | Check a package before adding it: vulns, malicious, exists, age, install scripts |
| `advisory CVE-2026-1234` | "Does this new advisory affect us?" |
| `inventory --grep laravel-lang` | Is a package from today's incident report in the tree, at which version? |
| `accept <ID> --reason "..." --until 30d` / `reopen <ID>` | Record or undo a decision |
| `doctor` | Paths, connectivity, installed scanners |

Exit codes: `0` nothing new · `10` lower-severity changes · `20` action needed · `30` check incomplete.

## Harness support

| Harness | Skill | Session-start check | Pre-install guard |
|---|---|---|---|
| Claude Code | ✅ plugin | ✅ hook | ✅ hook |
| Codex | ✅ plugin | ✅ hook | ✅ hook (best effort) |
| Grok, Antigravity | ✅ plugin | ✅ hook (Grok) | ✅ hook (Grok) |
| OpenCode | ✅ plugin | ✅ plugin | via skill |
| Pi / Oh My Pi | ✅ extension | ✅ extension | via skill |
| Gemini CLI | ✅ extension | via `GEMINI.md` | via skill |
| Cursor, Copilot, Zed, Qwen, Kimi, Hermes, Amp, Windsurf, Cline, ... | ✅ Agent Skills | via skill / rules snippet | via skill |
| CI (GitHub Actions) | n/a | ✅ daily workflow | n/a |

"via skill" means the agent follows the skill's instructions instead of a hook.
Details per harness in [INSTALL.md](INSTALL.md).

## Turn it off

```bash
export VULN_LEDGER_DISABLE=1                                  # this shell
mkdir -p ~/.config/vuln-ledger && touch ~/.config/vuln-ledger/disabled   # everywhere
```

Explicit commands (`scan`, `vet`) still work; only automatic checks stop.

## Privacy

Package names and versions go to `api.osv.dev`. CVE IDs go to `api.first.org`
(EPSS). The CISA KEV list is downloaded daily. `vet` asks the package registry
about the package being added. Nothing else leaves your machine; there is no
telemetry. Point `VULN_LEDGER_OSV_URL` at a mirror, or use `--offline`,
`--no-kev`, `--no-epss`. See [references/ledger.md](skills/vuln-ledger/references/ledger.md).

## Background: what changed in 2026

The skill's defaults come from how attacks and detection moved in the last six months:

- **Supply-chain worms move in hours.** TeamPCP's "Mini Shai-Hulud" wave published 84 malicious artifacts across 42 `@tanstack/*` packages in six minutes and hit Mistral AI's PyPI packages in the same campaign ([SafeDep](https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral/)). Laravel-Lang on Packagist was poisoned through rewritten Git tags ([Snyk](https://snyk.io/jp/blog/laravel-lang-supply-chain-advisory/)). Weekly CI scans miss these windows, hence session-start checks and the pre-install guard.
- **Install time is the attack surface**, and malicious packages now carry prompt-injection text aimed at LLM reviewers ([Phoenix Security](https://phoenix.security/accelerating-supply-chain-attacks-npm-pypi-vsx-ai-enabled-2026/), [TuxCare](https://tuxcare.com/blog/supply-chain-broke-in-2026/)). The skill treats all advisory and package text as data.
- **Cooldowns work.** npm (`min-release-age`, 11.10), pnpm (`minimumReleaseAge`), Bun and uv (`exclude-newer`) now support refusing brand-new releases; most attacks studied had windows under a week ([Andrew Nesbitt](https://nesbitt.io/2026/03/04/package-managers-need-to-cool-down)). The pre-install hook applies a 48h cooldown check even when your package manager does not.
- **OSV's `modified` field is noisy**: advisories get re-modified in bulk long after publication ([aiwatch #1696](https://github.com/bentleypark/aiwatch/issues/1696)). The ledger keys on advisory + package, so a re-published old advisory is never "new".
- **Existing agent tools are stateless**: OSV-Scanner skills/plugins, Socket's MCP server, and NVIDIA's SkillSpector (which vets skills themselves) all answer "what is vulnerable now?", not "what changed since you last told me?" ([mcpmarket](https://mcpmarket.com/tools/skills/osv-scanner), [Socket MCP](https://glama.ai/mcp/servers/SocketDev/socket-mcp), [SkillSpector](https://github.com/NVIDIA/SkillSpector)). vuln-ledger is the memory layer, and works next to them.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [AGENTS.md](AGENTS.md). Security
issues in vuln-ledger itself: [SECURITY.md](SECURITY.md).

## License

MIT. Vulnerability data: [OSV.dev](https://osv.dev) (CC-BY 4.0 and source
licenses), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
[FIRST EPSS](https://www.first.org/epss/).
