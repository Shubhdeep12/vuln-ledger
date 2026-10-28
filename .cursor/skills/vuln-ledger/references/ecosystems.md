# Ecosystem reference

Read the row for the ecosystem you are working in. Commands that change files
are for the "If the user approves" step only.

## Lockfiles read by `scan`

| Ecosystem (OSV name) | Files | Fallback scanner if Node is unavailable |
|---|---|---|
| PHP (`Packagist`) | `composer.lock` | `composer audit` |
| Node (`npm`) | `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lock` | `npm audit` / `yarn npm audit` / `pnpm audit` |
| Python (`PyPI`) | `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`, `requirements*.txt` (pinned lines only) | `pip-audit` |
| Go (`Go`) | `go.mod` (plus the Go toolchain as `stdlib`) | `govulncheck ./...` |
| Rust (`crates.io`) | `Cargo.lock` | `cargo audit` |
| Ruby (`RubyGems`) | `Gemfile.lock` | `bundle audit check --update` |
| Java (`Maven`) | `gradle.lockfile`, `pom.xml` (literal versions only) | `osv-scanner` (resolves transitive deps) |
| .NET (`NuGet`) | `packages.lock.json` | `dotnet list package --vulnerable --include-transitive` |
| Dart (`Pub`) | `pubspec.lock` | `osv-scanner` |
| Elixir (`Hex`) | `mix.lock` | `mix hex.audit` |

`osv-scanner` covers every row with the same database. If it is installed,
`scan --engine osv-scanner` uses it for parsing (better for Maven/Gradle).
It is never installed automatically.

## Minimal update commands

Update to the smallest fixed version reported, one package at a time.

| Ecosystem | Direct dependency | Transitive dependency |
|---|---|---|
| Composer | `composer require vendor/pkg:^X.Y.Z` then `composer update vendor/pkg` | `composer update vendor/pkg --with-dependencies`; if a parent pins it, update the parent |
| npm | `npm install pkg@X.Y.Z` | `npm update pkg`; else `"overrides": {"pkg": "X.Y.Z"}` in package.json, then `npm install` |
| pnpm | `pnpm add pkg@X.Y.Z` | `pnpm update pkg`; else `pnpm.overrides` |
| Yarn | `yarn add pkg@X.Y.Z` | `yarn up -R pkg` (Berry); else `"resolutions"` |
| Bun | `bun add pkg@X.Y.Z` | `"overrides"` in package.json |
| pip / requirements | edit the pin, then `pip install -r requirements.txt` | add a constraint line, or update the parent |
| uv | `uv add 'pkg>=X.Y.Z'` or `uv lock --upgrade-package pkg` | `uv lock --upgrade-package pkg` |
| Poetry | `poetry add pkg@^X.Y.Z` | `poetry update pkg` |
| Go | `go get module@vX.Y.Z && go mod tidy` | same command (Go has no separate transitive pin) |
| Go stdlib | update the `toolchain` line / install a newer Go | n/a |
| Cargo | `cargo update -p crate --precise X.Y.Z` | same |
| Bundler | `bundle update gem --conservative` | `bundle update gem --conservative` |
| Maven / Gradle | bump the version in `pom.xml` / `build.gradle` | `<dependencyManagement>` / Gradle `constraints {}` |
| NuGet | `dotnet add package Name --version X.Y.Z` | add a direct `PackageReference` at the fixed version |
| Dart | `dart pub upgrade pkg` (edit constraint if needed) | `dependency_overrides` |
| Hex | `mix deps.update pkg` | same |

Never use `npm audit fix --force`, `composer update` with no package names, or
other blanket upgrades as a vulnerability fix.

## Release-age cooldowns

Most 2025-2026 supply-chain attacks (Shai-Hulud waves, the TanStack/Mistral
npm+PyPI compromise, Laravel-Lang on Packagist) were live for hours to a few
days before removal. A cooldown that refuses brand-new releases blocks most of
them. Suggest one when the project has none. Check the tool's docs for the
current option name before editing config.

| Tool | Setting (verify against current docs) |
|---|---|
| npm (11.10+) | `min-release-age` in `.npmrc` (days) |
| pnpm (10.16+) | `minimumReleaseAge` in `pnpm-workspace.yaml` (minutes), `minimumReleaseAgeExclude` for trusted packages |
| Bun | `install.minimumReleaseAge` in `bunfig.toml` (seconds) |
| uv (0.9.17+) | `exclude-newer = "7 days"` in `pyproject.toml` / `uv.toml` |
| pip (26.0+) | `--uploaded-prior-to` (absolute timestamp) |
| Renovate / Dependabot | `minimumReleaseAge` / `cooldown` |

If a cooldown blocks an urgent security fix, tell the user and ask before
adding an exclusion. Do not loop on install errors.
