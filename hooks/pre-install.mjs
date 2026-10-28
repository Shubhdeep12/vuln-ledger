// PreToolUse hook (Bash): when a shell command adds or runs a dependency
// (npm/pnpm/yarn/bun add, npx/bunx/dlx/uvx/pipx, composer require,
// pip/uv/poetry add, cargo add, go get, gem install, dotnet add package,
// dart pub add), vet each package before it runs.
//
// Asks the user to confirm on a strong signal: a malicious version, a known
// high/critical vulnerability in the requested version, a name that does not
// exist on the registry (typo or hallucinated), a release younger than the
// cooldown (VULN_LEDGER_COOLDOWN, default 48h), an install whose package
// cannot be determined (variables, globs, stdin), or more than 20 packages at
// once. Otherwise silent.
// Never emits "allow", so it can only add friction, never remove it.
// Any failure or timeout exits 0 with no output (fail open).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const MAX_SPECS = 20;
const ENGINE = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'skills', 'vuln-ledger', 'scripts', 'vuln-ledger.mjs');

async function readStdin() {
  let data = '';
  for await (const chunk of process.stdin) data += chunk;
  return data;
}

try {
  const vl = await import(pathToFileURL(ENGINE).href);
  const input = JSON.parse((await readStdin()) || '{}');
  const command = input?.tool_input?.command;
  const parsed = vl.autoChecksDisabled() ? Object.assign([], { unparsed: [] }) : vl.parseInstallCommand(command);
  // `npx eslint` runs the project's own copy when that exact package is
  // installed locally. Exempt only that case: npm runner, no version, no
  // --package, and node_modules/<name>/package.json really is <name>.
  const cwd = input?.cwd || process.cwd();
  const localCopy = (s) => {
    if (!s.runner || s.explicit || s.version || s.ecosystem !== 'npm') return false;
    if (!/^(@[\w.-]+\/)?[\w.-]+$/.test(s.name) || s.name.includes('..')) return false;
    try {
      return JSON.parse(fs.readFileSync(path.join(cwd, 'node_modules', s.name, 'package.json'), 'utf8')).name === s.name;
    } catch {
      return false;
    }
  };
  const specs = parsed.filter((s) => !localCopy(s));
  const lines = [];
  if (parsed.unparsed.length) {
    lines.push(`Could not tell which package(s) this adds or runs: ${parsed.unparsed.slice(0, 3).map((x) => vl.sanitize(x, 60)).join(', ')}. Check them before approving.`);
  }
  if (specs.length > MAX_SPECS) lines.push(`Adds ${specs.length} packages; only the first ${MAX_SPECS} were vetted.`);
  if (specs.length) {
    const cooldown = vl.parseDuration(process.env.VULN_LEDGER_COOLDOWN || '48h');
    const deadline = Number(process.env.VULN_LEDGER_HOOK_TIMEOUT_MS || 12_000);
    const results = await Promise.race([
      Promise.all(specs.slice(0, MAX_SPECS).map((s) => vl.vetPackage(s, { cooldown }).catch(() => null))),
      new Promise((resolve) => setTimeout(() => resolve([]), deadline)),
    ]);
    for (const r of results.filter((x) => x?.verdict === 'BLOCK')) {
      lines.push(`${r.spec.ecosystem}:${vl.cell(r.spec.name, 100)}@${vl.cell(r.spec.version || '?', 40)}: ${r.reasons.map((m) => vl.sanitize(m, 200)).join(' ')}`);
    }
  }
  if (lines.length) {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          hookEventName: 'PreToolUse',
          permissionDecision: 'ask',
          permissionDecisionReason: `vuln-ledger flagged this install:\n${lines.join('\n')}`,
        },
      }),
    );
  }
} catch {
  // Fail open: never break the user's shell because a check failed.
}
process.exit(0);
