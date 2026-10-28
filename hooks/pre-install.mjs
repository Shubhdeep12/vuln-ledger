// PreToolUse hook (Bash): when a shell command adds a dependency
// (npm/pnpm/yarn/bun add, composer require, pip/uv/poetry add, cargo add,
// go get, gem install, dotnet add package, dart pub add), vet each package
// before it runs.
//
// Asks the user to confirm only on a strong signal: a malicious version, a
// known high/critical vulnerability in the requested version, a name that does
// not exist on the registry (typo or hallucinated), or a release younger than
// the cooldown (VULN_LEDGER_COOLDOWN, default 48h). Otherwise silent.
// Never emits "allow", so it can only add friction, never remove it.
// Any failure or timeout exits 0 with no output (fail open).

import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

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
  const specs = vl.autoChecksDisabled() ? [] : vl.parseInstallCommand(command).slice(0, 6);
  if (specs.length) {
    const cooldown = vl.parseDuration(process.env.VULN_LEDGER_COOLDOWN || '48h');
    const deadline = Number(process.env.VULN_LEDGER_HOOK_TIMEOUT_MS || 12_000);
    const results = await Promise.race([
      Promise.all(specs.map((s) => vl.vetPackage(s, { cooldown }).catch(() => null))),
      new Promise((resolve) => setTimeout(() => resolve([]), deadline)),
    ]);
    const blocked = results.filter((r) => r?.verdict === 'BLOCK');
    if (blocked.length) {
      const lines = blocked.map(
        (r) => `${r.spec.ecosystem}:${r.spec.name}@${r.spec.version || '?'}: ${r.reasons.map((m) => vl.sanitize(m, 200)).join(' ')}`,
      );
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
  }
} catch {
  // Fail open: never break the user's shell because a check failed.
}
process.exit(0);
