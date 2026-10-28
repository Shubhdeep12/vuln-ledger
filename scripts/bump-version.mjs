#!/usr/bin/env node
// Bumps the version everywhere it appears: manifests, engine, SKILL.md, the
// Actions example, the Cursor mirror, and the CHANGELOG heading.
// Usage: node scripts/bump-version.mjs patch|minor|major|<x.y.z>

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const write = (rel, text) => fs.writeFileSync(path.join(root, rel), text);

const current = JSON.parse(read('package.json')).version;
const arg = process.argv[2];
const [maj, min, pat] = current.split('.').map(Number);
const next = { major: `${maj + 1}.0.0`, minor: `${maj}.${min + 1}.0`, patch: `${maj}.${min}.${pat + 1}` }[arg]
  || (/^\d+\.\d+\.\d+$/.test(arg || '') ? arg : null);
if (!next) {
  console.error('usage: node scripts/bump-version.mjs patch|minor|major|<x.y.z>');
  process.exit(1);
}

function replace(rel, from, to) {
  const text = read(rel);
  if (!text.includes(from)) throw new Error(`${rel}: "${from}" not found`);
  write(rel, text.replace(from, to));
}

const JSON_FILES = ['package.json', '.claude-plugin/plugin.json', '.codex-plugin/plugin.json', 'gemini-extension.json', 'qwen-extension.json', 'kimi.plugin.json', 'plugin.json'];
for (const rel of JSON_FILES) replace(rel, `"version": "${current}"`, `"version": "${next}"`);
replace('skills/vuln-ledger/scripts/vuln-ledger.mjs', `export const VERSION = '${current}'`, `export const VERSION = '${next}'`);
replace('skills/vuln-ledger/SKILL.md', `version: "${current}"`, `version: "${next}"`);
replace('examples/github-actions/vuln-ledger-daily.yml', `#v${current}`, `#v${next}`);

// Unreleased notes become this version's section; a fresh empty Unreleased stays on top.
const today = new Date().toISOString().slice(0, 10);
replace('CHANGELOG.md', '## Unreleased\n', `## Unreleased\n\n## ${next} (${today})\n`);

execFileSync(process.execPath, [path.join(root, 'scripts', 'sync-mirrors.mjs')], { stdio: 'inherit' });
console.log(`${current} -> ${next}`);
