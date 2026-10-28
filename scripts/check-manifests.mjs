#!/usr/bin/env node
// Verifies every manifest parses, names the plugin "vuln-ledger", and carries
// the same version as package.json and the engine.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(root, rel), 'utf8');
const json = (rel) => JSON.parse(read(rel));

const version = json('package.json').version;
const problems = [];

const VERSIONED = ['.claude-plugin/plugin.json', '.codex-plugin/plugin.json', 'gemini-extension.json', 'qwen-extension.json', 'kimi.plugin.json', 'plugin.json'];
for (const rel of VERSIONED) {
  const m = json(rel);
  if (m.name !== 'vuln-ledger') problems.push(`${rel}: name is ${m.name}`);
  if (m.version !== version) problems.push(`${rel}: version ${m.version} != package.json ${version}`);
}
for (const rel of ['.claude-plugin/marketplace.json', '.agents/plugins/marketplace.json', 'hooks/hooks.json']) json(rel);

const engineVersion = read('skills/vuln-ledger/scripts/vuln-ledger.mjs').match(/export const VERSION = '([^']+)'/)?.[1];
if (engineVersion !== version) problems.push(`engine VERSION ${engineVersion} != ${version}`);

const skill = read('skills/vuln-ledger/SKILL.md');
const fm = skill.match(/^---\n([\s\S]*?)\n---/)?.[1] || '';
if (!/^name: vuln-ledger$/m.test(fm)) problems.push('SKILL.md: frontmatter name must be vuln-ledger');
const skillVersion = fm.match(/version: "([^"]+)"/)?.[1];
if (skillVersion !== version) problems.push(`SKILL.md metadata.version ${skillVersion} != ${version}`);
const desc = fm.match(/^description: '([\s\S]*?)'$/m)?.[1] || '';
if (desc.length > 1024) problems.push(`SKILL.md: description is ${desc.length} chars (max 1024)`);

if (problems.length) {
  console.error(problems.map((p) => `- ${p}`).join('\n'));
  process.exit(1);
}
console.log(`manifests OK (version ${version})`);
