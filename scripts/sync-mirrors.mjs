#!/usr/bin/env node
// Copies the canonical skill (skills/vuln-ledger/) into harness-specific mirror
// paths. `--check` exits 1 if any mirror is out of date (used in CI).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const source = path.join(root, 'skills', 'vuln-ledger');
const MIRRORS = [path.join(root, '.cursor', 'skills', 'vuln-ledger')];
const check = process.argv.includes('--check');

function listFiles(dir, base = dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) => {
    const full = path.join(dir, e.name);
    return e.isDirectory() ? listFiles(full, base) : [path.relative(base, full)];
  });
}

let drift = 0;
for (const mirror of MIRRORS) {
  const want = listFiles(source).sort();
  const have = listFiles(mirror).sort();
  for (const rel of want) {
    const a = fs.readFileSync(path.join(source, rel));
    const target = path.join(mirror, rel);
    const same = fs.existsSync(target) && a.equals(fs.readFileSync(target));
    if (same) continue;
    drift++;
    if (check) console.error(`out of date: ${path.relative(root, target)}`);
    else {
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(source, rel), target);
    }
  }
  for (const rel of have.filter((r) => !want.includes(r))) {
    drift++;
    if (check) console.error(`extra file: ${path.relative(root, path.join(mirror, rel))}`);
    else fs.rmSync(path.join(mirror, rel));
  }
}

if (check && drift) {
  console.error('Run: node scripts/sync-mirrors.mjs');
  process.exit(1);
}
console.log(check ? 'mirrors in sync' : `synced (${drift} file(s) updated)`);
