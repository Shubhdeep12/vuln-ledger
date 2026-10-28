#!/usr/bin/env node
// vuln-ledger: dependency vulnerability scanner with a memory.
//
// Reads lockfiles, asks OSV.dev which installed versions are affected, enriches
// findings with CISA KEV and FIRST EPSS, and diffs the result against a
// per-project ledger so the user hears about each change once: new, escalated,
// fix available, resolved. Zero dependencies, Node 18+.
//
// Read-only on the project. It writes only its own ledger and cache under
// VULN_LEDGER_HOME (default ~/.local/state/vuln-ledger), or to a shared
// .vuln-ledger.json when the project opted into one.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export const VERSION = '0.2.0';
const LEDGER_SCHEMA = 1;
const UA = `vuln-ledger/${VERSION} (+https://github.com/Shubhdeep12/vuln-ledger)`;

const env = (name, fallback) => process.env[name] || fallback;
const OSV_API = () => env('VULN_LEDGER_OSV_URL', 'https://api.osv.dev');
const KEV_URL = () =>
  env('VULN_LEDGER_KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');
const EPSS_API = () => env('VULN_LEDGER_EPSS_URL', 'https://api.first.org/data/v1/epss');
const NPM_REGISTRY = () => env('VULN_LEDGER_NPM_URL', 'https://registry.npmjs.org');

export const RANK = { UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4, MALICIOUS: 5 };
export const EXIT = { OK: 0, ERROR: 1, NEWS: 10, BLOCKING: 20, INCOMPLETE: 30 };

const DAY = 86_400_000;
const FRESH_WINDOW = 14 * DAY; // "newly disclosed" if published within this window
const KEV_TTL = DAY;
const EPSS_TTL = DAY;

// ---------------------------------------------------------------------------
// Paths and state
// ---------------------------------------------------------------------------

export function stateHome() {
  if (process.env.VULN_LEDGER_HOME) return process.env.VULN_LEDGER_HOME;
  if (process.platform === 'win32') {
    return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'vuln-ledger');
  }
  return path.join(process.env.XDG_STATE_HOME || path.join(os.homedir(), '.local', 'state'), 'vuln-ledger');
}

export function configHome() {
  if (process.env.VULN_LEDGER_CONFIG) return process.env.VULN_LEDGER_CONFIG;
  if (process.platform === 'win32') {
    return path.join(process.env.APPDATA || path.join(os.homedir(), 'AppData', 'Roaming'), 'vuln-ledger');
  }
  return path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), '.config'), 'vuln-ledger');
}

// Automatic checks (hooks, plugins) honor this; explicit CLI commands do not.
export function autoChecksDisabled() {
  return process.env.VULN_LEDGER_DISABLE === '1' || fs.existsSync(path.join(configHome(), 'disabled'));
}

// An in-repo ledger is controlled by whoever can commit to the repo: it could
// pre-mark findings as reported or accepted. Use it only on explicit opt-in.
export function sharedLedgerAllowed() {
  return process.env.VULN_LEDGER_SHARED === '1';
}

export function ledgerPathFor(root, explicit) {
  if (explicit) return path.resolve(explicit);
  const shared = path.join(root, '.vuln-ledger.json');
  if (sharedLedgerAllowed() && fs.existsSync(shared)) return shared;
  let real = root;
  try {
    real = fs.realpathSync(root);
  } catch {}
  const id = crypto.createHash('sha256').update(real).digest('hex').slice(0, 16);
  const base = path.basename(real).replace(/[^\w.-]/g, '_') || 'root';
  return path.join(stateHome(), 'projects', `${base}-${id}.json`);
}

function readJSON(file, fallback = null) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJSON(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2) + '\n');
  fs.renameSync(tmp, file);
}

export function newLedger(root) {
  return {
    schema: LEDGER_SCHEMA,
    tool: `vuln-ledger ${VERSION}`,
    project: root,
    created: new Date().toISOString(),
    lastScan: null,
    lastNetworkScan: null,
    inputsHash: null,
    inventory: null,
    findings: {},
    history: [],
  };
}

const STATUSES = new Set(['open', 'accepted', 'resolved']);
const isStr = (v, max = 256) => typeof v === 'string' && v.length <= max;
const isTime = (v) => v == null || (isStr(v, 40) && !Number.isNaN(Date.parse(v)));

// Drop anything that does not look like an entry this tool wrote. A ledger can
// be hand-edited or (with VULN_LEDGER_SHARED=1) come from the repository.
function validEntry(key, e) {
  return (
    e && typeof e === 'object' &&
    isStr(e.id, 80) && isStr(e.ecosystem, 40) && isStr(e.package, 256) && isStr(e.installed, 80) &&
    key === `${e.id}|${e.ecosystem}|${e.package}` &&
    STATUSES.has(e.status) && RANK[e.level] !== undefined &&
    Array.isArray(e.aliases ?? []) && (e.aliases ?? []).every((a) => isStr(a, 80)) &&
    (e.fixed == null || isStr(e.fixed, 80)) &&
    (e.score == null || (typeof e.score === 'number' && e.score >= 0 && e.score <= 10)) &&
    ['notifiedAt', 'remindedAt', 'firstSeen', 'lastSeen', 'resolvedAt'].every((k) => isTime(e[k])) &&
    (e.decision == null || (typeof e.decision === 'object' && isStr(e.decision.reason ?? '', 500) && isTime(e.decision.at) && isTime(e.decision.until)))
  );
}

export function loadLedger(file, root) {
  const data = readJSON(file);
  if (!data || data.schema !== LEDGER_SCHEMA || !data.findings || typeof data.findings !== 'object') return newLedger(root);
  const findings = {};
  for (const [key, e] of Object.entries(data.findings)) {
    if (!validEntry(key, e)) continue;
    // Malicious findings can never be accepted, whoever wrote the ledger.
    if (e.status === 'accepted' && (e.level === 'MALICIOUS' || e.malicious)) e.status = 'open';
    findings[key] = e;
  }
  data.findings = findings;
  data.history = Array.isArray(data.history) ? data.history.slice(-500) : [];
  if (!isTime(data.lastNetworkScan)) data.lastNetworkScan = null;
  return data;
}

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

export function parseDuration(text) {
  if (text == null || text === '') return null;
  if (typeof text === 'number') return text;
  const m = String(text).trim().match(/^(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)?$/i);
  if (!m) return null;
  const mult = { ms: 1, s: 1000, m: 60_000, h: 3_600_000, d: DAY, w: 7 * DAY }[(m[2] || 'h').toLowerCase()];
  return Math.round(Number(m[1]) * mult);
}

// "30d" -> now + 30 days; "2026-12-01" -> that date. Returns ISO string or null.
export function parseUntil(text, now = new Date()) {
  if (!text) return null;
  if (/^\d{4}-\d{2}-\d{2}/.test(text)) {
    const t = Date.parse(text);
    return Number.isNaN(t) ? null : new Date(t).toISOString();
  }
  const ms = parseDuration(text);
  return ms == null ? null : new Date(now.getTime() + ms).toISOString();
}

const day = (iso) => (iso ? String(iso).slice(0, 10) : '?');
const stamp = (iso) => (iso ? `${String(iso).slice(0, 16).replace('T', ' ')} UTC` : 'never');

function ago(iso, now = new Date()) {
  if (!iso) return 'never';
  const ms = now - Date.parse(iso);
  if (ms < 3_600_000) return `${Math.max(1, Math.round(ms / 60_000))}m ago`;
  if (ms < DAY) return `${Math.round(ms / 3_600_000)}h ago`;
  return `${Math.round(ms / DAY)}d ago`;
}

// Advisory text is untrusted. Strip anything that could become markup or a
// fake instruction block, and keep it short.
export function sanitize(text, max = 90) {
  const clean = String(text ?? '')
    .replace(/[\u0000-\u001f\u007f​-‏‪-‮]+/g, ' ')
    .replace(/[|`<>[\]{}*_#]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

// For values from lockfiles and the ledger (names, versions, paths): keep
// package-name punctuation, but no newlines, table pipes, or markup.
export function cell(text, max = 80) {
  const clean = String(text ?? '')
    .replace(/[\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2028\u2029]+/g, ' ')
    .replace(/[|`<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean;
}

async function pool(items, size, fn) {
  const out = new Array(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (next < items.length) {
      const i = next++;
      out[i] = await fn(items[i], i);
    }
  });
  await Promise.all(workers);
  return out;
}

export async function http(url, { method = 'GET', body, timeout = 15_000, headers = {}, text = false } = {}) {
  const res = await fetch(url, {
    method,
    headers: { 'user-agent': UA, accept: 'application/json', ...(body ? { 'content-type': 'application/json' } : {}), ...headers },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(timeout),
  });
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`${method} ${new URL(url).host}${new URL(url).pathname} -> HTTP ${res.status}`);
  return text ? res.text() : res.json();
}

// ---------------------------------------------------------------------------
// Versions and severity
// ---------------------------------------------------------------------------

function splitVersion(v) {
  const s = String(v).trim().replace(/^v(?=\d)/i, '').replace(/\+.*$/, '');
  const m = s.match(/^(\d+(?:[.]\d+)*)(.*)$/);
  if (!m) return { nums: [], rest: s };
  return { nums: m[1].split('.').map(Number), rest: m[2] };
}

// Ecosystem-agnostic ordering, good enough for range checks: numeric release
// parts first, then pre-releases sort before the release, post-releases after.
export function compareVersions(a, b) {
  const A = splitVersion(a);
  const B = splitVersion(b);
  const len = Math.max(A.nums.length, B.nums.length);
  for (let i = 0; i < len; i++) {
    const x = A.nums[i] ?? 0;
    const y = B.nums[i] ?? 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  const kind = (rest) => {
    if (!rest) return 0;
    if (/^[.-]?(post|p|pl|r|rev)\d*$/i.test(rest)) return 1;
    return -1;
  };
  const ka = kind(A.rest);
  const kb = kind(B.rest);
  if (ka !== kb) return ka < kb ? -1 : 1;
  if (A.rest === B.rest) return 0;
  return A.rest.localeCompare(B.rest, 'en', { numeric: true });
}

export function bumpType(from, to) {
  const A = splitVersion(from).nums;
  const B = splitVersion(to).nums;
  if (!A.length || !B.length) return 'unknown';
  if ((A[0] ?? 0) !== (B[0] ?? 0)) return 'major';
  if ((A[1] ?? 0) !== (B[1] ?? 0)) return A[0] === 0 ? 'minor, 0.x: may break' : 'minor';
  return 'patch';
}

function roundUp(x) {
  const i = Math.round(x * 100000);
  return i % 10000 === 0 ? i / 100000 : (Math.floor(i / 10000) + 1) / 10;
}

// CVSS v3.x base score from a vector string, per the FIRST specification.
export function cvss3(vector) {
  if (!/^CVSS:3\.[01]\//.test(vector || '')) return null;
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':')));
  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }[m.AV];
  const AC = { L: 0.77, H: 0.44 }[m.AC];
  const UI = { N: 0.85, R: 0.62 }[m.UI];
  const changed = m.S === 'C';
  const PR = (changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 })[m.PR];
  const CIA = { H: 0.56, L: 0.22, N: 0 };
  const C = CIA[m.C];
  const I = CIA[m.I];
  const A = CIA[m.A];
  if ([AV, AC, UI, PR, C, I, A].some((x) => x === undefined) || !['U', 'C'].includes(m.S)) return null;
  const iss = 1 - (1 - C) * (1 - I) * (1 - A);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15) : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploit = 8.22 * AV * AC * PR * UI;
  return roundUp(Math.min(changed ? 1.08 * (impact + exploit) : impact + exploit, 10));
}

export function scoreToLevel(score) {
  if (score == null) return null;
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  return 'LOW';
}

function normalizeLevel(text) {
  const t = String(text || '').toUpperCase();
  if (t === 'MODERATE') return 'MEDIUM';
  if (t === 'IMPORTANT') return 'HIGH';
  return RANK[t] !== undefined && t !== 'UNKNOWN' ? t : null;
}

export function isMalicious(vuln) {
  return /^MAL-/.test(vuln?.id || '') || Boolean(vuln?.database_specific?.['malicious-packages-origins']);
}

export function severityOf(vuln) {
  if (isMalicious(vuln)) return { level: 'MALICIOUS', score: null, vector: null };
  let score = null;
  let vector = null;
  const vectors = [...(vuln.severity || []), ...(vuln.affected || []).flatMap((a) => a.severity || [])];
  for (const s of vectors) {
    if (s.type === 'CVSS_V3' && score == null) {
      score = cvss3(s.score);
      vector = s.score;
    } else if (!vector) {
      vector = s.score;
    }
  }
  let level = normalizeLevel(vuln.database_specific?.severity);
  if (!level) {
    for (const a of vuln.affected || []) {
      level = normalizeLevel(a.ecosystem_specific?.severity) || normalizeLevel(a.database_specific?.severity);
      if (level) break;
    }
  }
  // A curated rating wins; drop a CVSS v3 score that contradicts it (e.g. a
  // placeholder all-None vector next to a newer CVSS v4 rating).
  if (level && score != null && scoreToLevel(score) !== level) score = null;
  return { level: level || scoreToLevel(score) || 'UNKNOWN', score, vector };
}

export function normName(ecosystem, name) {
  if (ecosystem === 'PyPI') return name.toLowerCase().replace(/[-_.]+/g, '-');
  if (ecosystem === 'Packagist' || ecosystem === 'NuGet') return name.toLowerCase();
  return name;
}

// The smallest fixed version for the range that contains `version`, else the
// smallest fixed version above it, else null (no fix published).
export function fixedFor(vuln, pkg) {
  const inRange = [];
  const above = [];
  for (const a of vuln.affected || []) {
    if (!a.package) continue;
    if (a.package.ecosystem.split(':')[0] !== pkg.ecosystem) continue;
    if (normName(pkg.ecosystem, a.package.name) !== normName(pkg.ecosystem, pkg.name)) continue;
    for (const r of a.ranges || []) {
      if (r.type === 'GIT') continue;
      let introduced = null;
      for (const e of r.events || []) {
        if (e.introduced !== undefined) introduced = e.introduced;
        else if (e.fixed !== undefined) {
          const lo = introduced == null || introduced === '0' || compareVersions(pkg.version, introduced) >= 0;
          if (lo && compareVersions(pkg.version, e.fixed) < 0) inRange.push(e.fixed);
          else if (compareVersions(e.fixed, pkg.version) > 0) above.push(e.fixed);
          introduced = null;
        }
      }
    }
  }
  const pick = (list) => list.sort(compareVersions)[0] ?? null;
  return pick(inRange) ?? pick(above);
}

// ---------------------------------------------------------------------------
// Lockfile discovery and parsing
// ---------------------------------------------------------------------------

const SKIP_DIRS = new Set([
  '.git', 'node_modules', 'vendor', 'bower_components', '.venv', 'venv', 'env', '.tox', '.nox',
  '__pycache__', 'target', 'dist', 'build', 'out', '.next', '.nuxt', '.cache', 'Pods', '.gradle',
  '.idea', '.vscode', 'coverage', '.terraform', '.dart_tool', '_build', 'deps',
]);

const PARSERS = {
  'composer.lock': ['Packagist', parseComposerLock],
  'package-lock.json': ['npm', parsePackageLock],
  'npm-shrinkwrap.json': ['npm', parsePackageLock],
  'yarn.lock': ['npm', parseYarnLock],
  'pnpm-lock.yaml': ['npm', parsePnpmLock],
  'bun.lock': ['npm', parseBunLock],
  'poetry.lock': ['PyPI', parseTomlPackages],
  'uv.lock': ['PyPI', parseTomlPackages],
  'pdm.lock': ['PyPI', parseTomlPackages],
  'Pipfile.lock': ['PyPI', parsePipfileLock],
  'Cargo.lock': ['crates.io', parseTomlPackages],
  'go.mod': ['Go', parseGoMod],
  'Gemfile.lock': ['RubyGems', parseGemfileLock],
  'pom.xml': ['Maven', parsePom],
  'gradle.lockfile': ['Maven', parseGradleLock],
  'packages.lock.json': ['NuGet', parseNugetLock],
  'pubspec.lock': ['Pub', parsePubspecLock],
  'mix.lock': ['Hex', parseMixLock],
};

const isRequirements = (base) => /^requirements([.-][\w.-]+)?\.txt$/i.test(base) || /^constraints\.txt$/i.test(base);

// Manifests that mean "dependencies exist but are not pinned by a lockfile".
const UNLOCKED_MANIFESTS = {
  'composer.json': ['composer.lock'],
  'package.json': ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock', 'bun.lockb'],
  'Cargo.toml': ['Cargo.lock'],
  Gemfile: ['Gemfile.lock'],
  'pyproject.toml': ['poetry.lock', 'uv.lock', 'pdm.lock', 'requirements.txt'],
};

export function discover(root, maxDepth = 4) {
  const found = [];
  const notes = [];
  const walk = (dir, depth) => {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const names = new Set(entries.map((e) => e.name));
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth && !SKIP_DIRS.has(e.name) && !e.name.startsWith('.')) walk(full, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      if (PARSERS[e.name]) found.push(full);
      else if (isRequirements(e.name)) found.push(full);
      else if (UNLOCKED_MANIFESTS[e.name] && !UNLOCKED_MANIFESTS[e.name].some((l) => names.has(l))) {
        // pyproject.toml without a lock is common for libraries; only note it if it declares deps.
        if (e.name === 'pyproject.toml' && !/dependencies\s*=/.test(safeRead(full))) continue;
        if (e.name === 'package.json' && !/"(dev)?[dD]ependencies"\s*:\s*\{\s*"/.test(safeRead(full))) continue;
        notes.push(`${path.relative(root, full) || e.name} has no lockfile next to it, so its versions are unresolved and were not checked.`);
      }
    }
  };
  walk(root, 0);
  return { files: found.sort(), notes };
}

function safeRead(file) {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return '';
  }
}

const looksLikeVersion = (v) => /^\d/.test(String(v || '').replace(/^v/i, ''));

export function parseComposerLock(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const [list, dev] of [[j.packages, false], [j['packages-dev'], true]]) {
    for (const p of list || []) {
      if (p.name && looksLikeVersion(p.version)) out.push({ name: p.name, version: p.version.replace(/^v/i, ''), dev });
    }
  }
  return out;
}

export function parsePackageLock(text) {
  const j = JSON.parse(text);
  const out = [];
  if (j.packages) {
    for (const [key, v] of Object.entries(j.packages)) {
      const at = key.lastIndexOf('node_modules/');
      if (at < 0 || v.link || !looksLikeVersion(v.version)) continue;
      out.push({ name: v.name || key.slice(at + 13), version: v.version, dev: Boolean(v.dev) });
    }
  } else if (j.dependencies) {
    const walk = (deps) => {
      for (const [name, v] of Object.entries(deps)) {
        if (looksLikeVersion(v.version)) out.push({ name, version: v.version, dev: Boolean(v.dev) });
        if (v.dependencies) walk(v.dependencies);
      }
    };
    walk(j.dependencies);
  }
  return out;
}

function splitNpmSpec(spec) {
  // "name@range", "@scope/name@range", "alias@npm:real@range"
  const at = spec.indexOf('@', 1);
  if (at < 0) return { name: spec, range: '' };
  let name = spec.slice(0, at);
  let range = spec.slice(at + 1);
  if (range.startsWith('npm:')) {
    const inner = range.slice(4);
    const innerAt = inner.indexOf('@', 1);
    if (innerAt > 0) {
      name = inner.slice(0, innerAt);
      range = inner.slice(innerAt + 1);
    } else range = inner;
  }
  return { name, range };
}

export function parseYarnLock(text) {
  const out = [];
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    if (!/^\s/.test(line)) {
      const first = line.replace(/:\s*$/, '').split(',')[0].trim().replace(/^"|"$/g, '');
      if (first === '__metadata') {
        current = null;
        continue;
      }
      const { name, range } = splitNpmSpec(first);
      current = /^(workspace|patch|link|file|portal|git|github|https?):/.test(range) || range.includes('#') ? null : name;
      continue;
    }
    const m = line.match(/^\s{2}version:?\s+"?([^"\s]+)"?\s*$/);
    if (m && current) {
      if (looksLikeVersion(m[1])) out.push({ name: current, version: m[1] });
      current = null;
    }
  }
  return out;
}

export function parsePnpmLock(text) {
  const out = [];
  let section = null;
  for (const line of text.split(/\r?\n/)) {
    const top = line.match(/^([A-Za-z][\w-]*):/);
    if (top) {
      section = top[1];
      continue;
    }
    if (section !== 'packages') continue;
    const m = line.match(/^ {2}['"]?\/?((?:@[^/@'"]+\/)?[^/@'"(\s]+)[@/]([^('":\s]+)/);
    if (!m) continue;
    const version = m[2].split('_')[0];
    if (looksLikeVersion(version)) out.push({ name: m[1], version });
  }
  return out;
}

export function parseBunLock(text) {
  const out = [];
  const start = text.indexOf('"packages"');
  if (start < 0) return out;
  const re = /^\s*"[^"]+":\s*\["((?:@[^@"/]+\/)?[^@"]+)@([^"]+)"/gm;
  re.lastIndex = start;
  for (let m; (m = re.exec(text)); ) {
    if (looksLikeVersion(m[2])) out.push({ name: m[1], version: m[2] });
  }
  return out;
}

export function parseTomlPackages(text, base) {
  const out = [];
  for (const block of text.split(/^\[\[package\]\]\s*$/m).slice(1)) {
    const body = block.split(/^\[/m)[0];
    const name = body.match(/^name\s*=\s*"([^"]+)"/m)?.[1];
    const version = body.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
    const source = body.match(/^source\s*=\s*(.+)$/m)?.[1] || '';
    if (!name || !looksLikeVersion(version)) continue;
    if (base === 'Cargo.lock' && !source) continue; // workspace member
    if (base === 'uv.lock' && /editable|virtual|directory|path\s*=/.test(source)) continue;
    out.push({ name, version });
  }
  return out;
}

export function parsePipfileLock(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const [section, dev] of [['default', false], ['develop', true]]) {
    for (const [name, v] of Object.entries(j[section] || {})) {
      const version = String(v.version || '').replace(/^==/, '');
      if (looksLikeVersion(version)) out.push({ name, version, dev, direct: null });
    }
  }
  return out;
}

export function parseRequirements(text) {
  const out = [];
  let unpinned = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').replace(/\\$/, '').trim();
    if (!line || line.startsWith('#') || line.startsWith('-')) continue;
    const m = line.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*===?\s*([^\s;,]+)/);
    if (m) out.push({ name: m[1], version: m[2], direct: true });
    else if (/^[A-Za-z0-9]/.test(line) && !/:\/\//.test(line)) unpinned++;
  }
  out.unpinned = unpinned;
  return out;
}

export function parseGoMod(text) {
  const out = [];
  let inBlock = false;
  let goVersion = null;
  let toolchain = null;
  for (const raw of text.split(/\r?\n/)) {
    const t = raw.trim();
    const g = t.match(/^go\s+(\d+\.\d+(?:\.\d+)?)\s*$/);
    if (g) goVersion = g[1];
    const tc = t.match(/^toolchain\s+go(\d+\.\d+\.\d+)/);
    if (tc) toolchain = tc[1];
    if (/^require\s*\($/.test(t)) {
      inBlock = true;
      continue;
    }
    if (inBlock && t === ')') {
      inBlock = false;
      continue;
    }
    const m = inBlock ? t.match(/^(\S+)\s+(v\S+)(.*)$/) : t.match(/^require\s+(\S+)\s+(v\S+)(.*)$/);
    if (m) out.push({ name: m[1], version: m[2].replace(/^v/, ''), direct: !/\/\/\s*indirect/.test(m[3]) });
  }
  const std = toolchain || (goVersion && goVersion.split('.').length === 3 ? goVersion : null);
  if (std) out.push({ name: 'stdlib', version: std, direct: true });
  return out;
}

export function parseGemfileLock(text) {
  const out = [];
  const direct = new Set();
  let section = null;
  let inSpecs = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^[A-Z]/.test(line)) {
      section = line.trim();
      inSpecs = false;
      continue;
    }
    if (line.trim() === 'specs:') {
      inSpecs = section === 'GEM';
      continue;
    }
    if (inSpecs) {
      const m = line.match(/^ {4}([^\s(]+) \(([^)]+)\)\s*$/);
      if (m) out.push({ name: m[1], version: m[2].replace(/-(x86|x64|arm|aarch|universal|java|mingw|mswin|darwin|linux).*$/, '') });
    } else if (section === 'DEPENDENCIES') {
      const d = line.match(/^ {2}([^\s(!]+)/);
      if (d) direct.add(d[1]);
    }
  }
  for (const p of out) p.direct = direct.size ? direct.has(p.name) : null;
  return out;
}

export function parsePom(text) {
  const out = [];
  for (const m of text.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)) {
    const g = m[1].match(/<groupId>\s*([^<\s]+)\s*<\/groupId>/)?.[1];
    const a = m[1].match(/<artifactId>\s*([^<\s]+)\s*<\/artifactId>/)?.[1];
    const v = m[1].match(/<version>\s*([^<\s]+)\s*<\/version>/)?.[1];
    if (g && a && v && !v.includes('${') && looksLikeVersion(v)) out.push({ name: `${g}:${a}`, version: v, direct: true });
  }
  return out;
}

export function parseGradleLock(text) {
  const out = [];
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([^#:\s]+):([^:\s]+):([^=\s]+)=/);
    if (m && looksLikeVersion(m[3])) out.push({ name: `${m[1]}:${m[2]}`, version: m[3] });
  }
  return out;
}

export function parseNugetLock(text) {
  const j = JSON.parse(text);
  const out = [];
  for (const deps of Object.values(j.dependencies || {})) {
    for (const [name, v] of Object.entries(deps)) {
      if (v.type === 'Project' || !looksLikeVersion(v.resolved)) continue;
      out.push({ name, version: v.resolved, direct: v.type === 'Direct' });
    }
  }
  return out;
}

export function parsePubspecLock(text) {
  const out = [];
  let cur = null;
  for (const line of text.split(/\r?\n/)) {
    const key = line.match(/^ {2}([\w-]+):\s*$/);
    if (key) {
      cur = { name: key[1], direct: null, source: null };
      continue;
    }
    if (!cur) continue;
    const dep = line.match(/^ {4}dependency:\s*"?([^"]+)"?/);
    if (dep) cur.direct = dep[1].startsWith('direct');
    const src = line.match(/^ {4}source:\s*(\S+)/);
    if (src) cur.source = src[1];
    const ver = line.match(/^ {4}version:\s*"?([^"\s]+)"?/);
    if (ver) {
      if (cur.source !== 'sdk' && cur.source !== 'path' && looksLikeVersion(ver[1])) {
        out.push({ name: cur.name, version: ver[1], direct: cur.direct });
      }
      cur = null;
    }
  }
  return out;
}

export function parseMixLock(text) {
  const out = [];
  for (const m of text.matchAll(/\{:hex,\s*:"?([\w-]+)"?,\s*"([^"]+)"/g)) {
    if (looksLikeVersion(m[2])) out.push({ name: m[1], version: m[2] });
  }
  return out;
}

// Direct dependency names declared in the manifest next to a lockfile.
function directNames(dir, base) {
  const read = (f) => safeRead(path.join(dir, f));
  try {
    if (base === 'composer.lock') {
      const j = JSON.parse(read('composer.json') || '{}');
      return new Set([...Object.keys(j.require || {}), ...Object.keys(j['require-dev'] || {})].map((n) => n.toLowerCase()));
    }
    if (['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lock'].includes(base)) {
      const j = JSON.parse(read('package.json') || '{}');
      return new Set(
        ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'].flatMap((k) => Object.keys(j[k] || {})),
      );
    }
    if (base === 'Cargo.lock') {
      const toml = read('Cargo.toml');
      const names = new Set();
      let inDeps = false;
      for (const line of toml.split(/\r?\n/)) {
        const sec = line.match(/^\[(.+)\]\s*$/);
        if (sec) {
          const s = sec[1];
          const tableDep = s.match(/(?:^|\.)(?:dev-|build-)?dependencies\.([\w-]+)$/);
          if (tableDep) names.add(tableDep[1]);
          inDeps = /(^|\.)(dev-|build-)?dependencies$/.test(s);
          continue;
        }
        const k = inDeps && line.match(/^([\w-]+)\s*=/);
        if (k) names.add(k[1]);
      }
      return names;
    }
    if (['poetry.lock', 'uv.lock', 'pdm.lock'].includes(base)) {
      const toml = read('pyproject.toml');
      const names = new Set();
      for (const m of toml.matchAll(/^\s*"([A-Za-z0-9][A-Za-z0-9._-]*)/gm)) names.add(normName('PyPI', m[1]));
      let inPoetry = false;
      for (const line of toml.split(/\r?\n/)) {
        const sec = line.match(/^\[(.+)\]\s*$/);
        if (sec) {
          inPoetry = /^tool\.poetry\.(.*\.)?dependencies$/.test(sec[1]);
          continue;
        }
        const k = inPoetry && line.match(/^([A-Za-z0-9][\w.-]*)\s*=/);
        if (k && k[1] !== 'python') names.add(normName('PyPI', k[1]));
      }
      return names.size ? names : null;
    }
  } catch {
    return null;
  }
  return null;
}

// Real package names and versions across ecosystems fit these. Anything else
// (spaces, newlines, markup) is rejected before it can reach agent context.
const VALID_NAME = /^[\w@.\/:+~-]{1,214}$/;
const VALID_VERSION = /^[\w.+~:-]{1,80}$/;

export function buildInventory(root, files) {
  const byKey = new Map();
  const notes = [];
  const errors = [];
  for (const file of files) {
    const base = path.basename(file);
    const rel = path.relative(root, file) || base;
    const [ecosystem, parser] = PARSERS[base] || ['PyPI', parseRequirements];
    let pkgs;
    try {
      pkgs = parser(fs.readFileSync(file, 'utf8'), base);
    } catch (err) {
      errors.push(rel);
      notes.push(`Could not parse ${rel} (${sanitize(err.message, 60)}); its packages were not checked.`);
      continue;
    }
    if (pkgs.unpinned) notes.push(`${rel}: ${pkgs.unpinned} unpinned requirement(s) skipped. Pin them or check a lockfile.`);
    const direct = directNames(path.dirname(file), base);
    const invalid = pkgs.filter((p) => !VALID_NAME.test(String(p.name)) || !VALID_VERSION.test(String(p.version)));
    if (invalid.length) notes.push(`${rel}: skipped ${invalid.length} entr${invalid.length === 1 ? 'y' : 'ies'} with malformed names or versions.`);
    for (const p of pkgs) {
      if (invalid.includes(p)) continue;
      const name = normName(ecosystem, p.name);
      const isDirect = p.direct ?? (direct ? direct.has(name) || direct.has(p.name) : null);
      const key = `${ecosystem}|${name}|${p.version}`;
      const prev = byKey.get(key);
      if (prev) {
        if (!prev.files.includes(rel)) prev.files.push(rel);
        prev.direct = prev.direct || isDirect;
        prev.dev = prev.dev && Boolean(p.dev);
      } else {
        byKey.set(key, { ecosystem, name, version: p.version, files: [rel], direct: isDirect, dev: Boolean(p.dev) });
      }
    }
  }
  return { packages: [...byKey.values()], notes, errors };
}

export function hashInputs(files) {
  const h = crypto.createHash('sha256');
  for (const f of files) {
    h.update(f);
    h.update('\0');
    h.update(safeRead(f));
    h.update('\0');
  }
  return h.digest('hex');
}

// ---------------------------------------------------------------------------
// OSV, KEV, EPSS
// ---------------------------------------------------------------------------

export async function osvQueryBatch(packages) {
  const hits = packages.map(() => []);
  for (let start = 0; start < packages.length; start += 1000) {
    const chunk = packages.slice(start, start + 1000);
    let queries = chunk.map((p, i) => ({ i: start + i, q: { package: { ecosystem: p.ecosystem, name: p.name }, version: p.version } }));
    for (let page = 0; queries.length && page < 5; page++) {
      const res = await http(`${OSV_API()}/v1/querybatch`, { method: 'POST', body: { queries: queries.map((x) => x.q) }, timeout: 30_000 });
      const next = [];
      (res?.results || []).forEach((r, k) => {
        const item = queries[k];
        for (const v of r.vulns || []) hits[item.i].push({ id: v.id, modified: v.modified });
        if (r.next_page_token) next.push({ i: item.i, q: { ...item.q, page_token: r.next_page_token } });
      });
      queries = next;
    }
  }
  return hits;
}

function cacheFile(kind, id) {
  return path.join(stateHome(), 'cache', kind, `${String(id).replace(/[^\w.-]/g, '_')}.json`);
}

export async function getVuln(id, modified) {
  const file = cacheFile('osv', id);
  const cached = readJSON(file);
  if (cached && (!modified || cached.modified === modified)) return cached;
  const data = await http(`${OSV_API()}/v1/vulns/${encodeURIComponent(id)}`);
  if (data) writeJSON(file, data);
  return data || cached;
}

async function loadKev(now) {
  const file = path.join(stateHome(), 'cache', 'kev.json');
  const cached = readJSON(file);
  if (cached && now - Date.parse(cached.fetchedAt) < KEV_TTL) return new Set(cached.cves);
  try {
    const data = await http(KEV_URL(), { timeout: 20_000 });
    const cves = (data?.vulnerabilities || []).map((v) => v.cveID).filter(Boolean);
    writeJSON(file, { fetchedAt: now.toISOString(), cves });
    return new Set(cves);
  } catch {
    return cached ? new Set(cached.cves) : null;
  }
}

async function loadEpss(cves, now) {
  const file = path.join(stateHome(), 'cache', 'epss.json');
  const cache = readJSON(file, {});
  const stale = cves.filter((c) => !cache[c] || now - Date.parse(cache[c].at) > EPSS_TTL);
  for (let i = 0; i < stale.length; i += 50) {
    const batch = stale.slice(i, i + 50);
    try {
      const res = await http(`${EPSS_API()}?cve=${batch.join(',')}&limit=100`, { timeout: 15_000 });
      for (const c of batch) cache[c] = { epss: null, at: now.toISOString() };
      for (const row of res?.data || []) cache[row.cve] = { epss: Number(row.epss), percentile: Number(row.percentile), at: now.toISOString() };
    } catch {
      break;
    }
  }
  try {
    writeJSON(file, cache);
  } catch {}
  return cache;
}

const ID_PREFERENCE = (id) => (id.startsWith('MAL-') ? 0 : id.startsWith('GHSA-') ? 1 : id.startsWith('CVE-') ? 3 : 2);

// Turn raw OSV hits into deduplicated findings: one per package per issue,
// even when GHSA, PYSEC and CVE records describe the same flaw.
export async function buildFindings(packages, hits, { now = new Date(), kev = true, epss = true, details = null } = {}) {
  const notes = [];
  const wanted = new Map();
  hits.forEach((list) => list.forEach((h) => wanted.set(h.id, h.modified)));
  const vulns = new Map();
  let failed = 0;
  await pool([...wanted.keys()], 8, async (id) => {
    try {
      const v = details?.get(id) || (await getVuln(id, wanted.get(id)));
      if (v) vulns.set(id, v);
      else failed++;
    } catch {
      failed++;
    }
  });
  if (failed) notes.push(`${failed} advisory record(s) could not be fetched; severities may be incomplete.`);

  // Fill unknown severities from a GHSA alias, which usually carries a rating.
  for (const v of [...vulns.values()]) {
    if (severityOf(v).level !== 'UNKNOWN') continue;
    const alias = (v.aliases || []).find((a) => a.startsWith('GHSA-'));
    if (!alias || vulns.has(alias)) continue;
    try {
      const g = await getVuln(alias);
      if (g) vulns.set(alias, g);
    } catch {}
  }

  const findings = [];
  packages.forEach((pkg, i) => {
    const ids = [...new Set(hits[i].map((h) => h.id))].sort((a, b) => ID_PREFERENCE(a) - ID_PREFERENCE(b) || a.localeCompare(b));
    const seen = new Set();
    for (const id of ids) {
      const v = vulns.get(id);
      if (seen.has(id)) continue;
      if (!v) {
        findings.push(makeFinding(pkg, { id, aliases: [] }, [], now));
        seen.add(id);
        continue;
      }
      if (v.withdrawn) continue;
      const group = [v, ...(v.aliases || []).map((a) => vulns.get(a)).filter(Boolean)];
      for (const g of group) {
        seen.add(g.id);
        (g.aliases || []).forEach((a) => seen.add(a));
      }
      findings.push(makeFinding(pkg, v, group, now));
    }
  });

  const cves = [...new Set(findings.flatMap((f) => f.cves))];
  if (cves.length && kev) {
    const set = await loadKev(now);
    if (set) for (const f of findings) f.kev = f.cves.some((c) => set.has(c));
    else notes.push('CISA KEV list unavailable; "actively exploited" flags are missing.');
  }
  if (cves.length && epss) {
    const cache = await loadEpss(cves, now);
    for (const f of findings) {
      const scores = f.cves.map((c) => cache[c]?.epss).filter((x) => typeof x === 'number');
      f.epss = scores.length ? Math.max(...scores) : null;
    }
  }
  return { findings, notes, failed };
}

function makeFinding(pkg, v, group, now) {
  const all = group.length ? group : [v];
  let best = { level: 'UNKNOWN', score: null, vector: null };
  for (const g of all) {
    const s = severityOf(g);
    if (RANK[s.level] > RANK[best.level] || (s.level === best.level && (s.score ?? -1) > (best.score ?? -1))) best = s;
  }
  const aliases = [...new Set(all.flatMap((g) => [g.id, ...(g.aliases || []), ...(g.upstream || [])]))].filter((a) => a !== v.id);
  const cves = [v.id, ...aliases].filter((a) => /^CVE-\d{4}-\d+$/.test(a));
  const fixed = all.map((g) => fixedFor(g, pkg)).filter(Boolean).sort(compareVersions)[0] ?? null;
  const published = all.map((g) => g.published).filter(Boolean).sort()[0] ?? null;
  return {
    key: `${v.id}|${pkg.ecosystem}|${pkg.name}`,
    id: v.id,
    aliases,
    cves,
    ecosystem: pkg.ecosystem,
    package: pkg.name,
    installed: pkg.version,
    fixed,
    bump: fixed ? bumpType(pkg.version, fixed) : null,
    level: best.level,
    score: best.score,
    vector: best.vector,
    kev: false,
    epss: null,
    malicious: best.level === 'MALICIOUS',
    published,
    modified: v.modified ?? null,
    summary: sanitize(v.summary || v.details || '', 120),
    direct: pkg.direct,
    dev: pkg.dev,
    files: pkg.files,
    newlyDisclosed: published ? now - Date.parse(published) < FRESH_WINDOW : false,
  };
}

// ---------------------------------------------------------------------------
// osv-scanner engine (optional, better lockfile coverage for Java/Gradle etc.)
// ---------------------------------------------------------------------------

export function hasOsvScanner() {
  const r = spawnSync('osv-scanner', ['--version'], { encoding: 'utf8', timeout: 10_000 });
  return !r.error && r.status === 0;
}

function runOsvScanner(root) {
  const r = spawnSync('osv-scanner', ['scan', 'source', '-r', '--format', 'json', root], {
    encoding: 'utf8',
    maxBuffer: 512 * 1024 * 1024,
    timeout: 600_000,
  });
  if (r.error) throw r.error;
  const j = JSON.parse(r.stdout || '{}');
  const packages = [];
  const hits = [];
  const details = new Map();
  for (const res of j.results || []) {
    const file = path.relative(root, res.source?.path || '') || res.source?.path || '?';
    for (const p of res.packages || []) {
      const eco = p.package.ecosystem;
      packages.push({ ecosystem: eco, name: normName(eco, p.package.name), version: p.package.version, files: [file], direct: null, dev: false });
      hits.push((p.vulnerabilities || []).map((v) => ({ id: v.id, modified: v.modified })));
      for (const v of p.vulnerabilities || []) details.set(v.id, v);
    }
  }
  return { packages, hits, details };
}

// ---------------------------------------------------------------------------
// Ledger reconciliation: what is worth telling the user right now?
// ---------------------------------------------------------------------------

export function isBlocking(item) {
  return item.malicious || item.kev || RANK[item.level] >= RANK.HIGH;
}

function snapshot(f) {
  const { newlyDisclosed, ...rest } = f;
  return rest;
}

// Event types: new, regressed, escalated, fix-available, still-affected,
// expired, resolved, reminder. Everything else is "known" and stays silent.
export function reconcile(ledger, findings, inventory, { now = new Date(), complete = true, erroredFiles = [], firstRun = false } = {}) {
  const events = [];
  const iso = now.toISOString();
  const current = new Set();
  const lastCheck = ledger.lastNetworkScan;

  for (const f of findings) {
    current.add(f.key);
    const prev = ledger.findings[f.key];
    if (!prev) {
      const why = firstRun
        ? 'baseline'
        : f.newlyDisclosed || (lastCheck && f.published && f.published > lastCheck)
          ? `newly disclosed ${day(f.published)}`
          : `new to this project (advisory from ${day(f.published)})`;
      ledger.findings[f.key] = { ...snapshot(f), status: 'open', firstSeen: iso, lastSeen: iso };
      events.push({ type: 'new', key: f.key, why });
      continue;
    }
    const entry = ledger.findings[f.key];
    const before = { level: entry.notifiedLevel ?? entry.level, kev: entry.notifiedKev ?? entry.kev, fixed: entry.notifiedFixed ?? entry.fixed, installed: entry.installed };
    Object.assign(entry, snapshot(f), { lastSeen: iso });

    if (entry.status === 'resolved') {
      entry.status = 'open';
      entry.resolvedAt = undefined;
      events.push({ type: 'regressed', key: f.key, why: 'came back after being resolved' });
      continue;
    }
    const escalated =
      RANK[f.level] > RANK[before.level] || (f.kev && !before.kev) || (f.malicious && before.level !== 'MALICIOUS');
    if (entry.status === 'accepted' && f.malicious) {
      entry.status = 'open';
      events.push({ type: 'escalated', key: f.key, why: 'malicious packages cannot be accepted' });
      continue;
    }
    if (entry.status === 'accepted') {
      if (entry.decision?.until && entry.decision.until < iso) {
        entry.status = 'open';
        events.push({ type: 'expired', key: f.key, why: `your acceptance from ${day(entry.decision.at)} expired` });
      } else if (escalated) {
        entry.status = 'open';
        events.push({ type: 'escalated', key: f.key, why: escalationWhy(before, f) + ' since you accepted it' });
      }
      continue;
    }
    if (!entry.notifiedAt) events.push({ type: 'new', key: f.key, why: 'not yet reported' });
    else if (escalated) events.push({ type: 'escalated', key: f.key, why: escalationWhy(before, f) });
    else if (f.fixed && !before.fixed) events.push({ type: 'fix-available', key: f.key, why: `fix published: ${f.fixed}` });
    else if (before.installed !== f.installed) events.push({ type: 'still-affected', key: f.key, why: `still affected after change ${before.installed} -> ${f.installed}` });
  }

  if (complete) {
    const inv = new Map();
    for (const p of inventory?.packages || []) {
      const k = `${p.ecosystem}|${p.name}`;
      if (!inv.has(k)) inv.set(k, []);
      inv.get(k).push(p.version);
    }
    for (const [key, entry] of Object.entries(ledger.findings)) {
      if (current.has(key) || entry.status === 'resolved') continue;
      if ((entry.files || []).some((f) => erroredFiles.includes(f))) continue;
      const versions = inv.get(`${entry.ecosystem}|${entry.package}`);
      const how = !versions ? 'package removed' : versions.includes(entry.installed) ? 'advisory withdrawn or no longer matches' : `upgraded to ${versions.join(', ')}`;
      const wasDecided = entry.status === 'accepted';
      entry.status = 'resolved';
      entry.resolvedAt = iso;
      entry.resolvedHow = how;
      // Only celebrate what the user was told about; silent entries just close.
      if (entry.notifiedAt || wasDecided) events.push({ type: 'resolved', key, why: how });
    }
  }
  return events;
}

function escalationWhy(before, f) {
  if (f.malicious && before.level !== 'MALICIOUS') return 'now flagged MALICIOUS';
  if (f.kev && !before.kev) return 'now actively exploited (CISA KEV)';
  return `severity raised ${before.level} -> ${f.level}`;
}

export function reminders(ledger, events, { now = new Date(), every = 7 * DAY } = {}) {
  const out = [];
  const already = new Set(events.map((e) => e.key));
  for (const [key, e] of Object.entries(ledger.findings)) {
    if (already.has(key) || e.status !== 'open' || !e.notifiedAt || !isBlocking(e)) continue;
    const last = e.remindedAt || e.notifiedAt;
    if (now - Date.parse(last) >= (e.level === 'MALICIOUS' ? Math.min(every, DAY) : every)) out.push({ type: 'reminder', key, why: `undecided since ${day(e.notifiedAt)}` });
  }
  return out;
}

export function expireAcceptances(ledger, { now = new Date() } = {}) {
  const iso = now.toISOString();
  const events = [];
  for (const [key, e] of Object.entries(ledger.findings)) {
    if (e.status === 'accepted' && e.decision?.until && e.decision.until < iso) {
      e.status = 'open';
      events.push({ type: 'expired', key, why: `your acceptance from ${day(e.decision.at)} expired` });
    }
  }
  return events;
}

function markNotified(ledger, events, now) {
  const iso = now.toISOString();
  for (const ev of events) {
    const e = ledger.findings[ev.key];
    if (!e) continue;
    if (ev.type === 'reminder') e.remindedAt = iso;
    else if (ev.type !== 'resolved') {
      e.notifiedAt = iso;
      e.remindedAt = iso;
      e.notifiedLevel = e.level;
      e.notifiedKev = e.kev;
      e.notifiedFixed = e.fixed;
    }
    ledger.history.push({ at: iso, type: ev.type, key: ev.key, level: e.level });
  }
  if (ledger.history.length > 500) ledger.history = ledger.history.slice(-500);
}

// ---------------------------------------------------------------------------
// Scan orchestration
// ---------------------------------------------------------------------------

export async function runScan(opts = {}) {
  const now = opts.now || new Date();
  const root = path.resolve(opts.root || process.cwd());
  const ledgerFile = ledgerPathFor(root, opts.ledger);
  const ledger = loadLedger(ledgerFile, root);
  const previousCheck = ledger.lastNetworkScan;
  const notes = [];
  const engine = opts.engine || process.env.VULN_LEDGER_ENGINE || 'builtin';
  const { files, notes: discoverNotes } = discover(root, Number(opts.depth ?? 4));
  notes.push(...discoverNotes);

  if (!files.length && engine !== 'osv-scanner') {
    return { root, ledgerFile, ledger, previousCheck, events: [], notes, complete: true, nothingToScan: true, exit: EXIT.OK, now, source: 'none' };
  }

  const inputsHash = hashInputs(files);
  const maxAge = parseDuration(opts.maxAge ?? 0) ?? 0;
  const cachedOk =
    !opts.fresh && ledger.lastNetworkScan && ledger.inputsHash === inputsHash && now - Date.parse(ledger.lastNetworkScan) < maxAge;

  let events = [];
  let complete = true;
  let source;
  if (opts.offline || cachedOk) {
    source = opts.offline ? 'offline: ledger only' : `cached, OSV checked ${ago(ledger.lastNetworkScan, now)}`;
    events = expireAcceptances(ledger, { now });
  } else {
    const firstRun = !ledger.lastNetworkScan && Object.keys(ledger.findings).length === 0;
    let inventory;
    let hits;
    let details = null;
    try {
      if (engine === 'osv-scanner') {
        ({ packages: inventory, hits, details } = runOsvScanner(root));
        inventory = { packages: inventory, notes: [], errors: [] };
        source = 'osv-scanner';
      } else {
        inventory = buildInventory(root, files);
        hits = await osvQueryBatch(inventory.packages);
        source = 'OSV.dev';
      }
    } catch (err) {
      const reason = err?.name === 'TimeoutError' ? 'timed out' : sanitize(err?.message || String(err), 80);
      notes.push(`Check incomplete: ${reason}. Do not treat the project as clean.`);
      events = expireAcceptances(ledger, { now });
      events.push(...reminders(ledger, events, { now, every: parseDuration(opts.remindEvery ?? '7d') }));
      if (!opts.noMark) markNotified(ledger, events, now);
      ledger.lastScan = now.toISOString();
      if (!opts.dryRun) saveLedger(ledgerFile, ledger);
      return { root, ledgerFile, ledger, previousCheck, events, notes, complete: false, exit: exitFor(ledger, events, false), now, source: 'failed' };
    }
    notes.push(...inventory.notes);
    const built = await buildFindings(inventory.packages, hits, { now, kev: !opts.noKev, epss: !opts.noEpss, details });
    notes.push(...built.notes);
    complete = built.failed === 0;
    events = reconcile(ledger, built.findings, inventory, { now, complete, erroredFiles: inventory.errors, firstRun });
    ledger.inventory = {
      count: inventory.packages.length,
      byEcosystem: inventory.packages.reduce((acc, p) => ((acc[p.ecosystem] = (acc[p.ecosystem] || 0) + 1), acc), {}),
      files: files.map((f) => path.relative(root, f)),
    };
    if (complete) {
      ledger.lastNetworkScan = now.toISOString();
      ledger.inputsHash = inputsHash;
    }
  }
  events.push(...reminders(ledger, events, { now, every: parseDuration(opts.remindEvery ?? '7d') }));
  if (!opts.noMark) markNotified(ledger, events, now);
  ledger.lastScan = now.toISOString();
  if (!opts.dryRun) saveLedger(ledgerFile, ledger);
  return { root, ledgerFile, ledger, previousCheck, events, notes, complete, exit: exitFor(ledger, events, complete), now, source };
}

function saveLedger(file, ledger) {
  ledger.tool = `vuln-ledger ${VERSION}`;
  writeJSON(file, ledger);
}

function exitFor(ledger, events, complete) {
  const loud = events.filter((e) => e.type !== 'resolved');
  if (loud.some((e) => isBlocking(ledger.findings[e.key] || {}))) return EXIT.BLOCKING;
  if (!complete) return EXIT.INCOMPLETE;
  if (events.length) return EXIT.NEWS;
  return EXIT.OK;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function severityCell(e) {
  if (e.malicious) return 'MALICIOUS';
  const bits = [typeof e.score === 'number' ? `${e.level} ${e.score}` : e.level];
  if (e.kev) bits.push('KEV: exploited');
  if (typeof e.epss === 'number' && e.epss >= 0.01) bits.push(`EPSS ${Math.round(e.epss * 100)}%`);
  return bits.join(' · ');
}

function scopeCell(e) {
  const scope = e.direct === true ? 'direct' : e.direct === false ? 'transitive' : '?';
  return e.dev ? `${scope}, dev` : scope;
}

function advisoryCell(e) {
  const aliases = e.aliases || [];
  const alt = aliases.find((a) => a.startsWith('CVE-')) || aliases.find((a) => a.startsWith('GHSA-'));
  return cell(alt ? `${e.id} (${alt})` : e.id, 90);
}

function row(e, why) {
  const fix = e.malicious ? 'remove / pin a clean version' : e.fixed ? `${cell(e.fixed, 40)} (${cell(e.bump, 24)})` : 'no fix yet';
  return `| ${cell(e.package, 80)} (${cell(e.ecosystem, 20)}) | ${cell(e.installed, 40)} | ${fix} | ${severityCell(e)} | ${advisoryCell(e)} | ${cell(why, 120)} | ${scopeCell(e)} |`;
}

const HEADER = '| Package | Installed | Fix | Severity | Advisory | What changed | Scope |\n|---|---|---|---|---|---|---|';

function bySeverity(ledger) {
  return (a, b) => {
    const x = ledger.findings[a.key];
    const y = ledger.findings[b.key];
    return (
      Number(isBlocking(y)) - Number(isBlocking(x)) ||
      RANK[y.level] - RANK[x.level] ||
      Number(y.kev) - Number(x.kev) ||
      (y.score ?? 0) - (x.score ?? 0)
    );
  };
}

export function renderReport(result, { all = false, quiet = false } = {}) {
  const { ledger, events, notes, now, complete } = result;
  const lines = [];
  if (result.nothingToScan) {
    if (quiet) return '';
    return `vuln-ledger: no lockfiles found under ${cell(result.root, 200)}. Nothing to check.${notes.length ? '\n' + notes.map((n) => `- ${cell(n, 240)}`).join('\n') : ''}`;
  }
  const open = Object.values(ledger.findings).filter((e) => e.status === 'open');
  const accepted = Object.values(ledger.findings).filter((e) => e.status === 'accepted');
  const shown = new Set(events.map((e) => e.key));
  const known = open.filter((e) => !shown.has(e.key));
  if (quiet && !events.length && complete) return '';

  const inv = ledger.inventory;
  const ecos = inv ? Object.entries(inv.byEcosystem).map(([k, v]) => `${k} ${v}`).join(', ') : '';
  lines.push(
    `vuln-ledger · ${cell(path.basename(result.root), 60)} · ${inv ? `${inv.count} packages (${ecos})` : 'inventory unknown'} · ${result.source} · ${stamp(now.toISOString())}`,
  );

  const loud = events.filter((e) => e.type !== 'resolved' && e.type !== 'reminder').sort(bySeverity(ledger));
  const resolved = events.filter((e) => e.type === 'resolved');
  const remind = events.filter((e) => e.type === 'reminder');
  const count = (t) => events.filter((e) => e.type === t).length;
  const parts = [];
  if (count('new')) parts.push(`${count('new')} new`);
  for (const t of ['regressed', 'escalated', 'fix-available', 'still-affected', 'expired']) if (count(t)) parts.push(`${count(t)} ${t}`);
  if (resolved.length) parts.push(`${resolved.length} resolved`);
  const summary = parts.length ? parts.join(' · ') : 'no changes';
  lines.push(
    `Since last check (${result.previousCheck ? stamp(result.previousCheck) : 'first run'}): ${summary}. Known and unchanged: ${known.length} open, ${accepted.length} accepted (not repeated).`,
  );

  const baseline = loud.length && loud.every((e) => e.why === 'baseline');
  const blocking = loud.filter((e) => isBlocking(ledger.findings[e.key]));
  const minor = loud.filter((e) => !isBlocking(ledger.findings[e.key]));

  if (blocking.length) {
    lines.push('', '### Action needed: ask the user before continuing', HEADER);
    const cap = all ? Infinity : 15;
    for (const ev of blocking.slice(0, cap)) lines.push(row(ledger.findings[ev.key], ev.why));
    if (blocking.length > cap) lines.push(`\n+${blocking.length - cap} more. Run \`status --all\` for the full list.`);
  }
  if (minor.length) {
    if (baseline && !all) {
      const tally = {};
      for (const ev of minor) tally[ledger.findings[ev.key].level] = (tally[ledger.findings[ev.key].level] || 0) + 1;
      lines.push('', `### Lower severity (baseline): ${Object.entries(tally).map(([k, v]) => `${v} ${k}`).join(', ')}. Run \`status --all\` to list them.`);
    } else {
      lines.push('', '### Other changes, lower severity (mention briefly, no need to stop)', HEADER);
      const cap = all ? Infinity : 10;
      for (const ev of minor.slice(0, cap)) lines.push(row(ledger.findings[ev.key], ev.why));
      if (minor.length > cap) lines.push(`\n+${minor.length - cap} more. Run \`status --all\`.`);
    }
  }
  if (resolved.length) {
    lines.push('', '### Resolved since last check');
    for (const ev of resolved) {
      const e = ledger.findings[ev.key];
      lines.push(`- ${cell(e.package)} ${cell(e.id, 40)}: ${cell(ev.why, 120)}`);
    }
  }
  if (remind.length) {
    lines.push('', '### Still open and undecided (reminder, shown at most weekly)');
    for (const ev of remind) {
      const e = ledger.findings[ev.key];
      lines.push(`- ${cell(e.package)} ${cell(e.installed, 40)}: ${cell(e.id, 40)} ${severityCell(e)}, fix ${cell(e.fixed, 40) || 'none yet'}; ${cell(ev.why, 120)}`);
    }
  }
  if (all && known.length) {
    lines.push('', '### Known, already reported', HEADER);
    for (const e of known.sort((a, b) => RANK[b.level] - RANK[a.level])) lines.push(row(e, `reported ${day(e.notifiedAt)}`));
  }
  if (all && accepted.length) {
    lines.push('', '### Accepted risks');
    for (const e of accepted) lines.push(`- ${cell(e.package)} ${cell(e.installed, 40)} ${cell(e.id, 40)} ${e.level}: "${sanitize(e.decision?.reason, 80)}" until ${e.decision?.until ? day(e.decision.until) : 'no expiry'}`);
  }
  if (notes.length) lines.push('', '### Notes', ...[...new Set(notes)].map((n) => `- ${cell(n, 240)}`));
  if (!complete) lines.push('', 'Check incomplete: report it as such, never as "no vulnerabilities".');
  return lines.join('\n');
}

export function renderJSON(result) {
  const { ledger } = result;
  const pick = (e) => ({ ...ledger.findings[e.key], event: e.type, why: e.why });
  return JSON.stringify(
    {
      tool: `vuln-ledger ${VERSION}`,
      project: result.root,
      ledger: result.ledgerFile,
      checkedAt: result.now.toISOString(),
      source: result.source,
      complete: result.complete,
      exit: result.exit,
      inventory: ledger.inventory,
      events: result.events.map(pick),
      open: Object.values(ledger.findings).filter((e) => e.status === 'open'),
      accepted: Object.values(ledger.findings).filter((e) => e.status === 'accepted'),
      notes: result.notes,
    },
    null,
    2,
  );
}

// ---------------------------------------------------------------------------
// Decisions: accept, reopen, forget
// ---------------------------------------------------------------------------

function matchEntries(ledger, ref, pkg) {
  return Object.values(ledger.findings).filter(
    (e) =>
      e.status !== 'resolved' &&
      (e.id === ref || e.aliases?.includes(ref) || e.key === ref) &&
      (!pkg || e.package === pkg),
  );
}

export function acceptFindings(ledger, refs, { reason, until, pkg, now = new Date() }) {
  const matched = [];
  for (const ref of refs) {
    for (const e of matchEntries(ledger, ref, pkg)) {
      if (e.level === 'MALICIOUS' || e.malicious) continue; // an incident, not a risk to accept
      e.status = 'accepted';
      e.decision = { reason, at: now.toISOString(), until: until || null, by: 'user' };
      ledger.history.push({ at: now.toISOString(), type: 'accepted', key: e.key, level: e.level });
      matched.push(e);
    }
  }
  return matched;
}

export function reopenFindings(ledger, refs, { pkg, now = new Date() }) {
  const matched = [];
  for (const ref of refs) {
    for (const e of matchEntries(ledger, ref, pkg)) {
      if (e.status !== 'accepted') continue;
      e.status = 'open';
      e.notifiedAt = null;
      ledger.history.push({ at: now.toISOString(), type: 'reopened', key: e.key, level: e.level });
      matched.push(e);
    }
  }
  return matched;
}

// ---------------------------------------------------------------------------
// Vetting a package before it is added
// ---------------------------------------------------------------------------

const ECOSYSTEMS = {
  npm: 'npm', node: 'npm', yarn: 'npm', pnpm: 'npm', bun: 'npm',
  pypi: 'PyPI', pip: 'PyPI', python: 'PyPI', uv: 'PyPI', poetry: 'PyPI',
  packagist: 'Packagist', composer: 'Packagist', php: 'Packagist',
  crates: 'crates.io', 'crates.io': 'crates.io', cargo: 'crates.io', rust: 'crates.io',
  go: 'Go', golang: 'Go',
  rubygems: 'RubyGems', gem: 'RubyGems', ruby: 'RubyGems',
  maven: 'Maven', java: 'Maven', nuget: 'NuGet', dotnet: 'NuGet', pub: 'Pub', dart: 'Pub', hex: 'Hex', elixir: 'Hex',
};

export function parseSpec(text, defaultEco) {
  let eco = defaultEco;
  let rest = text;
  const m = text.match(/^([a-z.]+):(.+)$/i);
  if (m && ECOSYSTEMS[m[1].toLowerCase()]) {
    eco = ECOSYSTEMS[m[1].toLowerCase()];
    rest = m[2];
  }
  eco = ECOSYSTEMS[String(eco || '').toLowerCase()] || eco;
  if (!eco) return null;
  let name = rest;
  let version = null;
  if (eco === 'PyPI') {
    const p = rest.match(/^([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*(?:===?\s*([^\s;,]+))?/);
    if (!p) return null;
    name = p[1];
    version = p[2] || null;
  } else if (eco === 'Packagist') {
    const p = rest.split(/[:=@\s]/);
    name = p[0];
    version = p[1] || null;
  } else {
    const at = rest.indexOf('@', eco === 'npm' ? 1 : 0);
    if (at > 0) {
      name = rest.slice(0, at);
      version = rest.slice(at + 1);
    }
  }
  if (version && !/^v?\d+(\.\d+)*([-.+][\w.]+)?$/.test(version)) version = null; // ranges/tags resolve to latest
  if (version) version = version.replace(/^v/, '');
  return { ecosystem: eco, name: normName(eco, name), version };
}

const goEscape = (mod) => mod.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);

// Registry facts the advisory databases do not know: does the package exist,
// how old is this version, does it run install scripts, is it deprecated.
export async function registryFacts(spec) {
  const { ecosystem: eco, name } = spec;
  let version = spec.version;
  const facts = { exists: true, version, published: null, installScripts: [], deprecated: null };
  try {
    if (eco === 'npm') {
      const doc = await http(`${NPM_REGISTRY()}/${name.replace('/', '%2F')}`, { timeout: 10_000 });
      if (!doc) return { ...facts, exists: false };
      version ||= doc['dist-tags']?.latest;
      const v = doc.versions?.[version];
      facts.published = doc.time?.[version] || null;
      facts.installScripts = Object.keys(v?.scripts || {}).filter((s) => ['preinstall', 'install', 'postinstall'].includes(s));
      facts.deprecated = v?.deprecated || null;
    } else if (eco === 'PyPI') {
      const doc = await http(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { timeout: 10_000 });
      if (!doc) return { ...facts, exists: false };
      version ||= doc.info?.version;
      const files = doc.releases?.[version] || [];
      facts.published = files.map((f) => f.upload_time_iso_8601).filter(Boolean).sort()[0] || null;
      facts.deprecated = files.length && files.every((f) => f.yanked) ? 'yanked' : null;
    } else if (eco === 'Packagist') {
      const doc = await http(`https://repo.packagist.org/p2/${name}.json`, { timeout: 10_000 });
      const list = doc?.packages?.[name];
      if (!list) return { ...facts, exists: false };
      const stable = list.filter((p) => /^v?\d+(\.\d+)*$/.test(p.version));
      const hit = version ? list.find((p) => p.version.replace(/^v/, '') === version) : stable[0] || list[0];
      version = hit?.version?.replace(/^v/, '') || version;
      facts.published = hit?.time || null;
      facts.deprecated = list[0]?.abandoned ? `abandoned${typeof list[0].abandoned === 'string' ? `, use ${list[0].abandoned}` : ''}` : null;
    } else if (eco === 'crates.io') {
      const doc = await http(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, { timeout: 10_000 });
      if (!doc) return { ...facts, exists: false };
      version ||= doc.crate?.max_stable_version || doc.crate?.newest_version;
      const v = (doc.versions || []).find((x) => x.num === version);
      facts.published = v?.created_at || null;
      facts.deprecated = v?.yanked ? 'yanked' : null;
    } else if (eco === 'RubyGems') {
      const list = await http(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`, { timeout: 10_000 });
      if (!list) return { ...facts, exists: false };
      const hit = version ? list.find((v) => v.number === version) : list.find((v) => !v.prerelease);
      version = hit?.number || version;
      facts.published = hit?.created_at || null;
    } else if (eco === 'Go') {
      const mod = goEscape(name);
      const info = await http(`https://proxy.golang.org/${mod}${version ? `/@v/v${version}.info` : '/@latest'}`, { timeout: 10_000 });
      if (!info) return { ...facts, exists: false };
      version = (info.Version || '').replace(/^v/, '') || version;
      facts.published = info.Time || null;
    } else {
      facts.exists = null; // not checked for this ecosystem
    }
  } catch {
    facts.exists = null;
  }
  facts.version = version;
  return facts;
}

export async function vetPackage(spec, { now = new Date(), cooldown = 2 * DAY } = {}) {
  const facts = await registryFacts(spec);
  const version = facts.version || spec.version;
  const reasons = [];
  const cautions = [];
  if (facts.exists === false) {
    reasons.push(`"${spec.name}" does not exist on the ${spec.ecosystem} registry: likely a typo or a hallucinated name (slopsquatting risk).`);
    return { spec: { ...spec, version }, verdict: 'BLOCK', reasons, cautions, vulns: [], facts };
  }
  let vulns = [];
  let history = [];
  try {
    const q = { package: { ecosystem: spec.ecosystem, name: spec.name } };
    const res = await http(`${OSV_API()}/v1/querybatch`, {
      method: 'POST',
      body: { queries: [version ? { ...q, version } : q, q] },
      timeout: 15_000,
    });
    const hitsFor = (r) => (r?.vulns || []).map((v) => v.id);
    const ids = version ? hitsFor(res?.results?.[0]) : [];
    history = hitsFor(res?.results?.[1]);
    const details = await pool(ids, 6, (id) => getVuln(id).catch(() => null));
    vulns = details.filter(Boolean).filter((v) => !v.withdrawn).map((v) => ({ id: v.id, ...severityOf(v), fixed: fixedFor(v, { ...spec, version }) }));
  } catch {
    cautions.push('OSV lookup failed; vulnerability status unknown.');
  }
  for (const v of vulns) {
    if (v.level === 'MALICIOUS') reasons.push(`${v.id}: this version is reported as MALICIOUS.`);
    else if (RANK[v.level] >= RANK.HIGH) reasons.push(`${v.id}: ${v.level}${v.score != null ? ` ${v.score}` : ''} in ${version}${v.fixed ? `, fixed in ${v.fixed}` : ', no fix yet'}.`);
    else cautions.push(`${v.id}: ${v.level} in ${version}${v.fixed ? `, fixed in ${v.fixed}` : ''}.`);
  }
  const priorMal = history.filter((id) => id.startsWith('MAL-'));
  if (priorMal.length && !vulns.some((v) => v.level === 'MALICIOUS')) cautions.push(`Other versions of this package were malicious (${priorMal.slice(0, 3).join(', ')}). Pin an exact, verified version.`);
  if (facts.published) {
    const age = now - Date.parse(facts.published);
    if (age < cooldown) reasons.push(`${version} was published ${ago(facts.published, now)}. Fresh releases are the window supply-chain attacks use; wait or pin the previous version.`);
    else if (age < 7 * DAY) cautions.push(`${version} is only ${ago(facts.published, now).replace(' ago', '')} old.`);
  }
  if (facts.installScripts.length) cautions.push(`Runs install scripts: ${facts.installScripts.join(', ')}.`);
  if (facts.deprecated) cautions.push(`Deprecated: ${sanitize(facts.deprecated, 80)}.`);
  const verdict = reasons.length ? 'BLOCK' : cautions.length ? 'CAUTION' : 'OK';
  return { spec: { ...spec, version }, verdict, reasons, cautions, vulns, facts };
}

// Pull package specs out of a shell command that adds or runs dependencies.
// Returns an array of specs with an `unparsed` list: install-like arguments
// whose package cannot be determined (variables, globs, stdin). Callers should
// treat a non-empty `unparsed` as "ask", never as "safe".
// Wrappers that run another command, with the options that consume a value.
const WRAPPERS = {
  sudo: ['-u', '-g', '-C', '-h', '-p', '-r', '-t', '-U', '-D', '-T', '--user', '--group', '--host', '--prompt', '--role', '--type', '--other-user', '--chdir', '--close-from', '--command-timeout'],
  doas: ['-u', '-C'],
  nice: ['-n', '--adjustment'],
  ionice: ['-c', '-n', '-p', '--class', '--classdata'],
  stdbuf: ['-i', '-o', '-e'],
  timeout: ['-s', '--signal', '-k', '--kill-after'],
  time: ['-f', '-o', '--format', '--output'],
  xargs: ['-n', '-I', '-i', '-L', '-l', '-P', '-s', '-d', '-E', '-e', '-a', '--max-args', '--replace', '--max-lines', '--max-procs', '--max-chars', '--delimiter', '--eof', '--arg-file'],
  env: ['-u', '--unset', '-C', '--chdir'],
  command: [], exec: ['-a'], builtin: [], nohup: [],
};
const WRAPPER_POSITIONAL = { timeout: 1 }; // `timeout 30 npm i x`
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish']);
const VALUE_OPTS = new Set([
  '--prefix', '--cwd', '-C', '--dir', '--filter', '-F', '--workspace', '--working-dir', '-d',
  '--registry', '--userconfig', '--manifest-path', '--directory', '--project', '--config',
]);
const SKIP_ARG = /^(\.|\/|~|file:|git[+:]|https?:|link:|workspace:)/;
const DYNAMIC = /[$*?{}%\\]/;
const INSTALL_WORDS = /\b(install|add|require|req|get|dlx|exec|isntall|in|i|x)\b|npx|bunx|pnpx|uvx|pipx/;
// npm accepts any unambiguous abbreviation of "install", plus common typos.
const NPM_INSTALL = new Set(['i', 'in', 'ins', 'inst', 'insta', 'instal', 'install', 'isnt', 'isnta', 'isntal', 'isntall', 'add']);
// npm subcommands that do not add packages. Anything else is treated as unknown.
const NPM_SAFE = new Set([
  'run', 'run-script', 'rum', 'urn', 'test', 't', 'tst', 'start', 'stop', 'restart', 'ci', 'clean-install', 'ic', 'install-clean', 'isntall-clean',
  'install-ci-test', 'cit', 'ls', 'list', 'll', 'la', 'view', 'v', 'info', 'show', 'outdated', 'audit', 'publish', 'pack',
  'version', 'config', 'c', 'get', 'set', 'cache', 'uninstall', 'un', 'remove', 'rm', 'r', 'unlink',
  'update', 'up', 'upgrade', 'udpate', 'prune', 'dedupe', 'ddp', 'rebuild', 'rb', 'doctor', 'help', 'help-search', 'login', 'logout', 'whoami',
  'adduser', 'owner', 'access', 'team', 'token', 'search', 's', 'find', 'se', 'explore', 'edit', 'docs', 'home', 'bugs', 'repo', 'fund',
  'pkg', 'query', 'root', 'bin', 'prefix', 'sbom', 'shrinkwrap', 'star', 'stars', 'unstar', 'deprecate', 'dist-tag', 'diff', 'hook', 'org',
  'ping', 'profile', 'completion', 'explain', 'why', 'undeprecate',
]);

// Split a command line into simple-command segments on ; & | && || newlines
// and parentheses, outside quotes, and pull out $(...) / `...` bodies.
function shellSegments(command) {
  const inner = [];
  const text = String(command || '').replace(/\$\(([^()]*)\)|`([^`]*)`/g, (_, a, b) => {
    inner.push(a ?? b);
    return ' $SUBST ';
  });
  const segs = [];
  let cur = '';
  let q = null;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (q === '"' && c === '\\' && i + 1 < text.length) {
        cur += c + text[++i];
        continue;
      }
      if (c === q) q = null;
      cur += c;
      continue;
    }
    if (c === '\\' && i + 1 < text.length) {
      cur += c + text[++i];
      continue;
    }
    if (c === '"' || c === "'") {
      q = c;
      cur += c;
      continue;
    }
    if (';&|\n()'.includes(c)) {
      segs.push(cur);
      cur = '';
      continue;
    }
    cur += c;
  }
  segs.push(cur);
  return [...segs, ...inner];
}

// Shell word splitting: quotes and backslashes are removed anywhere in a word
// and the pieces concatenated, as the shell does ("n"pm -> npm).
export function shellWords(seg) {
  const words = [];
  let cur = '';
  let has = false;
  let q = null;
  for (let i = 0; i < seg.length; i++) {
    const c = seg[i];
    if (q === "'") {
      if (c === "'") q = null;
      else cur += c;
      continue;
    }
    if (q === '"') {
      if (c === '"') q = null;
      else if (c === '\\' && '"\\$`'.includes(seg[i + 1] ?? '')) cur += seg[++i];
      else cur += c;
      continue;
    }
    if (c === "'" || c === '"') {
      q = c;
      has = true;
    } else if (c === '\\' && i + 1 < seg.length) {
      cur += seg[++i];
      has = true;
    } else if (/\s/.test(c)) {
      if (has) words.push(cur);
      cur = '';
      has = false;
    } else {
      cur += c;
      has = true;
    }
  }
  if (has) words.push(cur);
  return words;
}

// Pull package specs out of a shell command that adds or runs dependencies.
// Returns an array of specs with an `unparsed` list: install-like arguments
// whose package cannot be determined (variables, globs, stdin, unknown npm
// subcommands). Callers should treat a non-empty `unparsed` as "ask".
export function parseInstallCommand(command, depth = 0) {
  const specs = [];
  specs.unparsed = [];
  const merge = (nested) => {
    specs.push(...nested);
    specs.unparsed.push(...nested.unparsed);
  };
  for (const seg of shellSegments(command)) {
    const t = shellWords(seg);
    let fromStdin = false;
    let splitString = null;
    while (t.length) {
      if (/^\w+=/.test(t[0])) {
        t.shift();
        continue;
      }
      const w = path.basename(t[0]);
      if (!WRAPPERS[w]) break;
      t.shift();
      while (t.length && t[0].startsWith('-') && t[0] !== '--') {
        const o = t.shift();
        if (w === 'env' && (o === '-S' || o === '--split-string')) splitString = t.shift();
        else if (w === 'env' && o.startsWith('--split-string=')) splitString = o.slice(15);
        else if (WRAPPERS[w].includes(o)) t.shift();
      }
      if (t[0] === '--') t.shift();
      for (let k = 0; k < (WRAPPER_POSITIONAL[w] || 0); k++) t.shift();
      if (w === 'xargs') fromStdin = true;
      while (w === 'env' && t.length && /^\w+=/.test(t[0])) t.shift();
    }
    if (splitString && depth < 3) merge(parseInstallCommand(splitString, depth + 1));
    if (!t.length) continue;
    const tool = path.basename(t[0]);
    if (t[0].includes('$') && INSTALL_WORDS.test(seg)) {
      specs.unparsed.push(`${t[0]} (command name not known)`);
      continue;
    }
    if (SHELLS.has(tool) || tool === 'eval') {
      const at = tool === 'eval' ? 1 : t.findIndex((x, i) => i > 0 && /^-\w*c\w*$/.test(x)) + 1;
      if (depth < 3 && at > 0 && t[at]) merge(parseInstallCommand(tool === 'eval' ? t.slice(1).join(' ') : t[at], depth + 1));
      continue;
    }
    let found;
    if (RUNNERS.has(tool)) found = { eco: tool === 'uvx' ? 'PyPI' : 'npm', ...runnerArgs(t.slice(1)) };
    else {
      let i = 1;
      while (i < t.length && t[i].startsWith('-') && !(/^python[\d.]*$/.test(tool) && t[i] === '-m')) {
        if (VALUE_OPTS.has(t[i])) i++;
        i++;
      }
      found = classifyInstall(tool, t[i], t.slice(i + 1));
    }
    if (!found) continue;
    if (found.unknown) {
      specs.unparsed.push(found.unknown);
      continue;
    }
    const { eco, args, runner, explicit } = found;
    if (!args.length) {
      if (fromStdin || found.needsArg) specs.unparsed.push(`${tool} (package not named)`);
      continue;
    }
    for (const a of args) {
      if (DYNAMIC.test(a)) {
        specs.unparsed.push(a);
        continue;
      }
      if (SKIP_ARG.test(a) || a.endsWith('.tgz') || a.endsWith('.whl')) continue;
      if (eco === 'npm' && !a.startsWith('@') && a.includes('/')) continue; // github shorthand
      const spec = parseSpec(a, eco);
      if (spec) specs.push(runner ? { ...spec, runner: true, explicit: Boolean(explicit) } : spec);
      else specs.unparsed.push(a);
    }
  }
  return specs;
}

const RUNNERS = new Set(['npx', 'bunx', 'pnpx', 'uvx']);
const positional = (list) => list.filter((x) => !x.startsWith('-'));

// Packages a runner will fetch: every --package/-p/--from/--with value, else
// the first positional word (the package that provides the command).
function runnerArgs(list) {
  const pkgs = [];
  let first = null;
  for (let i = 0; i < list.length; i++) {
    const x = list[i];
    if (x === '--') {
      first ??= list[i + 1] ?? null;
      break;
    }
    const eq = x.match(/^--(package|from|with)=(.+)$/);
    if (eq) pkgs.push(eq[2]);
    else if (['--package', '-p', '--from', '--with'].includes(x)) {
      if (list[i + 1]) pkgs.push(list[++i]);
    } else if (VALUE_OPTS.has(x) || x === '-c' || x === '--call' || x === '--python') i++;
    else if (!x.startsWith('-')) {
      first = x;
      break;
    }
  }
  return { args: pkgs.length ? pkgs : first ? [first] : [], runner: true, explicit: pkgs.length > 0, needsArg: true };
}

// `npm init foo` / `pnpm create @scope/foo` fetch and run an initializer
// package: foo -> create-foo, @scope -> @scope/create, @scope/foo -> @scope/create-foo.
export function initializerPackage(spec) {
  const m = spec.match(/^(@[^/@]+)(?:\/([^@]+))?(@.+)?$/);
  if (m) return `${m[1]}/create${m[2] ? `-${m[2]}` : ''}${m[3] || ''}`;
  const at = spec.indexOf('@', 1);
  return at > 0 ? `create-${spec.slice(0, at)}${spec.slice(at)}` : `create-${spec}`;
}

function classifyInstall(tool, sub, rest) {
  if (['npm', 'pnpm', 'yarn', 'bun'].includes(tool)) {
    if (sub === undefined) return null;
    if (NPM_INSTALL.has(sub) || (tool === 'npm' && ['install-test', 'it'].includes(sub))) return { eco: 'npm', args: positional(rest) };
    // Linking a registry name installs it globally when it is not linked yet.
    if (tool === 'npm' && ['link', 'ln'].includes(sub)) return { eco: 'npm', args: positional(rest) };
    if (sub === 'create' || (tool === 'npm' && ['init', 'innit'].includes(sub))) {
      const first = positional(rest)[0];
      if (!first) return null; // plain `npm init` only writes package.json
      if (DYNAMIC.test(first)) return { eco: 'npm', args: [first] };
      // bun/yarn create also take GitHub templates (user/repo); those are skipped like other shorthands.
      return { eco: 'npm', args: [first.startsWith('@') || !first.includes('/') ? initializerPackage(first) : first], runner: true, explicit: true };
    }
    if (tool === 'yarn' && sub === 'global' && rest[0] === 'add') return { eco: 'npm', args: positional(rest.slice(1)) };
    if ((tool === 'npm' && ['exec', 'x'].includes(sub)) || (['pnpm', 'yarn'].includes(tool) && sub === 'dlx') || (tool === 'bun' && sub === 'x')) {
      return { eco: 'npm', ...runnerArgs(rest) };
    }
    // pnpm/yarn/bun run package scripts by bare name, so only npm's unknowns are suspicious.
    if (tool === 'npm' && !NPM_SAFE.has(sub)) return { unknown: `npm ${sub} (unrecognized subcommand)` };
    return null;
  }
  if (tool === 'composer' && ['require', 'req', 'r'].includes(sub)) return { eco: 'Packagist', args: positional(rest).filter((x) => x.includes('/') || DYNAMIC.test(x)) };
  if (/^pip[\d.]*$/.test(tool) && sub === 'install') return { eco: 'PyPI', args: pipArgs(rest) };
  if (/^python[\d.]*$/.test(tool) && sub === '-m' && /^pip[\d.]*$/.test(rest[0] || '') && rest[1] === 'install') return { eco: 'PyPI', args: pipArgs(rest.slice(2)) };
  if (tool === 'uv' && sub === 'add') return { eco: 'PyPI', args: pipArgs(rest) };
  if (tool === 'uv' && sub === 'pip' && rest[0] === 'install') return { eco: 'PyPI', args: pipArgs(rest.slice(1)) };
  if (tool === 'uv' && sub === 'tool' && ['install', 'run'].includes(rest[0])) return { eco: 'PyPI', ...runnerArgs(rest.slice(1)) };
  if (tool === 'pipx' && ['install', 'run'].includes(sub)) return { eco: 'PyPI', ...runnerArgs(rest) };
  if (['poetry', 'pdm'].includes(tool) && sub === 'add') return { eco: 'PyPI', args: pipArgs(rest) };
  if (tool === 'pipenv' && sub === 'install') return { eco: 'PyPI', args: pipArgs(rest) };
  if (tool === 'cargo' && ['add', 'install'].includes(sub)) return { eco: 'crates.io', args: positional(rest) };
  if (tool === 'go' && ['get', 'install'].includes(sub)) return { eco: 'Go', args: positional(rest).filter((x) => (x.includes('.') && !x.startsWith('.')) || DYNAMIC.test(x)) };
  if ((tool === 'gem' && sub === 'install') || (tool === 'bundle' && sub === 'add')) {
    const vi = rest.findIndex((x) => x === '-v' || x === '--version');
    const args = positional(rest.filter((_, k) => vi < 0 || k !== vi + 1));
    if (vi >= 0 && args[0] && rest[vi + 1]) args[0] = `${args[0]}@${rest[vi + 1]}`;
    return { eco: 'RubyGems', args };
  }
  if (tool === 'dotnet' && sub === 'add' && rest[0] === 'package') return { eco: 'NuGet', args: positional(rest.slice(1)).slice(0, 1) };
  if (['dart', 'flutter'].includes(tool) && sub === 'pub' && rest[0] === 'add') return { eco: 'Pub', args: positional(rest.slice(1)) };
  return null;
}

function pipArgs(list) {
  const out = [];
  for (let i = 0; i < list.length; i++) {
    const t = list[i];
    if (['-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url', '-f', '--find-links', '-t', '--target', '--group', '-G'].includes(t)) {
      i++;
      continue;
    }
    if (!t.startsWith('-')) out.push(t);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Advisory lookup: "does this new CVE / incident affect me?"
// ---------------------------------------------------------------------------

export async function checkAdvisory(id, root) {
  const v = await getVuln(id);
  if (!v) return { found: false, id };
  // CVE records in OSV often carry no package data; the GHSA/PYSEC aliases do.
  const group = [v];
  for (const a of v.aliases || []) {
    try {
      const g = await getVuln(a);
      if (g) group.push(g);
    } catch {}
  }
  const ids = new Set(group.flatMap((g) => [g.id, ...(g.aliases || [])]));
  const { files } = discover(root);
  const inv = buildInventory(root, files);
  const hits = await osvQueryBatch(inv.packages);
  const affected = [];
  inv.packages.forEach((p, i) => {
    if (!hits[i].some((h) => ids.has(h.id))) return;
    const fixed = group.map((g) => fixedFor(g, p)).filter(Boolean).sort(compareVersions)[0] ?? null;
    affected.push({ ...p, fixed });
  });
  const packages = [
    ...new Set(group.flatMap((g) => (g.affected || []).filter((a) => a.package?.name).map((a) => `${a.package.name} (${a.package.ecosystem})`))),
  ];
  const severity = group.map(severityOf).sort((a, b) => RANK[b.level] - RANK[a.level])[0];
  const published = group.map((g) => g.published).filter(Boolean).sort()[0] ?? null;
  return { found: true, id: v.id, aliases: [...ids].filter((x) => x !== v.id), summary: sanitize(v.summary || v.details, 140), severity, published, packages, affected };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const BOOLEAN_FLAGS = new Set(['json', 'quiet', 'all', 'offline', 'fresh', 'no-mark', 'no-kev', 'no-epss', 'help', 'version', 'dry-run', 'yes']);

export function parseArgs(argv) {
  const opts = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '-h') opts.help = true;
    else if (a.startsWith('--')) {
      const [k, inline] = a.slice(2).split(/=(.*)/s);
      const key = k.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
      if (BOOLEAN_FLAGS.has(k)) opts[key] = inline === undefined ? true : inline !== 'false';
      else opts[key] = inline !== undefined ? inline : argv[++i];
    } else opts._.push(a);
  }
  return opts;
}

const HELP = `vuln-ledger ${VERSION}: dependency vulnerability guard with a memory

Usage: node vuln-ledger.mjs <command> [options]

Commands
  scan                 Check lockfiles against OSV and report only what changed (default)
  status               Show the ledger without network (--all for every finding)
  vet <spec...>        Check a package before adding it, e.g. npm:express@4.21.2 composer:laravel/framework pypi:requests==2.32.3
  advisory <ID>        Does this advisory (CVE-, GHSA-, MAL-, PYSEC-...) affect this project?
  inventory            List the resolved packages found in lockfiles (--grep text)
  accept <ID...>       Record the user's decision to accept a finding (--reason required, --until 30d|YYYY-MM-DD)
  reopen <ID...>       Undo an acceptance
  doctor               Show paths, scanners, and connectivity
  forget --yes         Delete this project's ledger

Options
  --root DIR           Project root (default: cwd)
  --ledger FILE        Ledger file (default: per-project file under ${stateHome()})
  --max-age 6h         Reuse the last OSV result if newer than this and lockfiles are unchanged
  --fresh              Always query OSV
  --offline            Use the ledger only
  --remind-every 7d    Re-mention undecided critical/high findings at most this often
  --engine builtin|osv-scanner
  --json               Machine-readable output
  --quiet              Print nothing when nothing changed
  --all                Include known findings and accepted risks
  --no-mark            Do not mark events as reported (dry run of the memory)
  --no-kev, --no-epss  Skip exploitation enrichment

Exit codes: 0 nothing new · 10 new low/medium/resolved · 20 action needed (critical/high/KEV/malicious) · 30 check incomplete · 1 error`;

async function main(argv) {
  const opts = parseArgs(argv);
  const cmd = opts._.shift() || 'scan';
  if (opts.version) return console.log(VERSION), EXIT.OK;
  if (opts.help || cmd === 'help') return console.log(HELP), EXIT.OK;
  const root = path.resolve(opts.root || process.cwd());

  if (cmd === 'scan') {
    const result = await runScan({ ...opts, root });
    const out = opts.json ? renderJSON(result) : renderReport(result, opts);
    if (out) console.log(out);
    return result.exit;
  }

  if (cmd === 'status') {
    const file = ledgerPathFor(root, opts.ledger);
    const ledger = loadLedger(file, root);
    const result = { root, ledgerFile: file, ledger, events: [], notes: [], complete: true, now: new Date(), source: `ledger, OSV checked ${ago(ledger.lastNetworkScan)}` };
    if (!ledger.lastScan) return console.log(`No ledger yet for ${root}. Run: scan`), EXIT.OK;
    console.log(opts.json ? renderJSON(result) : renderReport(result, { all: true }));
    return EXIT.OK;
  }

  if (cmd === 'accept' || cmd === 'reopen') {
    const refs = opts._;
    if (!refs.length) return console.error(`Usage: ${cmd} <ID...> ${cmd === 'accept' ? '--reason "..." [--until 30d]' : ''}`), EXIT.ERROR;
    if (cmd === 'accept' && !opts.reason) return console.error('accept needs --reason "<the user\'s words>"'), EXIT.ERROR;
    const file = ledgerPathFor(root, opts.ledger);
    const ledger = loadLedger(file, root);
    const until = cmd === 'accept' ? parseUntil(opts.until || '30d') : null;
    const matched =
      cmd === 'accept'
        ? acceptFindings(ledger, refs, { reason: String(opts.reason), until, pkg: opts.package })
        : reopenFindings(ledger, refs, { pkg: opts.package });
    if (!matched.length) {
      const malicious = cmd === 'accept' && refs.some((r) => matchEntries(ledger, r, opts.package).some((e) => e.level === 'MALICIOUS'));
      console.error(malicious ? 'Malicious findings cannot be accepted. Treat them as an incident: see references/incident-response.md.' : `No open finding matches ${refs.join(', ')}. Run: status`);
      return EXIT.ERROR;
    }
    saveLedger(file, ledger);
    for (const e of matched) console.log(`${cmd === 'accept' ? 'Accepted' : 'Reopened'}: ${e.package} ${e.installed} ${e.id}${until ? ` until ${day(until)}` : ''}`);
    return EXIT.OK;
  }

  if (cmd === 'vet') {
    if (!opts._.length) return console.error('Usage: vet <eco:name[@version]> ...'), EXIT.ERROR;
    const specs = opts._.map((s) => parseSpec(s, opts.ecosystem)).filter(Boolean);
    if (specs.length !== opts._.length) return console.error('Prefix each spec with an ecosystem, e.g. npm:left-pad or composer:vendor/pkg'), EXIT.ERROR;
    const results = await pool(specs, 4, (s) => vetPackage(s, { cooldown: parseDuration(opts.cooldown ?? '48h') }));
    if (opts.json) console.log(JSON.stringify(results, null, 2));
    else {
      for (const r of results) {
        console.log(`${r.verdict}  ${r.spec.ecosystem}:${r.spec.name}@${r.spec.version || '?'}${r.facts.published ? ` (published ${day(r.facts.published)})` : ''}`);
        for (const m of [...r.reasons, ...r.cautions]) console.log(`  - ${m}`);
      }
    }
    return results.some((r) => r.verdict === 'BLOCK') ? EXIT.BLOCKING : results.some((r) => r.verdict === 'CAUTION') ? EXIT.NEWS : EXIT.OK;
  }

  if (cmd === 'advisory') {
    const id = opts._[0];
    if (!id) return console.error('Usage: advisory <CVE-/GHSA-/MAL-/PYSEC-... ID>'), EXIT.ERROR;
    const r = await checkAdvisory(id, root);
    if (opts.json) return console.log(JSON.stringify(r, null, 2)), r.affected?.length ? EXIT.BLOCKING : EXIT.OK;
    if (!r.found) return console.log(`${id}: not in OSV yet. It may be too new or use another ID; search osv.dev or the vendor advisory.`), EXIT.INCOMPLETE;
    console.log(`${r.id}${r.aliases.length ? ` (${r.aliases.slice(0, 4).join(', ')})` : ''}: ${r.severity.level}${r.severity.score != null ? ` ${r.severity.score}` : ''}, published ${day(r.published)}`);
    console.log(`Summary (untrusted text): ${r.summary}`);
    console.log(`Affects: ${r.packages.length ? r.packages.slice(0, 8).join(', ') : 'no package data in OSV yet'}${r.packages.length > 8 ? ` +${r.packages.length - 8} more` : ''}`);
    if (r.affected.length) {
      console.log('This project IS affected:');
      for (const p of r.affected) console.log(`  - ${p.name} ${p.version} in ${p.files.join(', ')}; fix ${p.fixed || 'none yet'}`);
    } else console.log('This project is not affected (no installed version matches).');
    return r.affected.length ? EXIT.BLOCKING : EXIT.OK;
  }

  if (cmd === 'inventory') {
    const { files, notes } = discover(root, Number(opts.depth ?? 4));
    const inv = buildInventory(root, files);
    const grep = opts.grep ? String(opts.grep).toLowerCase() : null;
    const list = inv.packages.filter((p) => !grep || p.name.toLowerCase().includes(grep));
    if (opts.json) console.log(JSON.stringify(list, null, 2));
    else {
      for (const p of list) console.log(`${p.ecosystem}\t${p.name}\t${p.version}\t${p.direct === true ? 'direct' : p.direct === false ? 'transitive' : '?'}\t${p.files.join(',')}`);
      console.error(`${list.length} package(s) from ${files.length} file(s).`);
      for (const n of [...notes, ...inv.notes]) console.error(`note: ${n}`);
    }
    return EXIT.OK;
  }

  if (cmd === 'doctor') {
    const file = ledgerPathFor(root, opts.ledger);
    const { files } = discover(root);
    const which = (bin, args = ['--version']) => {
      const r = spawnSync(bin, args, { encoding: 'utf8', timeout: 10_000 });
      return !r.error && r.status === 0 ? (r.stdout || r.stderr).trim().split('\n')[0] : 'not installed';
    };
    let osv = 'unreachable';
    try {
      await http(`${OSV_API()}/v1/vulns/GHSA-jfh8-c2jp-5v3q`, { timeout: 8000 });
      osv = 'reachable';
    } catch {}
    console.log(
      [
        `vuln-ledger ${VERSION} on Node ${process.version}`,
        `project:       ${root}`,
        `lockfiles:     ${files.length ? files.map((f) => path.relative(root, f)).join(', ') : 'none found'}`,
        `ledger:        ${file}${fs.existsSync(file) ? '' : ' (not created yet)'}`,
        `state home:    ${stateHome()}`,
        `auto checks:   ${autoChecksDisabled() ? 'disabled' : 'enabled'} (disable: VULN_LEDGER_DISABLE=1 or touch ${path.join(configHome(), 'disabled')})`,
        `OSV API:       ${OSV_API()} (${osv})`,
        `osv-scanner:   ${which('osv-scanner')}`,
        `composer:      ${which('composer')}`,
        `npm:           ${which('npm')}`,
        `pip-audit:     ${which('pip-audit')}`,
        `govulncheck:   ${which('govulncheck', ['-version'])}`,
        `cargo-audit:   ${which('cargo', ['audit', '--version'])}`,
      ].join('\n'),
    );
    return EXIT.OK;
  }

  if (cmd === 'forget') {
    const file = ledgerPathFor(root, opts.ledger);
    if (!opts.yes) return console.error(`This deletes ${file}. Re-run with --yes.`), EXIT.ERROR;
    fs.rmSync(file, { force: true });
    console.log(`Deleted ${file}`);
    return EXIT.OK;
  }

  console.error(`Unknown command: ${cmd}\n\n${HELP}`);
  return EXIT.ERROR;
}

const invokedDirectly = (() => {
  try {
    return import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1] || '')).href;
  } catch {
    return false;
  }
})();

if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code ?? 0),
    (err) => {
      console.error(`vuln-ledger: ${err?.stack || err}`);
      process.exit(EXIT.ERROR);
    },
  );
}

export { main };
