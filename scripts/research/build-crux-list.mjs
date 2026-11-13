/*
 * CrUX top list → the scanner's input list, for InfraNest Research
 * (plan: docs/research/email-dns-2027-plan.md, section 4).
 *
 * Source: the Chrome UX Report's monthly popularity buckets, as published per
 * country and globally by github.com/zakird/crux-top-lists (data/country/<cc>/
 * and data/global/<YYYYMM>.csv.gz; lines "origin,rank", rank = bucket 1000,
 * 5000, 10000, 50000, …). CrUX was the most accurate popularity list in Ruth et
 * al., "Toppling Top Lists", IMC 2022; it replaced Tranco after the November
 * 2026 dry run, whose .nl list was dominated beyond rank ~3,000 by a network of
 * generated domains (no mail, Cloudflare, random 13–22 letter names).
 *
 * Each origin (https://jouw.postnl.nl) is reduced to its registrable domain
 * (postnl.nl) with the Public Suffix List (ICANN and private sections, rules,
 * wildcards and exceptions; matched in ASCII/punycode). A domain takes the best
 * (smallest) bucket of any of its origins. With --cctld only domains under that
 * country-code TLD are kept. Output, deterministic: "bucket,domain" lines sorted
 * by bucket then domain, plus <out>.meta.json with the inputs' provenance.
 *
 * Usage:
 *   node scripts/research/build-crux-list.mjs --crux country-nl-202610.csv.gz \
 *     --psl public_suffix_list.dat --cctld nl --max-bucket 50000 --month 202610 \
 *     --source https://github.com/zakird/crux-top-lists/raw/main/data/country/nl/202610.csv.gz \
 *     --out research/lists/crux-nl-202610.csv
 */
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { dirname, basename } from 'node:path';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { domainToASCII } from 'node:url';

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []));
for (const k of ['crux', 'psl', 'out', 'month']) if (!args[k]) { console.error(`missing --${k}`); process.exit(1); }
const CCTLD = args.cctld ? String(args.cctld).replace(/^\./, '').toLowerCase() : null;
const MAX = Number(args['max-bucket'] ?? 50000);

// ---- Public Suffix List ----

const pslText = readFileSync(args.psl, 'utf8');
const rules = new Set();
const wildcards = new Set();
const exceptions = new Set();
for (const raw of pslText.split('\n')) {
  const line = raw.trim().split(/\s/)[0];
  if (!line || line.startsWith('//')) continue;
  const ascii = (s) => s.split('.').map((l) => (l === '*' ? '*' : domainToASCII(l) || l)).join('.').toLowerCase();
  if (line.startsWith('!')) exceptions.add(ascii(line.slice(1)));
  else if (line.startsWith('*.')) wildcards.add(ascii(line.slice(2)));
  else rules.add(ascii(line));
}

/** Registrable domain (public suffix + one label), or null for a bare public suffix. */
export function registrable(host) {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  let suffix = 1; // the implicit "*" rule: the last label
  for (let i = 0; i < labels.length; i++) {
    const cand = labels.slice(i).join('.');
    const n = labels.length - i;
    if (exceptions.has(cand)) { suffix = Math.max(suffix, n - 1); continue; }
    if (rules.has(cand)) suffix = Math.max(suffix, n);
    if (i + 1 < labels.length && wildcards.has(labels.slice(i + 1).join('.'))) suffix = Math.max(suffix, n);
  }
  return suffix >= labels.length ? null : labels.slice(-(suffix + 1)).join('.');
}

// ---- CrUX ----

const lines = gunzipSync(readFileSync(args.crux)).toString('utf8').split('\n');
if (!/^origin,rank\s*$/.test(lines[0])) throw new Error(`unexpected header: ${lines[0]}`);
const best = new Map();
let origins = 0;
for (const line of lines.slice(1)) {
  if (!line.trim()) continue;
  const comma = line.lastIndexOf(',');
  const origin = line.slice(0, comma);
  const bucket = Number(line.slice(comma + 1));
  origins++;
  if (!Number.isFinite(bucket) || bucket > MAX) continue;
  let host;
  try { host = new URL(origin).hostname; } catch { continue; }
  if (!host || /^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[')) continue;
  const domain = registrable(host);
  if (!domain || (CCTLD && !domain.endsWith(`.${CCTLD}`))) continue;
  if (!best.has(domain) || bucket < best.get(domain)) best.set(domain, bucket);
}

const list = [...best.entries()].sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0]));
mkdirSync(dirname(args.out), { recursive: true });
writeFileSync(args.out, list.map(([d, b]) => `${b},${d}`).join('\n') + '\n');
const counts = {};
for (const [, b] of list) counts[b] = (counts[b] ?? 0) + 1;
const sha = (buf) => createHash('sha256').update(buf).digest('hex');
const meta = {
  list: basename(args.out),
  source: args.source ?? null,
  crux_month: args.month,
  crux_file_sha256: sha(readFileSync(args.crux)),
  public_suffix_list_sha256: sha(pslText),
  cctld: CCTLD,
  max_bucket: MAX,
  origins_read: origins,
  domains: list.length,
  domains_per_bucket: counts,
  generated: new Date().toISOString(),
};
writeFileSync(`${args.out}.meta.json`, `${JSON.stringify(meta, null, 2)}\n`);
console.log(`${args.out}: ${list.length} domains (${JSON.stringify(counts)}) from ${origins} origins`);
