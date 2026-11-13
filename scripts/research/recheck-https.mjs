/*
 * Second vantage point for the HTTPS check. Some sites refuse connections from
 * datacenter addresses; from the scan server they look like "no HTTPS" when
 * an ordinary visitor would get a page. This re-runs the same handshake
 * (_https-check.mjs) from somewhere else, only for domains whose handshake
 * failed on the network (timeout, refused, reset) — not for domains without a
 * public address, which no vantage point changes — and writes
 * <out>/recheck-<vantage>.ndjson. The summariser counts those that answer here
 * as "blocks the scan server", not as broken.
 *
 * Addresses come from DNS-over-HTTPS (Cloudflare, Google as fallback), exactly
 * as in the scan, so the local network's resolver cannot change the result.
 * Same politeness: shuffled, at most 2 handshakes at once per IPv4 /24. Opted-
 * out domains (--exclude, default research/opt-out.txt) are skipped.
 *
 * Usage (after copying <out> back from the server):
 *   node scripts/research/recheck-https.mjs research/cc-nl --vantage home
 */
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { httpsCheck } from './_https-check.mjs';

const argv = process.argv.slice(2);
const opt = (k, d) => (argv.includes(`--${k}`) ? argv[argv.indexOf(`--${k}`) + 1] : d);
const dir = argv[0];
const vantage = opt('vantage', 'home').replace(/[^a-z0-9-]/gi, '-');
const EXCLUDE = opt('exclude', 'research/opt-out.txt');
if (!dir) { console.error('usage: recheck-https.mjs <out-dir> [--vantage name] [--exclude file]'); process.exit(1); }
const PER_NETWORK = 2;
const CONCURRENCY = 6;
const NOT_NETWORK = new Set(['no-address', 'dns-error', 'private-address']);

const excluded = new Set(existsSync(EXCLUDE) ? readFileSync(EXCLUDE, 'utf8').split('\n').map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#')) : []);
const last = new Map();
for (const l of readFileSync(join(dir, 'results.ndjson'), 'utf8').split('\n')) {
  if (!l.trim()) continue;
  try { const r = JSON.parse(l); last.set(r.domain, r); } catch { /* truncated line */ }
}
const todo = [...last.values()]
  .filter((r) => r.https && r.https.via === 'none' && !excluded.has(r.domain) && !(NOT_NETWORK.has(r.https.error) && NOT_NETWORK.has(r.https.www_error)))
  .map((r) => r.domain);
for (let i = todo.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [todo[i], todo[j]] = [todo[j], todo[i]]; }
console.log(`${todo.length} domains had a network failure on the scan server; re-checking from "${vantage}"`);

const TYPES = { A: 1, AAAA: 28 };
async function resolveAddr(name, type) {
  let lastErr;
  for (const base of ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve']) {
    try {
      const res = await fetch(`${base}?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(10_000) });
      const b = await res.json();
      if (b.Status === 0 || b.Status === 3) return (b.Answer ?? []).filter((a) => a.type === TYPES[type]).map((a) => a.data);
      lastErr = new Error(`rcode ${b.Status}`);
    } catch (e) { lastErr = e; }
  }
  throw lastErr;
}

async function networkOf(domain) {
  for (const name of [domain, `www.${domain}`]) {
    try { const ip = (await resolveAddr(name, 'A'))[0]; if (ip) return ip.split('.').slice(0, 3).join('.'); } catch { /* next */ }
  }
  return `none:${domain}`;
}

const busy = new Map();
const out = [];
const queue = [...todo];
await Promise.all(Array.from({ length: CONCURRENCY }, async () => {
  while (queue.length) {
    const domain = queue.shift();
    const net = await networkOf(domain);
    while ((busy.get(net) ?? 0) >= PER_NETWORK) await new Promise((r) => setTimeout(r, 200));
    busy.set(net, (busy.get(net) ?? 0) + 1);
    try {
      out.push({ domain, vantage, https: await httpsCheck(domain, resolveAddr) });
    } finally {
      busy.set(net, busy.get(net) - 1);
    }
  }
}));
writeFileSync(join(dir, `recheck-${vantage}.ndjson`), out.map((r) => JSON.stringify(r)).join('\n') + (out.length ? '\n' : ''));
const answered = out.filter((r) => r.https.ok).length;
console.log(`answered from "${vantage}": ${answered} of ${out.length} (these block the scan server, not visitors)`);
