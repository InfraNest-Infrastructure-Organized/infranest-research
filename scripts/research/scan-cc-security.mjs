/*
 * Email and DNS security of a country's most-visited domains, for InfraNest
 * Research (plan: docs/research/email-dns-2027-plan.md). The September 2026
 * data post (scan-email-auth.mjs) measured the global top 10,000; this one
 * takes the top N domains of one country-code TLD from a Tranco list (or, with
 * --tld all, the top N of the whole list: the global comparison) and runs:
 *
 *   - SPF and DMARC with the free tools' own analysers (functions/api/_spf.js,
 *     _dmarc.js). SPF also counts void lookups from a/mx terms (resolveAddr).
 *     The DMARC "t" tag (RFC 9989) is recorded raw; the summariser applies it.
 *   - DNSSEC: DS at the registry, and does a validating resolver accept the
 *     zone (SOA) and its apex address record (A)? "bogus" needs BOTH public
 *     resolvers to answer SERVFAIL with a DNSSEC reason in their extended error
 *     text, and the same query with checking disabled (cd=1) to answer.
 *     "bogus-partial": the zone validates but a record set (A, MX or a TXT the
 *     email checks need) fails validation. Checked first: a bogus zone answers
 *     SERVFAIL to everything and would otherwise be filed as unreadable.
 *   - HTTPS: one TLS handshake (_https-check.mjs) to the address found here
 *     over DNS-over-HTTPS, never the OS resolver; private addresses skipped.
 *   - Collected for provider and later studies (not used in the headline
 *     measures): NS hosts, MX hosts, SPF include domains, DMARC report domains,
 *     web IPv4/IPv6 and the IPv4 address's network (ASN via Team Cymru's DNS
 *     service, over DoH), IPv6 on the first mail host, CAA, MTA-STS, TLS-RPT.
 *
 * Politeness: the order is shuffled (seeded, recorded) and at most
 * --per-network handshakes run at once against one IPv4 /24. DNS only goes to
 * the two public resolvers, never to the sites' own servers.
 *
 * Domains in --exclude (default research/opt-out.txt, one per line) are
 * skipped: site owners who asked to be left out. They are counted, never named.
 *
 * Public data only. Results per domain stay in <out>/results.ndjson, which is
 * gitignored (/research/); only totals are published. <out>/run.json records
 * the list, seed and one segment per invocation (scanner commit, Node, vantage
 * point, times). Re-running the same command resumes and retries every domain
 * whose latest row had a read error, or was bogus (to confirm it).
 *
 * Then: recheck-https.mjs <out> from a second vantage point, and
 * summarise-cc-security.mjs <out>.
 *
 * Usage:
 *   node scripts/research/scan-cc-security.mjs --list research/lists/crux-nl-202610.csv --list-source crux \
 *     --list-id crux-202610 --tld nl --top 50000 --out research/cc-nl --vantage "DigitalOcean FRA1"
 */
import { createReadStream, existsSync, mkdirSync, appendFileSync, readFileSync, writeFileSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { join, basename } from 'node:path';
import { execSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { analyseSpf } from '../../functions/api/_spf.js';
import { analyseDmarc } from '../../functions/api/_dmarc.js';
import { httpsCheck } from './_https-check.mjs';

const args = Object.fromEntries(process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), []));
const LIST = args.list ?? 'top-1m.csv';
const TLD = String(args.tld ?? 'nl').replace(/^\./, '').toLowerCase();
const TOP = Number(args.top ?? 1000);
const OUT = args.out ?? (TLD === 'all' ? 'research/global' : `research/cc-${TLD}`);
const CONCURRENCY = Number(args.concurrency ?? 12);
const PER_NETWORK = Number(args['per-network'] ?? 2);
const EXCLUDE = args.exclude ?? 'research/opt-out.txt';
// tranco: column 1 is the exact rank; crux: column 1 is the CrUX bucket (1000, 5000, …), see build-crux-list.mjs.
const LIST_SOURCE = args['list-source'] ?? 'tranco';
if (!['tranco', 'crux'].includes(LIST_SOURCE)) { console.error('--list-source must be tranco or crux'); process.exit(1); }

// ---- DNS over HTTPS (Cloudflare, Google as fallback) ----

const RESOLVERS = [
  (name, type, cd) => `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}&do=1${cd ? '&cd=1' : ''}`,
  (name, type, cd) => `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}&do=1${cd ? '&cd=1' : ''}`,
];
const TYPE = { A: 1, NS: 2, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43, CAA: 257 };
const cache = new Map();

class DnsError extends Error {}

async function queryOnce(url) {
  const res = await fetch(url, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(10_000) });
  if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
  if (!res.ok) throw new DnsError(`HTTP ${res.status}`);
  const b = await res.json();
  // Keep only what is used: whole bodies (NSEC3 authority sections) for every
  // name of a 10,000-domain run would cost hundreds of megabytes.
  return {
    Status: b.Status,
    AD: Boolean(b.AD),
    Answer: (b.Answer ?? []).map(({ type, data }) => ({ type, data })),
    Comment: [].concat(b.Comment ?? []).join(' '),
  };
}

/**
 * The answer for name/type: { Status, AD, Answer, Comment, agreed }.
 * NOERROR or NXDOMAIN from either resolver is returned at once. A failure rcode
 * (SERVFAIL, REFUSED) is returned only after the other resolver has also been
 * asked; `agreed` is true when BOTH actually answered with a failure (not when
 * one only had transport errors), and `comments` holds both reasons. Only
 * NOERROR/NXDOMAIN answers are cached: a failure is never remembered, so a
 * passing hiccup on a popular name (an SPF include) cannot spread to later domains.
 */
function raw(name, type, { cd = false } = {}) {
  const key = `${type} ${cd ? 'cd ' : ''}${name.toLowerCase()}`;
  const hit = cache.get(key);
  if (hit) return hit;
  const p = (async () => {
    const failures = new Map();
    let lastErr;
    for (let attempt = 0; attempt < 8; attempt++) {
      const ri = attempt % RESOLVERS.length;
      if (failures.has(ri) && failures.size < RESOLVERS.length) continue;
      try {
        const body = await queryOnce(RESOLVERS[ri](name, type, cd));
        if (body.Status === 0 || body.Status === 3) return { ...body, agreed: true };
        failures.set(ri, body);
        if (failures.size >= RESOLVERS.length) break;
      } catch (e) {
        lastErr = e;
        await new Promise((r) => setTimeout(r, 250 * 2 ** Math.min(attempt, 4)));
      }
    }
    if (failures.size) {
      const bodies = [...failures.values()];
      return { ...bodies[bodies.length - 1], agreed: failures.size >= RESOLVERS.length, comments: bodies.map((b) => b.Comment).filter(Boolean) };
    }
    throw new DnsError(String(lastErr?.message ?? lastErr));
  })();
  cache.set(key, p);
  p.then((b) => { if (!(b.Status === 0 || b.Status === 3)) cache.delete(key); }, () => cache.delete(key));
  return p;
}

/** Answers for name/type; [] for NXDOMAIN or no data; throws DnsError otherwise. */
async function query(name, type) {
  const body = await raw(name, type);
  if (body.Status === 0 || body.Status === 3) return body.Answer.filter((a) => a.type === TYPE[type]);
  throw new DnsError(`rcode ${body.Status}`);
}

const txtData = (a) => String(a.data).replace(/"\s+"/g, '').replace(/^"|"$/g, '');
const resolveAddr = async (name, type) => (await query(name, type)).map((a) => a.data);

/**
 * A validation failure, as both resolvers report it: Cloudflare's extended DNS
 * error codes 1–12 (RFC 8914: DNSSEC indeterminate, bogus, signature expired,
 * DNSKEY missing …) or Google's "DNSSEC validation failure". Network-side
 * reasons (EDE 22 no reachable authority, 23 network error) are not.
 */
// RFC 8914 codes that mean a DNSSEC failure: 1, 2, 5–12 and 25 (not 3 "stale
// answer" or 4 "forged answer", which are not about signatures).
const DNSSEC_EDE = /EDE\((?:1|2|5|6|7|8|9|10|11|12|25)\)/;
const isDnssecText = (t) => DNSSEC_EDE.test(t) || /DNSSEC validation failure/i.test(t);
function dnssecReason(body) {
  // Every resolver that failed must give a DNSSEC reason: one resolver's
  // "bogus" next to another's "name server failure" is not proof.
  const texts = body.comments ?? [body.Comment].filter(Boolean);
  return texts.length >= RESOLVERS.length && texts.every(isDnssecText);
}

const inDomain = (name, domain) => name === domain || name.endsWith(`.${domain}`);

/**
 * Does name/type fail validation (both resolvers, DNSSEC reason each) yet
 * answer with checking disabled? true when the failure is in `domain`'s own
 * zone; 'elsewhere' when the answer follows a CNAME out of the domain (then
 * the broken signature belongs to someone else's zone); false otherwise.
 */
async function failsValidation(name, type, domain) {
  const checked = await raw(name, type);
  if (checked.Status !== 2 || !checked.agreed || !dnssecReason(checked)) return false;
  const unchecked = await raw(name, type, { cd: true });
  if (!(unchecked.Status === 0 || unchecked.Status === 3)) return false;
  const leaves = unchecked.Answer.some((a) => a.type === 5 && !inDomain(String(a.data).toLowerCase().replace(/\.$/, ''), domain));
  return leaves ? 'elsewhere' : true;
}

/** nxdomain | unsigned | valid | insecure | bogus | bogus-partial | error */
async function dnssec(domain) {
  const ds = await raw(domain, 'DS');
  if (ds.Status === 3) return { ds: false, state: 'nxdomain' };
  if (ds.Status !== 0) return { ds: null, state: 'error' };
  const hasDs = ds.Answer.some((a) => a.type === TYPE.DS);
  if (!hasDs) return { ds: false, state: 'unsigned' };
  const soa = await raw(domain, 'SOA');
  if (soa.Status === 0) {
    if (!soa.AD) return { ds: true, state: 'insecure' };
    // The zone validates; does the apex address record too? (Zones exist where
    // only some record sets carry bad signatures.)
    const a = await failsValidation(domain, 'A', domain);
    if (a === true) return { ds: true, state: 'bogus-partial', failed: `A ${domain}` };
    // The address follows a CNAME into someone else's broken zone: not this
    // zone's DNSSEC, but recorded so it is counted apart.
    if (a === 'elsewhere') return { ds: true, state: 'valid', web_elsewhere: true };
    return { ds: true, state: 'valid' };
  }
  if ((await failsValidation(domain, 'SOA', domain)) === true) return { ds: true, state: 'bogus' };
  return { ds: true, state: 'error', detail: `rcode ${soa.Status}` };
}

// ---- Collected for provider studies (failures here never affect a row) ----

/**
 * The website's IPv4 addresses for the network measure, asked of Google with
 * edns_client_subnet=0.0.0.0/0: without a location hint a CDN answers with its
 * own network, not a cache it runs inside the scan server's (or anyone's)
 * internet provider — which would credit a site to KPN or Orange instead of
 * Akamai. Falls back to the ordinary lookup. Sorted, so the result does not
 * depend on the order a resolver rotates its answers in.
 */
const ipKey = (ip) => ip.split('.').map((n) => n.padStart(3, '0')).join('.');
async function webAddresses(name) {
  // Two tries at Google without a location hint; no fallback to a resolver that
  // would answer for its own location (that is what this lookup avoids). If
  // both fail, the network is simply not measured for this domain.
  for (let i = 0; i < 2; i++) {
    try {
      const b = await queryOnce(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=A&edns_client_subnet=0.0.0.0/0`);
      if (b.Status === 0 || b.Status === 3) return b.Answer.filter((a) => a.type === TYPE.A).map((a) => a.data).sort((x, y) => ipKey(x).localeCompare(ipKey(y)));
    } catch { /* retry */ }
  }
  throw new DnsError('web addresses not readable');
}

const asnCache = new Map();
/** Network of one IPv4 address via Team Cymru's DNS service: the most specific prefix wins. */
async function network(ipv4) {
  try {
    const rev = ipv4.split('.').reverse().join('.');
    const rows = (await query(`${rev}.origin.asn.cymru.com`, 'TXT')).map(txtData).map((t) => t.split('|').map((x) => x.trim()));
    if (!rows.length) return null;
    const len = (r) => Number(String(r[1] ?? '').split('/')[1]) || 0;
    const best = rows.filter((r) => /^\d/.test(r[0] ?? '')).sort((x, y) => len(y) - len(x))[0];
    if (!best) return null;
    const [asnField, prefix, cc] = best;
    const asn = asnField.split(/\s+/)[0];
    if (!asnCache.has(asn)) {
      asnCache.set(asn, query(`AS${asn}.asn.cymru.com`, 'TXT').then((a) => (a.map(txtData)[0] ?? '').split('|').map((x) => x.trim())[4] ?? null).catch(() => null));
    }
    return { asn: Number(asn), prefix, cc, name: await asnCache.get(asn) };
  } catch {
    return null;
  }
}

async function extras(domain, mxHosts) {
  const safe = async (f) => { try { return await f(); } catch { return null; } };
  const [ns, a, aaaa, wwwA, wwwAaaa, caa, mtaSts, tlsRpt] = await Promise.all([
    safe(async () => (await query(domain, 'NS')).map((x) => String(x.data).toLowerCase().replace(/\.$/, '')).sort()),
    safe(() => webAddresses(domain)),
    safe(() => resolveAddr(domain, 'AAAA')),
    safe(() => webAddresses(`www.${domain}`)),
    safe(() => resolveAddr(`www.${domain}`, 'AAAA')),
    safe(async () => (await query(domain, 'CAA')).map((x) => String(x.data))),
    safe(async () => (await query(`_mta-sts.${domain}`, 'TXT')).map(txtData).some((t) => /^v=STSv1/i.test(t))),
    safe(async () => (await query(`_smtp._tls.${domain}`, 'TXT')).map(txtData).some((t) => /^v=TLSRPTv1/i.test(t))),
  ]);
  // The website as visitors reach it: the bare domain, else www.
  const site = a?.length || aaaa?.length ? { v4: a, v6: aaaa, via: 'apex' } : { v4: wwwA, v6: wwwAaaa, via: 'www' };
  const networksMeasured = Array.isArray(site.v4);
  const nets = [];
  for (const ip of (site.v4 ?? []).slice(0, 4)) {
    const n = await network(ip);
    if (n && !nets.some((x) => x.asn === n.asn)) nets.push(n);
  }
  return {
    ns,
    web: { via: site.via, ipv4: Boolean(site.v4?.length), ipv6: Boolean(site.v6?.length), networks: networksMeasured ? nets : null },
    mx_ipv6: mxHosts?.length ? await safe(async () => (await resolveAddr(mxHosts[0], 'AAAA')).length > 0) : null,
    caa,
    mta_sts: mtaSts,
    tls_rpt: tlsRpt,
  };
}

// ---- At most PER_NETWORK handshakes at once per IPv4 /24 ----

const busy = new Map();
const waiting = new Map();

async function networkOf(domain) {
  try {
    const a = (await query(domain, 'A'))[0]?.data ?? (await query(`www.${domain}`, 'A'))[0]?.data;
    return a ? a.split('.').slice(0, 3).join('.') : `none:${domain}`;
  } catch {
    return `none:${domain}`;
  }
}

async function withNetwork(net, fn) {
  while ((busy.get(net) ?? 0) >= PER_NETWORK) {
    await new Promise((r) => { if (!waiting.has(net)) waiting.set(net, []); waiting.get(net).push(r); });
  }
  busy.set(net, (busy.get(net) ?? 0) + 1);
  try {
    return await fn();
  } finally {
    busy.set(net, busy.get(net) - 1);
    waiting.get(net)?.shift()?.();
  }
}

// ---- Per domain ----

/**
 * The measures are independent: an unreadable SPF include marks only SPF
 * (`spf.unreadable`); a read error on MX or DMARC sets `email_error`; neither
 * touches DNSSEC or HTTPS, and a DNSSEC read error does not stop the email
 * checks. Each measure's population is the domains it could read
 * (summarise-cc-security.mjs). `prev` is this domain's previous row, if any,
 * for confirming broken DNSSEC on a second scan.
 */
async function scan(rank, tldRank, domain, prev) {
  const row = { rank, tld_rank: tldRank, domain };
  try {
    row.dnssec = await dnssec(domain);
  } catch (e) {
    row.dnssec = { ds: null, state: 'error', detail: String(e?.message ?? e) };
  }
  if (row.dnssec.state === 'nxdomain') return row; // not a registered domain any more

  let mxHosts = null;
  if (row.dnssec.state !== 'bogus') {
    // Lookups that failed during the email checks, tagged by stage, to tell a
    // DNSSEC failure apart from an ordinary read error. Only a stage's own
    // names decide that stage: the DMARC analyser also reads report-
    // authorisation records at other domains, which never decide anything.
    const failed = [];
    let stage = 'mx';
    const resolveTxt = async (name) => {
      try { return (await query(name, 'TXT')).map(txtData); } catch (e) { failed.push({ name, type: 'TXT', stage }); throw e; }
    };
    try {
      let mx;
      try { mx = await query(domain, 'MX'); } catch (e) { failed.push({ name: domain, type: 'MX', stage: 'mx' }); throw e; }
      const hosts = mx.map((x) => String(x.data).trim().split(/\s+/)).map(([pref, host]) => [Number(pref), (host ?? '').toLowerCase().replace(/\.$/, '')]);
      // Fixed order (preference, then name): equal-preference hosts come back in any order.
      mxHosts = hosts.filter(([, h]) => h).sort((x, y) => x[0] - y[0] || x[1].localeCompare(y[1])).map(([, h]) => h);
      const nullMx = hosts.length && hosts.every(([, h]) => h === '' || h === '.');
      // "MX 0 localhost" and similar point nowhere a sender can reach: not a mail domain.
      const unusable = mxHosts.length && mxHosts.every((h) => h === 'localhost' || h.endsWith('.localhost') || !h.includes('.'));
      row.mx = !hosts.length ? 'none' : nullMx ? 'null' : unusable ? 'unusable' : 'yes';
      row.mx_hosts = row.mx === 'yes' ? mxHosts : [];

      stage = 'spf';
      const spf = await analyseSpf(domain, resolveTxt, { resolveAddr });
      row.spf = { found: spf.found, lookups: spf.lookups ?? 0, void_lookups: spf.voidLookups ?? 0, includes: spf.includes ?? [], codes: (spf.findings ?? []).map((f) => f.code) };
      if (row.spf.codes.includes('dns-error')) row.spf.unreadable = true;

      stage = 'dmarc';
      const dmarc = await analyseDmarc(domain, resolveTxt, { hasSpf: spf.found });
      // RFC 9989 test mode, read with the tool's own tag parser (which also
      // splits tags glued together without a ';'). Applied in the summariser.
      const t = dmarc.tags?.find((x) => x.name === 't')?.value?.trim().toLowerCase() ?? null;
      row.dmarc = {
        found: dmarc.found,
        policy: dmarc.policy ?? null,
        sp: dmarc.subdomainPolicy ?? null,
        pct: dmarc.pct ?? null,
        t,
        rua: (dmarc.rua ?? []).length,
        rua_domains: [...new Set((dmarc.rua ?? []).map((u) => String(u).replace(/^mailto:/i, '').split('!')[0].split('@')[1]?.toLowerCase()).filter(Boolean))].sort(),
        codes: (dmarc.findings ?? []).map((f) => f.code),
      };
      if (row.dmarc.codes.includes('dns-error') || failed.some((f) => f.stage === 'dmarc' && f.name === `_dmarc.${domain}`)) throw new DnsError('dmarc dns-error');
    } catch (e) {
      delete row.mx;
      delete row.mx_hosts;
      delete row.spf;
      delete row.dmarc;
      row.email_error = String(e?.message ?? e);
    }

    // For each failed stage: was it a DNSSEC failure? Every relevant name is
    // checked and the domain's own zone wins over someone else's. Own zone =
    // signed, zone itself validates (valid, or already partly broken).
    const judge = async (entries) => {
      let elsewhere = false;
      for (const f of entries) {
        const r = await failsValidation(f.name, f.type, domain).catch(() => false);
        if (r === true && inDomain(f.name, domain) && row.dnssec.ds === true && (row.dnssec.state === 'valid' || row.dnssec.state === 'bogus-partial')) return { own: f };
        if (r) elsewhere = true;
      }
      return elsewhere ? { elsewhere: true } : null;
    };
    const markOwn = (f) => {
      if (row.dnssec.state === 'valid') row.dnssec = { ...row.dnssec, state: 'bogus-partial', failed: `${f.type} ${f.name}` };
    };
    if (row.email_error) {
      const v = await judge(failed.filter((f) => f.stage === 'mx' || (f.stage === 'dmarc' && f.name === `_dmarc.${domain}`)));
      if (v?.own) { markOwn(v.own); row.email_error = 'dnssec-bogus-partial'; } else if (v?.elsewhere) row.email_error = 'dnssec-elsewhere';
    }
    if (row.spf?.unreadable) {
      const v = await judge(failed.filter((f) => f.stage === 'spf'));
      if (v?.own) { markOwn(v.own); row.spf.unreadable = 'dnssec-bogus-partial'; } else if (v?.elsewhere) row.spf.unreadable = 'dnssec-elsewhere';
    }
  }

  // Broken DNSSEC is published only once two scans saw it.
  if (row.dnssec.state === 'bogus' || row.dnssec.state === 'bogus-partial') {
    // Confirmed = the same state on the same record set as last time.
    const same = prev?.dnssec?.state === row.dnssec.state && (prev.dnssec.failed ?? null) === (row.dnssec.failed ?? null);
    row.dnssec.confirmations = (same ? (prev.dnssec.confirmations ?? 1) : 0) + 1;
  }

  row.extra = await extras(domain, mxHosts);
  row.https = await withNetwork(await networkOf(domain), () => httpsCheck(domain, resolveAddr));
  return row;
}

/**
 * Scanned again on the next run: a read error in any measure (or the old
 * whole-row `error`), an unreadable SPF include, a website whose name could not
 * be resolved, and broken DNSSEC until a second scan has confirmed it.
 */
const needsRetry = (r) => Boolean(
  r.error
  || (r.email_error && !r.email_error.startsWith('dnssec-'))
  || r.spf?.unreadable === true
  || r.dnssec?.state === 'error'
  || ((r.dnssec?.state === 'bogus' || r.dnssec?.state === 'bogus-partial') && (r.dnssec.confirmations ?? 1) < 2)
  || (r.https?.via === 'none' && (r.https.error === 'dns-error' || r.https.www_error === 'dns-error')
    && !(r.dnssec?.state === 'bogus' || (r.dnssec?.state === 'bogus-partial' && (r.dnssec.confirmations ?? 1) >= 2))),
);

// ---- The list ----

const excluded = new Set(existsSync(EXCLUDE) ? readFileSync(EXCLUDE, 'utf8').split('\n').map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#')) : []);
let excludedHits = 0;
// Opted-out domains in this list, as hashes: run.json can count them across
// runs without naming them (summarise-cc-security.mjs takes the union).
const excludedHashes = new Set();
const hashOf = (d) => createHash('sha256').update(d).digest('hex').slice(0, 16);

let listed = 0; // domains in the list that fall within --top (incl. opted out), for the completeness check
async function* topDomains() {
  const rl = createInterface({ input: createReadStream(LIST) });
  let n = 0;
  for await (const line of rl) {
    const [rank, d] = line.trim().split(',');
    const domain = (d ?? '').toLowerCase();
    if (TLD !== 'all' && !domain.endsWith(`.${TLD}`)) continue;
    if (++n > TOP) break;
    listed = n;
    if (excluded.has(domain)) { excludedHits++; excludedHashes.add(hashOf(domain)); continue; }
    yield [Number(rank), n, domain];
  }
}

/** Seeded Fisher–Yates (mulberry32), so a run's order can be reproduced from run.json. */
function shuffle(items, seed) {
  let s = seed >>> 0;
  const rand = () => { s = (s + 0x6d2b79f5) >>> 0; let t = s; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
  for (let i = items.length - 1; i > 0; i--) { const j = Math.floor(rand() * (i + 1)); [items[i], items[j]] = [items[j], items[i]]; }
  return items;
}

mkdirSync(OUT, { recursive: true });
const file = join(OUT, 'results.ndjson');
const runFile = join(OUT, 'run.json');
const prevRun = existsSync(runFile) ? JSON.parse(readFileSync(runFile, 'utf8')) : null;
const listId = args['list-id'] ?? prevRun?.list?.id ?? null;
if (prevRun && (prevRun.tld !== TLD || prevRun.top !== TOP || prevRun.list?.file !== basename(LIST) || (prevRun.list?.id ?? null) !== listId || (prevRun.list?.source ?? 'tranco') !== LIST_SOURCE)) {
  console.error(`${OUT} holds a run of .${prevRun.tld} top ${prevRun.top} from ${prevRun.list?.file} (${prevRun.list?.id}); use another --out instead of mixing runs`);
  process.exit(1);
}
const seed = Number(args.seed ?? prevRun?.seed ?? Math.floor(Math.random() * 2 ** 31));
let commit = args.commit ?? null;
if (!commit) try { commit = execSync('git rev-parse --short HEAD', { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim(); } catch { /* copied without git: pass --commit */ }

// Resume: the LAST row per domain counts. A line cut off by a killed process is
// skipped, and a newline is added first so the next row does not join it.
const last = new Map();
if (existsSync(file)) {
  const text = readFileSync(file, 'utf8');
  if (text.length && !text.endsWith('\n')) appendFileSync(file, '\n');
  for (const l of text.split('\n')) {
    if (!l.trim()) continue;
    try { const r = JSON.parse(l); last.set(r.domain, r); } catch { /* truncated line */ }
  }
}
const done = new Set([...last.values()].filter((r) => !needsRetry(r)).map((r) => r.domain));
const retrying = [...last.values()].filter(needsRetry).length;
const todo = [];
for await (const d of topDomains()) if (!done.has(d[2])) todo.push(d);
shuffle(todo, seed);

const segment = { started: new Date().toISOString(), finished: null, scanner_commit: commit, node: process.version, vantage: args.vantage ?? 'unspecified (pass --vantage)', concurrency: CONCURRENCY, per_network: PER_NETWORK, domains: todo.length };
const run = {
  tld: TLD,
  top: TOP,
  list: { file: basename(LIST), id: listId, source: LIST_SOURCE },
  seed,
  concurrency: CONCURRENCY,
  per_network: PER_NETWORK,
  listed,
  excluded_opt_out: excludedHits,
  excluded_hashes: [...new Set([...(prevRun?.excluded_hashes ?? []), ...excludedHashes])].sort(),
  segments: [...(prevRun?.segments ?? []), segment],
};
writeFileSync(runFile, `${JSON.stringify(run, null, 2)}\n`);
console.log(`list ${LIST} (${listId ?? 'no id'}): top ${TOP} ${TLD === 'all' ? '(all TLDs)' : `.${TLD}`}, ${excludedHits} opted out, ${done.size} done, ${todo.length} to go incl. ${retrying} retries (concurrency ${CONCURRENCY}, ${PER_NETWORK} per /24, seed ${seed})`);

let n = 0;
let errors = 0;
const started = Date.now();
async function worker() {
  while (todo.length) {
    const [rank, tldRank, domain] = todo.shift();
    const row = await scan(rank, tldRank, domain, last.get(domain));
    if (needsRetry(row)) errors++;
    appendFileSync(file, `${JSON.stringify(row)}\n`);
    if (++n % 250 === 0) {
      const rate = n / ((Date.now() - started) / 1000);
      console.log(`${n} scanned · ${errors} to retry · ${rate.toFixed(1)}/s · ~${Math.round(todo.length / rate / 60)} min left`);
    }
  }
}
await Promise.all(Array.from({ length: CONCURRENCY }, worker));
segment.finished = new Date().toISOString();
writeFileSync(runFile, `${JSON.stringify(run, null, 2)}\n`);
console.log(`done: ${n} scanned this run, ${errors} to retry (read errors, or bogus to confirm) — re-run later; ${Math.round((Date.now() - started) / 1000)}s`);
