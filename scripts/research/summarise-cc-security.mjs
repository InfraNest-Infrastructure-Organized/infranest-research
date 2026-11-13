/*
 * Aggregates scan-cc-security.mjs output into the totals a study page quotes.
 * The definitions are those of the plan (docs/research/email-dns-2027-plan.md,
 * sections 5 and 8); where this file and the plan differ, that is a bug.
 *
 * Populations (each measure has its own; a domain leaves a measure only when
 * that measure could not be read, and the count is published):
 *   - removed everywhere: opted-out domains, domains that no longer exist
 *   - DMARC: mail domains (real MX; not null MX, not "MX 0 localhost") whose
 *     DMARC record could be read
 *   - SPF: those of them whose SPF record could be read (an unreadable include
 *     makes SPF unreadable, never "valid"); "protected" needs both readable
 *   - DNSSEC signed: domains whose DS could be read; the other DNSSEC states:
 *     domains whose state could be read
 *   - HTTPS: domains with a public address for the site that could be resolved
 *     (read errors and "no public address" are counted apart)
 *
 * Definitions:
 *   - valid SPF: exactly one record and no permanent error (RFC 7208)
 *   - near the SPF limit: valid with 8-10 lookups, as a share of valid records
 *   - DMARC published: exactly one record
 *   - effective DMARC policy (RFC 9989): t=y, or a legacy pct=0, means one level
 *     below p=; a pct of 1-99 is "partial"; a record receivers may not parse
 *     (bad characters, missing ';', no or invalid p=, invalid pct) is "invalid".
 *     Enforced = effective quarantine or reject.
 *   - broken DNSSEC: whole-zone or partial, counted only when two scans saw it
 *   - expired: end date passed; expiring: trusted, 0-7 days left; lifetimes:
 *     trusted certificates only
 *
 * Every block carries its denominator `n`; headline measures carry a 95% Wilson
 * interval; anything with n < 100 is flagged `publishable: false`.
 * summary.json holds totals only. Unrecognised provider values (which name
 * scanned domains) go to unmatched.json, which is internal and never published.
 *
 * Usage: node scripts/research/summarise-cc-security.mjs <out-dir> [--exclude file]
 */
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import { PROVIDERS, providerFor, region, tail } from './providers.mjs';

const argv = process.argv.slice(2);
const dir = argv[0] ?? 'research/cc-nl';
const EXCLUDE = argv.includes('--exclude') ? argv[argv.indexOf('--exclude') + 1] : 'research/opt-out.txt';
const excluded = new Set(existsSync(EXCLUDE) ? readFileSync(EXCLUDE, 'utf8').split('\n').map((l) => l.trim().toLowerCase()).filter((l) => l && !l.startsWith('#')) : []);
const run = existsSync(join(dir, 'run.json')) ? JSON.parse(readFileSync(join(dir, 'run.json'), 'utf8')) : null;

const latest = new Map();
for (const l of readFileSync(join(dir, 'results.ndjson'), 'utf8').split('\n')) {
  if (!l.trim()) continue;
  try { const r = JSON.parse(l); latest.set(r.domain, r); } catch { /* truncated line */ }
}
// Opted-out domains, counted once: those the scanner skipped (hashes in
// run.json) together with those that opted out after being scanned.
const hashOf = (d) => createHash('sha256').update(d).digest('hex').slice(0, 16);
const optedOutHashes = new Set([...(run?.excluded_hashes ?? []), ...[...latest.keys()].filter((d) => excluded.has(d)).map(hashOf)]);
// A run.json from before the hashes existed only has a count: add it, and say the total is approximate.
const optOutApprox = Boolean(run && !run.excluded_hashes && run.excluded_opt_out);
const optedOutCount = optedOutHashes.size + (optOutApprox ? run.excluded_opt_out : 0);
const all = [...latest.values()].filter((r) => !excluded.has(r.domain));
const nxdomain = all.filter((r) => r.dnssec?.state === 'nxdomain').length;
const rows = all.filter((r) => r.dnssec?.state !== 'nxdomain');
// Complete = every domain of the list has a row or opted out. Unknown without run.json.
// `listed` (domains of the list within --top) when the scanner recorded it; older runs only have --top.
const complete = run ? all.length + optedOutCount >= (run.listed ?? run.top) : null;
// Rows from different scanner versions may follow different definitions.
const commits = [...new Set((run?.segments ?? []).map((g) => g.scanner_commit).filter(Boolean))];
const mixedVersions = commits.length > 1;

// Second vantage point (recheck-https.mjs): a domain that failed on the network
// from the scan server but answered from elsewhere blocks datacenter addresses.
const recheckFiles = readdirSync(dir).filter((n) => /^recheck-.+\.ndjson$/.test(n));
const recheck = new Map();
for (const f of recheckFiles) {
  for (const l of readFileSync(join(dir, f), 'utf8').split('\n')) {
    if (!l.trim()) continue;
    try { const r = JSON.parse(l); if (r.https?.ok && !recheck.has(r.domain)) recheck.set(r.domain, r); } catch { /* skip */ }
  }
}
for (const r of rows) {
  if (r.https?.via === 'none' && recheck.has(r.domain)) r.https = { ...recheck.get(r.domain).https, blocked_server: true };
}

// ---- Definitions ----

const has = (r, part, code) => r[part]?.codes?.includes(code);
const SPF_PERMERROR = ['multiple-records', 'lookup-limit-exceeded', 'include-loop', 'void-lookups', 'include-missing', 'include-invalid', 'unknown-term', 'typo', 'bad-ip', 'empty-value', 'bad-characters'];
const spfValid = (r) => r.spf?.found && !SPF_PERMERROR.some((c) => has(r, 'spf', c));
const dmarcPublished = (r) => r.dmarc?.found && !has(r, 'dmarc', 'multiple-records');
// Not 'bad-pct': receivers ignore an invalid pct and apply the policy to all
// mail (RFC 7489 §6.6.3; RFC 9989 drops pct). Not 'missing-semicolon' alone
// either — it makes p= or v= invalid, which the policy check below catches.
const DMARC_UNPARSEABLE = ['bad-characters', 'missing-semicolon', 'no-policy', 'bad-policy'];
const DOWN = { reject: 'quarantine', quarantine: 'none', none: 'none' };

/** missing | invalid | partial | none | quarantine | reject — the policy receivers are asked to apply. */
function effectivePolicy(r) {
  if (!dmarcPublished(r)) return 'missing';
  if (DMARC_UNPARSEABLE.some((c) => has(r, 'dmarc', c)) || !['none', 'quarantine', 'reject'].includes(r.dmarc.policy)) return 'invalid';
  const pct = has(r, 'dmarc', 'bad-pct') ? 100 : r.dmarc.pct ?? 100;
  if (pct > 0 && pct < 100) return 'partial';
  if (r.dmarc.t === 'y' || pct === 0) return DOWN[r.dmarc.policy];
  return r.dmarc.policy;
}
const enforcing = (r) => ['quarantine', 'reject'].includes(effectivePolicy(r));

const pctOf = (k, n) => (n ? Math.round((1000 * k) / n) / 10 : null);
/** 95% Wilson score interval, in percent, one decimal. */
function wilson(k, n) {
  if (!n) return null;
  const z = 1.96;
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = (p + (z * z) / (2 * n)) / d;
  const h = (z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n))) / d;
  return [Math.round(1000 * Math.max(0, c - h)) / 10, Math.round(1000 * Math.min(1, c + h)) / 10];
}
const measure = (k, n) => ({ pct: pctOf(k, n), ci95: wilson(k, n), n, publishable: n >= 100 });
const block = (n, fields) => ({ n, publishable: n >= 100, ...fields });

// ---- Populations ----

const isMail = (r) => r.mx === 'yes';
const dmarcPop = rows.filter((r) => r.dmarc && !r.email_error && !r.error && isMail(r));
const spfPop = dmarcPop.filter((r) => r.spf && !r.spf.unreadable);
const dsReadable = rows.filter((r) => r.dnssec && r.dnssec.ds !== null && r.dnssec.ds !== undefined);
const dnssecReadable = rows.filter((r) => r.dnssec && r.dnssec.state !== 'error');
const nameFail = (e) => ['dns-error', 'no-address', 'private-address'].includes(e);
const httpsState = (r) => {
  if (!r.https) return 'unmeasured';
  if (r.https.via !== 'none' || !(nameFail(r.https.error) && nameFail(r.https.www_error))) return 'measured';
  return r.https.error === 'dns-error' || r.https.www_error === 'dns-error' ? 'read-error' : 'no-public-address';
};
const httpsPop = rows.filter((r) => httpsState(r) === 'measured');

function email(dPop) {
  const sPop = dPop.filter((r) => r.spf && !r.spf.unreadable);
  const both = sPop;
  const n = dPop.length;
  const eff = (p) => dPop.filter((r) => effectivePolicy(r) === p).length;
  const published = dPop.filter(dmarcPublished);
  const ofPub = (f) => pctOf(published.filter(f).length, published.length);
  const withSpf = sPop.filter((r) => r.spf.found);
  const valid = withSpf.filter(spfValid);
  return {
    dmarc: block(n, {
      published_pct: pctOf(published.length, n),
      multiple_records_pct: pctOf(dPop.filter((r) => has(r, 'dmarc', 'multiple-records')).length, n),
      // As published (p=), of domains with one DMARC record — comparable with September.
      published_policy: block(published.length, {
        none_pct: ofPub((r) => r.dmarc.policy === 'none'),
        quarantine_pct: ofPub((r) => r.dmarc.policy === 'quarantine'),
        reject_pct: ofPub((r) => r.dmarc.policy === 'reject'),
        other_pct: ofPub((r) => !['none', 'quarantine', 'reject'].includes(r.dmarc.policy)),
        test_mode_pct: ofPub((r) => r.dmarc.t === 'y' || r.dmarc.pct === 0),
        partial_pct_pct: ofPub((r) => r.dmarc.pct > 0 && r.dmarc.pct < 100),
      }),
      // What receivers are asked to apply, of all mail domains; adds up to 100.
      effective_policy: block(n, {
        ...Object.fromEntries(['missing', 'invalid', 'partial', 'none', 'quarantine', 'reject'].map((p) => [`${p}_pct`, pctOf(eff(p), n)])),
        // Counts too: the six percentages are rounded one by one and may not add up to exactly 100.0.
        counts: Object.fromEntries(['missing', 'invalid', 'partial', 'none', 'quarantine', 'reject'].map((p) => [p, eff(p)])),
      }),
      enforced: measure(dPop.filter(enforcing).length, n),
      not_enforced: measure(dPop.filter((r) => !enforcing(r)).length, n),
    }),
    spf: block(sPop.length, {
      published_pct: pctOf(withSpf.length, sPop.length),
      valid: measure(valid.length, sPop.length),
      of_spf_domains: block(withSpf.length, {
        permanent_error_pct: pctOf(withSpf.length - valid.length, withSpf.length),
        over_10_lookups_pct: pctOf(withSpf.filter((r) => has(r, 'spf', 'lookup-limit-exceeded')).length, withSpf.length),
        void_over_2_pct: pctOf(withSpf.filter((r) => has(r, 'spf', 'void-lookups')).length, withSpf.length),
        include_missing_pct: pctOf(withSpf.filter((r) => has(r, 'spf', 'include-missing')).length, withSpf.length),
        multiple_records_pct: pctOf(withSpf.filter((r) => has(r, 'spf', 'multiple-records')).length, withSpf.length),
        plus_all_pct: pctOf(withSpf.filter((r) => has(r, 'spf', 'plus-all')).length, withSpf.length),
      }),
      of_valid: block(valid.length, {
        near_limit_8_10_pct: pctOf(valid.filter((r) => has(r, 'spf', 'lookup-near-limit')).length, valid.length),
      }),
    }),
    protected: measure(both.filter((r) => spfValid(r) && enforcing(r)).length, both.length),
  };
}

function dnssec(dsPop, statePop) {
  const confirmed = (s) => statePop.filter((r) => r.dnssec.state === s && (r.dnssec.confirmations ?? 1) >= 2).length;
  const unconfirmed = statePop.filter((r) => (r.dnssec.state === 'bogus' || r.dnssec.state === 'bogus-partial') && (r.dnssec.confirmations ?? 1) < 2).length;
  const n = statePop.length;
  return {
    signed: measure(dsPop.filter((r) => r.dnssec.ds === true).length, dsPop.length),
    states: block(n, {
      // The zone itself validates (its SOA): fully valid, or valid with a broken record set.
      zone_validates_pct: pctOf(statePop.filter((r) => r.dnssec.state === 'valid' || r.dnssec.state === 'bogus-partial').length, n),
      insecure_pct: pctOf(statePop.filter((r) => r.dnssec.state === 'insecure').length, n),
      broken: measure(confirmed('bogus') + confirmed('bogus-partial'), n),
      broken_whole_zone: confirmed('bogus'),
      broken_partial: confirmed('bogus-partial'),
      broken_unconfirmed: unconfirmed,
    }),
  };
}

function https(pop) {
  const answered = pop.filter((r) => r.https.ok);
  const trusted = answered.filter((r) => r.https.authorized);
  const n = answered.length;
  const tally = (list, keyOf) => list.reduce((m, r) => { const k = keyOf(r) ?? 'unknown'; return { ...m, [k]: (m[k] ?? 0) + 1 }; }, {});
  const issuers = tally(trusted, (r) => r.https.issuer);
  return {
    answers: measure(n, pop.length),
    // The error of the name actually tried: www when the bare name had no (public) address.
    no_answer_reasons: tally(pop.filter((r) => !r.https.ok), (r) => (nameFail(r.https.error) ? r.https.www_error : r.https.error)),
    blocked_scan_server: answered.filter((r) => r.https.blocked_server).length,
    of_answering: block(n, {
      trusted: measure(trusted.length, n),
      untrusted_reasons: tally(answered.filter((r) => !r.https.authorized), (r) => r.https.error),
      expired_pct: pctOf(answered.filter((r) => r.https.days_left < 0).length, n),
      // Not "within 30 days": ACME clients renew around 30 days before expiry.
      expiring_7d_pct: pctOf(trusted.filter((r) => r.https.days_left >= 0 && r.https.days_left <= 7).length, n),
    }),
    of_trusted: block(trusted.length, {
      lifetime_upto_100d_pct: pctOf(trusted.filter((r) => r.https.lifetime_days <= 100).length, trusted.length),
      lifetime_101_200d_pct: pctOf(trusted.filter((r) => r.https.lifetime_days > 100 && r.https.lifetime_days <= 200).length, trusted.length),
      lifetime_over_100d: measure(trusted.filter((r) => r.https.lifetime_days > 100).length, trusted.length),
      lifetime_over_200d_pct: pctOf(trusted.filter((r) => r.https.lifetime_days > 200).length, trusted.length),
      top_issuers_pct: Object.fromEntries(Object.entries(issuers).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => [k, pctOf(v, trusted.length)])),
    }),
  };
}

// ---- Providers (plan section 5) ----

const BY_NAME = new Map(PROVIDERS.map((p) => [p.name, p]));
const OWN = 'Own domain';
const unmatchedAll = {};

/**
 * Per role: share of domains per provider and per region (where the provider is
 * based). A domain can use several providers in one role, so shares need not
 * add up. A value under the domain itself (mx.example.nl for example.nl)
 * counts as "own domain", not as unrecognised.
 */
function providers(role, pop, valuesOf) {
  const n = pop.length;
  const count = new Map();
  const regionCount = new Map();
  const unmatched = new Map();
  let unknownDomains = 0;
  let cdnDomains = 0;
  for (const r of pop) {
    const names = new Set();
    let anyUnknown = false;
    for (const v of valuesOf(r) ?? []) {
      const host = String(v).toLowerCase().replace(/\.$/, '');
      if (role !== 'web' && role !== 'issuer' && (host === r.domain || host.endsWith(`.${r.domain}`))) { names.add(OWN); continue; }
      const p = providerFor(role, v);
      if (p) names.add(p.name);
      else { anyUnknown = true; const t = role === 'web' || role === 'issuer' ? String(v) : tail(v); unmatched.set(t, (unmatched.get(t) ?? 0) + 1); }
    }
    if (anyUnknown && !names.size) unknownDomains++;
    if ([...names].some((nm) => BY_NAME.get(nm)?.cdn)) cdnDomains++;
    for (const nm of names) count.set(nm, (count.get(nm) ?? 0) + 1);
    for (const g of new Set([...names].map((nm) => (nm === OWN ? 'own domain' : region(BY_NAME.get(nm).hq))))) regionCount.set(g, (regionCount.get(g) ?? 0) + 1);
  }
  unmatchedAll[role] = Object.fromEntries([...unmatched.entries()].sort((a, b) => b[1] - a[1]));
  const top = (m, k) => Object.fromEntries([...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, k).map(([name, v]) => [name, pctOf(v, n)]));
  return block(n, {
    providers_pct: top(count, 20),
    region_pct: top(regionCount, 5),
    unrecognised_pct: pctOf(unknownDomains, n),
    ...(role === 'web' ? { behind_cdn_or_proxy_pct: pctOf(cdnDomains, n) } : {}),
  });
}

const mailPop = rows.filter((r) => isMail(r) && r.mx_hosts?.length);
const webNames = (r) => (Array.isArray(r.extra?.web?.networks) ? r.extra.web.networks : []).map((x) => x.name).filter(Boolean);

/** Mail domains using a US-based provider for at least one of mail, DNS or web network (a lower bound). */
function usDependency(pop) {
  const us = (role, values, domain) => (values ?? []).some((v) => {
    const h = String(v).toLowerCase();
    if (role !== 'web' && (h === domain || h.endsWith(`.${domain}`))) return false;
    const p = providerFor(role, v);
    return p && region(p.hq) === 'US';
  });
  const known = pop.filter((r) => r.extra);
  return measure(known.filter((r) => us('mail', r.mx_hosts, r.domain) || us('dns', r.extra.ns, r.domain) || us('web', webNames(r), r.domain)).length, known.length);
}

const providerSection = {
  mail: providers('mail', mailPop, (r) => r.mx_hosts),
  sending: providers('sending', spfPop.filter((r) => r.spf.found), (r) => r.spf.includes),
  dns: providers('dns', rows.filter((r) => r.extra?.ns?.length), (r) => r.extra.ns),
  web: providers('web', rows.filter((r) => webNames(r).length), webNames),
  reports: providers('reports', dmarcPop.filter((r) => r.dmarc.rua_domains?.length), (r) => r.dmarc.rua_domains),
  issuer: providers('issuer', httpsPop.filter((r) => r.https.ok && r.https.authorized), (r) => [r.https.issuer]),
  us_dependency_mail_dns_or_web: usDependency(mailPop),
};

const share = (pop, f) => measure(pop.filter(f).length, pop.length);
const extrasSection = {
  web_ipv6: share(rows.filter((r) => r.extra?.web?.ipv4 || r.extra?.web?.ipv6), (r) => r.extra.web.ipv6),
  mail_ipv6: share(mailPop.filter((r) => typeof r.extra?.mx_ipv6 === 'boolean'), (r) => r.extra.mx_ipv6),
  caa: share(rows.filter((r) => Array.isArray(r.extra?.caa)), (r) => r.extra.caa.length > 0),
  mta_sts: share(mailPop.filter((r) => typeof r.extra?.mta_sts === 'boolean'), (r) => r.extra.mta_sts),
  tls_rpt: share(mailPop.filter((r) => typeof r.extra?.tls_rpt === 'boolean'), (r) => r.extra.tls_rpt),
};

// Tiers (plan section 4). A CrUX list has popularity buckets, not ranks: the
// tiers are the buckets (column 1 of the list, `rank` in a row). A Tranco list
// has exact ranks within the country list (`tld_rank`).
const CRUX = (run?.list?.source ?? 'tranco') === 'crux';
const TIERS = CRUX
  ? { all: () => true, top_1000: (r) => r.rank <= 1000, top_5000: (r) => r.rank <= 5000, top_10000: (r) => r.rank <= 10000, rank_10001_50000: (r) => r.rank > 10000 && r.rank <= 50000 }
  : { all: () => true, top_100: (r) => r.tld_rank <= 100, rank_101_1000: (r) => r.tld_rank > 100 && r.tld_rank <= 1000, top_1000: (r) => r.tld_rank <= 1000, rank_1001_plus: (r) => r.tld_rank > 1000 };
const byTier = (f) => Object.fromEntries(Object.entries(TIERS).map(([k, t]) => [k, f(t)]));

// The top-100 tier stays internal (plan section 8): never marked publishable.
function internal(o) {
  if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) { if (k === 'publishable') o[k] = false; else internal(v); }
  return o;
}

const { excluded_hashes: _hashes, ...runInfo } = run ?? {};
const summary = {
  run: run ? runInfo : null,
  complete,
  mixed_scanner_versions: mixedVersions ? commits : false,
  scanned: latest.size,
  removed: { opted_out: optedOutCount, ...(optOutApprox ? { opted_out_approximate: true } : {}), nxdomain },
  not_readable: {
    mx_or_dmarc_all_domains: rows.filter((r) => (r.email_error && !r.email_error.startsWith('dnssec-')) || r.error).length,
    spf_of_mail_domains: rows.filter((r) => isMail(r) && !r.email_error && !r.error && r.spf?.unreadable === true).length,
    email_broken_dnssec_own: rows.filter((r) => r.dnssec?.state === 'bogus' || r.email_error === 'dnssec-bogus-partial').length,
    email_broken_dnssec_elsewhere: rows.filter((r) => r.email_error === 'dnssec-elsewhere').length,
    spf_broken_dnssec_own: rows.filter((r) => r.spf?.unreadable === 'dnssec-bogus-partial').length,
    spf_broken_dnssec_elsewhere: rows.filter((r) => r.spf?.unreadable === 'dnssec-elsewhere').length,
    web_address_broken_dnssec_elsewhere: rows.filter((r) => r.dnssec?.web_elsewhere).length,
    dnssec_ds: rows.filter((r) => !dsReadable.includes(r)).length,
    dnssec_state: rows.filter((r) => !dnssecReadable.includes(r)).length,
    https_read_error: rows.filter((r) => httpsState(r) === 'read-error').length,
  },
  mx: { mail_domains: rows.filter(isMail).length, null_mx: rows.filter((r) => r.mx === 'null').length, no_mx: rows.filter((r) => r.mx === 'none').length, unusable_mx: rows.filter((r) => r.mx === 'unusable').length },
  https_no_public_address: rows.filter((r) => httpsState(r) === 'no-public-address').length,
  https_recheck: { files: recheckFiles, blocked_scan_server: rows.filter((r) => r.https?.blocked_server).length },
  email: byTier((t) => email(dmarcPop.filter(t))),
  dnssec: byTier((t) => dnssec(dsReadable.filter(t), dnssecReadable.filter(t))),
  https: byTier((t) => https(httpsPop.filter(t))),
  providers: providerSection,
  extras: extrasSection,
};
for (const section of [summary.email, summary.dnssec, summary.https]) if (section.top_100) internal(section.top_100);
writeFileSync(join(dir, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`);
writeFileSync(join(dir, 'unmatched.json'), `${JSON.stringify({ note: 'INTERNAL — names scanned domains; never publish. For extending providers.mjs.', ...unmatchedAll }, null, 2)}\n`);

// ---- Console table ----
const tiers = CRUX ? ['all', 'top_1000', 'top_10000', 'rank_10001_50000'] : ['all', 'top_100', 'top_1000', 'rank_1001_plus'];
const line = (label, ...v) => console.log(`${label.padEnd(38)}${v.map((x) => String(x ?? '–').padStart(12)).join('')}`);
const pc = (x) => (x && typeof x === 'object' ? (x.publishable ? x.pct : `(${x.pct})`) : x);
if (complete === false) console.log(`WARNING: incomplete run — ${all.length} rows + ${optedOutCount} opted out < ${run.listed ?? run.top}\n`);
if (complete === null) console.log('WARNING: no run.json — completeness unknown\n');
if (mixedVersions) console.log(`WARNING: rows from different scanner versions (${commits.join(', ')}) — definitions may differ\n`);
console.log(`scanned ${summary.scanned}; removed ${JSON.stringify(summary.removed)}; not readable ${JSON.stringify(summary.not_readable)}\nmx ${JSON.stringify(summary.mx)}; (values in brackets: n < 100, not publishable)\n`);
line('(%)', ...tiers.map((t) => t.replace(/^rank_|^top_/, (m) => (m === 'top_' ? 'top ' : '')).replace('_', '-')));
const E = tiers.map((k) => summary.email[k]);
line('DMARC (mail domains)', ...E.map((s) => `n=${s.dmarc.n}`));
line('  NOT enforced (spoofable)', ...E.map((s) => pc(s.dmarc.not_enforced)));
line('  effective: missing', ...E.map((s) => s.dmarc.effective_policy.missing_pct));
line('  effective: none', ...E.map((s) => s.dmarc.effective_policy.none_pct));
line('  effective: invalid / partial', ...E.map((s) => `${s.dmarc.effective_policy.invalid_pct}/${s.dmarc.effective_policy.partial_pct}`));
line('  published p=reject (of published)', ...E.map((s) => s.dmarc.published_policy.reject_pct));
line('SPF', ...E.map((s) => `n=${s.spf.n}`));
line('  valid', ...E.map((s) => pc(s.spf.valid)));
line('  permanent error (of SPF)', ...E.map((s) => s.spf.of_spf_domains.permanent_error_pct));
line('  8-10 lookups (of valid)', ...E.map((s) => s.spf.of_valid.near_limit_8_10_pct));
line('  protected (SPF + DMARC)', ...E.map((s) => pc(s.protected)));
const D = tiers.map((k) => summary.dnssec[k]);
line('DNSSEC', ...D.map((s) => `n=${s.signed.n}`));
line('  signed', ...D.map((s) => pc(s.signed)));
line('  broken, confirmed (bogus+partial)', ...D.map((s) => pc(s.states.broken)));
line('  broken, unconfirmed', ...D.map((s) => s.states.broken_unconfirmed));
const H = tiers.map((k) => summary.https[k]);
line('HTTPS (public address)', ...H.map((s) => `n=${s.answers.n}`));
line('  answers on 443', ...H.map((s) => pc(s.answers)));
line('  trusted (of answering)', ...H.map((s) => pc(s.of_answering.trusted)));
line('  expired (of answering)', ...H.map((s) => s.of_answering.expired_pct));
line('  lifetime >100d (of trusted)', ...H.map((s) => pc(s.of_trusted.lifetime_over_100d)));
console.log('\nPROVIDERS (share of domains; top 5 per role)');
for (const role of ['mail', 'dns', 'web', 'sending', 'issuer', 'reports']) {
  const s = providerSection[role];
  const top5 = Object.entries(s.providers_pct).slice(0, 5).map(([k, v]) => `${k} ${v}`).join(' · ');
  console.log(`  ${role.padEnd(8)} n=${String(s.n).padEnd(5)} ${top5} | unrecognised ${s.unrecognised_pct}%${s.behind_cdn_or_proxy_pct !== undefined ? ` | behind CDN ${s.behind_cdn_or_proxy_pct}%` : ''}`);
}
console.log(`  US provider for mail, DNS or web (lower bound): ${pc(providerSection.us_dependency_mail_dns_or_web)}% of mail domains`);
console.log(`EXTRAS ${Object.entries(extrasSection).map(([k, v]) => `${k} ${pc(v)}`).join(' · ')}`);
