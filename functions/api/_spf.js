/*
 * SPF analysis: resolve the record, follow it, and count what it costs.
 *
 * Every SPF checker prints the record back at you. The part that matters and
 * almost nobody shows is the arithmetic: RFC 7208 allows a receiving server ten
 * DNS lookups to evaluate a policy, the budget is shared across every `include`
 * you delegate to, and going over it is a permerror — which receivers treat as
 * "this domain has no SPF at all". A record can therefore be perfectly
 * well-formed, name every sender correctly, and still fail, and the only way to
 * know is to walk the whole tree the way a receiver would.
 *
 * So this follows each include and redirect recursively, attributes the cost to
 * the sender that caused it, and reports the tree. "You are at 13 of 10, and
 * nine of those come from one provider" is a fix; "invalid record" is not.
 *
 * The resolver is injected: DNS-over-HTTPS at the edge in production, a stub in
 * the tests. Nothing here does I/O of its own.
 */

/** RFC 7208 §4.6.4. Ten lookups for the whole evaluation, not per record. */
export const LOOKUP_LIMIT = 10;
/** Lookups that return nothing. More than two is also a permerror. */
export const VOID_LOOKUP_LIMIT = 2;
/** Our own stop, well past anything legitimate, so a loop cannot run away. */
const MAX_TOTAL_QUERIES = 40;
const MAX_DEPTH = 10;

/** Mechanisms that cost a DNS lookup each. `all`, `ip4` and `ip6` are free. */
const COSTLY = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
const FREE = new Set(['all', 'ip4', 'ip6']);

const QUALIFIERS = { '+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral' };

/* ------------------------------------------------- syntax, value by value */

const MECHANISMS = ['all', 'include', 'a', 'mx', 'ptr', 'ip4', 'ip6', 'exists'];

function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      // A swapped pair ("inlcude") is one slip, not two.
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** The mechanism an unknown name was probably meant to be, or null when it is not clear. */
export function closestMechanism(name, value = '') {
  if (name === 'ip') return value.includes(':') ? 'ip6' : 'ip4';
  const scored = MECHANISMS.map((m) => ({ m, d: distance(name, m) })).filter((x) => x.d <= 2 && x.d < Math.max(name.length, 2));
  if (!scored.length) return null;
  scored.sort((x, y) => x.d - y.d || y.m.length - x.m.length);
  return scored[0].m;
}

export function validIp4(v) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(v);
  if (!m) return false;
  if (m.slice(1, 5).some((o) => Number(o) > 255)) return false;
  return m[5] === undefined || Number(m[5]) <= 32;
}

export function validIp6(v) {
  const [addr, len, ...rest] = String(v).split('/');
  if (rest.length || !addr.includes(':')) return false;
  if (len !== undefined && !(/^\d{1,3}$/.test(len) && Number(len) <= 128)) return false;
  try {
    new URL(`http://[${addr}]/`);
    return true;
  } catch {
    return false;
  }
}

/** Ranges that never appear on the public internet: in SPF they authorise nobody. */
function privateIp(name, v) {
  if (name === 'ip4') return /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v);
  return /^(f[cd][0-9a-f]{2}:|::1(\/|$))/i.test(v);
}

/** Split a record into terms, keeping each one's qualifier, name and value. */
function parseTerms(record) {
  return record
    .split(/\s+/)
    .slice(1) // drop the v=spf1 version token
    .filter(Boolean)
    .map((raw) => {
      // RFC 7208 §12: a modifier name may contain dots, dashes and underscores.
      const modifier = raw.match(/^([a-z][a-z0-9_.-]*)=(.*)$/i);
      if (modifier) return { raw, kind: 'modifier', name: modifier[1].toLowerCase(), value: modifier[2] };

      const q = QUALIFIERS[raw[0]] ? raw[0] : '+';
      const body = QUALIFIERS[raw[0]] ? raw.slice(1) : raw;
      const [name, ...rest] = body.split(':');
      return {
        raw,
        kind: 'mechanism',
        qualifier: q,
        name: (name || '').toLowerCase().split('/')[0],
        value: rest.join(':'),
      };
    });
}

/** The SPF record published at a name, if there is exactly one. */
async function recordFor(domain, resolveTxt, state) {
  if (state.queries >= MAX_TOTAL_QUERIES) return { error: 'query-budget' };
  state.queries++;
  let txt;
  try {
    txt = await resolveTxt(domain);
  } catch {
    return { error: 'dns-error' };
  }
  const records = (txt ?? []).filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  // `empty`: no TXT at all. Only that is a void lookup (RFC 7208 §4.6.4); a
  // name with other TXT records but no SPF is include-missing, not void.
  if (!records.length) return { error: 'no-record', empty: !(txt ?? []).length };
  if (records.length > 1) return { error: 'multiple-records', records };
  return { record: records[0].trim() };
}

/**
 * Walk one record, counting lookups against the shared budget in `state`.
 * Returns the node for the tree the UI draws.
 */
async function walk(domain, record, resolveTxt, state, depth, path = new Set([domain])) {
  const terms = parseTerms(record);
  const node = { domain, record, lookups: 0, children: [], problems: [] };

  for (const term of terms) {
    if (term.kind === 'modifier') {
      // `redirect` is followed only when no `all` is present, which is what a
      // receiver does — an `all` earlier in the record ends evaluation first.
      if (term.name === 'redirect' && !terms.some((t) => t.name === 'all')) {
        state.lookups++;
        node.lookups++;
        const child = await follow(term.value, resolveTxt, state, depth, 'redirect', path);
        if (child) node.children.push(child);
      }
      continue;
    }

    if (term.name === 'ptr') node.problems.push({ code: 'ptr-used', term: term.raw });
    if (!COSTLY.has(term.name) && !FREE.has(term.name)) {
      node.problems.push({ code: 'unknown-term', term: term.raw });
      continue;
    }
    if (!COSTLY.has(term.name)) continue;

    state.lookups++;
    node.lookups++;

    if (term.name === 'include') {
      const child = await follow(term.value, resolveTxt, state, depth, 'include', path);
      if (child) node.children.push(child);
    } else if (term.name === 'a' || term.name === 'mx') {
      // Not followed further — an `a` or `mx` costs exactly one lookup and
      // cannot nest. Whether it resolves is the sender's business, not SPF's.
      // A macro name (`a:%{i}._spf.example`) is only known per message: never a void candidate.
      if (!(term.value || '').includes('%{')) state.voidCandidates.push({ name: (term.value || domain).split('/')[0], kind: term.name });
    }
  }
  return node;
}

async function follow(target, resolveTxt, state, depth, via, path) {
  if (!target) return null;
  const name = target.toLowerCase().replace(/\.$/, '');
  if (depth >= MAX_DEPTH) return { domain: name, via, error: 'too-deep', lookups: 0, children: [], problems: [] };
  // A domain that includes itself, directly or round a ring, is a real record
  // people publish by accident; it has to stop rather than recurse. Only the
  // chain that led here counts: two senders that both include the same record
  // (Microsoft and a CRM both pulling in one provider, say) is not a loop, and
  // a receiver evaluates — and charges a lookup for — each of them.
  if (path.has(name)) {
    return { domain: name, via, error: 'loop', lookups: 0, children: [], problems: [] };
  }
  // A macro target (`include:%{ir}.%{v}.%{d}.spf.has.pphosted.com`) is only
  // known once real mail arrives — it is built from the sender's IP and
  // address. It costs its one lookup (already counted) and cannot be followed
  // or judged beforehand: not an error, not a missing include.
  if (name.includes('%{')) {
    return { domain: name, via, error: 'macro', lookups: 0, children: [], problems: [] };
  }

  const found = await recordFor(name, resolveTxt, state);
  if (found.error) {
    if (found.error === 'no-record' && found.empty) state.voidLookups++;
    return { domain: name, via, error: found.error, lookups: 0, children: [], problems: [] };
  }
  const child = await walk(name, found.record, resolveTxt, state, depth + 1, new Set([...path, name]));
  child.via = via;
  return child;
}

/** Every node of the tree, flattened — for totals and for the UI's list. */
function flatten(node, out = []) {
  out.push(node);
  for (const c of node.children ?? []) flatten(c, out);
  return out;
}

/**
 * @param {string} domain
 * @param {(name: string) => Promise<string[]>} resolveTxt
 */
/**
 * @param {string} domain
 * @param {(name: string) => Promise<string[]>} resolveTxt
 * @param {{ record?: string }} [opts] analyse this record instead of the
 *   published one — used by the generator to cost a record before it exists,
 *   which is the only moment the lookup budget can still be changed cheaply.
 */
export async function analyseSpf(domain, resolveTxt, opts = {}) {
  const state = { lookups: 0, queries: 0, voidLookups: 0, voidCandidates: [] };
  const findings = [];
  const add = (code, severity, data) => findings.push({ code, severity, ...(data ? { data } : {}) });

  const root = opts.record ? { record: opts.record.trim() } : await recordFor(domain, resolveTxt, state);
  if (root.error === 'no-record') {
    add('no-record', 'error', { domain });
    return { domain, found: false, findings, lookups: 0, limit: LOOKUP_LIMIT };
  }
  if (root.error === 'multiple-records') {
    // Fatal and worth stopping on: with two records a receiver evaluates
    // neither, so analysing one of them would describe a policy nobody applies.
    add('multiple-records', 'error', { count: root.records.length, records: root.records });
    return { domain, found: true, records: root.records, findings, lookups: 0, limit: LOOKUP_LIMIT };
  }
  if (root.error) {
    add('dns-error', 'error', { domain });
    return { domain, found: false, findings, lookups: 0, limit: LOOKUP_LIMIT };
  }

  const tree = await walk(domain, root.record, resolveTxt, state, 0);
  const nodes = flatten(tree);

  // `a` and `mx` terms whose name has no address / no MX are void lookups too
  // (RFC 7208 §4.6.4). Counting them needs A and MX lookups, so it only happens
  // when the caller passes `resolveAddr(name, type) → answers[]` (the research
  // scanner does; the tools' own SPF check does not, and keeps its behaviour).
  // A failed lookup is not a void one and is not counted.
  if (opts.resolveAddr) {
    for (const c of state.voidCandidates) {
      try {
        // `a` is void only with no address at all (IPv4 and IPv6), so a name that
        // has only AAAA is not called void for every sender.
        const empty = c.kind === 'mx'
          ? !(await opts.resolveAddr(c.name, 'MX')).length
          : !(await opts.resolveAddr(c.name, 'A')).length && !(await opts.resolveAddr(c.name, 'AAAA')).length;
        if (empty) state.voidLookups++;
      } catch { /* unreadable, not void */ }
    }
  }
  const terms = parseTerms(root.record);

  // --- the arithmetic, which is the reason this tool exists
  if (state.lookups > LOOKUP_LIMIT) {
    const worst = [...(tree.children ?? [])]
      .map((c) => ({ domain: c.domain, cost: flatten(c).reduce((n, x) => n + x.lookups, 0) + 1 }))
      .sort((a, b) => b.cost - a.cost)[0];
    add('lookup-limit-exceeded', 'error', { count: state.lookups, limit: LOOKUP_LIMIT, worst: worst?.domain, worstCost: worst?.cost });
  } else if (state.lookups >= LOOKUP_LIMIT - 2) {
    add('lookup-near-limit', 'warning', { count: state.lookups, limit: LOOKUP_LIMIT });
  }
  if (state.voidLookups > VOID_LOOKUP_LIMIT) {
    add('void-lookups', 'warning', { count: state.voidLookups, limit: VOID_LOOKUP_LIMIT });
  }

  // --- how the record ends, which decides what happens to everyone else
  const all = terms.find((t) => t.name === 'all');
  const redirect = terms.find((t) => t.kind === 'modifier' && t.name === 'redirect');
  if (!all && !redirect) add('no-all', 'warning');
  else if (all) {
    const q = QUALIFIERS[all.qualifier];
    if (q === 'pass') add('plus-all', 'error');
    else if (q === 'neutral') add('neutral-all', 'warning');
    else if (q === 'softfail') add('softfail-all', 'info');
    else add('hardfail-all', 'ok');
  }

  // --- problems gathered while walking
  const broken = nodes.filter((n) => n.error === 'no-record' && n.via);
  if (broken.length) add('include-missing', 'error', { domains: broken.map((n) => n.domain) });
  // An include or redirect target that could not be read: the record cannot be
  // judged, so say so instead of reporting a clean result with a short count.
  const unread = nodes.filter((n) => n.error === 'dns-error' && n.via);
  if (unread.length) add('dns-error', 'error', { domain: unread[0].domain });
  // An include or redirect target that a receiver rejects — two SPF records
  // (RFC 7208 §4.5), or a syntax error in its record (bad address, empty term,
  // invalid characters) — is a permanent error for this record too. Reported
  // per target domain, apart from the errors in this record itself, which the
  // suggestion can fix.
  const nestedSyntax = (n) => {
    const t = parseTerms(n.record).filter((x) => x.kind === 'mechanism');
    return /[^\x20-\x7e]/.test(n.record)
      || t.some((x) => (x.name === 'ip4' && x.value && !validIp4(x.value)) || (x.name === 'ip6' && x.value && !validIp6(x.value)))
      || t.some((x) => (['include', 'exists', 'ip4', 'ip6'].includes(x.name) && !x.value) || (['a', 'mx'].includes(x.name) && /^[-~?+]?[a-z]+:(\/|$)/i.test(x.raw)));
  };
  const invalidTargets = nodes.filter((n) => n.via && (n.error === 'multiple-records' || (n.record && nestedSyntax(n))));
  if (invalidTargets.length) add('include-invalid', 'error', { domains: [...new Set(invalidTargets.map((n) => n.domain))] });
  if (nodes.some((n) => n.error === 'loop')) {
    add('include-loop', 'error', { domain: nodes.find((n) => n.error === 'loop').domain });
  }
  const problems = nodes.flatMap((n) => n.problems ?? []);
  if (problems.some((p) => p.code === 'ptr-used')) add('ptr-used', 'warning');
  // An unknown mechanism is a permerror (RFC 7208 §5), wherever it sits.
  // At the root, the ones with an obvious intended spelling are reported as
  // typos below, with the fix.
  const rootTypos = new Set(terms.filter((t) => t.kind === 'mechanism' && !COSTLY.has(t.name) && !FREE.has(t.name) && closestMechanism(t.name, t.value)).map((t) => t.raw));
  const unknown = problems.filter((p) => p.code === 'unknown-term' && !rootTypos.has(p.term));
  if (unknown.length) add('unknown-term', 'error', { terms: unknown.map((p) => p.term).slice(0, 4) });
  // --- the record's own syntax. Any of these makes receivers return
  //     permerror: the whole record is void, not just the faulty term.
  //     Characters first: a curly quote or a non-breaking space pasted in
  //     from a document is invisible on screen and fatal in DNS.
  const odd = [...new Set(root.record.match(/[^\x20-\x7e]/g) ?? [])];
  if (odd.length) {
    add('bad-characters', 'error', { chars: odd.map((c) => `U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`).join(', ') });
  }
  const mech = terms.filter((t) => t.kind === 'mechanism');
  const typos = mech
    .filter((t) => !COSTLY.has(t.name) && !FREE.has(t.name))
    .map((t) => ({ term: t.raw, fix: closestMechanism(t.name, t.value) }))
    .filter((x) => x.fix);
  if (typos.length) {
    add('typo', 'error', {
      fixes: typos.map((x) => `\`${x.term}\` → \`${x.term.replace(/^([-~?+]?)[^:/]+/, `$1${x.fix}`)}\``).join(', '),
      typos: typos.map((x) => ({ term: x.term, fix: x.fix })),
    });
  }
  // Errors in this record itself (an included record's errors are reported as
  // include-invalid above). Empty `a:` / `mx:` count: a colon with nothing after it.
  const badIp = mech.filter((t) => (t.name === 'ip4' && t.value && !validIp4(t.value)) || (t.name === 'ip6' && t.value && !validIp6(t.value)));
  if (badIp.length) add('bad-ip', 'error', { terms: badIp.map((t) => t.raw) });
  const empty = mech.filter((t) => (['include', 'exists', 'ip4', 'ip6'].includes(t.name) && !t.value)
    || (['a', 'mx'].includes(t.name) && /^[-~?+]?[a-z]+:(\/|$)/i.test(t.raw)));
  if (empty.length) add('empty-value', 'error', { terms: empty.map((t) => t.raw) });
  // Evaluation stops at `all`; anything after it is never read.
  const allAt = terms.findIndex((t) => t.name === 'all' && t.kind === 'mechanism');
  const after = allAt === -1 ? [] : terms.slice(allAt + 1).filter((t) => t.kind === 'mechanism');
  if (after.length) add('after-all', 'warning', { terms: after.map((t) => t.raw) });
  const priv = mech.filter((t) => (t.name === 'ip4' || t.name === 'ip6') && t.value && privateIp(t.name, t.value));
  if (priv.length) add('private-ip', 'info', { terms: priv.map((t) => t.raw) });

  // The same include twice in one record is charged twice and adds nothing.
  const listed = terms.filter((t) => t.name === 'include').map((t) => t.value.toLowerCase());
  const doubled = [...new Set(listed.filter((x, i) => listed.indexOf(x) !== i))];
  if (doubled.length) add('duplicate-include', 'warning', { domains: doubled });

  if (!findings.some((f) => f.severity === 'error' || f.severity === 'warning')) {
    add('all-clear', 'ok', { count: state.lookups, limit: LOOKUP_LIMIT });
  }

  const severity = findings.some((f) => f.severity === 'error')
    ? 'error'
    : findings.some((f) => f.severity === 'warning')
      ? 'warning'
      : 'ok';
  const rank = { error: 0, warning: 1, info: 2, ok: 3 };

  return {
    domain,
    found: true,
    record: root.record,
    verdict: severity,
    lookups: state.lookups,
    limit: LOOKUP_LIMIT,
    voidLookups: state.voidLookups,
    // Every domain the evaluation reaches through include/redirect, at any
    // depth: "is Google's include in here somewhere" is asked of this list.
    includes: [...new Set(nodes.filter((n) => n.via).map((n) => n.domain))],
    senders: (tree.children ?? []).map((c) => ({
      domain: c.domain,
      via: c.via,
      error: c.error ?? null,
      cost: flatten(c).reduce((n, x) => n + x.lookups, 0) + 1,
    })),
    terms: terms.map((t) => ({
      raw: t.raw,
      kind: t.kind,
      name: t.name,
      qualifier: t.kind === 'mechanism' ? QUALIFIERS[t.qualifier] : null,
      cost: t.kind === 'mechanism' && COSTLY.has(t.name) ? 1 : t.name === 'redirect' ? 1 : 0,
    })),
    findings: findings.sort((a, b) => rank[a.severity] - rank[b.severity]),
  };
}
