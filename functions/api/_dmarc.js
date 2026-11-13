/*
 * DMARC analysis: read the policy, and say what it actually does.
 *
 * A DMARC record is short enough that most checkers stop at "valid syntax",
 * which is close to useless — nearly every published record is syntactically
 * fine and doing nothing. The things that decide whether it protects anything
 * are elsewhere:
 *
 *   - `p=none` is monitoring, not protection. It is the right place to start
 *     and the wrong place to stay, and a domain sits there for years because
 *     nothing ever tells it otherwise.
 *   - `pct=` silently applies the policy to a fraction of mail.
 *   - a `rua` address at another domain does nothing unless THAT domain
 *     publishes an authorisation record naming yours. This is the one almost
 *     nobody checks, and its failure mode is silence: no error, no reports, and
 *     the owner concludes nobody is forging them.
 *   - DMARC passes on SPF or DKIM alignment, so a policy with neither
 *     underneath it fails everything it is asked about.
 *
 * Resolver injected, no I/O here — same contract as _spf.js.
 */

const POLICIES = new Set(['none', 'quarantine', 'reject']);
// RFC 7489, plus DMARCbis's np/psd/t so a record already written for the
// update is not called broken.
const KNOWN_TAGS = new Set(['v', 'p', 'sp', 'rua', 'ruf', 'pct', 'adkim', 'aspf', 'fo', 'ri', 'rf', 'np', 'psd', 't']);
const TAG_LIST = [...KNOWN_TAGS];

function distance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
    }
  }
  return d[a.length][b.length];
}

/** The tag an unknown name was probably meant to be (`rau` → `rua`), or null. */
export function closestTag(name) {
  if (name.length < 2) return null;
  const best = TAG_LIST.map((t) => ({ t, d: distance(name, t) })).filter((x) => x.d <= (name.length > 3 ? 2 : 1) && x.d < name.length)
    .sort((a, b) => a.d - b.d || b.t.length - a.t.length);
  return best.length && (best.length === 1 || best[0].d < best[1].d) ? best[0].t : null;
}

/*
 * Who reads the reports, when it is a service built for it. Matched on the
 * reporting address's domain; anything else is shown as itself.
 */
const REPORT_SERVICES = [
  [/(^|\.)dmarcian\.(com|eu)$/, 'dmarcian'],
  [/(^|\.)dmarc\.postmarkapp\.com$/, 'Postmark'],
  [/(^|\.)vali\.email$/, 'Valimail'],
  [/(^|\.)easydmarc\.(com|eu|us|co)$/, 'EasyDMARC'],
  [/(^|\.)powerdmarc\.com$/, 'PowerDMARC'],
  [/(^|\.)ondmarc\.com$/, 'Red Sift OnDMARC'],
  [/(^|\.)uriports\.com$/, 'URIports'],
  [/(^|\.)dmarc-reports\.cloudflare\.net$/, 'Cloudflare'],
  [/(^|\.)agari\.com$/, 'Agari'],
  [/(^|\.)emaildefense\.proofpoint\.com$/, 'Proofpoint'],
];
export function reportService(domain) {
  return REPORT_SERVICES.find(([re]) => re.test(String(domain).toLowerCase()))?.[1] ?? null;
}

/** `v=DMARC1; p=none; rua=mailto:a@b` → { v: 'DMARC1', p: 'none', … } */
function parseTags(record) {
  const tags = {};
  const order = [];
  // A missing `;` (`p=reject rua=…`) is read apart here, so the rest of the
  // analysis sees what was meant; `glued` lets the caller still report it.
  let glued = null;
  for (const part of record.split(';').flatMap((x) => {
    const pieces = x.trim().split(/\s+(?=[a-z]{1,5}=)/i);
    if (pieces.length > 1) glued ??= x.trim();
    return pieces;
  })) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf('=');
    if (eq < 1) {
      order.push({ name: trimmed, value: '', malformed: true });
      continue;
    }
    const name = trimmed.slice(0, eq).trim().toLowerCase();
    const value = trimmed.slice(eq + 1).trim();
    tags[name] = value;
    order.push({ name, value });
  }
  return { tags, order, glued };
}

/** The domains a report address points at, deduplicated, in order. */
function reportDomains(value) {
  return [
    ...new Set(
      (value || '')
        .split(',')
        .map((uri) => uri.trim().replace(/!\d+[kmgt]?$/i, '')) // strip the size limit
        .filter((uri) => /^mailto:/i.test(uri))
        .map((uri) => uri.slice(7).split('@')[1]?.toLowerCase())
        .filter(Boolean),
    ),
  ];
}

/** Is `sub` the same as, or below, `domain`? */
const isSameOrBelow = (sub, domain) => sub === domain || sub.endsWith(`.${domain}`);

/**
 * RFC 7489 §7.1: to accept reports for another domain, the receiving domain
 * must publish `<sender>._report._dmarc.<receiver>` carrying a DMARC record.
 * Without it, conforming reporters send nothing at all.
 */
async function externalAuthorised(sender, receiver, resolveTxt) {
  try {
    const records = await resolveTxt(`${sender}._report._dmarc.${receiver}`);
    return records.some((r) => /^v=DMARC1\b/i.test(r.trim()));
  } catch {
    return null; // could not tell, which is not the same as "no"
  }
}

/**
 * @param {string} domain
 * @param {(name: string) => Promise<string[]>} resolveTxt
 * @param {{ hasSpf?: boolean|null }} [context]
 */
export async function analyseDmarc(domain, resolveTxt, context = {}) {
  const findings = [];
  const add = (code, severity, data) => findings.push({ code, severity, ...(data ? { data } : {}) });

  let txt;
  try {
    txt = await resolveTxt(`_dmarc.${domain}`);
  } catch {
    add('dns-error', 'error', { domain });
    return { domain, found: false, findings, verdict: 'error' };
  }

  const records = (txt ?? []).filter((r) => /^v=DMARC1\b/i.test(r.trim()));
  if (!records.length) {
    // A subdomain without a record of its own is covered by its organisational
    // domain's record, under `sp=` (RFC 7489 §6.6.3). Reporting that as "no
    // DMARC" would be a false alarm on every mail.example.com.
    if (context.orgDomain && context.orgDomain !== domain) {
      const org = await analyseDmarc(context.orgDomain, resolveTxt, { ...context, orgDomain: null, asSubdomain: true });
      if (org.found) return { ...org, domain, inherited: { from: context.orgDomain } };
    }
    add('no-record', 'error', { domain });
    return { domain, found: false, findings, verdict: 'error' };
  }
  if (records.length > 1) {
    // Same rule as SPF, same consequence: receivers discard the lot rather
    // than choosing, so the domain ends up with no policy at all.
    add('multiple-records', 'error', { count: records.length });
    return { domain, found: true, records, findings, verdict: 'error' };
  }

  // Trimmed for parsing, but characters are checked on the record as published:
  // a trailing non-breaking space is invisible here and still breaks the record
  // for a strict receiver.
  const rawRecord = records[0];
  const record = rawRecord.trim();
  const { tags, order, glued: gluedAt } = parseTags(record);

  // --- characters and separators. A curly quote or a non-breaking space
  //     pasted from a document, or a missing `;` (`p=reject rua=…` reads as
  //     the policy "reject rua=…"), and the record says something else.
  // Tab is allowed: DMARC's grammar permits WSP (space or tab) between tags.
  const odd = [...new Set(rawRecord.match(/[^\x09\x20-\x7e]/g) ?? [])];
  if (odd.length) add('bad-characters', 'error', { chars: odd.map((c) => `U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`).join(', ') });
  if (gluedAt) add('missing-semicolon', 'error', { at: gluedAt });

  // --- structure
  if (order[0]?.name !== 'v') add('v-not-first', 'error');
  const policy = (tags.p || '').toLowerCase();
  if (!policy) add('no-policy', 'error');
  else if (!POLICIES.has(policy)) add('bad-policy', 'error', { value: tags.p });

  const unknownTags = order.filter((t) => t.malformed || !KNOWN_TAGS.has(t.name));
  const typos = unknownTags.map((t) => ({ name: t.name, fix: t.malformed ? null : closestTag(t.name) })).filter((x) => x.fix);
  if (typos.length) {
    add('tag-typo', 'warning', { fixes: typos.map((x) => `\`${x.name}=\` → \`${x.fix}=\``).join(', '), typos });
  }
  const unknown = unknownTags.filter((t) => !typos.some((x) => x.name === t.name)).map((t) => t.name);
  if (unknown.length) add('unknown-tag', 'warning', { tags: unknown.slice(0, 4).join(', ') });

  // --- what the policy actually asks for. Checked as a subdomain, what
  //     applies is `sp=` when there is one.
  const spRaw = (tags.sp || '').toLowerCase();
  const effective = context.asSubdomain && POLICIES.has(spRaw) ? spRaw : policy;
  if (context.asSubdomain && effective !== policy) {
    if (effective === 'none') add('policy-none', 'warning');
    else add(`policy-${effective}`, 'ok');
  } else if (policy === 'none') add('policy-none', 'warning');
  else if (policy === 'quarantine') add('policy-quarantine', 'ok');
  else if (policy === 'reject') add('policy-reject', 'ok');

  // Only 0-100 written as plain digits is a pct: `pct=` (empty), `pct=1e2` or
  // `pct=50%` would otherwise read as numbers no receiver agrees on.
  const pct = tags.pct === undefined ? 100 : /^\d{1,3}$/.test(tags.pct.trim()) ? Number(tags.pct) : NaN;
  if (tags.pct !== undefined && (!Number.isFinite(pct) || pct < 0 || pct > 100)) {
    add('bad-pct', 'error', { value: tags.pct });
  } else if (pct < 100 && policy !== 'none') {
    add('partial-pct', 'warning', { pct });
  }

  const sp = (tags.sp || '').toLowerCase();
  if (sp && !POLICIES.has(sp)) add('bad-subdomain-policy', 'error', { value: tags.sp });
  else if (sp === 'none' && policy !== 'none' && !context.asSubdomain) add('subdomain-exempt', 'warning');

  // --- reporting
  const rua = reportDomains(tags.rua);
  // A misspelled `rua` is reported as the typo it is, not as a missing address.
  if (!tags.rua && !typos.some((x) => x.fix === 'rua')) add('no-rua', 'warning');
  else if (tags.rua && !rua.length) add('bad-rua', 'error', { value: tags.rua });

  const external = [];
  for (const target of rua) {
    if (isSameOrBelow(target, domain)) continue;
    const ok = await externalAuthorised(domain, target, resolveTxt);
    external.push({ domain: target, authorised: ok });
    if (ok === false) add('rua-unauthorised', 'error', { target, domain });
  }

  // --- what DMARC has to work with
  // Not for a subdomain read through its parent's record: whether that
  // subdomain sends mail at all is unknown, and one that does not needs no SPF.
  if (context.hasSpf === false && !context.asSubdomain) add('no-spf', 'error', { domain });

  const alignment = {
    spf: (tags.aspf || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed',
    dkim: (tags.adkim || 'r').toLowerCase() === 's' ? 'strict' : 'relaxed',
  };

  if (!findings.some((f) => f.severity === 'error' || f.severity === 'warning')) {
    add('all-clear', 'ok', { policy });
  }

  const rank = { error: 0, warning: 1, info: 2, ok: 3 };
  const verdict = findings.some((f) => f.severity === 'error')
    ? 'error'
    : findings.some((f) => f.severity === 'warning')
      ? 'warning'
      : 'ok';

  return {
    domain,
    found: true,
    record,
    verdict,
    policy: policy || null,
    effectivePolicy: effective || null,
    subdomainPolicy: sp || null,
    pct,
    alignment,
    rua: tags.rua ? tags.rua.split(',').map((s) => s.trim()) : [],
    ruf: tags.ruf ? tags.ruf.split(',').map((s) => s.trim()) : [],
    external,
    tags: order.filter((t) => !t.malformed),
    findings: findings.sort((a, b) => rank[a.severity] - rank[b.severity]),
  };
}
