/*
 * The HTTPS check shared by scan-cc-security.mjs (the server run) and
 * recheck-https.mjs (the second vantage point), so both apply exactly the same
 * rule: one TLS handshake, no HTTP request, verified against Node's bundled
 * (Mozilla-derived) root store.
 *
 * The address comes from the caller's DNS-over-HTTPS lookup, never from the
 * operating system's resolver: the result must not depend on the machine's
 * network (a router that rewrites answers, a local service on 127.0.0.1, a
 * resolver that does or does not validate DNSSEC). Loopback, private,
 * link-local and similar addresses are never contacted.
 */
import tls from 'node:tls';
import { isIP } from 'node:net';

/** IPv6 address → its eight 16-bit groups (handles `::` and a trailing dotted IPv4). */
function v6groups(ip) {
  let x = ip.toLowerCase();
  const v4 = x.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const [a, b, c, d] = v4[1].split('.').map(Number);
    x = x.slice(0, -v4[1].length) + `${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head, tail] = x.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
  const fill = tail !== undefined ? Array(8 - h.length - t.length).fill('0') : [];
  return [...h, ...fill, ...t].map((g) => parseInt(g || '0', 16));
}

/**
 * True for addresses that are not ordinary public unicast (RFC 6890 special-
 * purpose registries): never contacted by the scanner.
 */
export function isPrivateAddress(ip) {
  if (isIP(ip) === 4) {
    const [a, b, c] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224
      || (a === 100 && b >= 64 && b <= 127) // shared address space (CGNAT)
      || (a === 169 && b === 254) // link-local
      || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && b === 168)
      || (a === 192 && b === 0 && (c === 0 || c === 2)) // IETF protocol assignments, TEST-NET-1
      || (a === 198 && (b === 18 || b === 19)) // benchmarking
      || (a === 198 && b === 51 && c === 100) // TEST-NET-2
      || (a === 203 && b === 0 && c === 113) // TEST-NET-3
      || (a === 192 && b === 88 && c === 99); // 6to4 relay anycast (deprecated)
  }
  if (isIP(ip) === 6) {
    const g = v6groups(ip);
    if (g.length !== 8 || g.some((n) => Number.isNaN(n))) return true;
    const zeroUpTo = (k) => g.slice(0, k).every((n) => n === 0);
    return zeroUpTo(8) // ::
      || (zeroUpTo(7) && g[7] === 1) // ::1
      || zeroUpTo(6) // ::a.b.c.d (IPv4-compatible, deprecated)
      || (zeroUpTo(5) && g[5] === 0xffff) // ::ffff:a.b.c.d (IPv4-mapped)
      || (g[0] === 0x64 && g[1] === 0xff9b) // 64:ff9b::/96 NAT64
      || (g[0] & 0xfe00) === 0xfc00 // fc00::/7 unique local
      || (g[0] & 0xffc0) === 0xfe80 // fe80::/10 link-local
      || (g[0] & 0xff00) === 0xff00 // multicast
      || (g[0] === 0x2001 && g[1] === 0x0db8) // documentation
      || (g[0] & 0xfff0) === 0x3ff0 // 3fff::/20 documentation (RFC 9637)
      || (g[0] === 0x0100 && g[1] === 0 && g[2] === 0 && g[3] === 0) // 100::/64 discard
      || (g[0] === 0x2001 && g[1] === 0x0002 && g[2] === 0) // 2001:2::/48 benchmarking
      || (g[0] === 0x2001 && (g[1] & 0xfff0) === 0x0010); // 2001:10::/28 ORCHID
  }
  return true;
}

const ABSOLUTE_MS = 10_000;

/** One TLS handshake to ip:443 with SNI `host`. Never rejects; failures come back as { ok: false, error }. */
export function handshake(host, ip) {
  return new Promise((resolve) => {
    let finished = false;
    const socket = tls.connect({ host: ip, port: 443, servername: host, rejectUnauthorized: false, timeout: 8000 });
    // `timeout` above only fires on inactivity; a server that trickles bytes
    // would hold the worker forever without this absolute limit.
    const timer = setTimeout(() => done({ host, ip, ok: false, error: 'timeout' }), ABSOLUTE_MS);
    function done(r) {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(r);
    }
    socket.once('secureConnect', () => {
      const c = socket.getPeerCertificate();
      if (!c || !c.valid_to) return done({ host, ip, ok: false, error: 'no-certificate' });
      const from = Date.parse(c.valid_from);
      const to = Date.parse(c.valid_to);
      done({
        host,
        ip,
        ok: true,
        authorized: socket.authorized,
        error: socket.authorized ? null : String(socket.authorizationError ?? 'unauthorized'),
        issuer: c.issuer?.O ?? c.issuer?.CN ?? null,
        lifetime_days: Math.round((to - from) / 86_400_000),
        days_left: Math.floor((to - Date.now()) / 86_400_000),
      });
    });
    socket.once('timeout', () => done({ host, ip, ok: false, error: 'timeout' }));
    socket.once('error', (e) => done({ host, ip, ok: false, error: e.code ?? 'error' }));
  });
}

/**
 * Handshake with a name: its first IPv4 address, or its first IPv6 address
 * when it has no IPv4. `resolve(name, 'A' | 'AAAA')` → address strings (may throw).
 */
async function handshakeName(host, resolve) {
  let ip;
  try {
    ip = (await resolve(host, 'A'))[0] ?? (await resolve(host, 'AAAA'))[0];
  } catch {
    return { host, ok: false, error: 'dns-error' };
  }
  if (!ip) return { host, ok: false, error: 'no-address' };
  if (isPrivateAddress(ip)) return { host, ip, ok: false, error: 'private-address' };
  return handshake(host, ip);
}

/**
 * The bare domain first; www.<domain> when the bare one does not complete a
 * handshake or serves a certificate that fails (often a hosting default on the
 * bare name while the site itself lives on www, where visitors land).
 */
export async function httpsCheck(domain, resolve) {
  const apex = await handshakeName(domain, resolve);
  if (apex.ok && apex.authorized) return { ...apex, via: 'apex' };
  const www = await handshakeName(`www.${domain}`, resolve);
  if (www.ok && (www.authorized || !apex.ok)) return { ...www, via: 'www' };
  return apex.ok ? { ...apex, via: 'apex' } : { ...apex, via: 'none', www_error: www.error };
}
