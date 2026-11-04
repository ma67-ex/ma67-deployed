// Shared HTTP helpers for every check module. Authenticated scans work by
// storing session headers in an AsyncLocalStorage context for the duration of
// one scan; fetchSafe attaches them ONLY to requests that go to the scanned
// origin, so a Cookie/Authorization header can never leak to OSV, Supabase,
// Firestore or any other third party a check happens to call.
const { AsyncLocalStorage } = require('async_hooks');
const dns = require('dns').promises;
const net = require('net');

const authStore = new AsyncLocalStorage();

// Values we recommend per header, shared by the header check, the grader and
// the patch generator so the three never drift apart.
const HEADER_VALUES = {
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'x-content-type-options': 'nosniff',
};

function finding(id, title, severity, evidence, fix) {
  return { id, title, severity, evidence, fix };
}

// SSRF guard: a scan must never reach loopback, LAN, link-local or cloud-metadata addresses unless the
// target is literally localhost (see isLocalHost). Checked on every request, so redirects and hostnames
// that resolve to private IPs are covered too.
// ponytail: resolve-then-fetch leaves a small DNS-rebinding window; pin the IP with an undici dispatcher if needed.
function isPrivateIp(ip) {
  ip = String(ip).toLowerCase().replace(/^\[|\]$/g, '');
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) ip = mapped[1];
  const hex = ip.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/); // hex form of IPv4-mapped IPv6
  if (hex) {
    const n = (parseInt(hex[1], 16) << 16) | parseInt(hex[2], 16);
    ip = [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
  }
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 192 && b === 0) || a >= 224;
  }
  if (net.isIPv6(ip)) return ip === '::' || ip === '::1' || /^f[cd]/.test(ip) || /^fe[89ab]/.test(ip);
  return true; // not an IP at all: fail closed
}

// True when hostname is localhost, or resolves only to public addresses.
async function isSafeTarget(hostname) {
  if (isLocalHost(hostname)) return true;
  try {
    const addrs = await dns.lookup(String(hostname).replace(/^\[|\]$/g, ''), { all: true });
    return addrs.length > 0 && addrs.every((a) => !isPrivateIp(a.address));
  } catch {
    return false;
  }
}

async function fetchSafe(url, opts = {}) {
  const auth = authStore.getStore();
  let headers = opts.headers;
  if (auth) {
    try {
      if (new URL(url).origin === auth.origin) headers = { ...auth.headers, ...(opts.headers || {}) };
    } catch { /* unparseable URL: send without auth */ }
  }
  try {
    if (!(await isSafeTarget(new URL(url).hostname))) return null;
    return await fetch(url, {
      redirect: 'manual',
      signal: AbortSignal.timeout(6000),
      ...opts,
      ...(headers ? { headers } : {}),
    });
  } catch {
    return null;
  }
}

// Only Cookie and Authorization are accepted; CR/LF are stripped so a pasted
// value can't smuggle extra headers.
function sanitizeAuth(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const headers = {};
  for (const [key, name] of [['cookie', 'Cookie'], ['authorization', 'Authorization']]) {
    const v = raw[key];
    if (typeof v === 'string' && v.trim()) headers[name] = v.replace(/[\r\n]+/g, ' ').trim().slice(0, 4096);
  }
  return Object.keys(headers).length ? headers : null;
}

function withAuth(origin, headers, fn) {
  if (!headers) return fn();
  return authStore.run({ origin, headers }, fn);
}

// Same-site check for redirect-following below: only treats a redirect as
// "the site moving itself" (http→https, bare domain→www, etc.), never an
// arbitrary third party — a malicious/compromised site could otherwise
// redirect-rebind our scan onto someone else's domain without their
// attestation. "example.com" and "www.example.com" count as the same site;
// anything else doesn't.
function sameSite(hostA, hostB) {
  const strip = (h) => h.replace(/^www\./, '');
  return strip(hostA) === strip(hostB);
}

// Resolves through up to maxHops same-site redirects (http→https, bare→www,
// trailing slash, etc.) and returns the final URL actually reached — or the
// original if there's no redirect or it leaves the site. Checks like
// checkHeaders and friends should run against this, not the raw input URL:
// a bare domain that 301s to https://www.… almost never carries its own
// security headers on the redirect hop itself, which was making every real
// site look identical ("missing CSP/HSTS/..." on nearly everything).
async function resolveFinalUrl(url, maxHops = 5) {
  let current = url;
  const startHost = new URL(url).hostname;
  for (let i = 0; i < maxHops; i++) {
    const res = await fetchSafe(current);
    if (!res || ![301, 302, 303, 307, 308].includes(res.status)) return current;
    const loc = res.headers.get('location');
    if (!loc) return current;
    let next;
    try { next = new URL(loc, current).toString(); } catch { return current; }
    if (!sameSite(startHost, new URL(next).hostname)) return current; // stop before leaving the site
    current = next;
  }
  return current;
}

// The only hosts the attack-simulation checks may touch. 0.0.0.0 is how a local server often reports itself.
const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

// URL.hostname keeps the brackets on an IPv6 literal ("[::1]"), so strip them before comparing, or the IPv6
// loopback address the README promises would never match. Names like localhost.evil.com or 127.0.0.1.nip.io
// are not local and must stay out.
const isLocalHost = (hostname) => LOCAL_HOSTNAMES.has(String(hostname).replace(/^\[|\]$/g, '').toLowerCase());

module.exports = { HEADER_VALUES, finding, fetchSafe, sanitizeAuth, withAuth, resolveFinalUrl, isLocalHost, isPrivateIp, isSafeTarget };
