// Shared HTTP helpers for every check module. Authenticated scans work by
// storing session headers in an AsyncLocalStorage context for the duration of
// one scan; fetchSafe attaches them ONLY to requests that go to the scanned
// origin, so a Cookie/Authorization header can never leak to OSV, Supabase,
// Firestore or any other third party a check happens to call.
const { AsyncLocalStorage } = require('async_hooks');

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

async function fetchSafe(url, opts = {}) {
  const auth = authStore.getStore();
  let headers = opts.headers;
  if (auth) {
    try {
      if (new URL(url).origin === auth.origin) headers = { ...auth.headers, ...(opts.headers || {}) };
    } catch { /* unparseable URL: send without auth */ }
  }
  try {
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

module.exports = { HEADER_VALUES, finding, fetchSafe, sanitizeAuth, withAuth, resolveFinalUrl, isLocalHost };
