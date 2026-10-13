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
  'content-security-policy': "default-src 'self'",
  'x-frame-options': 'DENY',
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=()',
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

module.exports = { HEADER_VALUES, finding, fetchSafe, sanitizeAuth, withAuth };
