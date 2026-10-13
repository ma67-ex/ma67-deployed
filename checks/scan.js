// Read-only, non-exploitative checks only. No injection, no auth bypass, no
// brute force. Each check makes a handful of plain GET/OPTIONS requests and
// inspects headers/body — nothing that could harm a target.

const SECURITY_HEADERS = [
  ['content-security-policy', 'Content-Security-Policy', 'Medium', 'Clickjacking / XSS surface is wider without a CSP.'],
  ['x-frame-options', 'X-Frame-Options', 'Medium', 'Page can be framed by any site — clickjacking risk.'],
  ['strict-transport-security', 'Strict-Transport-Security (HSTS)', 'Medium', 'Browser won\'t force HTTPS on repeat visits.'],
  ['x-content-type-options', 'X-Content-Type-Options', 'Low', 'Browser may MIME-sniff responses.'],
  ['referrer-policy', 'Referrer-Policy', 'Low', 'Full URLs (incl. query params) may leak via the Referer header.'],
];

function finding(id, title, severity, evidence, fix) {
  return { id, title, severity, evidence, fix };
}

async function fetchSafe(url, opts = {}) {
  try {
    const res = await fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(6000), ...opts });
    return res;
  } catch {
    return null;
  }
}

async function checkHeaders(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const out = [];
  for (const [header, label, severity, why] of SECURITY_HEADERS) {
    if (!res.headers.get(header)) {
      out.push(finding(`header-${header}`, `Missing ${label}`, severity, why,
        `Add header: ${label}: ${header === 'content-security-policy' ? "default-src 'self'" : header === 'x-frame-options' ? 'DENY' : header === 'strict-transport-security' ? 'max-age=63072000; includeSubDomains' : header === 'x-content-type-options' ? 'nosniff' : 'strict-origin-when-cross-origin'}`));
    }
  }
  return out;
}

async function checkCors(base) {
  const res = await fetchSafe(base, { headers: { Origin: 'https://evil-test.example' } });
  if (!res) return [];
  const acao = res.headers.get('access-control-allow-origin');
  if (acao === '*') {
    return [finding('cors-wildcard', 'CORS allows wildcard origin', 'High',
      'Access-Control-Allow-Origin: * on a response that may carry credentials.',
      'Reflect a trusted allow-list instead of "*": set Access-Control-Allow-Origin to the request Origin only if it matches config.TRUSTED_DOMAINS.')];
  }
  return [];
}

async function checkExposedFiles(base) {
  const targets = [
    ['/.env', 'Env Leak', 'Critical', '.env file publicly accessible', (t) => /=/.test(t) && t.length < 20000],
    ['/.git/config', 'Source Control Exposed', 'Critical', '.git directory is served', (t) => t.includes('[core]') || t.includes('repositoryformatversion')],
    ['/.git/HEAD', 'Source Control Exposed', 'Critical', '.git/HEAD is served', (t) => t.startsWith('ref:')],
  ];
  const out = [];
  for (const [path, title, severity, desc, isReal] of targets) {
    const res = await fetchSafe(base + path);
    if (res && res.status === 200) {
      const text = await res.text().catch(() => '');
      if (isReal(text)) {
        out.push(finding(`exposed-${path}`, title, severity, `${desc} at ${path}`,
          'Block the path at the web server / reverse proxy, remove it from the deploy artifact, and rotate any leaked secrets immediately.'));
      }
    }
  }
  return out;
}

async function checkCookies(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const cookies = typeof res.headers.getSetCookie === 'function'
    ? res.headers.getSetCookie()
    : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []);
  const out = [];
  for (const c of cookies) {
    const lc = c.toLowerCase();
    const missing = [];
    if (!lc.includes('httponly')) missing.push('HttpOnly');
    if (!lc.includes('secure')) missing.push('Secure');
    if (!lc.includes('samesite')) missing.push('SameSite');
    if (missing.length) {
      out.push(finding('cookie-flags', 'Cookie missing security flags', 'Medium',
        `${c.split('=')[0]} is missing: ${missing.join(', ')}`,
        'Set cookies with HttpOnly; Secure; SameSite=Lax (or Strict) to reduce theft/CSRF risk.'));
      break; // one finding is enough, avoid spam
    }
  }
  return out;
}

async function checkRobots(base) {
  const res = await fetchSafe(base + '/robots.txt');
  if (!res || res.status !== 200) return [];
  const text = await res.text().catch(() => '');
  const disallows = [...text.matchAll(/Disallow:\s*(\S+)/gi)].map((m) => m[1]).filter((p) => p && p !== '/');
  const interesting = disallows.filter((p) => /admin|internal|debug|api|dashboard|private/i.test(p));
  if (interesting.length) {
    return [finding('robots-leak', 'robots.txt reveals sensitive routes', 'Low',
      `Disallowed (but publicly listed) paths: ${interesting.slice(0, 6).join(', ')}`,
      'Rely on auth, not robots.txt, to hide sensitive routes — robots.txt is advisory and fully public.')];
  }
  return [];
}

async function checkMethods(base) {
  const res = await fetchSafe(base, { method: 'OPTIONS' });
  if (!res) return [];
  const allow = res.headers.get('allow');
  if (allow && /PUT|DELETE/i.test(allow)) {
    return [finding('http-methods', 'Unexpected HTTP methods exposed', 'Low',
      `Allow: ${allow}`,
      'Restrict allowed methods per-route at the router/middleware level; return 405 for anything unused.')];
  }
  return [];
}

async function checkSourceMaps(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const html = await res.text().catch(() => '');
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+\.js)["']/gi)].map((m) => m[1]).slice(0, 5);
  for (let src of scripts) {
    if (!/^https?:/.test(src)) src = new URL(src, base).toString();
    const mapRes = await fetchSafe(src + '.map');
    if (mapRes && mapRes.status === 200) {
      return [finding('source-map', 'Source map publicly accessible', 'Medium',
        `${src}.map is served — original source is reconstructable.`,
        'Disable source map generation for production builds, or restrict .map files at the web server.')];
    }
  }
  return [];
}

async function checkRateLimit(base) {
  const N = 30; // enough to trip a typical ~20/10s limiter without being abusive
  const results = await Promise.all(Array.from({ length: N }, () => fetchSafe(base)));
  const got429 = results.some((r) => r && r.status === 429);
  if (!got429) {
    return [finding('rate-limit', 'No rate limiting observed', 'Low',
      `${N} rapid requests, no 429 response seen (low-signal check, not exhaustive).`,
      'Add rate limiting (e.g. token bucket per IP/user) on auth and write endpoints.')];
  }
  return [];
}

const CHECK_LIST = [
  ['Security Headers', checkHeaders],
  ['CORS Config', checkCors],
  ['Exposed Files', checkExposedFiles],
  ['Cookie Audit', checkCookies],
  ['Robots/Sitemap', checkRobots],
  ['HTTP Methods', checkMethods],
  ['Source Maps', checkSourceMaps],
  // These five were originally misfiled under AGGRESSIVE_CHECK_LIST even
  // though none of them send an attack payload — they only read what's
  // already public (homepage HTML, a JS bundle, package.json). That bug
  // meant they silently never ran against any public target, which is why
  // public scans looked thin/repetitive.
  ['Dependency Scan', checkDependencyExposure],
  ['Data Exposure', checkDataExposure],
  ['CSRF', checkCsrf],
  ['Upload Probe', checkUploadProbe],
  ['LocalStorage', checkLocalStorageUsage],
  // Rate Limiting moved to AGGRESSIVE_CHECK_LIST (localhost-only) — it's an
  // unreliable signal against real third-party sites (default fetch
  // multiplexes the burst over one kept-alive connection so real limits
  // never trip; forcing fresh connections instead just triggers generic
  // bot-blocking, not a real rate-limit signal) and bursting a site you
  // don't control with 30 requests to find out is borderline abusive
  // regardless of what it returns.
];

// ---------------------------------------------------------------------------
// Attack-simulation modules. These send malicious-shaped payloads (injection
// strings, bypass headers, unsigned webhooks) and are only ever invoked by
// the server for literal localhost targets — see server.js's isLiteralLocal
// gate, which an "I own this domain" attestation cannot override. Each one
// stays read/probe-only: no writes, no destructive payloads, bounded request
// counts, short timeouts.
// ---------------------------------------------------------------------------

const PROTECTED_PATH_GUESSES = ['/admin', '/api/admin', '/dashboard', '/api/users', '/api/account'];
const LOGIN_PATH_GUESSES = ['/api/login', '/api/auth/login', '/login', '/api/auth/signin'];
const WEBHOOK_PATH_GUESSES = ['/api/webhooks/stripe', '/api/webhook', '/webhook', '/api/webhooks'];

async function checkSqlInjection(base) {
  const probes = [
    base + `/?id=${encodeURIComponent("1' OR '1'='1")}`,
    base + `/api/search?q=${encodeURIComponent("' OR 1=1 --")}`,
  ];
  const sig = /SQL syntax|mysql_fetch|ORA-\d{5}|SQLite3::|PG::SyntaxError|SequelizeDatabaseError|sqlite_master/i;
  for (const url of probes) {
    const res = await fetchSafe(url);
    if (!res) continue;
    const text = await res.text().catch(() => '');
    if (sig.test(text)) {
      return [finding('sql-injection', 'SQL error disclosed via injection probe', 'Critical',
        `${url.replace(base, '')} returned a database error signature when sent a quote-breaking payload.`,
        'Use parameterized queries / an ORM everywhere — never string-concatenate user input into SQL. Add a generic error handler that never returns raw DB error text.')];
    }
  }
  return [];
}

async function checkNoSqlInjection(base) {
  const payload = JSON.stringify({ username: { $gt: '' }, password: { $gt: '' } });
  for (const path of LOGIN_PATH_GUESSES) {
    const res = await fetchSafe(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload });
    if (!res) continue;
    if (res.status === 200) {
      const text = await res.text().catch(() => '');
      if (/token|success|welcome|authenticated/i.test(text)) {
        return [finding('nosql-injection', 'Possible NoSQL auth bypass via operator injection', 'Critical',
          `${path} returned 200 with a success-looking body for {$gt:""} credentials.`,
          'Reject non-string values for username/password before querying, or use a schema validator (zod/joi) on the request body.')];
      }
    }
  }
  return [];
}

async function checkAuthBypass(base) {
  const bypassHeaders = { 'X-Forwarded-For': '127.0.0.1', 'X-Original-URL': '/', 'X-Rewrite-URL': '/' };
  for (const path of PROTECTED_PATH_GUESSES) {
    const baseline = await fetchSafe(base + path);
    if (!baseline || ![401, 403].includes(baseline.status)) continue;
    const bypass = await fetchSafe(base + path, { headers: bypassHeaders });
    if (bypass && bypass.status === 200) {
      return [finding('auth-bypass', 'Auth bypass via spoofable headers', 'Critical',
        `${path} returns ${baseline.status} normally but 200 with X-Forwarded-For/X-Original-URL set.`,
        'Never trust client-supplied X-Forwarded-For/X-Original-URL for auth decisions — they are fully attacker-controlled unless stripped and re-set by a trusted proxy.')];
    }
  }
  return [];
}

async function checkBrokenAccessControl(base) {
  const res1 = await fetchSafe(base + '/api/users/1');
  const res2 = await fetchSafe(base + '/api/users/2');
  if (res1?.status === 200 && res2?.status === 200) {
    const t1 = await res1.text().catch(() => '');
    if (/email|@/.test(t1)) {
      return [finding('broken-access-control', 'Possible IDOR on /api/users/:id', 'High',
        '/api/users/1 and /api/users/2 both return 200 with user data, no auth required.',
        'Require auth on the route, and check the requester owns/can access that specific :id server-side — never trust the URL alone.')];
    }
  }
  return [];
}

async function checkSupabaseRls(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const html = await res.text().catch(() => '');
  const urlMatch = html.match(/https:\/\/[a-z0-9-]+\.supabase\.co/i);
  const keyMatch = html.match(/eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}/);
  if (!urlMatch || !keyMatch) return [];
  const supaUrl = urlMatch[0];
  const anonKey = keyMatch[0];
  for (const table of ['users', 'profiles', 'accounts']) {
    const r = await fetchSafe(`${supaUrl}/rest/v1/${table}?select=*&limit=1`, { headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` } });
    if (r && r.status === 200) {
      const body = await r.text().catch(() => '');
      if (body.startsWith('[') && body.length > 2) {
        return [finding('supabase-rls', `Supabase table "${table}" readable with anon key`, 'Critical',
          `GET ${supaUrl}/rest/v1/${table} returned rows using the public anon key found in your app's own source.`,
          `Enable Row Level Security on "${table}" and add a policy that restricts rows to the authenticated owner (auth.uid() = owner_id).`)];
      }
    }
  }
  return [];
}

async function checkFirebaseRules(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const html = await res.text().catch(() => '');
  const projectMatch = html.match(/"projectId"\s*:\s*"([a-z0-9-]+)"/i);
  if (!projectMatch) return [];
  const projectId = projectMatch[1];
  const r = await fetchSafe(`https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/users?pageSize=1`);
  if (r && r.status === 200) {
    const body = await r.text().catch(() => '');
    if (body.includes('"documents"')) {
      return [finding('firebase-rules', 'Firestore readable without auth', 'Critical',
        `projects/${projectId}/databases/(default)/documents/users returned data with no auth token.`,
        'Add Firestore security rules requiring request.auth != null (and ownership checks) instead of the default open rules.')];
    }
  }
  return [];
}

async function checkCsrf(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const html = await res.text().catch(() => '');
  const forms = [...html.matchAll(/<form[^>]*method=["']?post["']?[^>]*>([\s\S]*?)<\/form>/gi)];
  for (const [, body] of forms) {
    if (!/csrf|_token|authenticity/i.test(body)) {
      return [finding('csrf', 'POST form without a CSRF token field', 'Medium',
        'A <form method="post"> was found with no csrf/_token hidden field.',
        'Add a per-session CSRF token to state-changing forms, or rely on SameSite=Strict cookies plus origin checking on the server.')];
    }
  }
  return [];
}

async function checkErrorDisclosure(base) {
  const res = await fetchSafe(base + '/api/users/%00');
  if (!res) return [];
  const text = await res.text().catch(() => '');
  if (/at\s+\S+\s+\(.*:\d+:\d+\)|node_modules|Traceback \(most recent|\/Users\/|\/home\//.test(text)) {
    return [finding('error-disclosure', 'Stack trace leaked in error response', 'Medium',
      'A malformed request returned a raw stack trace / file path instead of a generic error.',
      'Catch errors centrally and return a generic JSON message in production; log the real stack server-side only.')];
  }
  return [];
}

async function checkOpenRedirect(base) {
  const marker = 'https://deploysafe-test-marker.invalid';
  for (const param of ['redirect', 'next', 'return', 'url']) {
    const res = await fetchSafe(`${base}/?${param}=${encodeURIComponent(marker)}`);
    if (res && [301, 302, 303, 307, 308].includes(res.status)) {
      const loc = res.headers.get('location') || '';
      if (loc.includes('deploysafe-test-marker.invalid')) {
        return [finding('open-redirect', `Open redirect via ?${param}=`, 'Medium',
          `Server issued a 3xx redirect straight to an attacker-supplied URL via the "${param}" param.`,
          'Validate redirect targets against an allow-list of known paths/domains instead of redirecting to whatever the query param says.')];
      }
    }
  }
  return [];
}

async function checkPathTraversal(base) {
  const probes = [base + '/../../../../etc/passwd', base + '/public/..%2f..%2f..%2fetc%2fpasswd'];
  for (const url of probes) {
    const res = await fetchSafe(url);
    if (!res || res.status !== 200) continue;
    const text = await res.text().catch(() => '');
    if (/root:x:0:0/.test(text)) {
      return [finding('path-traversal', 'Path traversal reads server files', 'Critical',
        `${url.replace(base, '')} returned the contents of /etc/passwd.`,
        'Resolve and validate requested file paths against an allow-listed base directory; reject any path containing ".." after normalization.')];
    }
  }
  return [];
}

// Real CVE lookup via OSV.dev's free batch API (no key needed), capped at 25
// packages so a dependency-heavy app doesn't turn one scan into hundreds of
// outbound requests. Pins (exact versions only) are checked as-is; ranges
// (^, ~, >=, workspace:, etc.) are skipped — OSV needs a concrete version,
// and guessing one would produce false positives/negatives either way.
async function checkDependencyExposure(base) {
  const res = await fetchSafe(base + '/package.json');
  if (!res || res.status !== 200) return [];
  const text = await res.text().catch(() => '');
  let pkg;
  try {
    pkg = JSON.parse(text);
  } catch {
    return [];
  }
  if (!pkg.dependencies && !pkg.devDependencies) return [];

  const out = [finding('dependency-exposure', 'package.json publicly accessible', 'Low',
    'Dependency names and versions are visible at /package.json, making it easier to target known CVEs.',
    'Make sure your build/static server does not serve package.json, package-lock.json, or yarn.lock from the web root.')];

  const all = { ...pkg.dependencies, ...pkg.devDependencies };
  const pinned = Object.entries(all)
    .filter(([, v]) => /^\d+\.\d+\.\d+$/.test(v))
    .slice(0, 25);
  if (!pinned.length) return out;

  try {
    const queries = pinned.map(([name, version]) => ({ package: { name, ecosystem: 'npm' }, version }));
    const osvRes = await fetchSafe('https://api.osv.dev/v1/querybatch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ queries }),
    });
    if (osvRes && osvRes.status === 200) {
      const { results } = await osvRes.json();
      results.forEach((r, i) => {
        if (r.vulns && r.vulns.length) {
          const [name, version] = pinned[i];
          const ids = r.vulns.map((v) => v.id).slice(0, 5).join(', ');
          out.push(finding(`cve-${name}`, `Known vulnerability in ${name}@${version}`, 'High',
            `OSV.dev lists: ${ids}${r.vulns.length > 5 ? ` (+${r.vulns.length - 5} more)` : ''}`,
            `Update ${name} past the affected range (check https://osv.dev/list?q=${encodeURIComponent(name)} for the fixed version), or remove it if unused.`));
        }
      });
    }
  } catch { /* OSV unreachable — keep the exposure finding, skip CVE matching */ }

  return out;
}

async function checkDataExposure(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const text = await res.text().catch(() => '');
  const ssnLike = /\b\d{3}-\d{2}-\d{4}\b/;
  const cardLike = /\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{3,4}\b/; // real card format (4-4-4-3/4), not just any long digit run
  if (ssnLike.test(text) || cardLike.test(text)) {
    return [finding('data-exposure', 'Possible PII pattern (SSN/card-like number) in page source', 'Medium',
      'The homepage HTML contains a string matching an SSN or long card-number pattern (heuristic match, may be a false positive).',
      'Never render raw PII into HTML/JS; mask it server-side and only send what the UI needs, fetched per-request behind auth.')];
  }
  return [];
}

async function checkPrototypePollution(base) {
  const res = await fetchSafe(base + '/api', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ __proto__: { polluted: 'yes' } }) });
  if (res && res.status === 200) {
    return [finding('prototype-pollution', 'Endpoint accepts __proto__ key without rejection', 'Low',
      'POST with a {"__proto__": {...}} body returned 200 instead of being rejected (low-confidence heuristic — confirms acceptance, not actual pollution).',
      'Use JSON.parse reviver guards or a schema validator that strips __proto__/constructor/prototype keys before merging user input into objects.')];
  }
  return [];
}

async function checkWebhookSpoofing(base) {
  for (const path of WEBHOOK_PATH_GUESSES) {
    const res = await fetchSafe(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: 'test.event', data: {} }) });
    if (res && res.status === 200) {
      return [finding('webhook-spoofing', `${path} accepted an unsigned payload`, 'High',
        `POSTing a fake event to ${path} with no signature header returned 200.`,
        'Verify the provider\'s signature header (e.g. Stripe-Signature) server-side before processing any webhook, and reject unsigned/invalid ones with 400.')];
    }
  }
  return [];
}

async function checkUploadProbe(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const html = await res.text().catch(() => '');
  if (/<input[^>]+type=["']?file["']?/i.test(html)) {
    return [finding('upload-probe', 'File upload form detected', 'Low',
      'A <input type="file"> form was found. This clone does not attempt a real upload — verify manually that the server validates file type/size/content and never executes uploaded files.',
      'Validate MIME type and extension server-side (not just client-side), store uploads outside the web root or in object storage, and serve them with Content-Disposition: attachment.')];
  }
  return [];
}

async function checkLocalStorageUsage(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const html = await res.text().catch(() => '');
  const scripts = [...html.matchAll(/<script[^>]+src=["']([^"']+\.js)["']/gi)].map((m) => m[1]).slice(0, 3);
  for (let src of scripts) {
    if (!/^https?:/.test(src)) src = new URL(src, base).toString();
    const r = await fetchSafe(src);
    if (!r) continue;
    const js = await r.text().catch(() => '');
    if (/localStorage\.setItem\(\s*["'][^"']*(token|jwt|secret|auth)[^"']*["']/i.test(js)) {
      return [finding('localstorage-tokens', 'Auth token appears to be stored in localStorage', 'Medium',
        'Bundled JS writes something matching token/jwt/secret/auth into localStorage — readable by any XSS on the page.',
        'Store auth tokens in an HttpOnly cookie instead of localStorage so JavaScript (and XSS) can\'t read them.')];
    }
  }
  return [];
}

async function checkMiddlewareBypass(base) {
  for (const path of PROTECTED_PATH_GUESSES) {
    const baseline = await fetchSafe(base + path);
    if (!baseline || ![401, 403].includes(baseline.status)) continue;
    const variants = [path + '/', path + '/.', path + '%2f', path + '/..;/'];
    for (const v of variants) {
      const r = await fetchSafe(base + v);
      if (r && r.status === 200) {
        return [finding('middleware-bypass', `Protected route bypassed via path variant "${v}"`, 'High',
          `${path} returns ${baseline.status} but ${v} returns 200 — the auth middleware's path match doesn't cover this variant.`,
          'Match and normalize paths the same way your router does before applying auth middleware, or apply auth at the framework/router level, not via a separate path-string check.')];
      }
    }
  }
  return [];
}

const AGGRESSIVE_CHECK_LIST = [
  ['SQL Injection', checkSqlInjection],
  ['NoSQL Injection', checkNoSqlInjection],
  ['Auth Bypass', checkAuthBypass],
  ['Broken Access Control', checkBrokenAccessControl],
  ['Supabase RLS', checkSupabaseRls],
  ['Firebase Rules', checkFirebaseRules],
  ['Error Disclosure', checkErrorDisclosure],
  ['Open Redirects', checkOpenRedirect],
  ['Path Traversal', checkPathTraversal],
  ['Prototype Pollution', checkPrototypePollution],
  ['Webhook Spoofing', checkWebhookSpoofing],
  ['Middleware Bypass', checkMiddlewareBypass],
  ['Rate Limiting', checkRateLimit],
];

async function runScan(base, onProgress, includeAggressive) {
  const findings = [];
  const list = includeAggressive ? [...CHECK_LIST, ...AGGRESSIVE_CHECK_LIST] : CHECK_LIST;
  for (const [name, fn] of list) {
    onProgress?.(name);
    try {
      const res = await fn(base);
      findings.push(...res);
    } catch {
      // skip a failing check, keep scanning
    }
  }
  return findings;
}

module.exports = { runScan, CHECK_LIST, AGGRESSIVE_CHECK_LIST };
