// Pure-function tests (no server, no network): `node test_unit.js`.
const assert = require('assert');
const { scanText } = require('./checks/secrets');
const { gradeHeaders } = require('./checks/headers');
const { patchFor, buildPrompt, annotateFindings } = require('./checks/fixes');
const { sanitizeAuth, isLocalHost } = require('./checks/http');
const { classify, detectStack } = require('./checks/crawl');
const { buildReportHtml } = require('./report');

// Fake keys are assembled at runtime so no secret-shaped literal sits in the repo.
const fakeStripe = 'sk_' + 'live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2';
const fakeAnthropic = 'sk-' + 'ant-' + 'api03-' + 'x'.repeat(40);
const fakeAws = 'AKIA' + 'ABCDEFGHIJKLMNOP';

// 1. Secrets: detected, masked, de-duplicated, never echoed raw.
{
  const hits = scanText(`var a="${fakeStripe}"; var b="${fakeAnthropic}"; k='${fakeAws}'; var c="${fakeStripe}"`, '/app.js');
  const labels = hits.map((h) => h.label).sort();
  assert.deepStrictEqual(labels, ['AWS access key ID', 'Anthropic API key', 'Stripe secret key']);
  for (const h of hits) {
    assert.ok(h.masked.includes('…'), 'masked');
    assert.ok(![fakeStripe, fakeAnthropic, fakeAws].includes(h.masked), 'raw secret must not be returned');
  }
  assert.ok(!hits.some((h) => h.label === 'OpenAI API key'), 'sk-ant- must not double-count as OpenAI');
}

// 2. Supabase service_role JWT flagged, anon JWT ignored.
{
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = (role) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role, iss: 'supabase' })}.${'s'.repeat(24)}`;
  assert.deepStrictEqual(scanText(jwt('anon'), 'x'), []);
  const hits = scanText(`key="${jwt('service_role')}"`, 'x');
  assert.strictEqual(hits.length, 1);
  assert.strictEqual(hits[0].label, 'Supabase service-role key');
}

// 3. Header grading (works with whatever header set checks/headers.js SPEC defines).
{
  const all = {
    'content-security-policy': "default-src 'self'",
    'strict-transport-security': 'max-age=63072000; includeSubDomains',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'DENY',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=()',
  };
  assert.strictEqual(gradeHeaders((k) => all[k] || null).grade, 'A+');
  assert.strictEqual(gradeHeaders(() => null).grade, 'F');
  const weak = gradeHeaders((k) => ({ ...all, 'strict-transport-security': 'max-age=60' })[k] || null);
  assert.strictEqual(weak.headers.find((h) => h.key === 'strict-transport-security').status, 'weak');
  const leak = gradeHeaders((k) => ({ ...all, 'x-powered-by': 'Express 4.18.2' })[k] || null);
  assert.strictEqual(leak.leaks.length, 1);
}

// 4. Fix prompts + patches.
{
  const f = { id: 'header-x-frame-options', title: 'Missing X-Frame-Options', severity: 'Medium', evidence: 'e', fix: 'f' };
  assert.ok(patchFor(f, 'Next.js').code.includes('async headers()'));
  assert.ok(patchFor(f, null).code.includes("res.setHeader('X-Frame-Options', \"DENY\")"));
  assert.ok(patchFor(f, 'nginx').code.startsWith('add_header X-Frame-Options'));
  assert.strictEqual(patchFor({ id: 'checklist-9' }, null), null);
  assert.ok(buildPrompt(f, 'Next.js').includes('Next.js'));
  const [a] = annotateFindings([f], 'Next.js');
  assert.ok(a.aiPrompt && a.patch);
}

// 5. Auth sanitising: only Cookie/Authorization, CR/LF stripped, empty -> null.
{
  const h = sanitizeAuth({ cookie: 'a=1\r\nX-Evil: 1', authorization: 'Bearer t', host: 'evil' });
  assert.deepStrictEqual(Object.keys(h).sort(), ['Authorization', 'Cookie']);
  assert.ok(!/[\r\n]/.test(h.Cookie));
  assert.strictEqual(sanitizeAuth({ cookie: '  ' }), null);
  assert.strictEqual(sanitizeAuth('nope'), null);
}

// 6. Crawl helpers.
{
  assert.strictEqual(classify(200), 'open');
  assert.strictEqual(classify(403), 'protected');
  assert.strictEqual(classify(null), 'unreachable');
  const res = { headers: { get: (k) => ({ 'x-powered-by': 'Express' })[k] || '' } };
  assert.strictEqual(detectStack(res, '<html></html>'), 'Express');
  assert.strictEqual(detectStack({ headers: { get: () => '' } }, '<script src="/_next/static/a.js">'), 'Next.js');
}

// 7. Report HTML escapes everything user-controlled.
{
  const html = buildReportHtml({
    target: '<script>alert(1)</script>', riskScore: 3, stack: null, routes: [], generatedAt: 'now',
    findings: [{ severity: 'Low', title: '<img src=x onerror=1>', evidence: '"><b>', fix: '&', patch: null }],
  });
  assert.ok(!html.includes('<script>alert(1)'), 'target must be escaped');
  assert.ok(!html.includes('<img src=x'), 'title must be escaped');
  assert.ok(html.includes('&lt;img src=x'));
}

// Attack modules run only against loopback: IPv6 included (URL keeps the brackets), look-alike names excluded.
{
  for (const h of ['localhost', 'LOCALHOST', '127.0.0.1', '::1', '[::1]', '0.0.0.0']) assert.ok(isLocalHost(h), h);
  assert.ok(isLocalHost(new URL('http://[::1]:3000/').hostname), 'hostname of an IPv6 URL');
  for (const h of ['localhost.evil.com', 'evil.com', '127.0.0.1.nip.io', 'www.localhost', '10.0.0.5', '192.168.1.1', '[::2]', '', 'example.com:80']) {
    assert.ok(!isLocalHost(h), h);
  }
}

console.log('All unit checks passed.');
