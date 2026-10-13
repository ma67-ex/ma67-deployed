// ponytail: one runnable smoke test for the branching logic that matters
// (not a framework/suite) — run with `node test_smoke.js` against a running
// `node server.js` on PORT (default 4100). Exits non-zero on failure.
const assert = require('assert');

const PORT = process.env.PORT || 4100;
const BASE = `http://localhost:${PORT}`;

async function main() {
  // 1. Page serves.
  const home = await fetch(BASE + '/');
  assert.strictEqual(home.status, 200, 'homepage should serve');

  // 2. Security headers present (the thing we fixed earlier — regression guard).
  assert.ok(home.headers.get('content-security-policy'), 'CSP header missing');
  assert.ok(home.headers.get('x-frame-options'), 'X-Frame-Options header missing');

  // 3. Authorization gate: public URL without attestation is rejected before scanning.
  const blocked = await fetch(BASE + '/api/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com', attestOwnership: false }),
  });
  assert.strictEqual(blocked.status, 403, 'unattested public target should be 403');

  // 4. GitHub URL validation rejects a non-GitHub / injection-shaped value before shelling out.
  const badGithub = await fetch(BASE + '/api/audit/github', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repoUrl: 'not a url; rm -rf /' }),
  });
  assert.strictEqual(badGithub.status, 400, 'malformed GitHub URL should be rejected');

  // 5. Local-path audit works against this repo itself.
  const auditRes = await fetch(BASE + '/api/audit', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repoPath: __dirname }),
  });
  assert.strictEqual(auditRes.status, 200, 'local-path audit should succeed');
  const auditBody = await auditRes.json();
  assert.ok(Array.isArray(auditBody.findings), 'audit should return a findings array');

  // 5b. New endpoints: report round-trip, monitor lifecycle, authenticated scan
  // carries the Cookie to the scanned origin, JS-secret + route discovery.
  const http = require('http');
  const fakeKey = 'sk_' + 'live_' + 'Q1w2E3r4T5y6U7i8O9p0A1s2';
  const seenCookies = [];
  const stub = http.createServer((req, res) => {
    if (req.headers.cookie) seenCookies.push(req.headers.cookie);
    if (req.url === '/') {
      res.setHeader('content-type', 'text/html');
      return res.end('<html><body><a href="/about">about</a><script src="/bundle.js"></script></body></html>');
    }
    if (req.url === '/bundle.js') {
      res.setHeader('content-type', 'application/javascript');
      return res.end(`const k="${fakeKey}"; fetch("/api/internal/debug");`);
    }
    if (req.url === '/api/internal/debug') return res.end('{"ok":true}');
    res.statusCode = 404;
    res.end('nf');
  });
  await new Promise((r) => stub.listen(0, '127.0.0.1', r));
  const stubBase = `http://127.0.0.1:${stub.address().port}`;
  try {
    const stubRes = await fetch(BASE + '/api/scan', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: stubBase, attestOwnership: false, auth: { cookie: 'session=abc123' } }),
    });
    assert.strictEqual(stubRes.status, 200, 'stub scan should start');
    const stubDone = (await stubRes.text()).trim().split('\n').map((l) => JSON.parse(l)).find((l) => l.type === 'done');
    assert.ok(stubDone, 'stub scan should finish');
    const secret = stubDone.findings.find((f) => f.id.startsWith('js-secret-stripe-secret-key'));
    assert.ok(secret, 'leaked Stripe key should be found in bundle.js');
    assert.ok(!JSON.stringify(stubDone).includes(fakeKey), 'raw key must never be returned');
    assert.ok(secret.aiPrompt && secret.patch, 'finding should carry a fix prompt and patch');
    assert.ok(stubDone.routes.some((r) => r.path === '/api/internal/debug' && r.state === 'open'), 'bundle API route discovered and probed');
    assert.ok(stubDone.findings.some((f) => f.id === 'route-sensitive-/api/internal/debug'), 'sensitive open route flagged');
    assert.strictEqual(stubDone.authenticated, true);
    assert.ok(seenCookies.includes('session=abc123'), 'Cookie should reach the scanned origin');

    const rep = await (await fetch(BASE + '/api/report', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: stubBase, riskScore: stubDone.riskScore, findings: stubDone.findings, routes: stubDone.routes }),
    })).json();
    const repHtml = await (await fetch(BASE + rep.url)).text();
    assert.ok(repHtml.includes('Security scan report') && repHtml.includes('print-btn'), 'printable report should render');

    const keysTool = await (await fetch(BASE + '/api/tools/api-keys', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: stubBase }),
    })).json();
    assert.ok(keysTool.secrets.length >= 1 && keysTool.secrets[0].masked.includes('…'), 'api-key tool should report masked secret');

    const hdrTool = await (await fetch(BASE + '/api/tools/headers', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: stubBase }),
    })).json();
    assert.strictEqual(hdrTool.grade, 'F', 'stub sends no security headers');

    const created = await fetch(BASE + '/api/monitors', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: stubBase, intervalMinutes: 60 }),
    });
    assert.strictEqual(created.status, 201, 'monitor create');
    const { monitor } = await created.json();
    const dup = await fetch(BASE + '/api/monitors', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: stubBase }),
    });
    assert.strictEqual(dup.status, 409, 'duplicate monitor rejected');
    const trig = await (await fetch(`${BASE}/api/monitors/${monitor.id}/trigger`, { method: 'POST' })).json();
    assert.ok(typeof trig.riskScore === 'number' && trig.monitor.lastRunAt, 'deploy trigger should scan and record');
    const del = await fetch(`${BASE}/api/monitors/${monitor.id}`, { method: 'DELETE' });
    assert.strictEqual(del.status, 200, 'monitor delete');

    const blockedTool = await fetch(BASE + '/api/tools/headers', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'https://example.com', attestOwnership: false }),
    });
    assert.strictEqual(blockedTool.status, 403, 'tools honour the ownership gate');
  } finally {
    stub.close();
  }

  // 6. Live scan against self comes back clean. Runs LAST: its rate-limit
  // check fires 30 rapid requests at this same server by design, which
  // would otherwise trip the global limiter (20/10s) for whatever ran next.
  const scanRes = await fetch(BASE + '/api/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: BASE, attestOwnership: false }),
  });
  assert.strictEqual(scanRes.status, 200, 'self-scan should start');
  const text = await scanRes.text();
  const lines = text.trim().split('\n').map((l) => JSON.parse(l));
  const done = lines.find((l) => l.type === 'done');
  assert.ok(done, 'scan should emit a done event');
  // Known true positives on our own app: the 📎 zip-upload <input type="file">,
  // and /api/monitors being a real unauthenticated GET route discovered by
  // the crawler. Anything else is unexpected.
  const KNOWN_FINDINGS = new Set(['upload-probe', 'route-hidden-api']);
  const unexpected = done.findings.filter((f) => !KNOWN_FINDINGS.has(f.id));
  assert.strictEqual(unexpected.length, 0, `self-scan should only flag known findings, got: ${JSON.stringify(unexpected)}`);
  assert.ok('diff' in done && 'trend' in done, 'scan response should include diff/trend from history.js');

  console.log('All smoke checks passed.');
}

main().catch((e) => {
  console.error('SMOKE TEST FAILED:', e.message);
  process.exit(1);
});
