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
