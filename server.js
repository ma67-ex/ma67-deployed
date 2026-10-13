const express = require('express');
const dns = require('dns').promises;
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execFile } = require('child_process');
const multer = require('multer');
const { runScan, checkExposedFiles } = require('./checks/scan');
const { discoverRoutes } = require('./checks/crawl');
const { findSecrets } = require('./checks/secrets');
const { checkHeaderGrade } = require('./checks/headers');
const { annotateFindings } = require('./checks/fixes');
const { sanitizeAuth, withAuth } = require('./checks/http');
const history = require('./history');
const monitors = require('./monitors');
const report = require('./report');

const upload = multer({ dest: os.tmpdir(), limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB cap on uploaded zips

// Reuse security-checklist-audit's scan.py instead of re-implementing its
// 16-item regex logic in JS. Bundled under vendor/ so this works out of the
// box for anyone who clones the repo without that Claude Code skill
// installed; if the user's own installed copy exists, prefer it (newer).
const BUNDLED_SCAN_PY = path.join(__dirname, 'vendor/security-checklist-audit/scan.py');
const INSTALLED_SCAN_PY = path.join(os.homedir(), '.claude/skills/security-checklist-audit/scripts/scan.py');
const CHECKLIST_SCAN_PY = fs.existsSync(INSTALLED_SCAN_PY) ? INSTALLED_SCAN_PY : BUNDLED_SCAN_PY;

const app = express();

// Security headers (fixes the findings our own self-scan reported: missing
// CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy).
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  // HSTS only matters over HTTPS, but harmless to send over local HTTP too —
  // real deploys behind TLS will have it take effect immediately.
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains');
  next();
});

// Minimal in-memory rate limiter (fixes "no rate limiting observed").
// ponytail: single-process memory map, resets on restart — swap for a
// shared store (Redis) if this ever runs behind more than one instance.
const RATE_LIMIT = { windowMs: 10_000, max: 20 };
const hits = new Map();
app.use((req, res, next) => {
  const ip = req.ip;
  const now = Date.now();
  const entry = hits.get(ip);
  if (!entry || now - entry.start > RATE_LIMIT.windowMs) {
    hits.set(ip, { start: now, count: 1 });
    return next();
  }
  entry.count++;
  if (entry.count > RATE_LIMIT.max) {
    return res.status(429).json({ error: 'Too many requests, slow down.' });
  }
  next();
});

app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 4100;

const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 0;
  }
  if (net.isIPv6(ip)) return ip === '::1' || ip.startsWith('fc') || ip.startsWith('fe80');
  return false;
}

// Authorization gate: only scan localhost/private targets automatically.
// A public hostname is allowed ONLY if the client sent an explicit
// ownership attestation (checkbox in the UI) — this is a UI-level control,
// not a security boundary; it exists to keep this tool from being a
// one-click "attack any site" button.
async function assertAuthorized(hostname, attested) {
  if (LOCAL_HOSTNAMES.has(hostname)) return;
  if (attested !== true) {
    const err = new Error('Target not authorized. Only localhost/private IPs are scanned automatically; a public domain requires the ownership checkbox.');
    err.code = 'UNAUTHORIZED_TARGET';
    throw err;
  }
  // Still block scanning something that resolves to a private IP range
  // pretending to be public, and vice versa — just resolve and log; no
  // extra restriction once attested, since the user vouched for it.
  try {
    await dns.lookup(hostname);
  } catch {
    const err = new Error('Target hostname does not resolve.');
    err.code = 'DNS_FAIL';
    throw err;
  }
}

// Parses + authorizes a target URL. Returns { base, hostname } or sends the
// error response itself and returns null.
async function resolveTarget(res, url, attested) {
  let target;
  try {
    target = new URL(url);
    if (!['http:', 'https:'].includes(target.protocol)) throw new Error('bad protocol');
  } catch {
    res.status(400).json({ error: 'Enter a valid http(s) URL.' });
    return null;
  }
  try {
    await assertAuthorized(target.hostname, attested);
  } catch (e) {
    res.status(403).json({ error: e.message, code: e.code });
    return null;
  }
  return { base: `${target.protocol}//${target.host}`, hostname: target.hostname };
}

// One full live scan: route discovery + every check, optionally carrying a
// logged-in session (Cookie/Authorization) to same-origin requests only.
async function performScan(base, hostname, { onProgress, authHeaders } = {}) {
  const aggressive = LOCAL_HOSTNAMES.has(hostname);
  return withAuth(new URL(base).origin, authHeaders, async () => {
    onProgress?.('Route Discovery');
    const surface = await discoverRoutes(base);
    const found = await runScan(base, onProgress, aggressive);
    const findings = annotateFindings([...found, ...surface.findings], surface.stack);
    return { findings, routes: surface.routes, stack: surface.stack, aggressive, authenticated: !!authHeaders };
  });
}

app.post('/api/scan', async (req, res) => {
  const { url, attestOwnership, auth } = req.body || {};
  const t = await resolveTarget(res, url, attestOwnership);
  if (!t) return;

  const authHeaders = sanitizeAuth(auth);
  res.writeHead(200, { 'Content-Type': 'application/x-ndjson', 'Transfer-Encoding': 'chunked' });
  const send = (obj) => res.write(JSON.stringify(obj) + '\n');
  send({ type: 'start', base: t.base, aggressive: LOCAL_HOSTNAMES.has(t.hostname), authenticated: !!authHeaders });

  const scan = await performScan(t.base, t.hostname, {
    authHeaders,
    onProgress: (check) => send({ type: 'progress', check }),
  });
  const result = withHistory(t.base, scan.findings, scoreOf(scan.findings));

  send({ type: 'done', ...result, routes: scan.routes, stack: scan.stack, authenticated: scan.authenticated, target: t.base });
  res.end();
});

// --- Free tools -------------------------------------------------------------
// Standalone single-purpose checkers, same authorization gate as the scanner.

app.post('/api/tools/headers', async (req, res) => {
  const { url, attestOwnership } = req.body || {};
  const t = await resolveTarget(res, url, attestOwnership);
  if (!t) return;
  const result = await checkHeaderGrade(t.base);
  if (!result) return res.status(502).json({ error: 'Could not reach the target.' });
  res.json(result);
});

app.post('/api/tools/api-keys', async (req, res) => {
  const { url, attestOwnership } = req.body || {};
  const t = await resolveTarget(res, url, attestOwnership);
  if (!t) return;
  const hits = await findSecrets(t.base);
  const envFindings = await checkExposedFiles(t.base);
  res.json({
    target: t.base,
    secrets: hits, // already masked by the scanner
    envExposed: envFindings.filter((f) => f.id === 'exposed-/.env').length > 0,
  });
});

// --- Monitoring -------------------------------------------------------------

async function runMonitor(m, trigger) {
  const hostname = new URL(m.url).hostname;
  if (!LOCAL_HOSTNAMES.has(hostname) && m.attested !== true) throw new Error('monitor target is not attested');
  const scan = await performScan(m.url, hostname);
  const result = withHistory(m.url, scan.findings, scoreOf(scan.findings));
  const updated = monitors.recordRun(m.id, {
    riskScore: result.riskScore,
    findingCount: scan.findings.length,
    newCount: result.diff ? result.diff.new.length : 0,
    trigger,
  });
  return { monitor: updated, ...result };
}

app.get('/api/monitors', (req, res) => {
  res.json({ monitors: monitors.list(), minIntervalMinutes: monitors.MIN_INTERVAL_MIN });
});

app.post('/api/monitors', async (req, res) => {
  const { url, attestOwnership, intervalMinutes } = req.body || {};
  const t = await resolveTarget(res, url, attestOwnership);
  if (!t) return;
  try {
    const m = monitors.add({ url: t.base, attested: attestOwnership === true, intervalMinutes });
    res.status(201).json({ monitor: m });
  } catch (e) {
    res.status(409).json({ error: e.message, code: e.code });
  }
});

app.delete('/api/monitors/:id', (req, res) => {
  if (!monitors.remove(req.params.id)) return res.status(404).json({ error: 'No such monitor.' });
  res.json({ ok: true });
});

// "Scan on every deploy": call this from CI/CD after a deploy finishes.
//   curl -X POST http://localhost:4100/api/monitors/<id>/trigger
app.post('/api/monitors/:id/trigger', async (req, res) => {
  const m = monitors.get(req.params.id);
  if (!m) return res.status(404).json({ error: 'No such monitor.' });
  try {
    const out = await runMonitor(m, 'deploy');
    res.json({ riskScore: out.riskScore, findings: out.findings.length, diff: out.diff, monitor: out.monitor });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// --- Printable report ---------------------------------------------------------

app.post('/api/report', (req, res) => {
  const { target, riskScore, findings, routes, stack } = req.body || {};
  if (!Array.isArray(findings) || findings.length > 500) {
    return res.status(400).json({ error: 'findings must be an array (max 500).' });
  }
  const clean = findings.map((f) => ({
    severity: String(f.severity || ''),
    title: String(f.title || ''),
    evidence: String(f.evidence || ''),
    fix: String(f.fix || ''),
    patch: f.patch && typeof f.patch === 'object' ? { file: String(f.patch.file || ''), code: String(f.patch.code || '') } : null,
  }));
  const id = report.saveReport({
    target: String(target || 'unknown'),
    riskScore: Number(riskScore) || 0,
    findings: clean,
    routes: Array.isArray(routes) ? routes.slice(0, 120) : [],
    stack: stack ? String(stack) : null,
    generatedAt: new Date().toISOString(),
  });
  res.json({ url: `/report/${id}` });
});

app.get('/report/:id', (req, res) => {
  const html = report.getReport(req.params.id);
  if (!html) return res.status(404).send('Report not found (reports are kept in memory and cleared on restart).');
  res.type('html').send(html);
});

// --- Codebase audit (static, local-filesystem) ------------------------------
// Separate from the live URL scan above: this reads source code on disk via
// the user's own security-checklist-audit skill, not an HTTP probe. Scoped to
// a local path the user types, same trust model as them running the skill
// directly — no network targeting, so no ownership attestation needed.

function runChecklistScan(repoPath) {
  return new Promise((resolve, reject) => {
    execFile('python3', [CHECKLIST_SCAN_PY, repoPath], { maxBuffer: 20 * 1024 * 1024, timeout: 60_000 }, (err, stdout, stderr) => {
      if (err) return reject(new Error(stderr || err.message));
      try {
        resolve(JSON.parse(stdout));
      } catch {
        reject(new Error('scan.py did not return valid JSON'));
      }
    });
  });
}

// Mechanical, unreviewed classification of scan.py's raw evidence — the
// skill itself says a human (or Claude) should read the matched files before
// calling anything CONFIRMED. This endpoint can't do that, so it labels
// every verdict "(heuristic)" rather than pretending to a confidence level
// scan.py's regex output doesn't support on its own.
function classifyItem(item) {
  const hasPos = item.positive_evidence.length > 0;
  const hasNeg = item.negative_evidence.length > 0;
  if (hasNeg && !hasPos) return { status: 'FAIL', severity: 'High' };
  if (hasNeg && hasPos) return { status: 'PARTIAL', severity: 'Medium' };
  if (hasPos && !hasNeg) return { status: 'PASS (heuristic)', severity: null };
  return { status: 'NEEDS REVIEW', severity: 'Low' };
}

function checklistToFindings(result) {
  const findings = [];
  for (const item of result.items) {
    const { status, severity } = classifyItem(item);
    if (!severity) continue; // clean pass, not a finding
    const evidence = (item.negative_evidence[0] || item.positive_evidence[0]);
    const where = evidence ? `${evidence.file}:${evidence.line} — ${evidence.snippet}` : (item.note || 'No direct evidence found by the pattern scan.');
    findings.push({
      id: `checklist-${item.id}`,
      title: `[${item.category}] ${item.item} — ${status} (heuristic)`,
      severity,
      evidence: `${where}${item.note ? `\nNote: ${item.note}` : ''}`,
      fix: 'This is an unreviewed pattern match from security-checklist-audit — read the file before trusting the verdict. Re-run the skill directly for a full humanized report with WHAT/WHY copy and a proper CONFIRMED/NEEDS REVIEW classification.',
    });
  }
  for (const flag of result.supply_chain_flags || []) {
    findings.push({
      id: `supply-chain-${findings.length}`,
      title: 'Supply-chain flag',
      severity: 'Medium',
      evidence: JSON.stringify(flag),
      fix: 'Read the flagged file by hand — high false-positive rate by design (see the skill\'s own notes on agent-instruction files and install-lifecycle scripts).',
    });
  }
  for (const page of (result.legal_pages && result.legal_pages.missing) || []) {
    findings.push({
      id: `legal-${page}`,
      title: `Missing legal page: ${page}`,
      severity: 'Low',
      evidence: 'Not found by path or text-link match in scanned source.',
      fix: 'Informational, not legal advice. Add the page if your app collects data / takes signups, and confirm requirements with an actual lawyer beyond a personal project.',
    });
  }
  return findings;
}

async function auditDirAndRespond(res, dir, cleanup, targetKey) {
  try {
    if (!fs.existsSync(CHECKLIST_SCAN_PY)) {
      return res.status(500).json({ error: 'security-checklist-audit skill not found at ' + CHECKLIST_SCAN_PY });
    }
    const result = await runChecklistScan(dir);
    const findings = annotateFindings(checklistToFindings(result), null);
    res.json(withHistory(targetKey, findings, scoreOf(findings)));
  } catch (e) {
    res.status(500).json({ error: e.message });
  } finally {
    if (cleanup) fs.rm(dir, { recursive: true, force: true }, () => {});
  }
}

// Mode 1: a local filesystem path on the machine running this server.
app.post('/api/audit', async (req, res) => {
  const { repoPath } = req.body || {};
  if (!repoPath || typeof repoPath !== 'string') {
    return res.status(400).json({ error: 'Enter a local repo path to audit.' });
  }
  const resolved = path.resolve(repoPath.replace(/^~/, os.homedir()));
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    return res.status(400).json({ error: `Not a directory: ${resolved}` });
  }
  auditDirAndRespond(res, resolved, false, resolved);
});

// Mode 2: a .zip of a project uploaded from the browser (for when this runs
// on a machine other than the one holding the code — e.g. after you push
// this to GitHub and someone else runs it against their own project).
app.post('/api/audit/upload', upload.single('zipfile'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded.' });
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deploysafe-upload-'));
  try {
    await new Promise((resolve, reject) => {
      execFile('unzip', ['-q', '-o', req.file.path, '-d', tmpDir], { timeout: 30_000 }, (err, _out, stderr) => {
        if (err) return reject(new Error(stderr || 'Could not extract zip — is it a valid .zip file?'));
        resolve();
      });
    });
  } catch (e) {
    fs.rm(tmpDir, { recursive: true, force: true }, () => {});
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: e.message });
  }
  fs.unlink(req.file.path, () => {}); // done with the raw upload, keep only the extracted tree
  auditDirAndRespond(res, tmpDir, true, `upload:${req.file.originalname}`);
});

// Mode 3: a public GitHub repo URL — shallow-cloned, scanned, deleted.
const GITHUB_URL_RE = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+?(\.git)?\/?$/;
app.post('/api/audit/github', async (req, res) => {
  const { repoUrl } = req.body || {};
  if (!repoUrl || !GITHUB_URL_RE.test(repoUrl.trim())) {
    return res.status(400).json({ error: 'Enter a URL like https://github.com/owner/repo' });
  }
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deploysafe-clone-'));
  try {
    await new Promise((resolve, reject) => {
      // repoUrl is regex-validated above and passed as its own execFile arg
      // (not through a shell), so this isn't shell-injectable.
      execFile('git', ['clone', '--depth', '1', '--quiet', repoUrl.trim(), tmpDir], { timeout: 45_000 }, (err, _out, stderr) => {
        if (err) return reject(new Error(stderr || 'git clone failed — repo may be private, deleted, or too large.'));
        resolve();
      });
    });
  } catch (e) {
    fs.rm(tmpDir, { recursive: true, force: true }, () => {});
    return res.status(400).json({ error: e.message });
  }
  auditDirAndRespond(res, tmpDir, true, repoUrl.trim());
});

function scoreOf(findings) {
  const weight = { Critical: 40, High: 20, Medium: 8, Low: 3 };
  return Math.min(100, findings.reduce((s, f) => s + (weight[f.severity] || 0), 0));
}

// Records this scan under `targetKey`, diffs it against the prior scan of
// the same target (fixed/new findings), and returns the trend so the
// frontend can show "vs last scan" + a risk-score history without a
// separate round trip.
function withHistory(targetKey, findings, riskScore) {
  const prior = history.recordScan(targetKey, { findings, riskScore });
  return {
    findings,
    riskScore,
    diff: history.diffAgainst(prior, findings),
    trend: history.getTrend(targetKey),
  };
}

monitors.startScheduler(runMonitor);

app.listen(PORT, () => console.log(`deploysafe-clone running at http://localhost:${PORT}`));
