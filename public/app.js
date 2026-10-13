const MODULES = [
  ['SQL Injection', 'Full database access'],
  ['Auth Bypass', 'Anyone becomes admin'],
  ['Broken Access Control', "Read other users' data"],
  ['CORS Misconfig', 'Account takeover'],
  ['Supabase RLS', 'Your whole database, read by anyone'],
  ['Firebase Rules', 'Public database and files'],
  ['Source Maps', 'Your source code, downloadable'],
  ['CSRF', 'Actions without consent'],
  ['Header Audit', 'Session hijacking'],
  ['Rate Limiting', 'Brute force'],
  ['NoSQL Injection', 'Auth bypass via query'],
  ['Error Disclosure', 'Stack traces leaked'],
  ['Open Redirects', 'Phishing via your domain'],
  ['Path Traversal', 'Read server files'],
  ['Dependency Scan', 'Exposed version info'],
  ['Data Exposure', 'PII leaked'],
  ['Prototype Pollution', 'RCE'],
  ['Env Leak', '.env accessible'],
  ['Webhook Spoofing', 'Forged payment events'],
  ['Upload Probe', 'Malicious file execution'],
  ['LocalStorage', 'Tokens stored insecurely'],
  ['Middleware Bypass', 'Skip auth entirely'],
  ['HTTP Methods', 'PUT/DELETE exposed'],
  ['Robots/Sitemap', 'Hidden routes exposed'],
];
const SAFE_MODULE_NAMES = new Set(['CORS Misconfig', 'Source Maps', 'Header Audit', 'Env Leak', 'HTTP Methods', 'Robots/Sitemap', 'Dependency Scan', 'Data Exposure', 'CSRF', 'Upload Probe', 'LocalStorage']);

document.getElementById('module-grid').innerHTML = MODULES.map(([name, impact]) => `
  <div class="module-card ${SAFE_MODULE_NAMES.has(name) ? '' : 'aggressive'}">
    <div class="name">${name}</div>
    <div class="impact">→ ${impact}</div>
    ${SAFE_MODULE_NAMES.has(name) ? '' : '<div class="module-tag">localhost only</div>'}
  </div>
`).join('');

document.getElementById('scan-now-btn').addEventListener('click', () => {
  const urlEl = document.getElementById('url');
  urlEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  urlEl.focus();
});

const form = document.getElementById('scan-form');
const urlInput = document.getElementById('url');
const attestBox = document.getElementById('attest');
const zipInput = document.getElementById('repo-zip');
const statusEl = document.getElementById('status');
const resultsEl = document.getElementById('results');
const btn = document.getElementById('scan-btn');

const GITHUB_RE = /^https?:\/\/github\.com\/[\w.-]+\/[\w.-]+\/?$/;
const URL_RE = /^https?:\/\//i;
const LOCAL_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1', '0.0.0.0']);

const AUDIT_EMPTY_NOTE = '16-item codebase checklist came back clean of heuristic flags — still read the skill\'s full report for a human-reviewed verdict.';

// Remembers how to repeat the last scan (for the Re-scan button) — a plain
// closure so re-running a zip audit doesn't need the file to still be in the
// <input>, just the File object captured at upload time.
let lastRun = null;

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const value = urlInput.value.trim();
  if (!value) return;

  if (GITHUB_RE.test(value)) {
    return doGithubAudit(value);
  }

  if (URL_RE.test(value)) {
    // Client-side mirror of the server's own gate: don't even send the
    // request for a non-localhost target until the box is checked — the
    // server still enforces this (403) regardless, this just avoids the
    // round trip and shows the reason immediately instead of after a fetch.
    let hostname;
    try { hostname = new URL(value).hostname; } catch { hostname = ''; }
    if (!LOCAL_HOSTNAMES.has(hostname) && !attestBox.checked) {
      return showError(resultsEl, 'Check "I own this domain or have permission to test it" before scanning a non-localhost URL.');
    }
    return runLiveScan(value);
  }

  // Anything else is treated as a local filesystem path.
  return doPathAudit(value);
});

zipInput.addEventListener('change', () => {
  const file = zipInput.files[0];
  if (!file) return;
  doZipAudit(file);
  zipInput.value = '';
});

function doGithubAudit(repoUrl) {
  lastRun = { label: repoUrl, fn: () => doGithubAudit(repoUrl) };
  return run(fetch('/api/audit/github', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repoUrl }),
  }), 'cloning repo…', AUDIT_EMPTY_NOTE);
}

function doPathAudit(repoPath) {
  lastRun = { label: repoPath, fn: () => doPathAudit(repoPath) };
  return run(fetch('/api/audit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repoPath }),
  }), 'running security-checklist-audit…', AUDIT_EMPTY_NOTE);
}

function doZipAudit(file) {
  lastRun = { label: file.name, fn: () => doZipAudit(file) };
  const fd = new FormData();
  fd.append('zipfile', file);
  return run(fetch('/api/audit/upload', { method: 'POST', body: fd }), 'uploading & extracting…', AUDIT_EMPTY_NOTE);
}

async function runLiveScan(url) {
  lastRun = { label: url, fn: () => runLiveScan(url) };
  btn.disabled = true;
  statusEl.textContent = 'connecting…';
  resultsEl.innerHTML = '';

  let res;
  try {
    res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, attestOwnership: attestBox.checked, auth: readAuth() }),
    });
  } catch {
    statusEl.textContent = '';
    btn.disabled = false;
    return showError(resultsEl, 'Could not reach the scan server.');
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    statusEl.textContent = '';
    btn.disabled = false;
    return showError(resultsEl, body.error || `Scan failed (${res.status})`);
  }

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  let finalPayload = null;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const lines = buf.split('\n');
    buf = lines.pop();
    for (const line of lines) {
      if (!line.trim()) continue;
      const msg = JSON.parse(line);
      if (msg.type === 'progress') statusEl.textContent = `scanning: ${msg.check}…`;
      if (msg.type === 'done') finalPayload = msg;
    }
  }

  statusEl.textContent = '';
  btn.disabled = false;
  if (finalPayload) {
    renderResults(finalPayload, resultsEl, 'Covers headers, CORS, exposed files, cookies, robots.txt, methods, source maps, dependency CVEs, data exposure, CSRF, upload/localStorage hygiene — not a full pentest.');
  }
}

async function run(fetchPromise, statusMsg, emptyNote) {
  btn.disabled = true;
  statusEl.textContent = statusMsg;
  resultsEl.innerHTML = '';
  let res;
  try {
    res = await fetchPromise;
  } catch {
    statusEl.textContent = '';
    btn.disabled = false;
    return showError(resultsEl, 'Could not reach the scan server.');
  }
  const body = await res.json().catch(() => ({}));
  statusEl.textContent = '';
  btn.disabled = false;
  if (!res.ok) return showError(resultsEl, body.error || `Scan failed (${res.status})`);
  renderResults(body, resultsEl, emptyNote);
}

function showError(container, msg) {
  container.innerHTML = `<div class="error-box">${escapeHtml(msg)}</div>`;
}

let lastResultPayload = null; // kept for the Export button

function diffBadgesHtml(diff) {
  if (!diff) return '';
  const bits = [];
  if (diff.fixed.length) bits.push(`<span class="diff-badge fixed">✓ ${diff.fixed.length} fixed since last scan</span>`);
  if (diff.new.length) bits.push(`<span class="diff-badge new">⚠ ${diff.new.length} new since last scan (was ${diff.priorRiskScore})</span>`);
  if (!bits.length) bits.push(`<span class="diff-badge same">= no change since last scan (${diff.priorRiskScore})</span>`);
  return `<div class="diff-row">${bits.join('')}</div>`;
}

function trendHtml(trend) {
  if (!trend || trend.length < 2) return '';
  const scores = trend.map((t) => t.riskScore).slice(-8);
  return `<div class="trend-row">Risk score trend: ${scores.join(' → ')}</div>`;
}

function readAuth() {
  const cookie = document.getElementById('auth-cookie').value.trim();
  const authorization = document.getElementById('auth-authorization').value.trim();
  return cookie || authorization ? { cookie, authorization } : undefined;
}

function toolbarHtml() {
  if (!lastRun) return '';
  const isUrl = URL_RE.test(lastRun.label || '');
  return `
    <div class="toolbar-row">
      <button type="button" class="btn ghost" id="rescan-btn">↻ Re-scan</button>
      <button type="button" class="btn ghost" id="export-btn">⬇ Export .md</button>
      <button type="button" class="btn ghost" id="pdf-btn">🖨 PDF report</button>
      ${isUrl ? '<button type="button" class="btn ghost" id="monitor-btn">◉ Monitor this app</button>' : ''}
    </div>`;
}

function surfaceHtml(routes, stack, authenticated) {
  if (!routes || !routes.length) return '';
  // Discovery finds far more links than the probe budget covers (a locale
  // switcher alone can be 50+ links) — rows the crawler never got to probe
  // carry no information (state stays 'unprobed', status null), so they're
  // dropped from the table instead of flooding it; the count is still shown.
  const probed = routes.filter((r) => r.state !== 'unprobed');
  const unprobedCount = routes.length - probed.length;
  if (!probed.length) return '';
  const rows = probed.map((r) => `
    <tr><td>${escapeHtml(r.method)}</td><td class="mono">${escapeHtml(r.path)}</td>
    <td><span class="state ${escapeHtml(r.state)}">${escapeHtml(r.status === null ? '—' : r.status)} ${escapeHtml(r.state)}</span></td>
    <td>${escapeHtml(r.source)}</td></tr>`).join('');
  return `
    <details class="surface-box">
      <summary>Attack surface: ${probed.length} probed${unprobedCount ? ` (+${unprobedCount} discovered but not probed)` : ''}${stack ? ` · ${escapeHtml(stack)}` : ''}${authenticated ? ' · authenticated scan' : ''}</summary>
      <table class="surface-table"><thead><tr><th>Method</th><th>Path</th><th>Status</th><th>Found via</th></tr></thead><tbody>${rows}</tbody></table>
    </details>`;
}

function renderResults({ findings, riskScore, diff, trend, routes, stack, authenticated }, container, emptyNote) {
  lastResultPayload = { findings, riskScore, diff, trend, routes, stack, target: lastRun && lastRun.label };

  if (!findings.length) {
    container.innerHTML = `
      ${toolbarHtml()}
      <div class="score-row">
        <div class="score-card"><div class="num" style="color:#4ade80">0</div><div class="label">RISK SCORE</div></div>
        <div class="score-card"><div class="num">0</div><div class="label">FINDINGS</div></div>
      </div>
      ${diffBadgesHtml(diff)}
      ${trendHtml(trend)}
      <div class="empty-state">No issues found. (${emptyNote})</div>
      ${surfaceHtml(routes, stack, authenticated)}
    `;
    wireToolbar(container);
    return;
  }

  const order = { Critical: 0, High: 1, Medium: 2, Low: 3 };
  findings.sort((a, b) => order[a.severity] - order[b.severity]);

  const scoreColor = riskScore >= 60 ? '#ef4444' : riskScore >= 25 ? '#eab308' : '#4ade80';

  container.innerHTML = `
    ${toolbarHtml()}
    <div class="score-row">
      <div class="score-card"><div class="num" style="color:${scoreColor}">${riskScore}</div><div class="label">RISK SCORE</div></div>
      <div class="score-card"><div class="num">${findings.length}</div><div class="label">FINDINGS</div></div>
    </div>
    ${diffBadgesHtml(diff)}
    ${trendHtml(trend)}
    ${findings.map((f, i) => `
      <div class="finding">
        <div class="finding-top">
          <div class="finding-title">${escapeHtml(f.title)}</div>
          <span class="sev ${f.severity}">${f.severity}</span>
        </div>
        <div class="finding-evidence">${escapeHtml(f.evidence)}</div>
        <div class="fix-toggle" data-fix-target="fix-${i}">▸ View fix</div>
        <div class="fix-block" id="fix-${i}">${escapeHtml(f.fix)}${f.patch ? `\n\n— Patch template (${escapeHtml(f.patch.file)}) —\n${escapeHtml(f.patch.code)}` : ''}</div>
        ${f.aiPrompt ? `<button type="button" class="btn ghost mini copy-prompt" data-finding="${i}">Copy fix prompt for Cursor / Claude</button>` : ''}
      </div>
    `).join('')}
  `;
  wireToolbar(container);
}

function wireToolbar(container) {
  const rescanBtn = container.querySelector('#rescan-btn');
  if (rescanBtn) rescanBtn.addEventListener('click', () => lastRun && lastRun.fn());

  const exportBtn = container.querySelector('#export-btn');
  if (exportBtn) exportBtn.addEventListener('click', exportReport);

  const pdfBtn = container.querySelector('#pdf-btn');
  if (pdfBtn) pdfBtn.addEventListener('click', openPrintableReport);

  const monitorBtn = container.querySelector('#monitor-btn');
  if (monitorBtn) monitorBtn.addEventListener('click', addMonitor);
}

// Opens the popup synchronously (inside the click) so popup blockers allow it,
// then points it at the server-rendered report once the POST returns.
async function openPrintableReport() {
  if (!lastResultPayload) return;
  const win = window.open('', '_blank');
  const { findings, riskScore, target, routes, stack } = lastResultPayload;
  try {
    const res = await fetch('/api/report', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, riskScore, findings, routes, stack }),
    });
    const body = await res.json();
    if (!res.ok) throw new Error(body.error || 'report failed');
    if (win) win.location.href = body.url; else window.location.href = body.url;
  } catch (e) {
    if (win) win.close();
    showError(statusEl, `Could not build report: ${e.message}`);
  }
}

async function addMonitor() {
  if (!lastRun) return;
  const url = lastRun.label;
  let hostname = '';
  try { hostname = new URL(url).hostname; } catch { /* handled by server */ }
  if (!LOCAL_HOSTNAMES.has(hostname) && !attestBox.checked) {
    return showError(statusEl, 'Check the ownership box before monitoring a public domain.');
  }
  const res = await fetch('/api/monitors', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url, attestOwnership: attestBox.checked, intervalMinutes: 360 }),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) return showError(statusEl, body.error || 'Could not add monitor.');
  statusEl.textContent = 'Monitor added — re-scans every 6 hours.';
  loadMonitors();
}

// --- Monitors panel ---------------------------------------------------------

const monitorListEl = document.getElementById('monitor-list');

async function loadMonitors() {
  let body;
  try {
    body = await (await fetch('/api/monitors')).json();
  } catch {
    return;
  }
  if (!body.monitors.length) {
    monitorListEl.innerHTML = '<div class="empty-state">No monitors yet. Run a live scan, then press “Monitor this app”.</div>';
    return;
  }
  monitorListEl.innerHTML = body.monitors.map((m) => `
    <div class="monitor-row">
      <div>
        <div class="finding-title">${escapeHtml(m.url)}</div>
        <div class="finding-evidence">every ${m.intervalMinutes} min · last run ${m.lastRunAt ? escapeHtml(new Date(m.lastRunAt).toLocaleString()) : 'never'}
          ${m.lastRunAt ? `· risk ${escapeHtml(m.lastRiskScore)} · ${escapeHtml(m.lastFindingCount)} findings · ${escapeHtml(m.lastNewFindings)} new` : ''}</div>
        <div class="finding-evidence mono">POST /api/monitors/${escapeHtml(m.id)}/trigger</div>
      </div>
      <div class="monitor-actions">
        <button type="button" class="btn ghost mini" data-monitor-run="${escapeHtml(m.id)}">Scan now</button>
        <button type="button" class="btn ghost mini" data-monitor-del="${escapeHtml(m.id)}">Remove</button>
      </div>
    </div>`).join('');
}

monitorListEl.addEventListener('click', async (e) => {
  const run = e.target.closest('[data-monitor-run]');
  const del = e.target.closest('[data-monitor-del]');
  if (run) {
    run.disabled = true;
    run.textContent = 'Scanning…';
    await fetch(`/api/monitors/${run.dataset.monitorRun}/trigger`, { method: 'POST' });
    loadMonitors();
  } else if (del) {
    await fetch(`/api/monitors/${del.dataset.monitorDel}`, { method: 'DELETE' });
    loadMonitors();
  }
});

loadMonitors();

// --- Free tools -------------------------------------------------------------

async function runTool(endpoint, url, outEl, render) {
  if (!URL_RE.test(url)) return showError(outEl, 'Enter a full http(s) URL.');
  let hostname = '';
  try { hostname = new URL(url).hostname; } catch { /* server validates */ }
  if (!LOCAL_HOSTNAMES.has(hostname) && !attestBox.checked) {
    return showError(outEl, 'Check the ownership box at the top before testing a public domain.');
  }
  outEl.innerHTML = '<div class="status-line">checking…</div>';
  let res;
  try {
    res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, attestOwnership: attestBox.checked }),
    });
  } catch {
    return showError(outEl, 'Could not reach the server.');
  }
  const body = await res.json().catch(() => ({}));
  if (!res.ok) return showError(outEl, body.error || `Failed (${res.status})`);
  outEl.innerHTML = render(body);
}

document.getElementById('keys-form').addEventListener('submit', (e) => {
  e.preventDefault();
  runTool('/api/tools/api-keys', document.getElementById('keys-url').value.trim(), document.getElementById('keys-out'), (b) => {
    if (!b.secrets.length && !b.envExposed) return '<div class="empty-state">No leaked secrets found in the page, its same-origin scripts or /.env.</div>';
    const rows = b.secrets.map((s) => `<div class="finding"><div class="finding-top"><div class="finding-title">${escapeHtml(s.label)}</div><span class="sev ${escapeHtml(s.severity)}">${escapeHtml(s.severity)}</span></div><div class="finding-evidence mono">${escapeHtml(s.masked)} in ${escapeHtml(s.where)}</div></div>`).join('');
    const env = b.envExposed ? '<div class="finding"><div class="finding-top"><div class="finding-title">/.env is publicly accessible</div><span class="sev Critical">Critical</span></div></div>' : '';
    return rows + env + '<div class="tool-note">Rotate any key above, then move it server-side.</div>';
  });
});

document.getElementById('headers-form').addEventListener('submit', (e) => {
  e.preventDefault();
  runTool('/api/tools/headers', document.getElementById('headers-url').value.trim(), document.getElementById('headers-out'), (b) => {
    const rows = b.headers.map((h) => `
      <tr><td>${escapeHtml(h.name)}</td><td><span class="state ${h.status === 'pass' ? 'open' : h.status === 'weak' ? 'redirect' : 'error'}">${escapeHtml(h.status)}</span></td>
      <td>${escapeHtml(h.note)}</td></tr>`).join('');
    const leaks = b.leaks.length ? `<div class="tool-note">Version info leaked: ${b.leaks.map((l) => escapeHtml(`${l.name}: ${l.value}`)).join(', ')}</div>` : '';
    return `<div class="grade-row"><div class="grade">${escapeHtml(b.grade)}</div><div>${escapeHtml(b.score)}/100 for ${escapeHtml(b.target)}</div></div>
      <table class="surface-table"><thead><tr><th>Header</th><th>Result</th><th>Why</th></tr></thead><tbody>${rows}</tbody></table>${leaks}`;
  });
});

function exportReport() {
  if (!lastResultPayload) return;
  const { findings, riskScore, target } = lastResultPayload;
  const lines = [
    `# Security scan report`,
    ``,
    `**Target:** ${target || 'unknown'}`,
    `**Date:** ${new Date().toISOString()}`,
    `**Risk score:** ${riskScore}`,
    `**Findings:** ${findings.length}`,
    ``,
    ...findings.map((f) => [
      `## [${f.severity}] ${f.title}`,
      ``,
      f.evidence,
      ``,
      '**Fix:**',
      '```',
      f.fix,
      '```',
      ``,
    ].join('\n')),
  ];
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `scan-report-${Date.now()}.md`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// Event delegation instead of inline onclick= (CSP's script-src 'self' blocks
// inline handlers, same reason the old "Scan Now Free" onclick silently did
// nothing — see findings this scanner reported against itself).
resultsEl.addEventListener('click', async (e) => {
  const copy = e.target.closest('.copy-prompt');
  if (copy && lastResultPayload) {
    const f = lastResultPayload.findings[Number(copy.dataset.finding)];
    try {
      await navigator.clipboard.writeText(f.aiPrompt);
      copy.textContent = 'Copied ✓';
    } catch {
      copy.textContent = 'Copy failed — select the fix text instead';
    }
    return;
  }
  const toggle = e.target.closest('.fix-toggle');
  if (!toggle) return;
  document.getElementById(toggle.dataset.fixTarget)?.classList.toggle('open');
});

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
