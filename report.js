// Printable security report. Served as a normal HTML page with print CSS and
// a Print / Save-as-PDF button, so no PDF library is needed: every browser's
// "Save as PDF" produces the file. Everything user-supplied is HTML-escaped.
const crypto = require('crypto');

const store = new Map(); // id -> html (in memory; reports are disposable)
const MAX_REPORTS = 50;

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

const SEV_ORDER = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const SEV_COLOR = { Critical: '#b91c1c', High: '#c2410c', Medium: '#a16207', Low: '#475569' };

function buildReportHtml({ target, riskScore, findings, routes, stack, generatedAt }) {
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  for (const f of sorted) if (counts[f.severity] !== undefined) counts[f.severity]++;

  const findingHtml = sorted.map((f) => `
    <section class="finding">
      <h3><span class="sev" style="background:${SEV_COLOR[f.severity] || '#475569'}">${esc(f.severity)}</span> ${esc(f.title)}</h3>
      <p>${esc(f.evidence)}</p>
      <p class="label">Fix</p><pre>${esc(f.fix)}</pre>
      ${f.patch ? `<p class="label">Patch template — ${esc(f.patch.file)}</p><pre>${esc(f.patch.code)}</pre>` : ''}
    </section>`).join('');

  const routeHtml = (routes && routes.length)
    ? `<h2>Attack surface (${routes.length} routes)</h2>
       <table><thead><tr><th>Method</th><th>Path</th><th>Status</th><th>State</th><th>Found via</th></tr></thead><tbody>
       ${routes.map((r) => `<tr><td>${esc(r.method)}</td><td>${esc(r.path)}</td><td>${esc(r.status ?? '—')}</td><td>${esc(r.state)}</td><td>${esc(r.source)}</td></tr>`).join('')}
       </tbody></table>`
    : '';

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security report — ${esc(target)}</title>
<style>
  body{font:14px/1.5 -apple-system,Inter,system-ui,sans-serif;color:#0f172a;max-width:820px;margin:32px auto;padding:0 20px}
  h1{font-size:24px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #e2e8f0;padding-bottom:6px}
  h3{font-size:14.5px;margin:0 0 6px}
  .meta{color:#475569;margin:0 0 18px}
  .summary{display:flex;gap:12px;margin:14px 0}
  .box{border:1px solid #e2e8f0;border-radius:8px;padding:10px 16px;text-align:center}
  .box b{display:block;font-size:22px}
  .finding{border:1px solid #e2e8f0;border-radius:8px;padding:12px 14px;margin:10px 0;break-inside:avoid}
  .sev{color:#fff;font-size:11px;padding:2px 8px;border-radius:12px;margin-right:6px;text-transform:uppercase}
  .label{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#64748b;margin:10px 0 2px}
  pre{background:#f1f5f9;border-radius:6px;padding:10px;white-space:pre-wrap;word-break:break-word;font-size:12px;margin:0}
  table{border-collapse:collapse;width:100%;font-size:12.5px} th,td{border:1px solid #e2e8f0;padding:5px 8px;text-align:left}
  .actions{margin-bottom:18px} button{font:inherit;padding:8px 14px;border-radius:6px;border:1px solid #cbd5e1;background:#fff;cursor:pointer}
  @media print{.actions{display:none} body{margin:0}}
</style></head>
<body>
  <div class="actions"><button id="print-btn" type="button">Print / Save as PDF</button></div>
  <h1>Security scan report</h1>
  <p class="meta">Target: <b>${esc(target)}</b>${stack ? ` · Stack: ${esc(stack)}` : ''} · Generated ${esc(generatedAt)}</p>
  <div class="summary">
    <div class="box"><b>${esc(riskScore)}</b>Risk score</div>
    <div class="box"><b>${sorted.length}</b>Findings</div>
    <div class="box"><b>${counts.Critical}</b>Critical</div>
    <div class="box"><b>${counts.High}</b>High</div>
    <div class="box"><b>${counts.Medium}</b>Medium</div>
    <div class="box"><b>${counts.Low}</b>Low</div>
  </div>
  <h2>Findings</h2>
  ${findingHtml || '<p>No issues found by the checks that ran.</p>'}
  ${routeHtml}
  <p class="meta">Automated checks only. This is not a penetration test; confirm each finding before acting.</p>
  <script src="/print.js"></script>
</body></html>`;
}

function saveReport(payload) {
  const html = buildReportHtml(payload);
  const id = crypto.randomBytes(8).toString('hex');
  store.set(id, html);
  if (store.size > MAX_REPORTS) store.delete(store.keys().next().value);
  return id;
}

function getReport(id) {
  return store.get(id) || null;
}

module.exports = { saveReport, getReport, buildReportHtml };
