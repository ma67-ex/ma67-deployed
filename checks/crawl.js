// Attack-surface mapping: discovers routes the way a visitor/crawler would
// (links, forms, sitemap.xml, robots.txt, and "/api/..." string literals inside
// the target's own JS bundles), then does one plain GET per route to record
// its status. Passive and bounded: same-origin only, GET only, hard caps on
// pages, bundles and probes. Runs against any authorized target.
const { finding, fetchSafe } = require('./http');

const MAX_PAGES = 12;
const MAX_BUNDLES = 6;
const MAX_PROBES = 30;
const MAX_BYTES = 600_000;

const API_LITERAL_RE = /["'`](\/(?:api|v\d+|admin|internal|auth|graphql|rest|dashboard|account|users?|webhooks?|debug|health|metrics|_next\/data)(?:\/[A-Za-z0-9_\-.]+)*)["'`]/g;
const SENSITIVE_RE = /admin|internal|debug|metrics|actuator|phpinfo|console|backup|\.git|\.env|swagger|graphql/i;

function detectStack(res, html) {
  const powered = (res.headers.get('x-powered-by') || '').toLowerCase();
  const server = (res.headers.get('server') || '').toLowerCase();
  if (powered.includes('next') || /\/_next\/static\//.test(html)) return 'Next.js';
  if (/\/_nuxt\//.test(html)) return 'Nuxt';
  if (/wp-content|wp-includes/.test(html)) return 'WordPress';
  if (powered.includes('express')) return 'Express';
  if (powered.includes('php')) return 'PHP';
  if (/\/assets\/index-[\w-]+\.js/.test(html)) return 'Vite';
  if (server.includes('nginx')) return 'nginx';
  return null;
}

function toPath(href, base) {
  try {
    const u = new URL(href, base);
    if (u.origin !== new URL(base).origin) return null;
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    return u.pathname || '/';
  } catch {
    return null;
  }
}

function classify(status) {
  if (status === null) return 'unreachable';
  if (status === 401 || status === 403) return 'protected';
  if (status >= 200 && status < 300) return 'open';
  if (status >= 300 && status < 400) return 'redirect';
  if (status === 404) return 'not-found';
  return 'error';
}

async function discoverRoutes(base) {
  const routes = new Map(); // path -> { path, status, state, source }
  const note = (path, source) => {
    if (!path || routes.has(path)) return;
    routes.set(path, { path, method: 'GET', status: null, state: 'unprobed', source });
  };

  const home = await fetchSafe(base);
  if (!home) return { routes: [], stack: null, findings: [] };
  const homeHtml = (await home.text().catch(() => '')).slice(0, MAX_BYTES);
  const stack = detectStack(home, homeHtml);
  note('/', 'entry');

  // Pass 1: crawl HTML pages breadth-first for links/forms/scripts.
  const queue = ['/'];
  const visited = new Set();
  const bundles = new Set();
  const htmlCache = { '/': homeHtml };
  while (queue.length && visited.size < MAX_PAGES) {
    const path = queue.shift();
    if (visited.has(path)) continue;
    visited.add(path);
    let html = htmlCache[path];
    if (html === undefined) {
      const r = await fetchSafe(base + path);
      const ct = (r && r.headers.get('content-type')) || '';
      if (!r || r.status !== 200 || !ct.includes('text/html')) continue;
      html = (await r.text().catch(() => '')).slice(0, MAX_BYTES);
    }
    for (const m of html.matchAll(/(?:href|action)=["']([^"'#]+)["']/gi)) {
      const p = toPath(m[1], base);
      if (!p || /\.(css|png|jpe?g|svg|ico|woff2?|gif|webp)$/i.test(p)) continue;
      note(p, 'link');
      if (!visited.has(p) && queue.length < 40) queue.push(p);
    }
    for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
      const p = toPath(m[1], base);
      if (p && bundles.size < MAX_BUNDLES) bundles.add(p);
    }
  }

  // Pass 2: sitemap + robots.
  const sm = await fetchSafe(base + '/sitemap.xml');
  if (sm && sm.status === 200) {
    const xml = (await sm.text().catch(() => '')).slice(0, MAX_BYTES);
    for (const m of xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/g)) note(toPath(m[1], base), 'sitemap');
  }
  const rb = await fetchSafe(base + '/robots.txt');
  if (rb && rb.status === 200) {
    const txt = (await rb.text().catch(() => '')).slice(0, 50_000);
    for (const m of txt.matchAll(/(?:Dis)?[Aa]llow:\s*(\/\S*)/g)) {
      const p = m[1].replace(/[*$].*$/, '');
      if (p && p !== '/') note(p, 'robots');
    }
  }

  // Pass 3: API paths hiding in JS bundles.
  for (const bundle of bundles) {
    const r = await fetchSafe(base + bundle);
    if (!r || r.status !== 200) continue;
    const js = (await r.text().catch(() => '')).slice(0, MAX_BYTES);
    for (const m of js.matchAll(API_LITERAL_RE)) note(m[1], 'js-bundle');
  }

  // Probe each discovered route once with a plain GET.
  let probes = 0;
  for (const route of routes.values()) {
    if (probes >= MAX_PROBES) break;
    probes++;
    const r = await fetchSafe(base + route.path);
    route.status = r ? r.status : null;
    route.state = classify(route.status);
  }

  const list = [...routes.values()].slice(0, 120);
  const findings = [];
  const exposed = list.filter((r) => r.state === 'open' && SENSITIVE_RE.test(r.path) && r.source !== 'entry');
  for (const r of exposed.slice(0, 5)) {
    findings.push(finding(`route-sensitive-${r.path}`, `Sensitive-looking route is publicly reachable: ${r.path}`, 'Medium',
      `GET ${r.path} returned ${r.status} without credentials (discovered via ${r.source}).`,
      'Put the route behind authentication/authorization, or remove it from production builds. Do not rely on obscurity.'));
  }
  const hidden = list.filter((r) => r.source === 'js-bundle' && r.state === 'open' && /^\/api\//.test(r.path));
  if (hidden.length) {
    findings.push(finding('route-hidden-api', `${hidden.length} API route${hidden.length > 1 ? 's' : ''} found in JS bundles respond without auth`, 'Low',
      `Reachable with no credentials: ${hidden.slice(0, 6).map((r) => r.path).join(', ')}`,
      'Confirm each of these is meant to be public. Anything that returns user or account data needs authentication and per-object authorization.'));
  }
  return { routes: list, stack, findings };
}

module.exports = { discoverRoutes, classify, detectStack };
