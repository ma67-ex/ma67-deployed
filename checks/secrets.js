// Scans the target's own frontend JavaScript for leaked secrets (the
// "Exposed API Key Checker"). Read-only: fetches the homepage and up to
// MAX_SCRIPTS same-origin bundles, regex-matches, and reports every hit
// MASKED — a usable secret is never returned or stored. Public-by-design keys
// (Stripe publishable, Supabase anon) are deliberately not in the pattern list.
const { finding, fetchSafe } = require('./http');

const MAX_SCRIPTS = 10;
const MAX_BYTES = 1_500_000;

// [label, regex, severity]. Order matters: Anthropic before OpenAI because an
// sk-ant- key also satisfies the generic sk- shape.
const PATTERNS = [
  ['Stripe secret key', /\bsk_live_[0-9a-zA-Z]{20,}/g, 'Critical'],
  ['Stripe restricted key', /\brk_live_[0-9a-zA-Z]{20,}/g, 'Critical'],
  ['Anthropic API key', /\bsk-ant-[A-Za-z0-9_-]{32,}/g, 'Critical'],
  ['OpenAI API key', /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/g, 'Critical'],
  ['AWS access key ID', /\bAKIA[0-9A-Z]{16}\b/g, 'Critical'],
  ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}/g, 'Critical'],
  ['Slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}/g, 'High'],
  ['Google API key', /\bAIza[0-9A-Za-z_-]{35}\b/g, 'Medium'],
  ['Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, 'Critical'],
  ['Database connection string', /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^\s"'`<>\\]*:[^\s"'`<>@\\]+@[^\s"'`<>\\]+/g, 'Critical'],
];

const JWT_RE = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

function mask(s) {
  if (s.length <= 12) return `${s.slice(0, 2)}…(${s.length} chars)`;
  return `${s.slice(0, 6)}…${s.slice(-4)} (${s.length} chars)`;
}

function jwtRole(token) {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return payload.role || null;
  } catch {
    return null;
  }
}

// Pure function so it can be unit-tested without a network.
function scanText(text, where) {
  const hits = [];
  const seen = new Set();
  const add = (label, value, severity) => {
    const key = `${label}:${value}`;
    if (seen.has(key)) return;
    seen.add(key);
    hits.push({ label, masked: mask(value), severity, where });
  };
  for (const [label, re, severity] of PATTERNS) {
    for (const m of text.matchAll(re)) {
      if (label === 'OpenAI API key' && m[0].startsWith('sk-ant-')) continue;
      add(label, m[0], severity);
    }
  }
  for (const m of text.matchAll(JWT_RE)) {
    if (jwtRole(m[0]) === 'service_role') add('Supabase service-role key', m[0], 'Critical');
  }
  return hits;
}

async function collectScripts(base) {
  const res = await fetchSafe(base);
  if (!res) return [];
  const html = (await res.text().catch(() => '')).slice(0, MAX_BYTES);
  const sources = [{ where: '/ (inline HTML)', text: html }];
  const urls = [...html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)].map((m) => m[1]);
  const origin = new URL(base).origin;
  const unique = [];
  for (const src of urls) {
    let abs;
    try { abs = new URL(src, base); } catch { continue; }
    if (abs.origin !== origin) continue; // third-party scripts are not the target's secrets
    if (!unique.includes(abs.toString())) unique.push(abs.toString());
    if (unique.length >= MAX_SCRIPTS) break;
  }
  for (const url of unique) {
    const r = await fetchSafe(url);
    if (!r || r.status !== 200) continue;
    const text = (await r.text().catch(() => '')).slice(0, MAX_BYTES);
    sources.push({ where: new URL(url).pathname, text });
  }
  return sources;
}

async function findSecrets(base) {
  const sources = await collectScripts(base);
  return sources.flatMap((s) => scanText(s.text, s.where));
}

async function checkJsSecrets(base) {
  const hits = await findSecrets(base);
  return hits.map((h, i) => finding(
    `js-secret-${h.label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${i}`,
    `${h.label} exposed in frontend JavaScript`,
    h.severity,
    `${h.where} contains ${h.label}: ${h.masked}`,
    'Treat the key as compromised: rotate it now, then move it server-side so it never ships to the browser. Do not prefix server secrets with NEXT_PUBLIC_ / VITE_ / REACT_APP_.',
  ));
}

module.exports = { scanText, findSecrets, checkJsSecrets, mask };
