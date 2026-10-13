// Turns a finding into (a) an LLM-ready fix prompt and (b) where possible a
// concrete patch snippet for the detected stack. Patches are templates, not
// verified against the target's real code — the UI labels them as such.
const { HEADER_VALUES } = require('./http');

const HEADER_NAMES = {
  'content-security-policy': 'Content-Security-Policy',
  'x-frame-options': 'X-Frame-Options',
  'strict-transport-security': 'Strict-Transport-Security',
  'x-content-type-options': 'X-Content-Type-Options',
  'referrer-policy': 'Referrer-Policy',
  'permissions-policy': 'Permissions-Policy',
};

function headerPatch(key, stack) {
  const name = HEADER_NAMES[key];
  const value = HEADER_VALUES[key];
  if (stack === 'Next.js') {
    return { file: 'next.config.js', language: 'js', code:
`module.exports = {
  async headers() {
    return [{
      source: '/(.*)',
      headers: [{ key: '${name}', value: ${JSON.stringify(value)} }],
    }];
  },
};` };
  }
  if (stack === 'nginx') {
    return { file: 'nginx.conf (server block)', language: 'nginx', code: `add_header ${name} ${JSON.stringify(value)} always;` };
  }
  return { file: 'server entry (Express)', language: 'js', code:
`app.use((req, res, next) => {
  res.setHeader('${name}', ${JSON.stringify(value)});
  next();
});` };
}

function patchFor(f, stack) {
  const id = f.id || '';
  if (id.startsWith('header-')) {
    const key = id.slice('header-'.length);
    if (HEADER_NAMES[key]) return headerPatch(key, stack);
  }
  if (id === 'cors-wildcard') {
    return { file: 'server entry (Express + cors)', language: 'js', code:
`const cors = require('cors');
const TRUSTED = (process.env.TRUSTED_ORIGINS || '').split(',').filter(Boolean);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || TRUSTED.includes(origin)),
}));` };
  }
  if (id === 'cookie-flags') {
    return { file: 'wherever the cookie is set', language: 'js', code:
`res.cookie('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
});` };
  }
  if (id === 'rate-limit') {
    return { file: 'server entry (Express + express-rate-limit)', language: 'js', code:
`const rateLimit = require('express-rate-limit');
app.use('/api/', rateLimit({ windowMs: 60_000, max: 60, standardHeaders: true }));
app.use('/api/auth', rateLimit({ windowMs: 15 * 60_000, max: 10 }));` };
  }
  if (id === 'source-map') {
    if (stack === 'Next.js') return { file: 'next.config.js', language: 'js', code: 'module.exports = { productionBrowserSourceMaps: false };' };
    return { file: 'vite.config.js', language: 'js', code: 'export default { build: { sourcemap: false } };' };
  }
  if (id.startsWith('exposed-/.env') || id.startsWith('exposed-/.git')) {
    return { file: 'nginx.conf (server block)', language: 'nginx', code: 'location ~ /\\.(env|git) {\n  deny all;\n  return 404;\n}' };
  }
  if (id.startsWith('js-secret-')) {
    return { file: 'server code + env config', language: 'text', code:
`# 1. Rotate the leaked key in the provider dashboard NOW.
# 2. Keep the new key server-side only (no NEXT_PUBLIC_/VITE_/REACT_APP_ prefix).
# 3. Call the provider from an API route/server action, never from browser code.` };
  }
  return null;
}

function buildPrompt(f, stack) {
  const lines = [
    `You are a senior application security engineer. Fix the following vulnerability in my ${stack || 'web'} application.`,
    '',
    `Finding: ${f.title}`,
    `Severity: ${f.severity}`,
    `Evidence: ${f.evidence}`,
    `Recommended direction: ${f.fix}`,
    '',
    'Requirements:',
    '- Find the code responsible in this repository before changing anything.',
    '- Make the smallest change that fully closes the issue; do not refactor unrelated code.',
    '- Show the diff and explain in one or two sentences why it closes the hole.',
    '- Add or update a test that fails before the fix and passes after, if the project has tests.',
    '- Tell me how to verify the fix against the running app.',
  ];
  return lines.join('\n');
}

function annotateFindings(findings, stack) {
  return findings.map((f) => {
    const patch = patchFor(f, stack);
    return { ...f, aiPrompt: buildPrompt(f, stack), ...(patch ? { patch } : {}) };
  });
}

module.exports = { annotateFindings, patchFor, buildPrompt };
