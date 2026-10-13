// Security-header grader (the "Security Headers Checker" free tool): one GET,
// scores the six headers that matter, flags weak values and info-leaking
// headers, and returns a letter grade.
const { HEADER_VALUES, fetchSafe } = require('./http');

const SPEC = [
  { key: 'content-security-policy', label: 'Content-Security-Policy', weight: 27, why: 'Strongest browser-side defense against XSS.' },
  { key: 'strict-transport-security', label: 'Strict-Transport-Security', weight: 22, why: 'Stops protocol downgrade to plain HTTP.' },
  { key: 'x-content-type-options', label: 'X-Content-Type-Options', weight: 17, why: 'Stops MIME-sniffing of responses.' },
  { key: 'x-frame-options', label: 'X-Frame-Options', weight: 17, why: 'Blocks clickjacking by other sites framing the page.' },
  { key: 'referrer-policy', label: 'Referrer-Policy', weight: 17, why: 'Limits URL leakage to third parties.' },
];

function judge(key, value, allHeaders) {
  const v = value.toLowerCase();
  if (key === 'content-security-policy') {
    if (/unsafe-eval/.test(v) || /(^|[\s;])script-src[^;]*'unsafe-inline'/.test(v)) return ['weak', "script-src allows 'unsafe-inline'/'unsafe-eval', which undoes most XSS protection."];
    if (/default-src\s+\*|script-src\s+\*/.test(v)) return ['weak', 'Wildcard source allows scripts from anywhere.'];
  }
  if (key === 'strict-transport-security') {
    const age = Number((v.match(/max-age=(\d+)/) || [])[1] || 0);
    if (age < 15552000) return ['weak', `max-age=${age} is under 6 months; use 31536000 or more.`];
  }
  if (key === 'x-frame-options' && !/deny|sameorigin/.test(v)) return ['weak', 'Use DENY or SAMEORIGIN.'];
  if (key === 'x-content-type-options' && v.trim() !== 'nosniff') return ['weak', 'Value must be nosniff.'];
  if (key === 'referrer-policy' && /unsafe-url|no-referrer-when-downgrade/.test(v)) return ['weak', 'Policy still leaks full URLs cross-origin.'];
  return ['pass', null];
}

function gradeFor(score) {
  if (score >= 95) return 'A+';
  if (score >= 85) return 'A';
  if (score >= 70) return 'B';
  if (score >= 55) return 'C';
  if (score >= 35) return 'D';
  return 'F';
}

// Pure so it can be tested without a network. `get(name)` returns a header
// value or null.
function gradeHeaders(get) {
  let score = 0;
  const headers = SPEC.map((s) => {
    let value = get(s.key);
    let status = 'missing';
    let note = s.why;
    // A CSP frame-ancestors directive is an equivalent of X-Frame-Options.
    if (!value && s.key === 'x-frame-options') {
      const csp = get('content-security-policy') || '';
      if (/frame-ancestors/i.test(csp)) { value = '(via CSP frame-ancestors)'; }
    }
    if (value) {
      const [st, why] = judge(s.key, value);
      status = st;
      if (why) note = why;
      score += st === 'pass' ? s.weight : Math.round(s.weight / 2);
    }
    return { name: s.label, key: s.key, present: !!value, value: value || null, status, note, recommended: HEADER_VALUES[s.key] };
  });
  const leaks = [];
  for (const k of ['server', 'x-powered-by', 'x-aspnet-version']) {
    const v = get(k);
    if (v && /\d/.test(v)) leaks.push({ name: k, value: v });
  }
  return { score, grade: gradeFor(score), headers, leaks };
}

async function checkHeaderGrade(base) {
  const res = await fetchSafe(base);
  if (!res) return null;
  return { target: base, status: res.status, ...gradeHeaders((k) => res.headers.get(k)) };
}

module.exports = { gradeHeaders, checkHeaderGrade, gradeFor };
