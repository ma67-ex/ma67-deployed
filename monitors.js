// Scheduled monitoring: a list of targets that are re-scanned on an interval
// and on demand (a CI "deploy" step can POST to the trigger endpoint). One
// flat JSON file, same trade-off as history.js. Auth headers are deliberately
// NOT persisted here — a cookie on disk is a liability, so monitors scan the
// unauthenticated surface only.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const FILE = path.join(__dirname, '.monitors.json');
const MAX_MONITORS = 10;
const MIN_INTERVAL_MIN = 15;
const TICK_MS = 60_000;

function load() {
  try { return JSON.parse(fs.readFileSync(FILE, 'utf8')); } catch { return []; }
}
function save(list) {
  fs.writeFileSync(FILE, JSON.stringify(list, null, 2));
}

function list() {
  return load();
}

function add({ url, attested, intervalMinutes }) {
  const all = load();
  if (all.length >= MAX_MONITORS) {
    const err = new Error(`Monitor limit reached (${MAX_MONITORS}).`);
    err.code = 'LIMIT';
    throw err;
  }
  const origin = new URL(url).origin;
  if (all.some((m) => m.url === origin)) {
    const err = new Error('That app is already monitored.');
    err.code = 'DUPLICATE';
    throw err;
  }
  const minutes = Math.max(MIN_INTERVAL_MIN, Math.min(Number(intervalMinutes) || 360, 7 * 24 * 60));
  const monitor = {
    id: crypto.randomBytes(6).toString('hex'),
    url: origin,
    attested: attested === true,
    intervalMinutes: minutes,
    createdAt: new Date().toISOString(),
    lastRunAt: null,
    lastRiskScore: null,
    lastFindingCount: null,
    lastNewFindings: 0,
    lastTrigger: null,
  };
  all.push(monitor);
  save(all);
  return monitor;
}

function remove(id) {
  const all = load();
  const next = all.filter((m) => m.id !== id);
  if (next.length === all.length) return false;
  save(next);
  return true;
}

function get(id) {
  return load().find((m) => m.id === id) || null;
}

function recordRun(id, { riskScore, findingCount, newCount, trigger }) {
  const all = load();
  const m = all.find((x) => x.id === id);
  if (!m) return null;
  m.lastRunAt = new Date().toISOString();
  m.lastRiskScore = riskScore;
  m.lastFindingCount = findingCount;
  m.lastNewFindings = newCount;
  m.lastTrigger = trigger;
  save(all);
  return m;
}

function due(now = Date.now()) {
  return load().filter((m) => !m.lastRunAt || now - Date.parse(m.lastRunAt) >= m.intervalMinutes * 60_000);
}

// runFn(monitor, trigger) must never throw into the timer; errors are logged.
function startScheduler(runFn) {
  let busy = false;
  const timer = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
      for (const m of due()) {
        try { await runFn(m, 'schedule'); } catch (e) { console.error(`monitor ${m.id} failed:`, e.message); }
      }
    } finally {
      busy = false;
    }
  }, TICK_MS);
  timer.unref();
  return timer;
}

module.exports = { list, add, remove, get, recordRun, due, startScheduler, MIN_INTERVAL_MIN };
