// Local scan-history store: one JSON file on disk, keyed by target. Powers
// re-scan diffing and the risk-score trend. ponytail: flat JSON file, not a
// DB — this is a single-user local tool, swap for sqlite if that changes.
const fs = require('fs');
const path = require('path');

const HISTORY_FILE = path.join(__dirname, '.scan-history.json');
const MAX_RECORDS_PER_TARGET = 20;

function load() {
  try {
    return JSON.parse(fs.readFileSync(HISTORY_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function save(data) {
  fs.writeFileSync(HISTORY_FILE, JSON.stringify(data, null, 2));
}

function normalizeTarget(target) {
  return target.trim().toLowerCase().replace(/\/$/, '');
}

// Returns the most recent prior record for this target (before this call
// adds a new one), plus appends the new record and prunes to the cap.
function recordScan(target, { findings, riskScore }) {
  const key = normalizeTarget(target);
  const data = load();
  const prior = (data[key] && data[key][data[key].length - 1]) || null;

  const record = {
    timestamp: new Date().toISOString(),
    riskScore,
    findingIds: findings.map((f) => f.id),
  };
  data[key] = [...(data[key] || []), record].slice(-MAX_RECORDS_PER_TARGET);
  save(data);

  return prior;
}

function diffAgainst(prior, findings) {
  if (!prior) return null;
  const currentIds = new Set(findings.map((f) => f.id));
  const priorIds = new Set(prior.findingIds);
  const fixed = prior.findingIds.filter((id) => !currentIds.has(id));
  const newOnes = findings.filter((f) => !priorIds.has(f.id)).map((f) => f.id);
  return { fixed, new: newOnes, priorRiskScore: prior.riskScore, priorTimestamp: prior.timestamp };
}

function getTrend(target) {
  const key = normalizeTarget(target);
  const data = load();
  return (data[key] || []).map((r) => ({ timestamp: r.timestamp, riskScore: r.riskScore }));
}

module.exports = { recordScan, diffAgainst, getTrend, normalizeTarget };
