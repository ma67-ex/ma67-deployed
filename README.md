# Ma67-Deployed

A self-hosted, free, no-login clone of [deploysafe.io](https://deploysafe.io)'s
scanning UI. Runs entirely on your own machine against targets you control.

## What it does

**Live URL scan** (`/`, top of page): 25 check modules against a running app.
- 8 passive checks (headers, CORS, exposed `.env`/`.git`, cookies, robots.txt,
  HTTP methods, source maps, rate-limit signal) — these can run against
  `localhost` freely, or against a public domain you own once you check the
  "I own this domain" box.
- 17 attack-simulation checks (SQL/NoSQL injection, auth bypass, path
  traversal, Supabase RLS, Firebase rules, CSRF, webhook spoofing, etc.) —
  these **only ever run against `localhost`/`127.0.0.1`**, regardless of the
  attestation checkbox. There's no way to point them at someone else's site
  through this UI.

**Codebase audit** (further down the page): the 16-item static checklist from
the `security-checklist-audit` Claude Code skill, run against source code
instead of a live URL. Three ways to give it code:
- a local path on the machine running the server
- a `.zip` you upload from the browser
- a public GitHub repo URL (shallow-cloned, scanned, then deleted)

This mode reads files, it doesn't send network probes, so there's no
ownership gate — same trust model as running the skill directly yourself.

One input box routes to the right mode automatically: a URL runs the live
scan, a `github.com/owner/repo` link runs the codebase audit against a
shallow clone, anything else is treated as a local path, and the 📎 button
uploads a `.zip` for the same audit.

**Dependency Scan** does a real CVE lookup: pinned versions in an exposed
`package.json` are checked against [OSV.dev](https://osv.dev)'s free API, not
just flagged as "exposed."

**Every scan is remembered** (`.scan-history.json`, gitignored, local only):
- **Re-scan** button reruns the last target with one click
- results show a diff badge (`✓ N fixed` / `⚠ N new`) against the previous scan
- a risk-score trend line once a target's been scanned more than once
- **Export report** downloads the current findings as a Markdown file

## Install & run

Requires Node.js, plus `git` and `unzip` on your `PATH` (both ship with
macOS/Linux by default) for the GitHub-URL and zip-upload audit modes.

```bash
git clone <this-repo-url>
cd deploysafe-clone
npm install
node server.js
```

Then open `http://localhost:4100`.

To verify the install: `node test_smoke.js` while the server's running —
checks the auth gate, GitHub-URL validation, codebase audit, and a clean
self-scan.

## Safety model

- The 17 attack-simulation modules are hard-gated to literal `localhost` /
  `127.0.0.1` / `::1` in `server.js` — the ownership checkbox in the UI
  **cannot** unlock them for a public target. Don't remove that gate; it's
  the only thing standing between this tool and "one-click attack any URL."
- The codebase-audit verdicts are an unreviewed heuristic (regex matches,
  auto-classified PASS/FAIL/NEEDS REVIEW with no human or LLM reading the
  matched files). Treat them as leads, not confirmed findings — same caveat
  the underlying skill gives when run directly.
- Zip uploads are capped at 50MB and extracted to a temp dir that's deleted
  after the scan. GitHub clones are shallow (`--depth 1`) and also deleted
  after. Neither mode executes the scanned code — the audit is static
  (regex over file contents), not a sandboxed run.

## Credit

Modeled on [deploysafe.io](https://deploysafe.io)'s public landing page and
feature set, for local/educational use. Not affiliated with DeploySafe.

## About the name

"Ma67-Deployed" — a nod to ma67-ex (the author's handle), not DeploySafe's own branding.
