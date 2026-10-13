"""
Heuristic static scanner for the 16-item security checklist.

Walks a repo directory, applies regex-based checks per checklist item, and
prints JSON with positive evidence (mitigation present) and negative evidence
(risky pattern present) per item, each with file:line and a snippet.

This is pattern-matching, not real static analysis (no AST, no data-flow).
It will miss things and it will flag things that turn out to be fine on
closer read. Its job is to point a human (or the calling skill) at the right
files fast, not to be the final word. Treat every match as a lead, not a verdict.

Usage: python3 scan.py <repo_path>
"""
import argparse
import json
import os
import re
import sys
EXCLUDE_DIRS = {
    "node_modules", ".git", ".next", "dist", "build", "out", "coverage",
    ".vercel", ".turbo", "venv", ".venv", "__pycache__", ".cache",
    "vendor", "target", ".pytest_cache", ".idea", ".vscode",
}
CODE_EXTS = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
    ".py", ".php", ".rb", ".go", ".java",
}
MAX_FILE_BYTES = 1_500_000
def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS and not d.startswith(".git")]
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            yield full
def is_scannable(path):
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path).lower()
    if ext in CODE_EXTS:
        return True
    if base in ("next.config.js", "next.config.mjs", "next.config.ts", "vercel.json",
                "package.json", ".env", ".env.local", ".env.example", ".env.production",
                "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
                "gemfile.lock", "go.sum"):
        return True
    if base.startswith(".env"):
        return True
    return False
def read_text(path):
    try:
        if os.path.getsize(path) > MAX_FILE_BYTES:
            return None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except OSError:
        return None
def is_frontend_path(path):
    p = path.replace("\\", "/").lower()
    backend_only_markers = ("/pages/api/", "/app/api/", "/server/", "/routes/",
                             "/middleware/", "/api/")
    return not any(m in p for m in backend_only_markers)
def is_api_route(path):
    p = path.replace("\\", "/").lower()
    return ("/pages/api/" in p) or ("/app/api/" in p and p.endswith(("route.js", "route.ts", "route.jsx", "route.tsx"))) or "/routes/" in p
COMMENT_LINE_PREFIXES = ("//", "#", "*", "/*")
def find_matches(text, pattern, path, flags=re.IGNORECASE):
    out = []
    for m in re.finditer(pattern, text, flags):
        line_no = text.count("\n", 0, m.start()) + 1
        line = text.splitlines()[line_no - 1].strip()
        if line.startswith(COMMENT_LINE_PREFIXES):
            continue
        out.append({"file": path, "line": line_no, "snippet": line[:160]})
    return out
class Item:
    def __init__(self, id_, category, name):
        self.id = id_
        self.category = category
        self.name = name
        self.positive = []
        self.negative = []
        self.note = ""
    def to_dict(self):
        return {
            "id": self.id,
            "category": self.category,
            "item": self.name,
            "positive_evidence": self.positive[:15],
            "negative_evidence": self.negative[:15],
            "note": self.note,
        }
def scan(root):
    items = {i: Item(i, cat, name) for i, cat, name in [
        (1, "Frontend Security", "Use HTTPS everywhere"),
        (2, "Frontend Security", "Input validation and sanitization"),
        (3, "Frontend Security", "Don't store sensitive data in the browser"),
        (4, "Frontend Security", "CSRF protection"),
        (5, "Frontend Security", "Never expose API keys in frontend"),
        (6, "Backend Security", "Authentication fundamentals"),
        (7, "Backend Security", "Authorization checks"),
        (8, "Backend Security", "API endpoint protection"),
        (9, "Backend Security", "SQL injection prevention"),
        (10, "Backend Security", "Basic security headers"),
        (11, "Backend Security", "DDoS protection"),
        (12, "Practical Security Habits", "Keep dependencies updated"),
        (13, "Practical Security Habits", "Proper error handling"),
        (14, "Practical Security Habits", "Secure cookies"),
        (15, "Practical Security Habits", "File upload security"),
        (16, "Practical Security Habits", "Rate limiting"),
    ]}
    files = list(iter_files(root))
    scannable = [f for f in files if is_scannable(f)]
    api_route_files = [f for f in scannable if is_api_route(f)]
    has_orm = False
    has_db_driver_raw = False
    committed_env_files = []
    has_lockfile = False
    lockfile_path = None
    has_supabase = False
    has_firebase = False
    idor_suspects = []
    has_rate_limit_lib = False
    rate_limit_lib_files = []
    route_has_rate_limit = {}
    middleware_has_rate_limit = False
    has_secrets_vault = False
    has_bot_gate = False
    has_monitoring = False
    for path in scannable:
        rel = os.path.relpath(path, root)
        text = read_text(path)
        if text is None:
            continue
        base = os.path.basename(path).lower()
        if base in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt",
                    "gemfile.lock", "go.sum"):
            has_lockfile = True
            lockfile_path = rel
            continue
        frontend = is_frontend_path(path)
        api_route = is_api_route(path)
        items[1].negative += find_matches(text, r'["\'`]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|schemas?\.|www\.w3\.org|json-schema)[a-z0-9.\-]+', rel)
        items[1].positive += find_matches(text, r'(strict-transport-security|hsts|forceSSL|upgrade-insecure-requests)', rel)
        items[1].negative += find_matches(text, r'sslmode\s*=\s*disable|\bssl\s*:\s*false\b|rejectUnauthorized\s*:\s*false', rel)
        items[1].positive += find_matches(text, r'sslmode\s*=\s*require|\bssl\s*:\s*true\b|rejectUnauthorized\s*:\s*true', rel)
        items[2].negative += find_matches(text, r'dangerouslySetInnerHTML|\.innerHTML\s*=|document\.write\(|v-html=', rel)
        items[2].positive += find_matches(text, r'\b(zod|yup|joi|express-validator|DOMPurify|sanitize-html|validator\.js|z\.object\(|z\.string\(\))\b', rel)
        items[2].negative += find_matches(text, r'\beval\(|new\s+Function\(|child_process|execSync\(|vm\.runInNewContext\(|vm\.runInContext\(', rel)
        items[2].negative += find_matches(
            text,
            r'(create|update|insert|set|save)\(\s*\{?\s*\.\.\.\s*(req|request)\.body\b'
            r'|(create|update|insert|set|save)\(\s*(req|request)\.body\s*\)',
            rel,
        )
        if re.search(r'login|signup|sign-up|register|signin|sign-in', rel, re.IGNORECASE) or re.search(r'\b(username|password)\b\s*[:=]', text):
            takes_identity_field = re.search(r'(req|request)\.body\.(username|email|password)\b|const\s*\{[^}]*\b(username|email|password)\b[^}]*\}\s*=\s*(await\s+)?(req|request)\.body', text)
            has_field_validation = re.search(r'\.test\(|z\.(string|object)\(|yup\.|joi\.|validator\.|\.trim\(\)\.length|\.match\(/', text)
            if takes_identity_field and not has_field_validation:
                items[2].negative.append({
                    "file": rel, "line": 1,
                    "snippet": "possible unvalidated identity field: username/email/password read from the request with no format-check pattern (regex .test/.match, zod/yup/joi schema, validator.js) found in this file -- read by hand, exploitability depends entirely on where this value goes next",
                })
        items[3].negative += find_matches(
            text,
            r'(localStorage|sessionStorage)\.setItem\(\s*["\'`][^"\'`]*'
            r'(token|password|secret|apikey|api_key|ssn|ccnum|credit|card|'
            r'email|phone|address|dob|birth|passport|licen[sc]e|'
            r'firstname|lastname|fullname|user(name|info|data)?)[^"\'`]*["\'`]',
            rel,
        )
        if frontend:
            for m in re.finditer(r'[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}', text):
                addr = m.group(0)
                low = addr.lower()
                if any(bad in low for bad in ("example.com", "example.org", "noreply", "no-reply",
                                              "your-domain", "yourdomain", "domain.com", "email.com",
                                              "sentry.io", "test@", "user@", "@test", "placeholder")):
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                items[3].negative.append({
                    "file": rel, "line": line_no,
                    "snippet": f"hardcoded email address in client code: {addr} -- visible verbatim in dev tools Sources; confirm it's an intentional public contact, not a real person's personal address",
                })
            items[3].negative += find_matches(text, r'\b\d{3}-\d{2}-\d{4}\b', rel, flags=0)
            items[3].negative += find_matches(text, r'["\'`]\d{13,16}["\'`]', rel, flags=0)
            items[3].negative += find_matches(
                text,
                r'window\.(__)?\w*(user|state|data|store|config|debug|auth|session)\w*(__)?\s*=',
                rel,
            )
        items[4].positive += find_matches(text, r'csrf|csurf|sameSite\s*:\s*["\']?(strict|lax)', rel)
        if frontend:
            items[5].negative += find_matches(
                text,
                r'\b(sk_live|sk_test|sk-proj-|sk-ant-|AIza[0-9A-Za-z_\-]{20,}|AKIA[0-9A-Z]{12,})[A-Za-z0-9_\-]*',
                rel, flags=0,
            )
            items[5].negative += find_matches(text, r'process\.env\.(NEXT_PUBLIC|VITE|REACT_APP|PUBLIC)_[A-Z0-9_]*(KEY|SECRET|TOKEN)[A-Z0-9_]*', rel, flags=0)
            items[5].negative += find_matches(text, r'SUPABASE_SERVICE_ROLE|service_role.{0,40}key|supabaseAdmin', rel)
            if "app/" in rel.replace("\\", "/") and '"use client"' not in text[:200] and "'use client'" not in text[:200]:
                if re.search(r'(process\.env\.|\.select\(|prisma\.\w+\.find|supabase\.from\()', text) and re.search(r'\{\.\.\.\w*(config|secret|key|env|credential)\w*\}|\w*(config|secret|key|credential)\w*\s*=\s*\{[^}]*\}\s*/?>', text, re.IGNORECASE):
                    items[5].negative.append({
                        "file": rel, "line": 1,
                        "snippet": "possible RSC payload leak: server-side fetch + object spread into JSX props in the same file -- read by hand, don't trust this regex alone",
                    })
        if base.startswith(".env") and "example" not in base:
            committed_env_files.append(rel)
        if re.search(r'@aws-sdk/client-secrets-manager|node-vault|@google-cloud/secret-manager|@1password/connect|infisical|doppler', text, re.IGNORECASE):
            has_secrets_vault = True
        if re.search(r'sec-fetch-site|sec-fetch-mode|turnstile|recaptcha|hcaptcha|cf-turnstile|@cloudflare/turnstile', text, re.IGNORECASE):
            has_bot_gate = True
        if re.search(r'@sentry/|Sentry\.init\(|datadog|logrocket|@rollbar|bugsnag|newrelic', text, re.IGNORECASE):
            has_monitoring = True
        items[6].positive += find_matches(text, r'\b(bcrypt|argon2|scrypt|next-auth|firebase/auth|passport|@clerk|supabase\.auth|getServerSession)\b', rel)
        items[6].negative += find_matches(text, r'password\s*===?\s*[a-zA-Z_]+\.password\b|md5\(.*password', rel)
        if re.search(r'@supabase/supabase-js|createClient\(.*supabase|NEXT_PUBLIC_SUPABASE', text, re.IGNORECASE):
            has_supabase = True
        if re.search(r'firebase/(app|firestore|auth)|initializeApp\(', text):
            has_firebase = True
        if api_route:
            items[7].positive += find_matches(text, r'\b(role|permission|isAdmin|requireRole|can\(|authorize\()\b', rel)
            takes_raw_id = re.search(r'(params\.id|query\.id|req\.query\[|searchParams\.get\(["\']id)', text)
            scopes_by_owner = re.search(r'\b(uid|userId|user_id|owner|session\.user|auth\(\))\b', text, re.IGNORECASE)
            if takes_raw_id and not scopes_by_owner:
                is_destructive = re.search(r'\.delete\(|deleteDoc\(|\.destroy\(|\.remove\(|DELETE\s+FROM|DROP\s+TABLE|\.deleteOne\(|\.deleteMany\(', text, re.IGNORECASE)
                if is_destructive:
                    idor_suspects.append({"file": rel, "line": 1, "snippet": "DESTRUCTIVE: route deletes/mutates by a raw id from the request with no owner/session check found in this file -- anyone who can guess or enumerate the id can delete someone else's data, read by hand before calling this a FAIL"})
                else:
                    idor_suspects.append({"file": rel, "line": 1, "snippet": "route reads an id from the request and queries/mutates by it with no owner/session check found in this file -- possible IDOR, read by hand"})
        if api_route:
            has_auth_check = bool(re.search(
                r'getServerSession|requireAuth|verifyToken|authMiddleware|req\.session|withAuth|checkAuth'
                r'|jwt\.verify\(|\.verify\(.*token|Authorization.{0,40}(===|!==|\.startsWith\(|split\()',
                text, re.IGNORECASE,
            ))
            if has_auth_check:
                items[8].positive.append({"file": rel, "line": 1, "snippet": "auth check present in route file"})
            else:
                items[8].negative.append({"file": rel, "line": 1, "snippet": "no auth-check pattern found in this API route file"})
            outbound_call = re.search(r'\b(fetch|axios(\.\w+)?|http\.get|https\.get|request)\(\s*[a-zA-Z_$][\w.]*\s*[,)]', text)
            has_req_input = re.search(r'req\.(body|query|params)\b|searchParams\.get\(', text, re.IGNORECASE)
            has_url_shaped_name = re.search(r'\b\w*(url|target|endpoint|dest|host|uri)\w*\b', text, re.IGNORECASE)
            if outbound_call and has_req_input and has_url_shaped_name:
                items[8].negative.append({"file": rel, "line": 1, "snippet": "possible SSRF: outbound HTTP call with a variable (not hardcoded string) destination, in a route that also reads request input into something URL/host-shaped -- verify the fetched destination is validated against an allowlist, not passed through raw"})
        items[9].negative += find_matches(
            text,
            r'(SELECT\s+.{0,200}?\s+FROM|INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM)\b[^;\n]{0,200}(\+\s*[a-zA-Z_]|\$\{[^}]+\})',
            rel, flags=re.IGNORECASE,
        )
        if re.search(r'\b(prisma|sequelize|knex|typeorm|mongoose)\b', text, re.IGNORECASE):
            has_orm = True
            items[9].positive += find_matches(text, r'\b(prisma|sequelize|knex|typeorm|mongoose)\b', rel)
        if re.search(r'\.query\(\s*["\'`][^"\'`]*\?[^"\'`]*["\'`]\s*,\s*\[', text):
            items[9].positive += find_matches(text, r'\.query\(\s*["\'`][^"\'`]*\?', rel)
        if re.search(r'\b(mysql|pg|sqlite3?)\b.*\.query\(', text, re.IGNORECASE):
            has_db_driver_raw = True
        items[10].positive += find_matches(text, r'(X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security|Content-Security-Policy|helmet\(\))', rel)
        if base == "vercel.json":
            items[11].note = "Deployed via Vercel config found -- Vercel provides platform-level DDoS mitigation by default."
        elif base in ("wrangler.toml", "wrangler.jsonc") or (base == "package.json" and "cloudflare" in text.lower()):
            items[11].note = "Cloudflare config/dependency found -- Cloudflare's network sits in front of the app and provides DDoS/WAF mitigation by default at the plan tier in use."
        items[13].negative += find_matches(text, r'\b(res|response)\.(json|send)\(\s*\{[^}]*\berr(or)?\.(message|stack)\b', rel)
        items[13].negative += find_matches(text, r'catch\s*\([a-zA-Z_]+\)\s*\{\s*(console\.(log|error)\([a-zA-Z_]+\);?\s*)?(res|response)\.(json|send)\([a-zA-Z_]+\)', rel)
        items[13].negative += find_matches(
            text,
            r'\b(console\.(log|info|debug|warn|error)|logger\.\w+)\([^)]*\b(password|token|secret|api[_-]?key|authorization)\b[^)]*\)',
            rel,
        )
        cookie_sets = find_matches(text, r'(res\.cookie\(|Set-Cookie|cookies\(\)\.set\()', rel)
        for c in cookie_sets:
            window = text[max(0, text.find(c["snippet"]) - 20): text.find(c["snippet"]) + 200] if c["snippet"] in text else ""
            if re.search(r'httpOnly\s*:\s*true', window, re.IGNORECASE) and re.search(r'secure\s*:\s*true', window, re.IGNORECASE):
                items[14].positive.append(c)
            else:
                items[14].negative.append(c)
        upload_hits = find_matches(text, r'\b(multer|formidable|busboy|createReadStream)\b|\bnew\s+FormData\(', rel)
        if upload_hits:
            has_validation_nearby = bool(re.search(r'(mimetype|fileFilter|maxFileSize|limits\s*:|accept\s*=)', text, re.IGNORECASE))
            if has_validation_nearby:
                items[15].positive += upload_hits
            else:
                items[15].negative += upload_hits
        rate_limit_hit = bool(re.search(
            r'\b(express-rate-limit|@upstash/ratelimit|next-rate-limit|slowDown|rate-limiter-flexible)\b'
            r'|[Rr]ate[-_]?[Ll]imit(er)?\('
            r'|from\s+[\'"][^\'"]*rate-?limit',
            text,
        ))
        if rate_limit_hit:
            has_rate_limit_lib = True
            rate_limit_lib_files.append(rel)
            if base in ("middleware.js", "middleware.ts", "middleware.mjs"):
                middleware_has_rate_limit = True
        if api_route:
            route_has_rate_limit[rel] = rate_limit_hit
    if committed_env_files:
        items[5].negative.append({"file": ", ".join(committed_env_files), "line": 0, "snippet": "non-example .env file present in repo (verify it's gitignored, not just present on disk)"})
    if not has_orm and has_db_driver_raw and not items[9].positive:
        items[9].note = "Raw DB driver used without ORM detected -- check parameterization manually."
    if idor_suspects:
        items[7].negative += idor_suspects[:15]
    for rel, hit in route_has_rate_limit.items():
        if hit:
            items[16].positive.append({"file": rel, "line": 1, "snippet": "rate-limit call/import found directly in this route file"})
        elif middleware_has_rate_limit:
            items[16].positive.append({"file": rel, "line": 1, "snippet": "no rate-limit reference in this route file, but middleware.ts applies rate limiting repo-wide -- verify this route is matched by its config"})
        elif has_rate_limit_lib:
            items[16].negative.append({"file": rel, "line": 1, "snippet": f"no rate-limit reference in this route file; a rate-limit library is used elsewhere in the repo ({rate_limit_lib_files[0]}) but not provably applied here -- needs review, not a confirmed pass"})
        else:
            items[16].negative.append({"file": rel, "line": 1, "snippet": "no rate limiting detected for this endpoint anywhere in the repo -- open to spam/brute-force"})
    if not api_route_files:
        no_api_note = "No server-side API route files detected (no /api or /routes dir) -- likely a client-only app or a different backend layer (e.g. BaaS like Firebase/Supabase). Mark N/A and verify manually."
        items[7].note = no_api_note
        items[8].note = no_api_note
        items[16].note = no_api_note
    baas_note = None
    if has_supabase:
        baas_note = "Supabase detected -- access control lives in Row Level Security (RLS) policies configured in the Supabase dashboard/migrations, not in this repo's JS. A table with RLS off is readable/writable by anyone holding the anon key (which is meant to be public). Check for RLS policy definitions (SQL migrations with 'ENABLE ROW LEVEL SECURITY' / 'CREATE POLICY') or verify in the dashboard before calling item 7 a pass."
    elif has_firebase:
        baas_note = "Firebase detected -- access control lives in Firestore/Storage Security Rules, not in this repo's JS. Look for a firestore.rules / storage.rules file in the repo; if absent, the rules only exist in the Firebase console and can't be verified from code alone."
    if baas_note:
        items[7].note = (items[7].note + " " if items[7].note else "") + baas_note
    items[12].note = f"Lockfile found: {lockfile_path}" if has_lockfile else "No lockfile found in scanned tree."
    items[12].note += (" This script does not check a live vulnerability database (no network calls) -- run `npm audit` / `pip-audit` manually for CVE data."
                        " AI-generated projects commonly pin whatever dependency version was current in the model's training data, which can be a year or more stale by the time you're reading this -- worth an actual `npm outdated` check, not just a lockfile-exists check.")
    vault_note = ("Dedicated secrets vault detected (AWS Secrets Manager / GCP Secret Manager / Vault / 1Password Connect / Infisical / Doppler)." if has_secrets_vault
                  else "No dedicated secrets vault detected -- secrets likely live in .env / platform env vars only. Fine at small/personal-project scale; worth a real vault before handling other people's data in production.")
    items[5].note = (items[5].note + " " if items[5].note else "") + vault_note
    if has_bot_gate:
        items[8].note = (items[8].note + " " if items[8].note else "") + "Bot/abuse gating detected (Sec-Fetch-Site/Origin check or a challenge widget) -- distinct from item 16's rate limiting, this identifies non-human callers before doing any work."
    monitoring_note = ("Error monitoring detected (Sentry/Datadog/LogRocket/Rollbar/Bugsnag/New Relic)." if has_monitoring
                        else "No error monitoring/observability tool detected -- distinct from item 13's own description (not leaking errors to the client): this is about whether anyone finds out server-side when something breaks. Not a vulnerability by itself, worth a note for anything beyond a personal project.")
    items[13].note = (items[13].note + " " if items[13].note else "") + monitoring_note
    if not any(f.lower().endswith("vercel.json") or "cloudflare" in f.lower() for f in files):
        items[11].note = items[11].note or "No CDN/edge config detected in repo -- DDoS mitigation is an infra-level concern, verify at the hosting/platform layer, not in code."
    return [items[i].to_dict() for i in sorted(items)]
AGENT_INSTRUCTION_FILES = {
    "agents.md", "claude.md", ".cursorrules", ".windsurfrules", ".clinerules",
    "copilot-instructions.md",
}
SUSPICIOUS_DIRECTIVE_PATTERN = re.compile(
    r'(ignore\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions'
    r'|disregard\s+(previous|prior|your)\s+(instructions|guidelines)'
    r'|curl\s+[^\n|]{0,80}\|\s*(sh|bash)'
    r'|wget\s+[^\n|]{0,80}\|\s*(sh|bash)'
    r'|base64\s+-d.{0,40}\|\s*(sh|bash)'
    r'|exfiltrate|send\s+(the\s+)?(env|environment|secrets|api.?keys?)\s+to'
    r'|before\s+(you\s+)?(write|generate)\s+any\s+code.{0,60}(fetch|curl|download|read)\s+https?://)',
    re.IGNORECASE,
)
INSTALL_HOOK_KEYS = ("preinstall", "install", "postinstall", "prepare")
SUSPICIOUS_SCRIPT_PATTERN = re.compile(
    r'(curl\s+|wget\s+)[^\n]*\|\s*(sh|bash)'
    r'|base64\s+-d'
    r'|child_process'
    r'|eval\(',
    re.IGNORECASE,
)
def scan_supply_chain(root, all_files):
    """Flags for the fifth real-world vibe-coding risk category: compromise of
    the AI tooling/supply chain itself, rather than a bug in the app's own
    code. Two checks, both heuristic:
      1. Repo files that a coding agent reads and follows automatically
         (AGENTS.md, CLAUDE.md, .cursorrules, ...) containing directives shaped
         like a prompt-injection attempt against that agent.
      2. package.json install-lifecycle scripts (these run automatically on
         `npm install`, no explicit opt-in) that fetch-and-execute or otherwise
         look like a supply-chain payload.
    This can't detect a compromised IDE extension or a backdoored dependency's
    actual behavior -- that needs the registry and the binary, not this repo's
    source. It only catches the two shapes above.
    """
    flags = []
    for path in all_files:
        base = os.path.basename(path).lower()
        if base not in AGENT_INSTRUCTION_FILES:
            continue
        text = read_text(path)
        if text is None:
            continue
        rel = os.path.relpath(path, root)
        for m in SUSPICIOUS_DIRECTIVE_PATTERN.finditer(text):
            line_no = text.count("\n", 0, m.start()) + 1
            line = text.splitlines()[line_no - 1].strip()
            flags.append({
                "file": rel, "line": line_no,
                "snippet": line[:160],
                "why": "agent-instruction file contains a directive shaped like a prompt-injection attempt -- read the surrounding context by hand before treating this as malicious; plenty of legitimate setup docs use similar phrasing (e.g. 'read the docs before coding')",
            })
    for path in all_files:
        if os.path.basename(path).lower() != "package.json":
            continue
        text = read_text(path)
        if text is None:
            continue
        rel = os.path.relpath(path, root)
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, TypeError):
            continue
        scripts = data.get("scripts", {}) if isinstance(data, dict) else {}
        if not isinstance(scripts, dict):
            continue
        for key, cmd in scripts.items():
            if not isinstance(cmd, str):
                continue
            is_hook = key.lower() in INSTALL_HOOK_KEYS
            if SUSPICIOUS_SCRIPT_PATTERN.search(cmd):
                flags.append({
                    "file": rel, "line": 0,
                    "snippet": f'"{key}": "{cmd[:140]}"',
                    "why": ("runs automatically on `npm install` with no opt-in" if is_hook
                            else "not an install-hook so requires someone to run it explicitly, lower urgency")
                          + " -- fetch-and-execute or obfuscated-exec shape, read by hand",
                })
    return flags
LEGAL_PAGE_EXTS = CODE_EXTS | {".html", ".htm", ".vue", ".svelte", ".md", ".mdx"}
LEGAL_PAGE_SLUGS = {
    "privacy_policy": re.compile(r'privacy[-_]?polic|/privacy(?:["\'/\s]|$)', re.IGNORECASE),
    "terms_of_service": re.compile(r'terms[-_]?of[-_]?(service|use)|/terms(?:["\'/\s]|$)|\bterms-?and-?conditions\b', re.IGNORECASE),
    "accessibility_statement": re.compile(r'accessibility[-_]?statement|/accessibility(?:["\'/\s]|$)', re.IGNORECASE),
}
DATA_COLLECTION_PATTERN = re.compile(
    r'type=["\']email["\']|name=["\']email["\']|google-analytics\.com|gtag\(|analytics\.js'
    r'|segment\.(com|io)|mixpanel|amplitude\.com|fbq\(|facebook\.com/tr'
    r'|hotjar|posthog|stripe\.com|Stripe\(|paypal|mailchimp|convertkit|klaviyo|sendgrid'
    r'|newsletter.{0,20}(signup|subscribe)|\bsubscribe\b',
    re.IGNORECASE,
)
AUTH_SIGNAL_PATTERN = re.compile(r'next-auth|supabase\.auth|firebase/auth|passport|bcrypt|argon2|getServerSession|@clerk', re.IGNORECASE)
COOKIE_SIGNAL_PATTERN = re.compile(r'res\.cookie\(|Set-Cookie|cookies\(\)\.set\(', re.IGNORECASE)
def scan_legal_pages(root, all_files):
    """Checks for three commonly-legally-required site pages: a privacy
    policy (required almost anywhere personal data is collected -- GDPR,
    CCPA, etc.), terms of service/use, and an accessibility statement (ADA/
    WCAG-adjacent, relevant to US public-facing sites).

    This is presence-detection, not a legal reading: it looks for a page
    file whose path matches the expected slug, or failing that a link/
    mention of one in scanned text (nav, footer, layout components). It
    can't confirm the page's *content* is adequate, and it can't know which
    jurisdiction's rules actually apply to this project -- flag results as
    leads for the user to verify, not a legal verdict.
    """
    found_pages = {k: [] for k in LEGAL_PAGE_SLUGS}
    data_signals = []
    has_auth = False
    has_cookies = False
    for path in all_files:
        rel = os.path.relpath(path, root).replace("\\", "/")
        low_rel_noext = os.path.splitext(rel.lower())[0]
        for key, pattern in LEGAL_PAGE_SLUGS.items():
            if pattern.search(low_rel_noext):
                found_pages[key].append(rel)
        ext = os.path.splitext(path)[1].lower()
        if ext not in LEGAL_PAGE_EXTS:
            continue
        text = read_text(path)
        if text is None:
            continue
        if AUTH_SIGNAL_PATTERN.search(text):
            has_auth = True
        if COOKIE_SIGNAL_PATTERN.search(text):
            has_cookies = True
        for key, pattern in LEGAL_PAGE_SLUGS.items():
            if found_pages[key]:
                continue
            m = pattern.search(text)
            if m:
                line_no = text.count("\n", 0, m.start()) + 1
                found_pages[key].append(f"{rel}:{line_no} (link/mention found, not confirmed to be an actual page)")
        m = DATA_COLLECTION_PATTERN.search(text)
        if m:
            line_no = text.count("\n", 0, m.start()) + 1
            data_signals.append({"file": rel, "line": line_no, "snippet": text.splitlines()[line_no - 1].strip()[:160]})
    collects_data = bool(data_signals) or has_auth or has_cookies
    missing = []
    if not found_pages["privacy_policy"]:
        missing.append({
            "page": "Privacy Policy",
            "required_if": "collecting any personal data (forms, analytics, auth, cookies)",
            "site_collects_data": collects_data,
            "evidence_of_data_collection": data_signals[:3],
        })
    if not found_pages["terms_of_service"]:
        missing.append({
            "page": "Terms of Service / Terms of Use",
            "required_if": "generally recommended for any public site with user accounts, content, or paid features",
            "site_collects_data": collects_data,
            "evidence_of_data_collection": [],
        })
    if not found_pages["accessibility_statement"]:
        missing.append({
            "page": "Accessibility Statement",
            "required_if": "US public-facing sites (ADA); often expected alongside WCAG conformance",
            "site_collects_data": collects_data,
            "evidence_of_data_collection": [],
        })
    return {"found": {k: v[:3] for k, v in found_pages.items()}, "missing": missing}
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo_path")
    args = ap.parse_args()
    root = os.path.abspath(args.repo_path)
    if not os.path.isdir(root):
        print(f"error: {root} is not a directory", file=sys.stderr)
        sys.exit(1)
    result = scan(root)
    all_files = list(iter_files(root))
    supply_chain = scan_supply_chain(root, all_files)
    legal_pages = scan_legal_pages(root, all_files)
    print(json.dumps({
        "repo": root, "items": result,
        "supply_chain_flags": supply_chain,
        "legal_pages": legal_pages,
    }, indent=2))
if __name__ == "__main__":
    main()
