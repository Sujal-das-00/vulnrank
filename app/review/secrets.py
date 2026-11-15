"""Secret and weak-pattern scanner. Secrets are NEVER echoed: evidence shows only a short prefix and the length."""
from __future__ import annotations

import re
from collections import defaultdict

from app.review.findings import Finding

TESTISH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|examples?|samples?|mocks?|docs?)(/|$)|\.(example|sample|template)$|(^|/)\.env\.(example|sample|template)$", re.I)

SECRET_RULES = [
    ("aws-access-key", "AWS access key id", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "critical"),
    ("private-key", "Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "critical"),
    ("github-token", "GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "critical"),
    ("stripe-live", "Stripe live secret key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{16,}\b"), "critical"),
    ("slack-token", "Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    ("google-api-key", "Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    ("generic-secret", "Hard-coded credential", re.compile(
        r"""(?i)\b(?:password|passwd|secret(?:_key)?|api[_-]?key|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['"]([^'"\s]{8,})['"]"""), "high"),
]
PLACEHOLDER = re.compile(r"(?i)^(x+|\*+|changeme|change_me|your[_-].*|<.*>|\$\{.*\}|\{\{.*\}\}|example.*|test.*|dummy.*|todo|none|null|password|secret|xxxx.*|process\.env.*|os\.environ.*)$")

CODE_RULES = [
    # id, title, CWE/OWASP, regex, file extensions (None = any), severity, fix
    ("tls-verify-off", "TLS certificate verification disabled", "CWE-295", re.compile(r"verify\s*=\s*False|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true"),
     None, "high", "Remove the override so certificates are verified; trust a private CA explicitly if you need one."),
    ("sql-string-format", "SQL built from strings (possible injection)", "CWE-89",
     re.compile(r"""(?i)\b(?:execute|query|raw)\s*\(\s*(?:f['"]|['"][^'"]*(?:select|insert|update|delete)[^'"]*['"]\s*(?:%|\+|\.format))"""),
     {".py", ".js", ".ts", ".php", ".rb", ".java"}, "high", "Use parameterised queries or the ORM's bound parameters."),
    ("eval-exec", "Dynamic code execution (eval/exec)", "CWE-95", re.compile(r"(?<![\w.])(?:eval|exec)\s*\((?!\s*['\"])"), {".py", ".js", ".ts", ".php"}, "high",
     "Replace eval/exec with explicit parsing or a lookup table; never run caller-supplied text."),
    ("unsafe-deserialize", "Unsafe deserialisation", "CWE-502", re.compile(r"\bpickle\.loads?\(|\byaml\.load\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)"), {".py"}, "high",
     "Use yaml.safe_load / json instead of pickle or unsafe yaml.load for untrusted data."),
    ("shell-true", "Shell command built with shell=True", "CWE-78", re.compile(r"shell\s*=\s*True"), {".py"}, "medium",
     "Pass an argument list without shell=True; validate any user input."),
    ("debug-on", "Debug mode enabled", "CWE-489", re.compile(r"(?m)^\s*DEBUG\s*=\s*True\b|\.run\([^)]*debug\s*=\s*True"), {".py"}, "medium",
     "Disable debug in production; drive it from an environment variable."),
    ("weak-hash", "Weak hash (MD5/SHA-1) used", "CWE-328", re.compile(r"hashlib\.(?:md5|sha1)\(|createHash\(\s*['\"](?:md5|sha1)['\"]"), {".py", ".js", ".ts"}, "medium",
     "Use SHA-256+, and a password hasher (argon2/bcrypt/scrypt) for passwords."),
    ("xss-sink", "HTML injected from a variable (possible XSS)", "CWE-79", re.compile(r"\.innerHTML\s*=(?!\s*['\"`]\s*['\"`])|dangerouslySetInnerHTML|document\.write\("),
     {".js", ".jsx", ".ts", ".tsx", ".vue", ".html"}, "medium", "Use textContent or a sanitiser (e.g. DOMPurify) before inserting HTML."),
    ("cors-any", "CORS allows any origin", "CWE-942", re.compile(r"(?i)Access-Control-Allow-Origin['\"]?\s*[:,]\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"]|allow_origins\s*=\s*\[\s*['\"]\*['\"]"), None, "medium",
     "Restrict allowed origins to the sites that need access, especially with credentials."),
    ("hardcoded-jwt-secret", "JWT/session secret hard-coded", "CWE-798", re.compile(r"""(?i)(?:jwt[_-]?secret|SECRET_KEY|session[_-]?secret)\s*[:=]\s*['"][^'"]{6,}['"]"""), None, "high",
     "Load the secret from the environment or a secrets manager and rotate the leaked one."),
]


def _redact(v: str) -> str:
    return f"{v[:4]}… ({len(v)} chars)"


def scan_secrets(files: dict[str, str]) -> list[Finding]:
    out: list[Finding] = []
    for name in sorted(files):
        base = name.rsplit("/", 1)[-1].lower()
        if base == ".env" or (base.startswith(".env.") and not TESTISH.search(name)):
            testy = bool(TESTISH.search(name))
            out.append(Finding(f"secret-env-file:{name}", "security", "secret", f"Environment file committed: {name}", "low" if testy else "high",
                               "Remove the file from the repository and its history, add it to .gitignore, and rotate every value it held.",
                               confidence="low" if testy else "medium", evidence=[{"path": name}], tags=["CWE-798"]))
    grouped: dict[str, list[dict]] = defaultdict(list)
    meta: dict[str, tuple[str, str]] = {}
    for path, text in files.items():
        if path.endswith((".lock", "package-lock.json")) or len(text) > 400_000:
            continue
        low_conf = bool(TESTISH.search(path))
        for ln, line in enumerate(text.splitlines(), 1):
            if len(line) > 2000:
                continue
            for rid, title, rx, sev in SECRET_RULES:
                m = rx.search(line)
                if not m:
                    continue
                val = m.group(1) if rid == "generic-secret" else m.group(0)
                if rid == "generic-secret" and PLACEHOLDER.match(val):
                    continue
                grouped[rid].append({"path": path, "line": ln, "match": _redact(val), "test_or_example_path": low_conf})
                meta[rid] = (title, sev)
    for rid, hits in grouped.items():
        title, sev = meta[rid]
        real = [h for h in hits if not h["test_or_example_path"]]
        use = real or hits
        eff = sev if real else "low"
        out.append(Finding(f"secret:{rid}", "security", "secret", f"{title} found in source ({len(use)} location{'s' if len(use) != 1 else ''})", eff,
                           "Revoke and rotate the credential now (assume it is compromised), remove it from the code and git history, and load it from the environment or a secrets manager.",
                           confidence="high" if real and rid != "generic-secret" else "medium" if real else "low",
                           evidence=use[:5], tags=["CWE-798"], detail={"locations": len(use)}))
    return out


def scan_code_patterns(files: dict[str, str], *, any_ext: bool = False) -> list[Finding]:
    out: list[Finding] = []
    for rid, title, cwe, rx, exts, sev, fix in CODE_RULES:
        hits = []
        for path, text in files.items():
            if TESTISH.search(path) or len(text) > 400_000:
                continue
            ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path.rsplit("/", 1)[-1] else ""
            if not any_ext and (ext in {".md", ".txt", ".rst", ".lock"} or (exts is not None and ext not in exts)):
                continue
            for ln, line in enumerate(text.splitlines(), 1):
                if len(line) <= 2000 and rx.search(line):
                    hits.append({"path": path, "line": ln, "snippet": line.strip()[:120]})
        if hits:
            out.append(Finding(f"code:{rid}", "security", "code_pattern", f"{title} ({len(hits)} location{'s' if len(hits) != 1 else ''})", sev, fix,
                               confidence="low" if len(hits) > 10 else "medium", evidence=hits[:5], tags=[cwe],
                               detail={"locations": len(hits), "note": "Pattern match, not proof of exploitability; review each location."}))
    return out
