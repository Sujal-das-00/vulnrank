"""Parse the free-text `target` (<=256 bytes on-chain) plus optional params into a review request.

A target can be: a public GitHub repo, a website, package versions ("lodash 4.17.15 on npm", "django==3.2.0", "left-pad@1.3.0"),
a pasted code snippet or unified diff, or any mix of these with country/sector words.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from app.review.github import parse_repo
from app.review.legal import JURISDICTIONS, parse_jurisdictions, parse_sector

_URL = re.compile(r"https?://[^\s,;)>\]\"']+", re.I)
_BARE = re.compile(r"(?<![@\w/.-])((?:[a-z0-9-]{2,63}\.)+(?:com|org|net|io|in|co|dev|app|ai|eu|de|fr|uk|shop|store|xyz|info|us|co\.in|co\.uk))(/[^\s,;)>\]\"']*)?(?![\w@-])", re.I)
_VER = r"v?(\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.]+)?)"
_PKG_AT = re.compile(r"(?<![\w@./-])((?:@[a-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]{0,80})@" + _VER)
_PKG_EQ = re.compile(r"(?<![\w./-])([A-Za-z0-9][\w.-]{0,80})\s*===?\s*" + _VER)
_PKG_SP = re.compile(r"(?<![\w@./-])([A-Za-z0-9][\w.-]{0,60})\s+" + _VER + r"(?:\s+(?:on|in|from|for)\s+(npm|pypi|pip|python|node|go|golang|rubygems|ruby|gem))?", re.I)
_PKG_PV = re.compile(r"(?<![\w@./-])([A-Za-z0-9][\w.-]{0,60})\s+version\s+" + _VER, re.I)   # "npm package lodash version 4.17.15"
_CODE_MARK = re.compile(r"\bdef \w+\(|\bfunction\b|=>|\bimport \w|\brequire\(|\bclass \w+|<\?php|\bSELECT\b.+\bFROM\b|\bexec\(|\beval\(|\bos\.system|subprocess\.|\bcursor\.|\bconsole\.log|[{};]\s*$", re.I | re.M)
_ECO_HINT = [(re.compile(r"\b(npm|node(?:\.?js)?|javascript|yarn)\b", re.I), "npm"), (re.compile(r"\b(pypi|pip|python)\b", re.I), "PyPI"),
             (re.compile(r"\b(golang|go\.mod|go module)\b", re.I), "Go"), (re.compile(r"\b(rubygems|ruby|gem)\b", re.I), "RubyGems")]
_STOP_NAMES = {"version", "python", "node", "nodejs", "npm", "pip", "release", "v", "update", "upgrade", "ubuntu", "debian", "windows", "linux", "chrome", "firefox", "java", "php", "ruby", "go", "http", "https"}
MAX_PACKAGES = 20


@dataclass
class Target:
    raw: str
    repo: tuple[str, str] | None = None
    site_url: str | None = None
    packages: list[tuple[str, str, str]] = field(default_factory=list)   # ecosystem, name, version
    snippet: str | None = None
    jurisdictions: list[str] = field(default_factory=list)
    sector: str | None = None
    assumptions: list[str] = field(default_factory=list)
    legal_requested: bool = False

    @property
    def reviewable(self) -> bool:
        return bool(self.repo or self.site_url or self.packages or self.snippet)


def looks_like_code(text: str) -> bool:
    if text.lstrip().startswith(("diff --git", "--- a/", "@@ ")) or "```" in text:
        return True
    marks = len(_CODE_MARK.findall(text))
    return marks >= 2 or (marks >= 1 and "\n" in text.strip())


def extract_snippet(text: str) -> str:
    m = re.findall(r"```[a-zA-Z0-9]*\n(.*?)```", text, re.S)
    body = "\n".join(m) if m else text
    if re.search(r"^(diff --git|@@ -)", body, re.M):          # unified diff: review the added lines only
        body = "\n".join(l[1:] for l in body.splitlines() if l.startswith("+") and not l.startswith("+++"))
    return body[:60_000]


def _hint(text: str) -> str | None:
    for rx, eco in _ECO_HINT:
        if rx.search(text):
            return eco
    return None


def extract_packages(text: str, *, allow_spaced: bool) -> list[tuple[str, str, str]]:
    hint, found = _hint(text), []
    for m in _PKG_AT.finditer(text):
        name, ver = m.group(1), m.group(2)
        found.append(("npm" if name.startswith("@") or hint == "npm" else (hint or "?"), name, ver))
    for m in _PKG_EQ.finditer(text):
        found.append((hint or "PyPI", m.group(1), m.group(2)))
    for m in _PKG_PV.finditer(text):
        name = m.group(1)
        if name.lower() not in _STOP_NAMES | {"package", "library", "module", "dependency"} and not re.fullmatch(r"\d+", name):
            found.append((hint or "?", name, m.group(2)))
    if allow_spaced:
        for m in _PKG_SP.finditer(text):
            name, ver, eco = m.group(1), m.group(2), (m.group(3) or "").lower()
            if name.lower() in _STOP_NAMES or re.fullmatch(r"\d+", name):
                continue
            e = {"npm": "npm", "node": "npm", "pypi": "PyPI", "pip": "PyPI", "python": "PyPI", "go": "Go", "golang": "Go", "rubygems": "RubyGems", "ruby": "RubyGems", "gem": "RubyGems"}.get(eco) or hint or "?"
            found.append((e, name, ver))
    out, seen = [], set()
    for eco, name, ver in found:
        key = (eco, name.lower(), ver)
        if key not in seen:
            seen.add(key)
            out.append((eco, name, ver))
    return out[:MAX_PACKAGES]


def parse_target(text: str, *, country: str | None = None, sector: str | None = None) -> Target:
    raw = (text or "").strip()[:60_000]
    t = Target(raw)
    t.repo = parse_repo(raw)
    site = None
    for m in _URL.finditer(raw):
        u = m.group(0).rstrip(".")
        if "github.com" not in u.lower():
            site = u
            break
    if site is None and not looks_like_code(raw):
        for m in _BARE.finditer(raw):
            host = m.group(1).lower()
            if host in ("github.com", "www.github.com", "gitlab.com"):
                continue
            site = "https://" + host + (m.group(2) or "")
            break
    t.site_url = site
    code = looks_like_code(raw)
    t.snippet = extract_snippet(raw) if code and not (t.repo or t.site_url) else (extract_snippet(raw) if code else None)
    t.packages = extract_packages(raw, allow_spaced=not code)
    explicit_juris = parse_jurisdictions(country or "") or parse_jurisdictions(raw[:2000] if not code else "")
    t.legal_requested = bool(t.repo or t.site_url)
    if explicit_juris:
        t.jurisdictions = explicit_juris
    elif t.legal_requested:
        t.jurisdictions = list(JURISDICTIONS)
        t.assumptions.append("No country/region was given, so EU, India and US rules were all checked.")
    t.sector = (sector.strip().lower() if sector and sector.strip().lower() in ("saas", "ecommerce") else None) or parse_sector(raw[:2000])
    return t
