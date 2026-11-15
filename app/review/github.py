"""Fetch a PUBLIC GitHub repository as a read-only text snapshot. Nothing from the repo is ever executed.

Only codeload.github.com is contacted (fixed host, so no SSRF surface). Downloads and extraction are
size-capped; binaries, vendored dirs and oversized files are skipped and reported in `stats`.
"""
from __future__ import annotations

import io
import re
import zipfile
from dataclasses import dataclass, field

import httpx

CODELOAD = "https://codeload.github.com/{owner}/{repo}/zip/HEAD"
MAX_DOWNLOAD = 15_000_000
MAX_UNCOMPRESSED = 20_000_000
MAX_FILES = 4000
MAX_FILE_BYTES = 300_000
SKIP_DIRS = {"node_modules", ".git", "vendor", "dist", "build", ".venv", "venv", "__pycache__", "target", ".next", "coverage", "bower_components"}
TEXT_EXT = {".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".html", ".htm", ".md", ".txt", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".env",
            ".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs", ".sql", ".sh", ".tf", ".vue", ".svelte", ".erb", ".ejs", ".hbs", ".twig", ".jinja", ".j2", ".xml",
            ".lock", ".mod", ".sum", ".gemspec", ".gradle", ""}
SPECIAL_NAMES = {"dockerfile", "gemfile", "gemfile.lock", "requirements.txt", "package.json", "package-lock.json", "go.mod", "poetry.lock", "pipfile.lock", ".env"}

_REPO_RE = re.compile(r"(?:https?://)?(?:www\.)?github\.com/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))/([A-Za-z0-9._-]{1,100})", re.I)


class RepoError(Exception):
    pass


@dataclass
class RepoSnapshot:
    owner: str
    repo: str
    files: dict[str, str]
    stats: dict = field(default_factory=dict)


def parse_repo(text: str) -> tuple[str, str] | None:
    m = _REPO_RE.search(text or "")
    if not m:
        return None
    owner, repo = m.group(1), re.sub(r"(\.git)?[/.]*$", "", m.group(2))
    repo = repo[:-4] if repo.lower().endswith(".git") else repo
    return (owner, repo) if repo and repo not in (".", "..") else None


def extract_zip(data: bytes) -> tuple[dict[str, str], dict]:
    stats = {"files_read": 0, "skipped_binary": 0, "skipped_large": 0, "skipped_dirs": 0, "truncated": False}
    files: dict[str, str] = {}
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise RepoError("repository archive was not a valid zip")
    infos = [i for i in zf.infolist() if not i.is_dir()]
    if sum(i.file_size for i in infos) > MAX_UNCOMPRESSED:
        stats["truncated"] = True
    total = 0
    for i in infos:
        parts = i.filename.split("/")[1:]  # drop the "repo-sha/" prefix
        if not parts:
            continue
        path = "/".join(parts)
        if any(p in SKIP_DIRS for p in parts[:-1]):
            stats["skipped_dirs"] += 1
            continue
        name = parts[-1].lower()
        ext = "." + name.rsplit(".", 1)[1] if "." in name else ""
        if ext not in TEXT_EXT and name not in SPECIAL_NAMES:
            stats["skipped_binary"] += 1
            continue
        if i.file_size > MAX_FILE_BYTES:
            stats["skipped_large"] += 1
            continue
        if len(files) >= MAX_FILES or total + i.file_size > MAX_UNCOMPRESSED:
            stats["truncated"] = True
            break
        raw = zf.open(i).read(MAX_FILE_BYTES + 1)
        if b"\x00" in raw[:2000]:
            stats["skipped_binary"] += 1
            continue
        total += len(raw)
        files[path] = raw.decode("utf-8", "replace")
    stats["files_read"] = len(files)
    return files, stats


async def fetch_repo(client: httpx.AsyncClient, owner: str, repo: str, *, timeout: float = 20.0) -> RepoSnapshot:
    url = CODELOAD.format(owner=owner, repo=repo)
    buf = bytearray()
    try:
        async with client.stream("GET", url, follow_redirects=True, timeout=httpx.Timeout(timeout)) as r:
            if r.status_code == 404:
                raise RepoError("repository not found or not public")
            if r.status_code != 200:
                raise RepoError(f"GitHub returned HTTP {r.status_code}")
            if r.url.host != "codeload.github.com":
                raise RepoError("unexpected redirect target")
            async for chunk in r.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > MAX_DOWNLOAD:
                    raise RepoError("repository archive is larger than the 15 MB review limit")
    except httpx.TimeoutException:
        raise RepoError("GitHub did not respond in time")
    except httpx.HTTPError as ex:
        raise RepoError(f"could not reach GitHub ({type(ex).__name__})")
    files, stats = extract_zip(bytes(buf))
    stats["archive_bytes"] = len(buf)
    return RepoSnapshot(owner, repo, files, stats)
