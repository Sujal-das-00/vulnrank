"""CVE identifier validation, normalisation and extraction."""
from __future__ import annotations

import re

_DASHES = "‐‑‒–—―−"
_SEP = rf"[-{_DASHES}_]"
STRICT_RE = re.compile(r"^CVE-(\d{4})-(\d{4,19})$")
FIND_RE = re.compile(rf"(?<![A-Za-z0-9])CVE{_SEP}(\d{{4}}){_SEP}(\d{{4,19}})(?![0-9])", re.IGNORECASE)


def normalize_cve_id(value: str) -> str:
    """Return canonical CVE-YYYY-NNNN+ or raise ValueError."""
    if not isinstance(value, str):
        raise ValueError("cve_id must be a string")
    v = value.strip().upper()
    for d in _DASHES + "_":
        v = v.replace(d, "-")
    m = STRICT_RE.match(v)
    if not m:
        raise ValueError(f"invalid CVE identifier: {value[:40]!r} (expected CVE-YYYY-NNNN)")
    year = int(m.group(1))
    if year < 1999 or year > 2100:
        raise ValueError(f"implausible CVE year in {value[:40]!r}")
    return v


def extract_cve_ids(text: str) -> list[str]:
    """All CVE ids found in free text, in order of first appearance, de-duplicated."""
    seen: dict[str, None] = {}
    for m in FIND_RE.finditer(text or ""):
        seen.setdefault(f"CVE-{m.group(1)}-{m.group(2)}", None)
    return list(seen)
