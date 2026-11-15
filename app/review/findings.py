"""Shared finding type for the launch review (security and compliance findings are ranked together)."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEV_SCORE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}


@dataclass
class Finding:
    id: str
    category: str                 # security | compliance
    kind: str                     # dependency | secret | code_pattern | site_header | legal_check | ...
    title: str
    severity: str                 # critical | high | medium | low | info
    fix: str
    score: float = 0.0            # 0-100, used to order the fix-first list
    confidence: str = "medium"    # high | medium | low
    evidence: list[dict[str, Any]] = field(default_factory=list)
    cves: list[str] = field(default_factory=list)
    basis: dict[str, Any] | None = None   # compliance: law, citation, url, as_of
    tags: list[str] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.score:
            self.score = float(SEV_SCORE.get(self.severity, 5))

    def to_dict(self) -> dict[str, Any]:
        d = {"id": self.id, "category": self.category, "kind": self.kind, "title": self.title, "severity": self.severity,
             "score": round(self.score, 1), "confidence": self.confidence, "fix": self.fix, "evidence": self.evidence[:5]}
        if self.cves:
            d["cves"] = self.cves
        if self.basis:
            d["basis"] = self.basis
        if self.tags:
            d["tags"] = self.tags
        if self.detail:
            d["detail"] = self.detail
        return d
