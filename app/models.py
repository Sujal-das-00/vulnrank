"""Domain models (Pydantic). Independent of the Telegraph transport."""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.ids import normalize_cve_id

Criticality = Literal["critical", "high", "medium", "low", "unknown"]
Environment = Literal["production", "staging", "development", "test", "unknown"]
Exposure = Literal["internet", "internal", "isolated", "unknown"]
ScannerSeverity = Literal["critical", "high", "medium", "low", "info", "unknown"]


class Asset(BaseModel):
    model_config = ConfigDict(extra="forbid")
    asset_id: str | None = Field(None, max_length=128)
    environment: Environment | None = None
    criticality: Criticality | None = None
    internet_exposed: bool | None = None
    exposure: Exposure | None = None
    business_service: str | None = Field(None, max_length=128)

    def effective_exposure(self) -> str | None:
        if self.exposure:
            return self.exposure
        if self.internet_exposed is True:
            return "internet"
        if self.internet_exposed is False:
            return "internal"
        return None


class Finding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cve_id: str
    asset: Asset | None = None
    scanner_severity: ScannerSeverity | None = None  # caller context, never evidence
    component: str | None = Field(None, max_length=200)
    installed_version: str | None = Field(None, max_length=100)

    @field_validator("cve_id")
    @classmethod
    def _norm(cls, v: str) -> str:
        return normalize_cve_id(v)


class Preferences(BaseModel):
    model_config = ConfigDict(extra="forbid")
    top_n: int | None = Field(None, ge=1, le=1000)
    include_remediation: bool = True


class RawTriageRequest(BaseModel):
    """Findings are validated one by one so a single bad item yields a field-level error
    instead of rejecting (or silently dropping) the whole batch."""
    model_config = ConfigDict(extra="forbid")
    request_id: str | None = Field(None, max_length=128)
    findings: list[dict[str, Any]] = Field(min_length=1)
    preferences: Preferences = Preferences()


class ItemError(BaseModel):
    index: int | None = None
    input: str | None = None
    field: str | None = None
    code: str
    message: str


class Evidence(BaseModel):
    source_name: str
    source_url: str | None = None
    retrieved_at: str | None = None
    source_updated_at: str | None = None
    field: str
    value: Any = None
    status: str
    notes: str | None = None


class ScoreComponent(BaseModel):
    dimension: str
    raw_value: float | None
    status: str
    nominal_weight: float
    effective_weight: float
    points: float
    detail: str


class ScoreBreakdown(BaseModel):
    score_version: str
    base_score: float | None
    components: list[ScoreComponent]
    floors_applied: list[str]


class Priority(BaseModel):
    rank: int
    cve_id: str
    asset_id: str | None = None
    status: Literal["scored", "insufficient_evidence"]
    priority: Literal["critical", "high", "medium", "low", "insufficient_evidence"]
    risk_score: float | None
    score_version: str
    evidence_coverage: float
    confidence_label: Literal["high", "medium", "low"]
    why_ranked_here: list[str]
    signals: dict[str, Any]
    score_breakdown: ScoreBreakdown
    recommended_action: str | None
    evidence: list[Evidence]
    uncertainty: list[str]
    scanner_severity: str | None = None
    component: str | None = None
    installed_version: str | None = None
    duplicates_merged: int = 0


class Summary(BaseModel):
    total_submitted: int
    successfully_analysed: int
    insufficient_evidence: int
    failed: int
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TriageResponse(BaseModel):
    request_id: str | None
    engine_version: str
    score_version: str
    generated_at: str
    summary: Summary
    priorities: list[Priority]
    errors: list[ItemError]
    limitations: list[str]
    source_status: dict[str, str]
