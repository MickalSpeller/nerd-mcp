"""Structured contracts for diagnosis and recommended configuration changes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

DiagnosisState = Literal[
    "diagnosing", "inconclusive", "recommended", "ignored", "prepared",
    "applying", "applied_pending_save", "saved", "rolled_back", "failed",
]


@dataclass(frozen=True)
class Evidence:
    device: str
    kind: str
    status: str
    timestamp: str
    revision: str
    data: dict[str, Any]
    error: str | None = None


@dataclass(frozen=True)
class ConfigurationFinding:
    """Exact configuration lines observed on one device and judged incorrect."""

    device: str
    lines: tuple[str, ...]


@dataclass(frozen=True)
class RootCause:
    summary: str
    confidence: Literal["high", "medium", "low"]
    evidence: tuple[str, ...]
    incorrect_configuration: tuple[ConfigurationFinding, ...] = ()


@dataclass(frozen=True)
class ChangeRecommendation:
    summary: str
    operations: tuple[dict[str, Any], ...]
    next_steps: tuple[str, ...] = ()


@dataclass(frozen=True)
class DiagnosisReport:
    diagnosis_id: str
    state: DiagnosisState
    created_at: str
    question: str
    devices: tuple[str, ...]
    evidence_revision: str
    evidence: tuple[Evidence, ...]
    root_cause: RootCause
    recommendation: ChangeRecommendation | None
    change_id: str | None = None
    decision: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
