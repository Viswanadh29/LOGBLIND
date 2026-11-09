"""Data models for gap analysis results and coverage reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class CoverageStatus(Enum):
    """Coverage status for a technique."""

    COVERED = "COVERED"
    PARTIAL = "PARTIAL"
    BLIND = "BLIND"

    @property
    def symbol(self) -> str:
        """Get an ASCII-safe status symbol for CLI display."""
        return {"COVERED": "[+]", "PARTIAL": "[~]", "BLIND": "[-]"}[self.value]

    @property
    def color(self) -> str:
        return {"COVERED": "green", "PARTIAL": "yellow", "BLIND": "red"}[self.value]


@dataclass
class EventGap:
    """A single missing or misconfigured event detection."""

    event_id: int
    channel: str
    condition: str
    importance: str
    reason: str
    fix_command: str = ""


@dataclass
class TechniqueGapResult:
    """Analysis result for a single ATT&CK technique."""

    technique_id: str
    technique_name: str
    coverage_percent: float
    status: CoverageStatus
    total_requirements: int
    met_requirements: int
    gaps: list[EventGap] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def has_gaps(self) -> bool:
        return len(self.gaps) > 0


@dataclass
class CoverageReport:
    """Overall coverage report across all analyzed techniques."""

    overall_score: float
    total_techniques: int
    covered_count: int
    partial_count: int
    blind_count: int
    technique_results: list[TechniqueGapResult] = field(default_factory=list)
    critical_gaps: list[EventGap] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.overall_score >= 80:
            return "LOW RISK"
        elif self.overall_score >= 50:
            return "MEDIUM RISK"
        return "HIGH RISK"

    @property
    def risk_color(self) -> str:
        if self.overall_score >= 80:
            return "green"
        elif self.overall_score >= 50:
            return "yellow"
        return "red"
