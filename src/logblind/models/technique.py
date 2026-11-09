"""Data models for MITRE ATT&CK techniques and detection requirements."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class EventRequirement:
    """A Windows Event ID required to detect a technique."""

    event_id: int
    channel: str = "Security"
    condition: str = ""
    importance: str = "HIGH"
    audit_subcategory: str | None = None
    audit_setting: str = "Success"
    registry_check: str | None = None
    sysmon_required: bool = False


@dataclass
class AdditionalCheck:
    """An additional non-event-log check (registry, Sysmon config, etc.)."""

    check_type: str
    description: str
    path: str = ""
    value_name: str = ""
    expected_value: str = ""
    importance: str = "MEDIUM"


@dataclass
class Technique:
    """A MITRE ATT&CK technique with all its detection requirements."""

    technique_id: str
    name: str
    tactic: str = "Lateral Movement"
    description: str = ""
    real_world_tools: list[str] = field(default_factory=list)
    event_requirements: list[EventRequirement] = field(default_factory=list)
    additional_checks: list[AdditionalCheck] = field(default_factory=list)
    references: list[str] = field(default_factory=list)


@dataclass
class KnowledgeBase:
    """Collection of all loaded ATT&CK technique mappings."""

    techniques: list[Technique] = field(default_factory=list)

    def get_technique(self, technique_id: str) -> Technique | None:
        """Look up a technique by its ATT&CK ID."""
        for tech in self.techniques:
            if tech.technique_id == technique_id:
                return tech
        return None

    def get_technique_ids(self) -> list[str]:
        """Get a sorted list of all technique IDs."""
        return sorted(t.technique_id for t in self.techniques)
