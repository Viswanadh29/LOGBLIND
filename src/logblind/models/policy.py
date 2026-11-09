"""Data models representing Windows audit policy state."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class AuditSetting(Enum):
    """Possible states for an audit subcategory."""
    NO_AUDITING = "No Auditing"
    SUCCESS = "Success"
    FAILURE = "Failure"
    SUCCESS_AND_FAILURE = "Success and Failure"

    @classmethod
    def from_string(cls, value: str) -> "AuditSetting":
        """Parse an audit setting from auditpol output string."""
        normalized = value.strip()
        for member in cls:
            if member.value.lower() == normalized.lower():
                return member
        return cls.NO_AUDITING

    def includes_success(self) -> bool:
        """Check if this setting includes success auditing."""
        return self in (self.SUCCESS, self.SUCCESS_AND_FAILURE)

    def includes_failure(self) -> bool:
        """Check if this setting includes failure auditing."""
        return self in (self.FAILURE, self.SUCCESS_AND_FAILURE)


@dataclass
class AuditSubcategory:
    """A single Windows Advanced Audit Policy subcategory."""
    name: str
    category: str
    setting: AuditSetting
    guid: str = ""


@dataclass
class RegistryCheck:
    """Result of a Windows registry check."""
    name: str
    path: str
    value_name: str
    expected_value: str | int | bool
    actual_value: str | int | bool | None
    is_configured: bool
    description: str = ""


@dataclass
class RegistrySnapshot:
    """Collection of registry-based configuration checks."""
    checks: list[RegistryCheck] = field(default_factory=list)
    sysmon_installed: bool = False
    sysmon_version: str | None = None
    scriptblock_logging: bool = False
    commandline_audit: bool = False
    wef_configured: bool = False


@dataclass
class PolicySnapshot:
    """Complete snapshot of a Windows machine's audit configuration."""
    machine_name: str = ""
    subcategories: dict[str, AuditSubcategory] = field(default_factory=dict)
    registry: RegistrySnapshot = field(default_factory=RegistrySnapshot)
    collection_timestamp: str = ""
    source: str = "live"

    def get_subcategory(self, name: str) -> AuditSubcategory | None:
        """Look up an audit subcategory by name (case-insensitive)."""
        normalized = name.strip().lower()
        for key, sub in self.subcategories.items():
            if key.lower() == normalized or sub.name.lower() == normalized:
                return sub
        return None

    def is_success_enabled(self, subcategory_name: str) -> bool:
        """Check if success auditing is enabled for a subcategory."""
        sub = self.get_subcategory(subcategory_name)
        return sub.setting.includes_success() if sub else False

    def is_failure_enabled(self, subcategory_name: str) -> bool:
        """Check if failure auditing is enabled for a subcategory."""
        sub = self.get_subcategory(subcategory_name)
        return sub.setting.includes_failure() if sub else False

    def merge_registry(self, registry_snapshot: RegistrySnapshot) -> None:
        """Merge registry check results into this snapshot."""
        self.registry = registry_snapshot
