"""Input validation helpers for LogBlind."""

import re
from typing import Optional


def validate_technique_id(technique_id: str) -> bool:
    """Validate a MITRE ATT&CK technique ID (e.g., T1021, T1021.001)."""
    return bool(re.match(r"^T\d{4}(\.\d{3})?$", technique_id))


def validate_severity(severity: Optional[str]) -> Optional[str]:
    """Validate and normalize severity level string."""
    if severity is None:
        return None
    valid = {"low", "medium", "high", "critical"}
    normalized = severity.strip().lower()
    return normalized if normalized in valid else None


def severity_to_int(severity: str) -> int:
    """Convert severity string to int: low=0, medium=1, high=2, critical=3."""
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(severity.lower(), 0)
