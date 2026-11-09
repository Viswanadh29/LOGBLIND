"""Collector that imports audit policy from exported CSV files.

Enables offline analysis — export on one machine, analyze on another.
Export command: auditpol /get /category:* /r > policy.csv
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from logblind.collectors.auditpol import AuditPolCollector
from logblind.models.policy import PolicySnapshot


class FileImportError(Exception):
    """Raised when the imported file cannot be parsed."""


class FileImportCollector:
    """Imports audit policy from an exported auditpol CSV file."""

    def collect(self, file_path: Path) -> PolicySnapshot:
        """Read and parse an exported audit policy file."""
        if not file_path.exists():
            raise FileImportError(f"File not found: {file_path}")

        try:
            try:
                raw_content = file_path.read_text(encoding="utf-16")
            except (UnicodeDecodeError, UnicodeError):
                raw_content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            raise FileImportError(f"Failed to read file: {e}")

        if not raw_content.strip():
            raise FileImportError("File is empty.")

        collector = AuditPolCollector()
        subcategories = collector._parse_csv(raw_content)

        if not subcategories:
            raise FileImportError(
                "No audit subcategories found. "
                "Make sure the file was exported with: auditpol /get /category:* /r"
            )

        return PolicySnapshot(
            subcategories=subcategories,
            source="file",
            collection_timestamp=datetime.now(timezone.utc).isoformat(),
            machine_name=f"imported:{file_path.name}",
        )
