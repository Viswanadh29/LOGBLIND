"""Collector that reads Windows Advanced Audit Policy via auditpol.exe.

Runs `auditpol /get /category:* /r` to get the current audit policy
in CSV format, then parses it into a PolicySnapshot.
Requires: Administrator privileges on Windows.
"""

from __future__ import annotations

import csv
import io
import subprocess
from datetime import datetime, timezone

from logblind.models.policy import AuditSetting, AuditSubcategory, PolicySnapshot


class AuditPolError(Exception):
    """Raised when auditpol.exe fails to execute."""


class AuditPolCollector:
    """Collects Windows audit policy by running auditpol.exe."""

    def collect(self) -> PolicySnapshot:
        """Run auditpol and parse output into a PolicySnapshot."""
        raw_output = self._run_auditpol()
        subcategories = self._parse_csv(raw_output)

        snapshot = PolicySnapshot(
            subcategories=subcategories,
            collection_timestamp=datetime.now(timezone.utc).isoformat(),
            source="live",
        )

        try:
            import platform
            snapshot.machine_name = platform.node()
        except Exception:
            snapshot.machine_name = "unknown"

        return snapshot

    def _run_auditpol(self) -> str:
        """Execute auditpol.exe and return raw CSV output."""
        try:
            result = subprocess.run(
                ["auditpol.exe", "/get", "/category:*", "/r"],
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            return result.stdout
        except FileNotFoundError:
            raise AuditPolError("auditpol.exe not found. Are you running on Windows?")
        except subprocess.CalledProcessError as e:
            raise AuditPolError(
                f"auditpol.exe failed (exit code {e.returncode}). "
                f"Make sure you're running as Administrator.\nstderr: {e.stderr}"
            )
        except subprocess.TimeoutExpired:
            raise AuditPolError("auditpol.exe timed out after 30 seconds.")

    def _parse_csv(self, raw_csv: str) -> dict[str, AuditSubcategory]:
        """Parse auditpol CSV output into AuditSubcategory objects."""
        subcategories: dict[str, AuditSubcategory] = {}

        lines = raw_csv.strip().splitlines()
        cleaned_lines = [line for line in lines if line.strip() and "," in line]
        if not cleaned_lines:
            return subcategories

        cleaned_csv = "\n".join(cleaned_lines)
        reader = csv.DictReader(io.StringIO(cleaned_csv))
        current_category = ""

        for row in reader:
            subcategory_name = row.get("Subcategory", "").strip()
            if not subcategory_name:
                continue

            category = row.get("Category", current_category).strip()
            if category:
                current_category = category

            setting_str = row.get("Inclusion Setting", "No Auditing").strip()
            guid = row.get("Subcategory GUID", "").strip()

            subcategories[subcategory_name] = AuditSubcategory(
                name=subcategory_name,
                category=current_category,
                setting=AuditSetting.from_string(setting_str),
                guid=guid,
            )

        return subcategories

    @staticmethod
    def parse_from_string(raw_csv: str) -> PolicySnapshot:
        """Parse a raw auditpol CSV string into a PolicySnapshot (for testing)."""
        collector = AuditPolCollector()
        subcategories = collector._parse_csv(raw_csv)
        return PolicySnapshot(
            subcategories=subcategories,
            source="string",
            collection_timestamp=datetime.now(timezone.utc).isoformat(),
        )
