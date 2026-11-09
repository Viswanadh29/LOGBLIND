"""YAML knowledge base loader and validator."""

from __future__ import annotations

from pathlib import Path

import yaml

from logblind.models.technique import (
    AdditionalCheck, EventRequirement, KnowledgeBase, Technique,
)


class KnowledgeBaseError(Exception):
    """Raised when a knowledge base file is invalid."""


class KnowledgeBaseLoader:
    """Loads and validates ATT&CK technique mappings from YAML files."""

    def __init__(self, kb_dir: Path | None = None) -> None:
        if kb_dir is None:
            self._kb_dir = Path(__file__).parent / "techniques"
        else:
            self._kb_dir = kb_dir

    def load(self) -> KnowledgeBase:
        """Load all technique YAML files and return a KnowledgeBase."""
        if not self._kb_dir.exists():
            raise KnowledgeBaseError(f"Knowledge base directory not found: {self._kb_dir}")

        yaml_files = sorted(self._kb_dir.glob("*.yaml"))
        if not yaml_files:
            raise KnowledgeBaseError(f"No technique YAML files found in: {self._kb_dir}")

        techniques = [self._load_technique(f) for f in yaml_files]
        return KnowledgeBase(techniques=techniques)

    def _load_technique(self, yaml_path: Path) -> Technique:
        """Load a single technique YAML file."""
        try:
            with open(yaml_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise KnowledgeBaseError(f"Invalid YAML in {yaml_path.name}: {e}")

        if not data or "technique" not in data:
            raise KnowledgeBaseError(f"Missing 'technique' root key in {yaml_path.name}")

        tech_data = data["technique"]
        for field in ["id", "name"]:
            if field not in tech_data:
                raise KnowledgeBaseError(f"Missing required field '{field}' in {yaml_path.name}")

        event_requirements = [
            EventRequirement(
                event_id=evt["id"],
                channel=evt.get("channel", "Security"),
                condition=evt.get("condition", ""),
                importance=evt.get("importance", "HIGH"),
                audit_subcategory=evt.get("audit_subcategory"),
                audit_setting=evt.get("audit_setting", "Success"),
                registry_check=evt.get("registry_check"),
                sysmon_required=evt.get("sysmon_required", False),
            )
            for evt in tech_data.get("detection_requirements", {}).get("event_ids", [])
        ]

        additional_checks = [
            AdditionalCheck(
                check_type=chk.get("check_type", chk.get("type", "registry")),
                description=chk.get("description", ""),
                path=chk.get("path", ""),
                value_name=chk.get("value", ""),
                expected_value=str(chk.get("expected", "")),
                importance=chk.get("importance", "MEDIUM"),
            )
            for chk in tech_data.get("detection_requirements", {}).get("additional_checks", [])
        ]

        return Technique(
            technique_id=tech_data["id"],
            name=tech_data["name"],
            tactic=tech_data.get("tactic", "Lateral Movement"),
            description=tech_data.get("description", ""),
            real_world_tools=tech_data.get("real_world_tools", []),
            event_requirements=event_requirements,
            additional_checks=additional_checks,
            references=tech_data.get("references", []),
        )
