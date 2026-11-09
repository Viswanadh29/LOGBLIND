"""ATT&CK Navigator JSON layer exporter.

Generates a JSON file compatible with MITRE ATT&CK Navigator
(https://mitre-attack.github.io/attack-navigator/) to visualize
LogBlind coverage results as a heatmap layer.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from logblind import __version__
from logblind.models.analysis import CoverageReport, CoverageStatus, TechniqueGapResult


class NavigatorExporter:
    """Exports coverage results as an ATT&CK Navigator layer JSON."""

    # Navigator layer format version
    LAYER_VERSION = "4.5"
    NAV_VERSION = "4.9.6"
    ATTACK_VERSION = "16"
    DOMAIN = "enterprise-attack"

    def export(
        self,
        report: CoverageReport,
        gap_results: list[TechniqueGapResult],
        *,
        layer_name: str = "LogBlind Coverage",
        description: str | None = None,
    ) -> str:
        """Generate a Navigator layer JSON string.

        Colors:
          - Green  (#22c55e) = COVERED (score >= 80)
          - Yellow (#eab308) = PARTIAL (0 < score < 80)
          - Red    (#ef4444) = BLIND   (score == 0)
        """
        timestamp = datetime.now(timezone.utc).isoformat()

        if description is None:
            description = (
                f"LogBlind v{__version__} audit coverage analysis. "
                f"Overall score: {report.overall_score:.0f}% ({report.risk_level}). "
                f"Generated: {timestamp}"
            )

        techniques = []
        for result in gap_results:
            color = self._status_color(result.status)
            score = self._score_bucket(result.coverage_percent)

            comment_lines = [
                f"Coverage: {result.coverage_percent:.0f}%",
                f"Status: {result.status.value}",
                f"Met: {result.met_requirements}/{result.total_requirements} requirements",
            ]
            if result.gaps:
                comment_lines.append(f"Gaps: {len(result.gaps)}")
                for gap in result.gaps[:5]:  # Top 5 gaps
                    comment_lines.append(f"  - EID {gap.event_id}: {gap.reason}")
                if len(result.gaps) > 5:
                    comment_lines.append(f"  ... and {len(result.gaps) - 5} more")

            tid = result.technique_id
            # Handle sub-techniques: T1021.001 -> tactic technique T1021 with sub .001
            technique_entry = {
                "techniqueID": tid,
                "tactic": "lateral-movement",
                "color": color,
                "comment": "\n".join(comment_lines),
                "score": score,
                "enabled": True,
                "showSubtechniques": False,
            }
            # If it's a sub-technique, also mark the parent
            if "." in tid:
                technique_entry["showSubtechniques"] = True

            techniques.append(technique_entry)

        layer = {
            "name": layer_name,
            "versions": {
                "attack": self.ATTACK_VERSION,
                "navigator": self.NAV_VERSION,
                "layer": self.LAYER_VERSION,
            },
            "domain": self.DOMAIN,
            "description": description,
            "filters": {
                "platforms": [
                    "Windows",
                ],
            },
            "sorting": 3,  # Sort by score descending
            "layout": {
                "layout": "side",
                "aggregateFunction": "average",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False,
            },
            "hideDisabled": False,
            "techniques": techniques,
            "gradient": {
                "colors": ["#ef4444", "#eab308", "#22c55e"],
                "minValue": 0,
                "maxValue": 100,
            },
            "legendItems": [
                {"label": "Covered (80-100%)", "color": "#22c55e"},
                {"label": "Partial (1-79%)", "color": "#eab308"},
                {"label": "Blind (0%)", "color": "#ef4444"},
                {"label": "Not assessed", "color": "#ffffff"},
            ],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#1e293b",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
            "selectVisibleTechniques": False,
            "metadata": [
                {"name": "tool", "value": f"LogBlind v{__version__}"},
                {"name": "generated", "value": timestamp},
                {"name": "overall_score", "value": f"{report.overall_score:.0f}%"},
                {"name": "risk_level", "value": report.risk_level},
            ],
        }

        return json.dumps(layer, indent=2, ensure_ascii=False)

    @staticmethod
    def _status_color(status: CoverageStatus) -> str:
        return {
            CoverageStatus.COVERED: "#22c55e",
            CoverageStatus.PARTIAL: "#eab308",
            CoverageStatus.BLIND: "#ef4444",
        }[status]

    @staticmethod
    def _score_bucket(coverage: float) -> int:
        """Map coverage percentage to a Navigator score (0-100)."""
        return max(0, min(100, round(coverage)))
