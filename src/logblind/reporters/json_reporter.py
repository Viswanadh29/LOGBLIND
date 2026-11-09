"""JSON reporter — exports analysis results as structured JSON."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from logblind import __version__
from logblind.models.analysis import CoverageReport, TechniqueGapResult


class JSONReporter:
    """Exports analysis results as JSON."""

    def render(self, report: CoverageReport, gap_results: list[TechniqueGapResult]) -> str:
        """Render the analysis as a JSON string."""
        output = {
            "logblind_version": __version__,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "overall_score": report.overall_score,
                "risk_level": report.risk_level,
                "total_techniques": report.total_techniques,
                "covered": report.covered_count,
                "partial": report.partial_count,
                "blind": report.blind_count,
            },
            "techniques": [
                {
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "coverage_percent": r.coverage_percent,
                    "status": r.status.value,
                    "total_requirements": r.total_requirements,
                    "met_requirements": r.met_requirements,
                    "gaps": [
                        {"event_id": g.event_id, "channel": g.channel,
                         "condition": g.condition, "importance": g.importance,
                         "reason": g.reason, "fix_command": g.fix_command}
                        for g in r.gaps
                    ],
                    "notes": r.notes,
                }
                for r in gap_results
            ],
            "critical_gaps": [
                {"event_id": g.event_id, "channel": g.channel,
                 "condition": g.condition, "importance": g.importance,
                 "reason": g.reason, "fix_command": g.fix_command}
                for g in report.critical_gaps
            ],
        }
        return json.dumps(output, indent=2, ensure_ascii=False)
