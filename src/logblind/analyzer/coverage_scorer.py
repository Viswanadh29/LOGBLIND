"""Coverage scoring engine — aggregates gap results into an overall report."""

from __future__ import annotations

from logblind.models.analysis import CoverageReport, CoverageStatus, EventGap, TechniqueGapResult


class CoverageScorer:
    """Computes overall coverage scores from technique gap results."""

    def score(self, gap_results: list[TechniqueGapResult]) -> CoverageReport:
        """Calculate the overall coverage report."""
        if not gap_results:
            return CoverageReport(
                overall_score=0.0,
                total_techniques=0,
                covered_count=0,
                partial_count=0,
                blind_count=0,
            )

        covered = sum(1 for r in gap_results if r.status == CoverageStatus.COVERED)
        partial = sum(1 for r in gap_results if r.status == CoverageStatus.PARTIAL)
        blind = sum(1 for r in gap_results if r.status == CoverageStatus.BLIND)
        overall_score = round(sum(r.coverage_percent for r in gap_results) / len(gap_results), 1)

        # Collect unique critical/high gaps
        seen: set[tuple[int, str, str]] = set()
        critical_gaps: list[EventGap] = []
        for result in gap_results:
            for gap in result.gaps:
                if gap.importance in ("CRITICAL", "HIGH"):
                    key = (gap.event_id, gap.channel, gap.reason)
                    if key not in seen:
                        seen.add(key)
                        critical_gaps.append(gap)

        return CoverageReport(
            overall_score=overall_score,
            total_techniques=len(gap_results),
            covered_count=covered,
            partial_count=partial,
            blind_count=blind,
            technique_results=gap_results,
            critical_gaps=critical_gaps,
        )
