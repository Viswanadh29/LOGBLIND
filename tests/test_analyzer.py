"""Tests for LogBlind analysis engine."""

from logblind.analyzer.coverage_scorer import CoverageScorer
from logblind.analyzer.gap_detector import GapDetector
from logblind.models.analysis import CoverageStatus


class TestGapDetector:
    def test_full_coverage(self, sample_policy_all_enabled, sample_knowledge_base):
        results = GapDetector().analyze(sample_policy_all_enabled, sample_knowledge_base)
        assert len(results) == 1
        assert results[0].status == CoverageStatus.COVERED
        assert results[0].coverage_percent >= 80

    def test_no_coverage(self, sample_policy_minimal, sample_knowledge_base):
        results = GapDetector().analyze(sample_policy_minimal, sample_knowledge_base)
        assert len(results) == 1
        assert results[0].status in (CoverageStatus.BLIND, CoverageStatus.PARTIAL)
        assert len(results[0].gaps) > 0

    def test_technique_filter(self, sample_policy_all_enabled, sample_knowledge_base):
        results = GapDetector().analyze(
            sample_policy_all_enabled, sample_knowledge_base, technique_filter=["T9999"]
        )
        assert len(results) == 0

    def test_gaps_have_fix_commands(self, sample_policy_minimal, sample_knowledge_base):
        results = GapDetector().analyze(sample_policy_minimal, sample_knowledge_base)
        has_fix = any(g.fix_command for r in results for g in r.gaps)
        assert has_fix


class TestCoverageScorer:
    def test_empty(self):
        report = CoverageScorer().score([])
        assert report.overall_score == 0.0

    def test_full_coverage(self, sample_policy_all_enabled, sample_knowledge_base):
        results = GapDetector().analyze(sample_policy_all_enabled, sample_knowledge_base)
        report = CoverageScorer().score(results)
        assert report.overall_score >= 80
        assert report.blind_count == 0

    def test_no_coverage(self, sample_policy_minimal, sample_knowledge_base):
        results = GapDetector().analyze(sample_policy_minimal, sample_knowledge_base)
        report = CoverageScorer().score(results)
        assert report.overall_score < 80
        assert len(report.critical_gaps) > 0
