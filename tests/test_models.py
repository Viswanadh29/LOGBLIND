"""Tests for LogBlind data models."""

from logblind.models.analysis import CoverageReport, CoverageStatus
from logblind.models.policy import AuditSetting


class TestAuditSetting:
    def test_from_string_success(self):
        assert AuditSetting.from_string("Success") == AuditSetting.SUCCESS

    def test_from_string_failure(self):
        assert AuditSetting.from_string("Failure") == AuditSetting.FAILURE

    def test_from_string_both(self):
        assert AuditSetting.from_string("Success and Failure") == AuditSetting.SUCCESS_AND_FAILURE

    def test_from_string_no_auditing(self):
        assert AuditSetting.from_string("No Auditing") == AuditSetting.NO_AUDITING

    def test_from_string_case_insensitive(self):
        assert AuditSetting.from_string("success") == AuditSetting.SUCCESS

    def test_from_string_unknown(self):
        assert AuditSetting.from_string("garbage") == AuditSetting.NO_AUDITING

    def test_includes_success(self):
        assert AuditSetting.SUCCESS.includes_success() is True
        assert AuditSetting.SUCCESS_AND_FAILURE.includes_success() is True
        assert AuditSetting.FAILURE.includes_success() is False
        assert AuditSetting.NO_AUDITING.includes_success() is False

    def test_includes_failure(self):
        assert AuditSetting.FAILURE.includes_failure() is True
        assert AuditSetting.SUCCESS_AND_FAILURE.includes_failure() is True
        assert AuditSetting.SUCCESS.includes_failure() is False


class TestPolicySnapshot:
    def test_get_subcategory(self, sample_policy_all_enabled):
        assert sample_policy_all_enabled.get_subcategory("Logon") is not None

    def test_get_subcategory_case_insensitive(self, sample_policy_all_enabled):
        assert sample_policy_all_enabled.get_subcategory("logon") is not None

    def test_get_subcategory_not_found(self, sample_policy_all_enabled):
        assert sample_policy_all_enabled.get_subcategory("NonExistent") is None

    def test_is_success_enabled(self, sample_policy_all_enabled):
        assert sample_policy_all_enabled.is_success_enabled("Logon") is True

    def test_is_success_not_enabled(self, sample_policy_minimal):
        assert sample_policy_minimal.is_success_enabled("Logon") is False


class TestKnowledgeBase:
    def test_get_technique(self, sample_knowledge_base):
        assert sample_knowledge_base.get_technique("T1021.001") is not None

    def test_get_technique_not_found(self, sample_knowledge_base):
        assert sample_knowledge_base.get_technique("T9999") is None


class TestCoverageStatus:
    def test_symbol(self):
        assert CoverageStatus.COVERED.symbol == "[+]"
        assert CoverageStatus.BLIND.symbol == "[-]"

    def test_color(self):
        assert CoverageStatus.COVERED.color == "green"


class TestCoverageReport:
    def test_risk_levels(self):
        assert CoverageReport(30, 4, 0, 1, 3).risk_level == "HIGH RISK"
        assert CoverageReport(60, 4, 2, 1, 1).risk_level == "MEDIUM RISK"
        assert CoverageReport(85, 4, 3, 1, 0).risk_level == "LOW RISK"
