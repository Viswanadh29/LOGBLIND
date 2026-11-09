"""Tests for LogBlind collectors."""

from logblind.collectors.auditpol import AuditPolCollector
from logblind.models.policy import AuditSetting
from tests.conftest import SAMPLE_AUDITPOL_CSV


class TestAuditPolCollector:
    def test_parse_csv_basic(self):
        snapshot = AuditPolCollector.parse_from_string(SAMPLE_AUDITPOL_CSV)
        assert len(snapshot.subcategories) > 0

    def test_parse_csv_logon_setting(self):
        snapshot = AuditPolCollector.parse_from_string(SAMPLE_AUDITPOL_CSV)
        logon = snapshot.get_subcategory("Logon")
        assert logon is not None
        assert logon.setting == AuditSetting.SUCCESS_AND_FAILURE

    def test_parse_csv_no_auditing(self):
        snapshot = AuditPolCollector.parse_from_string(SAMPLE_AUDITPOL_CSV)
        fs = snapshot.get_subcategory("File Share")
        assert fs is not None
        assert fs.setting == AuditSetting.NO_AUDITING

    def test_parse_csv_empty(self):
        snapshot = AuditPolCollector.parse_from_string("")
        assert len(snapshot.subcategories) == 0
