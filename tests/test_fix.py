"""Tests for the logblind fix command and fix generator."""

import re

import pytest
from typer.testing import CliRunner

from logblind.analyzer.fix_generator import FixGenerator
from logblind.cli import app
from logblind.models.analysis import (
    CoverageReport,
    CoverageStatus,
    EventGap,
    TechniqueGapResult,
)

runner = CliRunner()
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    return _ANSI_RE.sub("", text)


@pytest.fixture
def sample_report_with_gaps() -> CoverageReport:
    """Create a coverage report with mixed gaps for testing."""
    gaps = [
        EventGap(
            event_id=4625,
            channel="Security",
            condition="Failed logon Type 10",
            importance="HIGH",
            reason="Logon not set to Failure",
            fix_command='auditpol /set /subcategory:"Logon" /failure:enable',
        ),
        EventGap(
            event_id=5140,
            channel="Security",
            condition="Network share accessed",
            importance="CRITICAL",
            reason="File Share not enabled",
            fix_command='auditpol /set /subcategory:"File Share" /success:enable',
        ),
        EventGap(
            event_id=4104,
            channel="Microsoft-Windows-PowerShell/Operational",
            condition="Script block logging",
            importance="CRITICAL",
            reason="ScriptBlock Logging not configured",
            fix_command="# Configure: PowerShell ScriptBlock Logging",
        ),
        EventGap(
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            condition="Process creation",
            importance="HIGH",
            reason="Sysmon not installed",
            fix_command="# Install Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon",
        ),
    ]
    result = TechniqueGapResult(
        technique_id="T1021.001",
        technique_name="RDP",
        coverage_percent=40.0,
        status=CoverageStatus.PARTIAL,
        total_requirements=9,
        met_requirements=5,
        gaps=gaps,
    )
    return CoverageReport(
        overall_score=40.0,
        total_techniques=1,
        covered_count=0,
        partial_count=1,
        blind_count=0,
        technique_results=[result],
        critical_gaps=gaps,
    )


class TestFixGenerator:
    def test_generates_powershell(self, sample_report_with_gaps):
        script = FixGenerator().generate(sample_report_with_gaps)
        assert "#Requires -RunAsAdministrator" in script
        assert "LogBlind" in script

    def test_contains_auditpol_fixes(self, sample_report_with_gaps):
        script = FixGenerator().generate(sample_report_with_gaps)
        assert 'auditpol /set /subcategory:"Logon" /failure:enable' in script
        assert 'auditpol /set /subcategory:"File Share" /success:enable' in script

    def test_contains_scriptblock_registry_fix(self, sample_report_with_gaps):
        script = FixGenerator().generate(sample_report_with_gaps)
        assert "ScriptBlockLogging" in script
        assert "EnableScriptBlockLogging" in script

    def test_contains_sysmon_recommendation(self, sample_report_with_gaps):
        script = FixGenerator().generate(sample_report_with_gaps)
        assert "Sysmon" in script

    def test_contains_whatif_support(self, sample_report_with_gaps):
        script = FixGenerator().generate(sample_report_with_gaps)
        assert "$WhatIf" in script
        assert "[PREVIEW]" in script

    def test_dry_run_mode(self, sample_report_with_gaps):
        script = FixGenerator().generate(sample_report_with_gaps, dry_run=True)
        assert "[DRY-RUN]" in script

    def test_section_count(self, sample_report_with_gaps):
        script = FixGenerator().generate(sample_report_with_gaps)
        # Should have 3 sections: audit, registry, recommendations
        assert "Section 1: Audit Policy Changes" in script
        assert "Section 2: Registry-Based Configuration" in script
        assert "Section 3: Manual Recommendations" in script

    def test_no_gaps_report(self):
        report = CoverageReport(
            overall_score=90.0,
            total_techniques=1,
            covered_count=1,
            partial_count=0,
            blind_count=0,
            technique_results=[],
            critical_gaps=[],
        )
        script = FixGenerator().generate(report)
        # Should still generate a valid script header
        assert "LogBlind" in script


class TestFixCLI:
    def test_fix_help(self):
        result = runner.invoke(app, ["fix", "--help"])
        assert result.exit_code == 0
        plain = _plain(result.stdout)
        assert "fix" in plain.lower() or "Generate" in plain

    def test_fix_with_sample_csv(self, tmp_path):
        csv = tmp_path / "policy.csv"
        csv.write_text(
            "Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting\n"
            "PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success\n"
            "PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},No Auditing\n",
            encoding="utf-8",
        )
        output = tmp_path / "fix.ps1"
        result = runner.invoke(app, ["fix", "--file", str(csv), "--output", str(output)])
        assert result.exit_code == 0
        assert output.exists()
        content = output.read_text(encoding="utf-8")
        assert "#Requires -RunAsAdministrator" in content
