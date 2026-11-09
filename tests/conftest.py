"""Shared pytest fixtures for LogBlind tests."""

from __future__ import annotations

import pytest

from logblind.models.policy import AuditSetting, AuditSubcategory, PolicySnapshot, RegistrySnapshot
from logblind.models.technique import EventRequirement, KnowledgeBase, Technique


@pytest.fixture
def sample_policy_all_enabled() -> PolicySnapshot:
    """Policy where all relevant subcategories are enabled."""
    return PolicySnapshot(
        machine_name="TEST-PC",
        source="test",
        subcategories={
            "Logon": AuditSubcategory(
                name="Logon", category="Logon/Logoff", setting=AuditSetting.SUCCESS_AND_FAILURE
            ),
            "Special Logon": AuditSubcategory(
                name="Special Logon", category="Logon/Logoff", setting=AuditSetting.SUCCESS
            ),
            "Other Logon/Logoff Events": AuditSubcategory(
                name="Other Logon/Logoff Events",
                category="Logon/Logoff",
                setting=AuditSetting.SUCCESS,
            ),
            "File Share": AuditSubcategory(
                name="File Share", category="Object Access", setting=AuditSetting.SUCCESS
            ),
            "Detailed File Share": AuditSubcategory(
                name="Detailed File Share", category="Object Access", setting=AuditSetting.SUCCESS
            ),
            "Process Creation": AuditSubcategory(
                name="Process Creation", category="Detailed Tracking", setting=AuditSetting.SUCCESS
            ),
        },
        registry=RegistrySnapshot(
            sysmon_installed=True, scriptblock_logging=True, commandline_audit=True
        ),
    )


@pytest.fixture
def sample_policy_minimal() -> PolicySnapshot:
    """Minimal policy with almost nothing enabled."""
    return PolicySnapshot(
        machine_name="VULN-PC",
        source="test",
        subcategories={
            "Logon": AuditSubcategory(
                name="Logon", category="Logon/Logoff", setting=AuditSetting.NO_AUDITING
            ),
            "Special Logon": AuditSubcategory(
                name="Special Logon", category="Logon/Logoff", setting=AuditSetting.NO_AUDITING
            ),
            "File Share": AuditSubcategory(
                name="File Share", category="Object Access", setting=AuditSetting.NO_AUDITING
            ),
            "Process Creation": AuditSubcategory(
                name="Process Creation",
                category="Detailed Tracking",
                setting=AuditSetting.NO_AUDITING,
            ),
        },
        registry=RegistrySnapshot(
            sysmon_installed=False, scriptblock_logging=False, commandline_audit=False
        ),
    )


@pytest.fixture
def sample_technique_rdp() -> Technique:
    """Simplified RDP technique for testing."""
    return Technique(
        technique_id="T1021.001",
        name="Remote Desktop Protocol (RDP)",
        event_requirements=[
            EventRequirement(
                event_id=4624,
                channel="Security",
                condition="Logon Type 10",
                importance="CRITICAL",
                audit_subcategory="Logon",
                audit_setting="Success",
            ),
            EventRequirement(
                event_id=4778,
                channel="Security",
                condition="Session reconnected",
                importance="HIGH",
                audit_subcategory="Other Logon/Logoff Events",
                audit_setting="Success",
            ),
            EventRequirement(
                event_id=1,
                channel="Microsoft-Windows-Sysmon/Operational",
                condition="Process creation",
                importance="MEDIUM",
                sysmon_required=True,
            ),
        ],
    )


@pytest.fixture
def sample_knowledge_base(sample_technique_rdp: Technique) -> KnowledgeBase:
    return KnowledgeBase(techniques=[sample_technique_rdp])


SAMPLE_AUDITPOL_CSV = """\
Machine,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting
TEST-PC,System,Logon,{0CCE9215-69AE-11D9-BED3-505054503030},Success and Failure
TEST-PC,System,Special Logon,{0CCE921B-69AE-11D9-BED3-505054503030},Success
TEST-PC,System,Process Creation,{0CCE922B-69AE-11D9-BED3-505054503030},Success
TEST-PC,System,File Share,{0CCE9224-69AE-11D9-BED3-505054503030},No Auditing
TEST-PC,System,Detailed File Share,{0CCE9244-69AE-11D9-BED3-505054503030},No Auditing
"""
