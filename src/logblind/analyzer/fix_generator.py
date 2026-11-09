"""Fix script generator — generates PowerShell remediation scripts."""

# ruff: noqa: E501

from __future__ import annotations

from datetime import datetime, timezone

from logblind import __version__
from logblind.models.analysis import CoverageReport


class FixGenerator:
    """Generates PowerShell scripts to fix audit configuration gaps."""

    def generate(self, report: CoverageReport, *, dry_run: bool = False) -> str:
        """Generate a PowerShell script to fix all detected gaps.

        Args:
            report: The coverage report from a scan.
            dry_run: If True, wraps commands in Write-Host so they
                     are displayed but not executed.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        lines = [
            "# ================================================================",
            f"# LogBlind v{__version__} -- Audit Configuration Remediation Script",
            f"# Generated: {timestamp}",
            f"# Overall Coverage Before Fix: {report.overall_score:.0f}%",
            "# ================================================================",
            "#",
            "# REVIEW THIS SCRIPT BEFORE RUNNING.",
            "# Must be run as Administrator.",
            "#",
            "# Usage:",
            "#   .\\logblind_fix.ps1            # Apply fixes",
            "#   .\\logblind_fix.ps1 -WhatIf    # Preview only",
            "# ================================================================",
            "",
            "#Requires -RunAsAdministrator",
            "",
            "param(",
            "    [switch]$WhatIf",
            ")",
            "",
            "$ErrorActionPreference = 'Stop'",
            "",
            "Write-Host ''",
            "Write-Host '[LogBlind] Audit Configuration Remediation' -ForegroundColor Cyan",
            "Write-Host ('=' * 60)",
            "Write-Host ''",
            "",
        ]

        seen: set[str] = set()
        audit_fixes: list[tuple[str, int, str]] = []  # (command, event_id, description)
        registry_fixes: list[tuple[str, str]] = []  # (description, instruction)
        recommendations: list[str] = []

        for tr in report.technique_results:
            for gap in tr.gaps:
                if not gap.fix_command or gap.fix_command in seen:
                    continue
                seen.add(gap.fix_command)

                if gap.fix_command.startswith("auditpol"):
                    audit_fixes.append((gap.fix_command, gap.event_id, gap.condition))
                elif gap.fix_command.startswith("# Configure:"):
                    registry_fixes.append((gap.condition, gap.fix_command))
                elif gap.fix_command.startswith("# Install"):
                    recommendations.append(gap.fix_command)

        # --- Section 1: Audit Policy Changes ---
        if audit_fixes:
            lines.append("# ----------------------------------------------------------")
            lines.append("# Section 1: Audit Policy Changes")
            lines.append("# ----------------------------------------------------------")
            lines.append("")
            lines.append(
                f"Write-Host '[1/{self._section_count(audit_fixes, registry_fixes, recommendations)}] Applying audit policy changes...' -ForegroundColor Yellow"
            )
            lines.append("")

            for i, (cmd, eid, desc) in enumerate(audit_fixes, 1):
                lines.append(f"# Fix #{i}: Event ID {eid} - {desc}")
                if dry_run:
                    lines.append(f'Write-Host "  [DRY-RUN] Would execute: {cmd}"')
                else:
                    lines.append("if ($WhatIf) {")
                    lines.append(f'    Write-Host "  [PREVIEW] {cmd}"')
                    lines.append("} else {")
                    lines.append(f"    {cmd}")
                    lines.append(
                        f'    Write-Host "  [OK] Applied: Event ID {eid}" -ForegroundColor Green'
                    )
                    lines.append("}")
                lines.append("")

        # --- Section 2: Registry-Based Fixes ---
        if registry_fixes:
            lines.append("# ----------------------------------------------------------")
            lines.append("# Section 2: Registry-Based Configuration")
            lines.append("# ----------------------------------------------------------")
            lines.append("")

            section_num = 2 if audit_fixes else 1
            total_sections = self._section_count(audit_fixes, registry_fixes, recommendations)
            lines.append(
                f"Write-Host '[{section_num}/{total_sections}] Applying registry fixes...' -ForegroundColor Yellow"
            )
            lines.append("")

            for desc, instruction in registry_fixes:
                lines.append(f"# {desc}")
                if "ScriptBlock" in instruction or "ScriptBlock" in desc:
                    reg_path = (
                        r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
                    )
                    lines.append("if ($WhatIf) {")
                    lines.append(
                        '    Write-Host "  [PREVIEW] Enable PowerShell ScriptBlock Logging"'
                    )
                    lines.append("} else {")
                    lines.append(f'    $regPath = "{reg_path}"')
                    lines.append(
                        "    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }"
                    )
                    lines.append(
                        '    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord'
                    )
                    lines.append(
                        '    Write-Host "  [OK] Enabled ScriptBlock Logging" -ForegroundColor Green'
                    )
                    lines.append("}")
                elif "Module" in instruction or "Module" in desc:
                    reg_path = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
                    lines.append("if ($WhatIf) {")
                    lines.append('    Write-Host "  [PREVIEW] Enable PowerShell Module Logging"')
                    lines.append("} else {")
                    lines.append(f'    $regPath = "{reg_path}"')
                    lines.append(
                        "    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }"
                    )
                    lines.append(
                        '    Set-ItemProperty -Path $regPath -Name "EnableModuleLogging" -Value 1 -Type DWord'
                    )
                    lines.append(
                        '    Write-Host "  [OK] Enabled Module Logging" -ForegroundColor Green'
                    )
                    lines.append("}")
                elif (
                    "Command" in instruction
                    or "command" in instruction
                    or "Command" in desc
                    or "command" in desc
                ):
                    reg_path = (
                        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
                    )
                    lines.append("if ($WhatIf) {")
                    lines.append(
                        '    Write-Host "  [PREVIEW] Enable command-line auditing in process creation events"'
                    )
                    lines.append("} else {")
                    lines.append(f'    $regPath = "{reg_path}"')
                    lines.append(
                        "    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }"
                    )
                    lines.append(
                        '    Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord'
                    )
                    lines.append(
                        '    Write-Host "  [OK] Enabled command-line auditing" -ForegroundColor Green'
                    )
                    lines.append("}")
                else:
                    lines.append(f"# Manual action required: {instruction}")
                lines.append("")

        # --- Section 3: Manual Recommendations ---
        if recommendations:
            lines.append("# ----------------------------------------------------------")
            lines.append("# Section 3: Manual Recommendations")
            lines.append("# ----------------------------------------------------------")
            lines.append("")

            seen_rec: set[str] = set()
            for rec in recommendations:
                if rec not in seen_rec:
                    seen_rec.add(rec)
                    lines.append(f"Write-Host '  {rec}' -ForegroundColor DarkYellow")
            lines.append("")

        # --- Summary ---
        lines.extend(
            [
                "# ----------------------------------------------------------",
                "# Done",
                "# ----------------------------------------------------------",
                "Write-Host ''",
                "if ($WhatIf) {",
                "    Write-Host '[PREVIEW MODE] No changes were made. Remove -WhatIf to apply.' -ForegroundColor Yellow",
                "} else {",
                f"    Write-Host '[DONE] Applied {len(audit_fixes)} audit policy fixes and {len(registry_fixes)} registry fixes.' -ForegroundColor Green",
                "}",
                "Write-Host 'Re-run: logblind scan -- to verify improvement.' -ForegroundColor Cyan",
                "",
            ]
        )

        return "\n".join(lines)

    @staticmethod
    def _section_count(audit: list, registry: list, recs: list) -> int:
        return sum(1 for lst in (audit, registry, recs) if lst)
