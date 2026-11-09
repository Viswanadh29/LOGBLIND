# ================================================================
# LogBlind v0.2.0 -- Audit Configuration Remediation Script
# Generated: 2026-11-09 12:02:08 UTC
# Overall Coverage Before Fix: 51%
# ================================================================
#
# REVIEW THIS SCRIPT BEFORE RUNNING.
# Must be run as Administrator.
#
# Usage:
#   .\logblind_fix.ps1            # Apply fixes
#   .\logblind_fix.ps1 -WhatIf    # Preview only
# ================================================================

#Requires -RunAsAdministrator

param(
    [switch]$WhatIf
)

$ErrorActionPreference = 'Stop'

Write-Host ''
Write-Host '[LogBlind] Audit Configuration Remediation' -ForegroundColor Cyan
Write-Host ('=' * 60)
Write-Host ''

# ----------------------------------------------------------
# Section 1: Audit Policy Changes
# ----------------------------------------------------------

Write-Host '[1/3] Applying audit policy changes...' -ForegroundColor Yellow

# Fix #1: Event ID 4625 - Failed logon Type 10 — failed RDP attempts
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"Logon" /failure:enable"
} else {
    auditpol /set /subcategory:"Logon" /failure:enable
    Write-Host "  [OK] Applied: Event ID 4625" -ForegroundColor Green
}

# Fix #2: Event ID 4778 - Session reconnected to a Window Station (RDP reconnect)
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable"
} else {
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable
    Write-Host "  [OK] Applied: Event ID 4778" -ForegroundColor Green
}

# Fix #3: Event ID 4672 - Special privileges assigned to new logon (admin RDP)
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"Special Logon" /success:enable"
} else {
    auditpol /set /subcategory:"Special Logon" /success:enable
    Write-Host "  [OK] Applied: Event ID 4672" -ForegroundColor Green
}

# Fix #4: Event ID 5140 - Network share accessed — detect ADMIN$, C$, IPC$ access
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"File Share" /success:enable"
} else {
    auditpol /set /subcategory:"File Share" /success:enable
    Write-Host "  [OK] Applied: Event ID 5140" -ForegroundColor Green
}

# Fix #5: Event ID 5145 - Detailed file share access — specific files on shares
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"Detailed File Share" /success:enable"
} else {
    auditpol /set /subcategory:"Detailed File Share" /success:enable
    Write-Host "  [OK] Applied: Event ID 5145" -ForegroundColor Green
}

# Fix #6: Event ID 4776 - NTLM authentication — DCOM often authenticates via NTLM
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"Credential Validation" /success:enable"
} else {
    auditpol /set /subcategory:"Credential Validation" /success:enable
    Write-Host "  [OK] Applied: Event ID 4776" -ForegroundColor Green
}

# Fix #7: Event ID 4698 - Scheduled task was created — captures task name, action, and creator
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"Other Object Access Events" /success:enable"
} else {
    auditpol /set /subcategory:"Other Object Access Events" /success:enable
    Write-Host "  [OK] Applied: Event ID 4698" -ForegroundColor Green
}

# Fix #8: Event ID 4663 - Object access — file write/create operations on sensitive paths
if ($WhatIf) {
    Write-Host "  [PREVIEW] auditpol /set /subcategory:"File System" /success:enable"
} else {
    auditpol /set /subcategory:"File System" /success:enable
    Write-Host "  [OK] Applied: Event ID 4663" -ForegroundColor Green
}

# ----------------------------------------------------------
# Section 2: Registry-Based Configuration
# ----------------------------------------------------------

Write-Host '[2/3] Applying registry fixes...' -ForegroundColor Yellow

# Script block logging — captures full remote PowerShell commands
if ($WhatIf) {
    Write-Host "  [PREVIEW] Enable PowerShell ScriptBlock Logging"
} else {
    $regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    Set-ItemProperty -Path $regPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord
    Write-Host "  [OK] Enabled ScriptBlock Logging" -ForegroundColor Green
}

# ----------------------------------------------------------
# Section 3: Manual Recommendations
# ----------------------------------------------------------

Write-Host '  # Install Sysmon: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon' -ForegroundColor DarkYellow

# ----------------------------------------------------------
# Done
# ----------------------------------------------------------
Write-Host ''
if ($WhatIf) {
    Write-Host '[PREVIEW MODE] No changes were made. Remove -WhatIf to apply.' -ForegroundColor Yellow
} else {
    Write-Host '[DONE] Applied 8 audit policy fixes and 1 registry fixes.' -ForegroundColor Green
}
Write-Host 'Re-run: logblind scan -- to verify improvement.' -ForegroundColor Cyan
