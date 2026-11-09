"""Collector for Windows registry-based audit configuration checks.

Checks for: Sysmon, PowerShell ScriptBlock Logging, command-line
process creation auditing, and Windows Event Forwarding.
"""

from __future__ import annotations

import subprocess

from logblind.models.policy import RegistryCheck, RegistrySnapshot


class RegistryCollector:
    """Checks Windows registry for supplementary logging configuration."""

    def collect(self) -> RegistrySnapshot:
        """Collect all registry-based configuration checks."""
        snapshot = RegistrySnapshot()

        sysmon_check = self._check_sysmon()
        snapshot.checks.append(sysmon_check)
        snapshot.sysmon_installed = sysmon_check.is_configured

        scriptblock_check = self._check_scriptblock_logging()
        snapshot.checks.append(scriptblock_check)
        snapshot.scriptblock_logging = scriptblock_check.is_configured

        cmdline_check = self._check_commandline_audit()
        snapshot.checks.append(cmdline_check)
        snapshot.commandline_audit = cmdline_check.is_configured

        wef_check = self._check_wef()
        snapshot.checks.append(wef_check)
        snapshot.wef_configured = wef_check.is_configured

        return snapshot

    def _check_sysmon(self) -> RegistryCheck:
        """Check if Sysmon is installed by looking for its service."""
        for svc in ["sysmon64", "sysmon"]:
            try:
                result = subprocess.run(
                    ["sc", "query", svc],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0 and "RUNNING" in result.stdout:
                    return RegistryCheck(
                        name="Sysmon",
                        path=f"Service: {svc}",
                        value_name="State",
                        expected_value="RUNNING",
                        actual_value="RUNNING",
                        is_configured=True,
                        description=f"Sysmon ({svc}) is installed and running.",
                    )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return RegistryCheck(
            name="Sysmon",
            path="Service: Sysmon64/Sysmon",
            value_name="State",
            expected_value="RUNNING",
            actual_value=None,
            is_configured=False,
            description="Sysmon is NOT installed or not running.",
        )

    def _check_scriptblock_logging(self) -> RegistryCheck:
        """Check if PowerShell ScriptBlock Logging is enabled."""
        return self._read_registry_value(
            name="PowerShell ScriptBlock Logging",
            path=r"HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging",
            value_name="EnableScriptBlockLogging",
            expected_value=1,
            description="Enables Event ID 4104 — logs full PowerShell script content.",
        )

    def _check_commandline_audit(self) -> RegistryCheck:
        """Check if command-line process creation auditing is enabled."""
        return self._read_registry_value(
            name="Command-Line Process Auditing",
            path=r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit",
            value_name="ProcessCreationIncludeCmdLine_Enabled",
            expected_value=1,
            description="Includes command-line arguments in Event ID 4688.",
        )

    def _check_wef(self) -> RegistryCheck:
        """Check if Windows Event Forwarding client is configured."""
        try:
            result = subprocess.run(
                ["sc", "query", "wecsvc"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            is_running = result.returncode == 0 and "RUNNING" in result.stdout
            return RegistryCheck(
                name="Windows Event Forwarding",
                path="Service: wecsvc",
                value_name="State",
                expected_value="RUNNING",
                actual_value="RUNNING" if is_running else "STOPPED",
                is_configured=is_running,
                description="Windows Event Collector service for centralized log forwarding.",
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return RegistryCheck(
                name="Windows Event Forwarding",
                path="Service: wecsvc",
                value_name="State",
                expected_value="RUNNING",
                actual_value=None,
                is_configured=False,
                description="Could not check WEF service status.",
            )

    def _read_registry_value(
        self,
        name: str,
        path: str,
        value_name: str,
        expected_value: int | str,
        description: str,
    ) -> RegistryCheck:
        """Read a registry value using reg.exe query."""
        try:
            result = subprocess.run(
                ["reg", "query", path, "/v", value_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if value_name in line:
                        parts = line.strip().split()
                        if len(parts) >= 3:
                            actual = parts[-1]
                            if actual.startswith("0x"):
                                actual_int = int(actual, 16)
                                return RegistryCheck(
                                    name=name,
                                    path=path,
                                    value_name=value_name,
                                    expected_value=expected_value,
                                    actual_value=actual_int,
                                    is_configured=(actual_int == expected_value),
                                    description=description,
                                )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return RegistryCheck(
            name=name,
            path=path,
            value_name=value_name,
            expected_value=expected_value,
            actual_value=None,
            is_configured=False,
            description=f"{name} is not configured. {description}",
        )
