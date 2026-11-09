# 🛡️ LogBlind

[![CI](https://github.com/VISWANADH/logblind/actions/workflows/ci.yml/badge.svg)](https://github.com/VISWANADH/logblind/actions/workflows/ci.yml)
[![PyPI version](https://badge.fury.io/py/logblind.svg)](https://badge.fury.io/py/logblind)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Windows Log Configuration Auditor for Lateral Movement Blind Spots**
>
> Maps your Windows audit policy against MITRE ATT&CK lateral movement techniques to reveal exactly what you **can** and **cannot** detect.

---

## The Problem

Organizations think they're logging everything. But default Windows audit configurations miss **~60% of lateral movement indicators** — PsExec, WMI, WinRM, RDP hijacking, Pass-the-Hash. SOC teams discover the blind spots only *after* an incident.

Existing tools (Sysmon, KAPE, Wazuh) help **collect and analyze** logs. But **no tool audits whether your log configuration is even capable of detecting specific ATT&CK techniques before an attack happens.**

**LogBlind is that tool.**

## Features

- 🔍 **Scans** your live Windows audit policy (`auditpol`) and registry settings
- 📚 **Maps** against a curated knowledge base of MITRE ATT&CK lateral movement techniques
- 📊 **Scores** your detection coverage with weighted per-technique analysis
- 🔴 **Identifies** exactly which techniques you're blind to and why
- 🔧 **Generates** PowerShell remediation scripts to close gaps
- 📂 **Supports offline mode** — export policy on one machine, analyze on another
- 🎯 **Outputs** colored CLI heatmaps, JSON reports, and ATT&CK Navigator layers

## Quick Start

### Install

```bash
pip install logblind
```

### Scan (requires Administrator on Windows)

```bash
# Scan local machine
logblind scan

# Scan with detailed per-event breakdown
logblind scan --verbose

# Export to JSON
logblind scan --output report.json --format json

# Offline mode: analyze an exported policy
auditpol /get /category:* /r > policy.csv
logblind scan --file policy.csv
```

### Example Output

```
╭─────────────────────────────────────────────╮
│   LogBlind v0.1.0                           │
│   Windows Lateral Movement Detection Auditor│
╰─────────────────────────────────────────────╯

📊 Overall Coverage Score: 42%
  ████████░░░░░░░░░░░░ [HIGH RISK]

┌────────────┬───────────────────────────┬──────────┬───────────┐
│ ATT&CK ID  │ Technique                 │ Coverage │ Status    │
├────────────┼───────────────────────────┼──────────┼───────────┤
│ T1021.001  │ Remote Desktop (RDP)      │  75%     │ 🟡 PARTIAL │
│ T1021.002  │ SMB/Admin Shares (PsExec) │  25%     │ 🔴 BLIND   │
│ T1021.006  │ WinRM/PS Remoting         │   0%     │ 🔴 BLIND   │
│ T1047      │ WMI Execution             │  50%     │ 🟡 PARTIAL │
└────────────┴───────────────────────────┴──────────┴───────────┘

🔴 CRITICAL GAPS FOUND:
  ╶ "Logon" subcategory: Not set to Success auditing
    → Missing: Event 4624 for RDP, SMB, WinRM, WMI
    → Fix: auditpol /set /subcategory:"Logon" /success:enable
```

## Covered ATT&CK Techniques

| ATT&CK ID | Technique | Common Tools |
|-----------|-----------|-------------|
| T1021.001 | Remote Desktop Protocol (RDP) | mstsc, SharpRDP |
| T1021.002 | SMB/Windows Admin Shares | PsExec, Impacket, CME |
| T1021.006 | Windows Remote Mgmt (WinRM) | winrs, Invoke-Command, Evil-WinRM |
| T1047 | WMI | wmic, Invoke-WmiMethod, wmiexec |

*More techniques coming in v0.2.0+*

## How It Works

1. **Collects** your current audit policy via `auditpol.exe` + registry checks
2. **Loads** a knowledge base of YAML files mapping ATT&CK techniques to required Event IDs
3. **Compares** your config against requirements using weighted scoring
4. **Reports** coverage gaps with actionable fix commands

## Contributing

We especially welcome **new ATT&CK technique mappings**! See [CONTRIBUTING.md](CONTRIBUTING.md).

Each technique is a simple YAML file — no code changes needed:

```yaml
technique:
  id: T1021.001
  name: "Remote Desktop Protocol (RDP)"
  detection_requirements:
    event_ids:
      - id: 4624
        audit_subcategory: "Logon"
        importance: "CRITICAL"
```

## References

- [MITRE ATT&CK — Lateral Movement (TA0008)](https://attack.mitre.org/tactics/TA0008/)
- [JPCERT/CC — Detecting Lateral Movement via Event Logs](https://www.jpcert.or.jp/english/pub/sr/DetectLateralMovement_en.pdf)
- [Microsoft — Advanced Security Auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)

## License

MIT — see [LICENSE](LICENSE)
