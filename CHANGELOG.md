# Changelog

All notable changes to LogBlind will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-11-09

### Added
- **`logblind fix` command** — generates ready-to-run PowerShell remediation scripts
  - Audit policy fixes via `auditpol /set`
  - Registry fixes for ScriptBlock Logging, Module Logging, command-line auditing
  - Sysmon installation recommendations
  - `-WhatIf` preview mode built into generated scripts
- **`logblind report` command** — generates standalone HTML or JSON reports
- **`logblind export` command** — exports MITRE ATT&CK Navigator layer JSON
  - Direct import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
  - Color-coded heatmap: green (covered), yellow (partial), red (blind)
  - Per-technique comments with gap details
- **HTML reporter** — self-contained dark-theme HTML report with:
  - Interactive coverage heatmap
  - Technique table with ATT&CK links
  - Critical gaps section with fix commands
- **4 new P1 technique mappings:**
  - T1021.003 — Distributed Component Object Model (DCOM)
  - T1053.005 — Scheduled Task/Job: Scheduled Task
  - T1059.001 — Command and Scripting Interpreter: PowerShell
  - T1570 — Lateral Tool Transfer
- **`--format html`** option for the `scan` command
- 10 new tests for fix generator and CLI (47 total)

### Changed
- Knowledge base now covers **8 ATT&CK techniques** (up from 4)
- Fix generator produces production-quality PowerShell with `#Requires -RunAsAdministrator`, `$ErrorActionPreference`, and `param($WhatIf)` block

### Fixed
- All Unicode/emoji issues on Windows legacy console (cp1252)
- ANSI escape codes no longer break version assertion in tests
- YAML loader now accepts both `check_type` and `type` field names for additional checks

## [0.1.0] - 2026-10-26

### Added
- Initial project scaffold
- Core data models (PolicySnapshot, Technique, GapResult)
- AuditPol collector for Windows audit policy parsing
- Registry collector (Sysmon, ScriptBlock Logging, command-line audit, WEF)
- File import collector for offline CSV analysis
- Knowledge base schema and YAML loader
- P0 technique mappings: RDP (T1021.001), SMB/PsExec (T1021.002), WinRM (T1021.006), WMI (T1047)
- Gap detection engine with weighted coverage scoring
- CLI with `logblind scan` command (table, JSON, verbose modes)
- Rich CLI heatmap reporter
- JSON report export
- 37 unit tests
- GitHub Actions CI workflow
- MIT license, CONTRIBUTING.md, SECURITY.md, issue/PR templates
