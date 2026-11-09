# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in LogBlind, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

LogBlind is a **read-only auditing tool**. It reads Windows audit policies and
compares them against a knowledge base. It does NOT:

- Modify any system settings (unless explicitly running `logblind fix`)
- Collect or transmit any data externally
- Require network access
- Store credentials

The `logblind fix` command generates PowerShell scripts but does NOT execute them
automatically. Users must review and run the scripts themselves.
