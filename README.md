# Linux Security Audit Tool

A comprehensive CLI tool for auditing Linux system security posture.

[![PyPI](https://img.shields.io/pypi/v/linux-security-audit-tool.svg)](https://pypi.org/project/linux-security-audit-tool/)
[![Python](https://img.shields.io/pypi/pyversions/linux-security-audit-tool.svg)](https://pypi.org/project/linux-security-audit-tool/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Install

```bash
pip install linux-security-audit-tool
```

## Usage

```bash
security-audit --help
security-audit audit
security-audit audit -p 0 -1           # Run specific phases
security-audit audit -o report.md      # Save markdown report
security-audit audit --quiet           # Summary only
security-audit audit --debug           # Show executed commands
security-audit audit --remediate-all   # Generate remediation script for all findings
security-audit audit --remediate-only-critical  # Generate remediation script for CRITICAL only
security-audit audit --remediate-non-critical   # Generate remediation script for non-CRITICAL
security-audit audit --pdf report.pdf  # Generate PDF report
```

## CLI

```bash
security-audit [OPTIONS] COMMAND [ARGS]...

Options:
  --version  Show the version and exit.
  --help     Show this message and exit.

Commands:
  audit    Run a full security audit.
  version  Show version information.
```

## Audit Command Options

- `--output`, `-o FILE`            - Output file for markdown report
- `--phases`, `-p [0-9]`          - Specific phases to run (can be repeated)
- `--quiet`, `-q`                 - Suppress detailed output
- `--verbose`, `-v`               - Show descriptions and remediation
- `--debug`, `-d`                 - Show low-level commands being executed
- `--remediate-all`, `-r`         - Generate remediation script for all findings
- `--remediate-only-critical`     - Generate remediation script for CRITICAL findings only
- `--remediate-non-critical`      - Generate remediation script for non-CRITICAL findings
- `--pdf FILE`                    - Generate PDF executive report

## Development

```bash
git clone https://github.com/daedalus/linux-security-audit-tool.git
cd linux-security-audit-tool
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```

## API

```python
from security_audit import gather_context, run_identity_checks, calculate_security_score
from security_audit.core import Finding, Severity

# Run a full audit
context = gather_context()
findings = run_identity_checks()
score = calculate_security_score(findings)
```

## Audit Phases

The tool performs security checks across 9 phases:

- **Phase 0**: Context Gathering (hostname, OS, kernel)
- **Phase 1**: Identity & Access Control (users, sudo, SSH)
- **Phase 2**: Network Exposure (listening services, firewall, sysctl)
- **Phase 3**: File System & Permissions (SUID, world-writable, cron)
- **Phase 4**: Process & Service Posture (services, AppArmor, SELinux, rkhunter)
- **Phase 5**: Kernel & OS Hardening (sysctl, ASLR, module blacklist)
- **Phase 6**: Logging & Monitoring (auditd, logs, syslog)
- **Phase 7**: Package & Update Hygiene (updates, repos)
- **Phase 8**: Cryptographic Posture (SSH keys, TLS, password hashing)