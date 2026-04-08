# Contributing to Linux Security Audit Tool

Thanks for your interest in contributing!

## Development Setup

```bash
git clone https://github.com/daedalus/linux-security-audit-tool.git
cd linux-security-audit-tool
python3 -m venv venv
source venv/bin/activate
pip install -e ".[all]"
```

## Running Tests

```bash
pytest
```

## Code Quality

We use ruff and mypy:

```bash
ruff check src/ tests/
ruff format src/ tests/
mypy src/
```

## Adding New Checks

1. Find the appropriate phase module in `src/security_audit/phases/`
2. Add a new check function following the pattern:

```python
def check_new_thing() -> list[Finding]:
    """Description of what this check looks for."""
    findings = []
    stdout, stderr, rc = run_command("command_to_check")
    if rc == 0 and some_condition:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="PHAS-001",
                title="Title of finding",
                description="Detailed description",
                evidence=stdout,
                impact="Security impact",
                remediation="How to fix",
                phase="Phase 1",
            )
        )
    return findings
```

3. Add the check to the phase's `run_*_checks()` function
4. Add tests in `tests/`

## Check ID Format

- Prefix: Phase name (IDENT, NETW, FSEC, PROC, KERN, LOGG, PACK, CRYP)
- Number: 3-digit sequential (001, 002, ...)

## Severity Guidelines

- **CRITICAL**: Direct root compromise
- **HIGH**: Easy privilege escalation
- **MEDIUM**: Increased attack surface
- **LOW**: Defense-in-depth gap
- **INFO**: Non-security hygiene

## Submitting Changes

1. Fork and create a feature branch
2. Run tests and linting
3. Update tests if needed
4. Submit a pull request

## Code Style

- Follow PEP 8 (enforced by ruff)
- Use Google-style docstrings
- Add type hints
- Keep functions focused and small