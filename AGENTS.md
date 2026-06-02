# AGENTS.md — Linux Security Audit Tool

## Overview

A CLI tool for comprehensive Linux system security auditing. Runs 100+ checks across 9 phases
(context, identity, network, filesystem, process, kernel, logging, packages, crypto).

## Commands

| Command | Description |
|---------|------------|
| `pytest` | Run test suite |
| `ruff format` | Format code |
| `mdformat` | Format markdown |
| `prospector --with-tool ruff --with-tool mypy --with-tool pylint src/` | Lint + type check (with blending) |
| `opengrep --config=auto --severity=ERROR src/` | Security and pattern scanning |
| `vulture --min-confidence 90 src/` | Dead/unused code detection |
| `lizard src/ --CCN 10` | Code complexity analysis |
| `impactguard-check-staged` | API impact analysis for staged changes |

## Development

```bash
# Setup
pip install -e ".[test]"

# Test
pytest

# Format
ruff format src/ tests/

# Format markdown
mdformat .

# Lint + type check (prospector runs ruff check + mypy + pylint together)
prospector --with-tool ruff --with-tool mypy --with-tool pylint src/
opengrep --config=auto --severity=ERROR src/

# find unused code
vulture --min-confidence 90 src/

# analyze code complexity
lizard src/ --CCN 10

# track API impact
impactguard-check-staged
```

## Testing

Pytest with mock-based test suites in `tests/`. All `run_command()` calls need a
corresponding mock `side_effect` in test mocks.

## Code Style

- Format: ruff format
- Lint + Type check: prospector (runs ruff check + mypy + pylint with blending)
- Docstrings: Google style

## Key Conventions

- Google-style docstrings required
- Ruff (line-length=88, google pydocstyle)
- mypy strict mode
- All `run_command()` calls need a corresponding mock `side_effect` in test mocks
- Package name in `pyproject.toml` must match PyPI slug
- Version string lives in `src/security_audit/__init__.py` __version__
- New phase? Register it in `src/security_audit/phases/__init__.py`
- New check? Add to phase file + `.PLAN.md` + test file

## Release

Use `tools/release.sh` to automate version bumps, builds, and GitHub releases:

```bash
./tools/release.sh          # bump patch (default)
./tools/release.sh minor
./tools/release.sh major
```

The script:

- Checks working tree is clean; warns if not on `master`/`main`
- Runs `bumpversion <part> --tag --verbose`
- Pushes commit + tags
- Builds the package
- Creates a GitHub release with auto-generated notes

## Do NOT Change Without Discussion

- The URL scheme (https:// without embedded tokens)
- The `src/` layout
- The `rtk` git workflow
- Any check ID prefix scheme (KERN-, IDENT-, FS-, NET-, etc.)
