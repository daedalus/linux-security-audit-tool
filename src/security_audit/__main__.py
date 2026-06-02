"""CLI entry point for the security audit tool."""

from security_audit.cli import main


def entry_point() -> int:
    """Run the CLI and return exit code."""
    return main()


if __name__ == "__main__":
    raise SystemExit(entry_point())
