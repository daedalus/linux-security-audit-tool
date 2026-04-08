"""Tests for the CLI module."""

from unittest.mock import patch

from click.testing import CliRunner

from security_audit import __version__
from security_audit.cli import cli, print_finding, print_summary, version
from security_audit.core import Finding, Severity


class TestCLI:
    """Tests for CLI commands."""

    def test_cli_help(self):
        """Test CLI shows help."""
        runner = CliRunner()
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "Security Audit" in result.output

    def test_version_command(self):
        """Test version command."""
        runner = CliRunner()
        result = runner.invoke(version)
        assert result.exit_code == 0
        assert f"v{__version__}" in result.output


class TestPrintFinding:
    """Tests for print_finding function."""

    def test_print_finding_verbose(self):
        """Test print_finding with verbose=True."""
        finding = Finding(
            severity=Severity.HIGH,
            check_id="TEST-001",
            title="Test Finding",
            description="Test description",
            evidence="Test evidence",
            impact="Test impact",
            remediation="Test remediation",
            phase="Test",
        )
        with patch("security_audit.cli.console"):
            print_finding(finding, verbose=True)


class TestPrintSummary:
    """Tests for print_summary function."""

    def test_print_summary_empty(self):
        """Test print_summary with no findings."""
        with patch("security_audit.cli.console"):
            print_summary([])

    def test_print_summary_with_findings(self):
        """Test print_summary with findings."""
        findings = [
            Finding(
                severity=Severity.HIGH,
                check_id="TEST-001",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
        ]
        with patch("security_audit.cli.console"):
            print_summary(findings)


class TestRootCheck:
    """Tests for root check functionality."""

    @patch("os.geteuid")
    def test_check_root_true(self, mock_euid):
        """Test check_root returns True when root."""
        mock_euid.return_value = 0
        from security_audit.core import check_root

        assert check_root() is True

    @patch("os.geteuid")
    def test_check_root_false(self, mock_euid):
        """Test check_root returns False when not root."""
        mock_euid.return_value = 1000
        from security_audit.core import check_root

        assert check_root() is False
