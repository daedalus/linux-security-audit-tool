"""Tests for the packages phase."""

from unittest.mock import patch

from security_audit.phases.packages import (
    check_deprecated_packages,
    check_pending_updates,
    check_unnecessary_packages,
    run_package_checks,
)


class TestCheckPendingUpdates:
    """Tests for check_pending_updates."""

    @patch("security_audit.phases.packages.run_command")
    def test_no_pending_updates(self, mock_run):
        """Test when no pending updates."""
        mock_run.return_value = ("", "", 1)
        findings = check_pending_updates()
        assert len(findings) == 0

    @patch("security_audit.phases.packages.run_command")
    def test_pending_updates_found(self, mock_run):
        """Test when pending security updates found."""
        mock_run.return_value = ("openssl security update available", "", 0)
        findings = check_pending_updates()
        assert len(findings) >= 1
        assert findings[0].check_id == "PKG-001"


class TestCheckUnnecessaryPackages:
    """Tests for check_unnecessary_packages."""

    @patch("security_audit.phases.packages.run_command")
    def test_unnecessary_package_found(self, mock_run):
        """Test when unnecessary package found."""
        mock_run.return_value = ("ii  telnet    1.0.0", "", 0)
        findings = check_unnecessary_packages()
        assert len(findings) == 1
        assert findings[0].check_id == "PKG-004"


class TestCheckDeprecatedPackages:
    """Tests for check_deprecated_packages."""

    @patch("security_audit.phases.packages.run_command")
    def test_deprecated_package_found(self, mock_run):
        """Test when deprecated package found."""
        mock_run.return_value = ("ii  libssl1.0    1.0.0", "", 0)
        findings = check_deprecated_packages()
        assert len(findings) == 1
        assert findings[0].check_id == "PKG-005"


class TestRunPackageChecks:
    """Tests for run_package_checks."""

    @patch("security_audit.phases.packages.run_command")
    def test_run_package_checks_returns_list(self, mock_run):
        """Test that run_package_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_package_checks()
        assert isinstance(findings, list)
