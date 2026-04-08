"""Tests for the logging phase."""

from unittest.mock import patch

from security_audit.phases.logging import (
    check_audit_rules,
    check_auditd_status,
    check_auth_log_permissions,
    check_journald_persistence,
    run_logging_checks,
)


class TestCheckAuditdStatus:
    """Tests for check_auditd_status."""

    @patch("security_audit.phases.logging.run_command")
    def test_auditd_active(self, mock_run):
        """Test when auditd is active."""
        mock_run.return_value = ("active", "", 0)
        findings = check_auditd_status()
        assert len(findings) == 0

    @patch("security_audit.phases.logging.run_command")
    def test_auditd_not_running(self, mock_run):
        """Test when auditd is not running."""
        mock_run.return_value = ("inactive", "", 1)
        findings = check_auditd_status()
        assert len(findings) == 1
        assert findings[0].check_id == "LOG-001"


class TestCheckAuditRules:
    """Tests for check_audit_rules."""

    @patch("security_audit.phases.logging.run_command")
    def test_no_audit_rules(self, mock_run):
        """Test when no audit rules configured."""
        mock_run.return_value = ("", "", 1)
        findings = check_audit_rules()
        assert len(findings) == 1
        assert findings[0].check_id == "LOG-002"


class TestCheckAuthLogPermissions:
    """Tests for check_auth_log_permissions."""

    @patch("security_audit.phases.logging.run_command")
    def test_log_permissions_ok(self, mock_run):
        """Test when log permissions are correct."""
        mock_run.return_value = ("-rw-r----- 1 root adm 1000 /var/log/auth.log", "", 0)
        findings = check_auth_log_permissions()
        assert len(findings) == 0


class TestCheckJournaldPersistence:
    """Tests for check_journald_persistence."""

    @patch("security_audit.phases.logging.run_command")
    def test_journal_not_persistent(self, mock_run):
        """Test when journal is not persistent."""
        mock_run.return_value = ("Journal disk usage: 0 B", "", 0)
        findings = check_journald_persistence()
        assert len(findings) == 1
        assert findings[0].check_id == "LOG-007"


class TestRunLoggingChecks:
    """Tests for run_logging_checks."""

    @patch("security_audit.phases.logging.run_command")
    def test_run_logging_checks_returns_list(self, mock_run):
        """Test that run_logging_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_logging_checks()
        assert isinstance(findings, list)
