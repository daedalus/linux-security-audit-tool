"""Tests for the identity phase."""

import pytest
from unittest.mock import patch, MagicMock
from security_audit.phases.identity import (
    check_uid_zero_accounts,
    check_system_accounts_with_shells,
    check_passwordless_accounts,
    check_sudo_nopasswd,
    check_sudo_wildcard_abuse,
    check_privileged_groups,
    check_ssh_root_login,
    check_ssh_password_auth,
    run_identity_checks,
)
from security_audit.core import Severity


class TestCheckUidZeroAccounts:
    """Tests for check_uid_zero_accounts."""

    @patch("security_audit.phases.identity.run_command")
    def test_no_uid_zero_accounts(self, mock_run):
        """Test when no UID 0 accounts exist."""
        mock_run.return_value = ("", "", 1)
        findings = check_uid_zero_accounts()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_single_root_account(self, mock_run):
        """Test when only root account exists."""
        mock_run.return_value = ("root:x:0:0:root:/root:/bin/bash", "", 0)
        findings = check_uid_zero_accounts()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].check_id == "IDENT-001"


class TestCheckSystemAccountsWithShells:
    """Tests for check_system_accounts_with_shells."""

    @patch("security_audit.phases.identity.run_command")
    def test_no_system_accounts_with_shells(self, mock_run):
        """Test when no system accounts have shells."""
        mock_run.return_value = ("", "", 1)
        findings = check_system_accounts_with_shells()
        assert len(findings) == 0


class TestCheckSudoNopasswd:
    """Tests for check_sudo_nopasswd."""

    @patch("security_audit.phases.identity.run_command")
    def test_no_nopasswd_rules(self, mock_run):
        """Test when no NOPASSWD rules exist."""
        mock_run.return_value = ("", "", 1)
        findings = check_sudo_nopasswd()
        assert len(findings) == 0


class TestCheckSshRootLogin:
    """Tests for check_ssh_root_login."""

    @patch("security_audit.phases.identity.run_command")
    def test_root_login_disabled(self, mock_run):
        """Test when root login is disabled."""
        mock_run.return_value = ("permitrootlogin no", "", 0)
        findings = check_ssh_root_login()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_root_login_enabled(self, mock_run):
        """Test when root login is enabled."""
        mock_run.return_value = ("permitrootlogin yes", "", 0)
        findings = check_ssh_root_login()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestCheckSshPasswordAuth:
    """Tests for check_ssh_password_auth."""

    @patch("security_audit.phases.identity.run_command")
    def test_password_auth_disabled(self, mock_run):
        """Test when password authentication is disabled."""
        mock_run.return_value = ("passwordauthentication no", "", 0)
        findings = check_ssh_password_auth()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_password_auth_enabled(self, mock_run):
        """Test when password authentication is enabled."""
        mock_run.return_value = ("passwordauthentication yes", "", 0)
        findings = check_ssh_password_auth()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestRunIdentityChecks:
    """Tests for run_identity_checks."""

    @patch("security_audit.phases.identity.run_command")
    def test_run_identity_checks_returns_list(self, mock_run):
        """Test that run_identity_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_identity_checks()
        assert isinstance(findings, list)
