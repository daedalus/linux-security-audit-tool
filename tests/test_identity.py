"""Tests for the identity phase."""

from unittest.mock import patch

from security_audit.core import Severity
from security_audit.phases.identity import (
    check_group_modifications,
    check_locked_accounts_with_shells,
    check_pam_faillock,
    check_password_policy,
    check_privileged_groups,
    check_session_timeout,
    check_ssh_password_auth,
    check_ssh_root_login,
    check_sudo_nopasswd,
    check_sudo_wildcard_abuse,
    check_system_accounts_with_shells,
    check_uid_zero_accounts,
    check_umask,
    check_unauthorized_ssh_keys,
    run_identity_checks,
)


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
        mock_run.return_value = ("password authentication no", "", 0)
        findings = check_ssh_password_auth()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_password_auth_enabled(self, mock_run):
        """Test when password authentication is enabled."""
        mock_run.return_value = ("password authentication yes", "", 0)
        findings = check_ssh_password_auth()
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


class TestCheckSudoWildcardAbuse:
    """Tests for check_sudo_wildcard_abuse."""

    @patch("security_audit.phases.identity.run_command")
    def test_dangerous_wildcard_found(self, mock_run):
        """Test when dangerous sudo wildcard found."""
        mock_run.return_value = ("ALL=(ALL) /usr/bin/vi", "", 0)
        findings = check_sudo_wildcard_abuse()
        assert len(findings) >= 1


class TestCheckPrivilegedGroups:
    """Tests for check_privileged_groups."""

    @patch("security_audit.phases.identity.run_command")
    def test_docker_group_members(self, mock_run):
        """Test when docker group has members."""
        mock_run.return_value = ("docker:x:999:user1,user2", "", 0)
        findings = check_privileged_groups()
        assert any(f.title == "Users in docker Group" for f in findings)


class TestCheckUnauthorizedSSHKeys:
    """Tests for check_unauthorized_ssh_keys."""

    @patch("security_audit.phases.identity.run_command")
    def test_authorized_keys_found(self, mock_run):
        """Test when authorized_keys found."""
        mock_run.side_effect = [
            ("/home/user/.ssh/authorized_keys", "", 0),
            ("ssh-rsa AAAA...", "", 0),
        ]
        findings = check_unauthorized_ssh_keys()
        assert len(findings) >= 1


class TestCheckPasswordPolicy:
    """Tests for check_password_policy."""

    @patch("security_audit.phases.identity.run_command")
    def test_excessive_max_days(self, mock_run):
        """Test when PASS_MAX_DAYS is excessive."""
        mock_run.return_value = ("PASS_MAX_DAYS 999", "", 0)
        findings = check_password_policy()
        assert any(f.check_id == "IDENT-010" for f in findings)


class TestCheckLockedAccountsWithShells:
    """Tests for check_locked_accounts_with_shells."""

    @patch("security_audit.phases.identity.run_command")
    def test_locked_account_with_shell(self, mock_run):
        """Test when locked account has valid shell."""
        mock_run.return_value = ("lockeduser:x:!:1000:/bin/bash", "", 0)
        findings = check_locked_accounts_with_shells()
        assert len(findings) == 1


class TestCheckGroupModifications:
    """Tests for check_group_modifications."""

    @patch("security_audit.phases.identity.run_command")
    def test_group_modified(self, mock_run):
        """Test when /etc/group modification time found."""
        mock_run.return_value = ("2024-01-01 12:00:00.000000000 /etc/group", "", 0)
        findings = check_group_modifications()
        assert len(findings) == 1


class TestRunIdentityChecks:
    """Tests for run_identity_checks."""

    @patch("security_audit.phases.identity.run_command")
    def test_run_identity_checks_returns_list(self, mock_run):
        """Test that run_identity_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_identity_checks()
        assert isinstance(findings, list)


class TestCheckPamFaillock:
    """Tests for check_pam_faillock."""

    @patch("security_audit.phases.identity.run_command")
    def test_faillock_configured(self, mock_run):
        """Test when pam_faillock is configured."""
        mock_run.return_value = ("auth required pam_faillock.so preauth", "", 0)
        findings = check_pam_faillock()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_tally2_configured(self, mock_run):
        """Test when pam_tally2 is configured."""
        mock_run.side_effect = [
            ("", "", 1),
            ("auth required pam_tally2.so", "", 0),
        ]
        findings = check_pam_faillock()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_no_lockout_configured(self, mock_run):
        """Test when no account lockout is configured."""
        mock_run.return_value = ("", "", 1)
        findings = check_pam_faillock()
        assert len(findings) == 1
        assert findings[0].check_id == "IDENT-016"
        assert findings[0].severity == Severity.MEDIUM


class TestCheckSessionTimeout:
    """Tests for check_session_timeout."""

    @patch("security_audit.phases.identity.run_command")
    def test_tmout_configured(self, mock_run):
        """Test when TMOUT is configured."""
        mock_run.return_value = ("TMOUT=900", "", 0)
        findings = check_session_timeout()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_no_tmout_configured(self, mock_run):
        """Test when TMOUT is not configured."""
        mock_run.return_value = ("", "", 1)
        findings = check_session_timeout()
        assert len(findings) == 1
        assert findings[0].check_id == "IDENT-017"
        assert findings[0].severity == Severity.MEDIUM


class TestCheckUmask:
    """Tests for check_umask."""

    @patch("security_audit.phases.identity.run_command")
    def test_secure_umask_027(self, mock_run):
        """Test when umask is set to 027."""
        mock_run.return_value = ("UMASK 027", "", 0)
        findings = check_umask()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_secure_umask_077(self, mock_run):
        """Test when umask is set to 077."""
        mock_run.return_value = ("umask 077", "", 0)
        findings = check_umask()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_insecure_umask_022(self, mock_run):
        """Test when umask is 022 (insecure)."""
        mock_run.return_value = ("umask 022", "", 0)
        findings = check_umask()
        assert len(findings) == 1
        assert findings[0].check_id == "IDENT-018"
        assert findings[0].severity == Severity.MEDIUM

    @patch("security_audit.phases.identity.run_command")
    def test_no_umask_configured(self, mock_run):
        """Test when umask is not configured anywhere."""
        mock_run.return_value = ("", "", 1)
        findings = check_umask()
        assert len(findings) == 1
        assert findings[0].check_id == "IDENT-018"
