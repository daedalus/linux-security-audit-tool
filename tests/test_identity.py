"""Tests for the identity phase."""

from unittest.mock import patch

from security_audit.core import Severity
from security_audit.phases.identity import (
    check_group_modifications,
    check_locked_accounts_with_shells,
    check_pam_faillock,
    check_password_policy,
    check_path_hijacking,
    check_privileged_groups,
    check_session_timeout,
    check_ssh_password_auth,
    check_ssh_root_login,
    check_sudo_gtfobins,
    check_sudo_nopasswd,
    check_sudo_timestamp_timeout,
    check_sudo_wildcard_abuse,
    check_system_accounts_with_shells,
    check_uid_zero_accounts,
    check_umask,
    check_unauthorized_ssh_keys,
    check_weak_service_credentials,
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
    def test_single_root_account_skipped(self, mock_run):
        """Test when only the canonical root account exists — not flagged."""
        mock_run.return_value = ("root:x:0:0:root:/root:/bin/bash", "", 0)
        findings = check_uid_zero_accounts()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_duplicate_uid_zero_flagged(self, mock_run):
        """Test when an additional UID-0 account exists — flagged."""
        mock_run.return_value = (
            "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0:backdoor:/root:/bin/bash",
            "",
            0,
        )
        findings = check_uid_zero_accounts()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].check_id == "IDENT-001"
        assert "backdoor" in findings[0].description


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


class TestCheckWeakServiceCredentials:
    """Tests for check_weak_service_credentials."""

    @patch("security_audit.phases.identity.run_command")
    def test_mysql_plaintext_password(self, mock_run):
        """MySQL config with plaintext password."""
        mock_run.side_effect = [
            ("[client]\npassword = s3cret\n", "", 0),  # cat /etc/mysql/my.cnf
            ("", "", 1),  # cat /root/.my.cnf — not found
            ("", "", 1),  # dpkg -l redis-server — not installed
            ("", "", 1),  # grep requirepass — not found
            ("", "", 1),  # grep trust — not found
            ("", "", 1),  # ls -la /root/.pgpass — not found
        ]
        findings = check_weak_service_credentials()
        assert any("MySQL" in f.title for f in findings)

    @patch("security_audit.phases.identity.run_command")
    def test_redis_no_requirepass(self, mock_run):
        """Redis with no requirepass set."""
        mock_run.side_effect = [
            ("", "", 1),  # cat /etc/mysql/my.cnf
            ("", "", 1),  # cat /root/.my.cnf
            ("ii  redis-server  5:7.4.2-1  amd64  ...", "", 0),  # dpkg — installed
            ("", "", 1),  # grep requirepass — no match
            ("", "", 1),  # grep trust — not found
            ("", "", 1),  # ls -la /root/.pgpass — not found
        ]
        findings = check_weak_service_credentials()
        assert any("Redis" in f.title for f in findings)

    @patch("security_audit.phases.identity.run_command")
    def test_postgres_trust_auth(self, mock_run):
        """PostgreSQL with trust authentication."""
        mock_run.side_effect = [
            ("", "", 1),  # cat /etc/mysql/my.cnf
            ("", "", 1),  # cat /root/.my.cnf
            ("ii  redis-server  5:7.4.2-1  amd64  ...", "", 0),  # dpkg — installed
            ("requirepass changeme", "", 0),  # grep requirepass — set
            ("trust", "", 0),  # grep trust — found
            ("", "", 1),  # ls -la /root/.pgpass — not found
        ]
        findings = check_weak_service_credentials()
        assert any("PostgreSQL" in f.title for f in findings)

    @patch("security_audit.phases.identity.run_command")
    def test_no_issues(self, mock_run):
        """All services configured securely."""
        mock_run.side_effect = [
            ("", "", 1),  # cat /etc/mysql/my.cnf — not found
            ("", "", 1),  # cat /root/.my.cnf
            ("ii  redis-server  5:7.4.2-1  amd64  ...", "", 0),  # dpkg — installed
            ("requirepass strongpass", "", 0),  # Redis has password
            ("", "", 1),  # grep trust — not found
            ("", "", 1),  # ls -la /root/.pgpass — not found
        ]
        findings = check_weak_service_credentials()
        assert len(findings) == 0


class TestCheckPathHijacking:
    """Tests for check_path_hijacking."""

    @patch("security_audit.phases.identity.os.environ")
    @patch("security_audit.phases.identity.run_command")
    def test_world_writable_in_path(self, mock_run, mock_env):
        """World-writable dir early in PATH is flagged."""
        mock_env.get.return_value = "/usr/local/bin:/tmp"
        mock_run.side_effect = [
            ("drwxrwxrwx 2 root root 4096 /usr/local/bin", "", 0),
            ("drwxrwxrwx 2 root root 4096 /tmp", "", 0),
            ("", "", 1),  # systemd grep — no output
        ]
        findings = check_path_hijacking()
        ww = [f for f in findings if "World-Writable" in f.title]
        assert len(ww) >= 1
        assert any(
            "tmp" in f.description or "/usr/local/bin" in f.description for f in ww
        )

    @patch("security_audit.phases.identity.os.environ")
    @patch("security_audit.phases.identity.run_command")
    def test_secure_path_no_findings(self, mock_run, mock_env):
        """No writable dirs in PATH, no relative systemd paths."""
        mock_env.get.return_value = "/usr/local/bin:/usr/bin:/bin"
        mock_run.side_effect = [
            ("drwxr-xr-x 2 root root 4096 /usr/local/bin", "", 0),
            ("drwxr-xr-x 2 root root 4096 /usr/bin", "", 0),
            ("drwxr-xr-x 2 root root 4096 /bin", "", 0),
            ("", "", 1),  # systemd grep — no output
        ]
        findings = check_path_hijacking()
        assert len(findings) == 0


class TestCheckSudoTimestampTimeout:
    """Tests for check_sudo_timestamp_timeout."""

    @patch("security_audit.phases.identity.run_command")
    def test_timeout_too_long(self, mock_run):
        """timestamp_timeout > 15 is flagged."""
        mock_run.return_value = ("Defaults timestamp_timeout=60", "", 0)
        findings = check_sudo_timestamp_timeout()
        assert len(findings) == 1
        assert findings[0].check_id == "IDENT-027"
        assert "MEDIUM" in str(findings[0].severity)

    @patch("security_audit.phases.identity.run_command")
    def test_timeout_disabled(self, mock_run):
        """timestamp_timeout=0 is CRITICAL."""
        mock_run.return_value = ("Defaults timestamp_timeout=0", "", 0)
        findings = check_sudo_timestamp_timeout()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "never expire" in findings[0].impact.lower()

    @patch("security_audit.phases.identity.run_command")
    def test_timeout_reasonable(self, mock_run):
        """timestamp_timeout=15 produces no finding."""
        mock_run.return_value = ("Defaults timestamp_timeout=15", "", 0)
        findings = check_sudo_timestamp_timeout()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_timeout_not_set(self, mock_run):
        """No timestamp_timeout set — no finding (defaults to 15)."""
        mock_run.return_value = ("", "", 1)
        findings = check_sudo_timestamp_timeout()
        assert len(findings) == 0


class TestCheckSudoGtfobins:
    """Tests for check_sudo_gtfobins."""

    @patch("security_audit.phases.identity.run_command")
    def test_gtfobin_found(self, mock_run):
        """Dangerous sudo rule for a GTFOBins command is flagged."""
        mock_run.return_value = (
            "user ALL=(ALL) /usr/bin/git\nuser ALL=(ALL) /usr/bin/less\n",
            "",
            0,
        )
        findings = check_sudo_gtfobins()
        assert len(findings) == 2
        assert all(f.check_id == "IDENT-028" for f in findings)

    @patch("security_audit.phases.identity.run_command")
    def test_no_gtfobins(self, mock_run):
        """No dangerous sudo rules."""
        mock_run.return_value = ("user ALL=(ALL) /usr/bin/apt\n", "", 0)
        findings = check_sudo_gtfobins()
        assert len(findings) == 0

    @patch("security_audit.phases.identity.run_command")
    def test_no_sudoers(self, mock_run):
        """No sudoers files found."""
        mock_run.return_value = ("", "", 1)
        findings = check_sudo_gtfobins()
        assert len(findings) == 0
