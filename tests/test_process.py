"""Tests for the process phase."""

from unittest.mock import patch

from security_audit.phases.process import (
    check_apparmor_status,
    check_docker_socket,
    check_rkhunter_installation,
    check_running_services,
    check_seccomp_status,
    check_selinux_status,
    check_service_file_permissions,
    check_systemd_timers,
    check_sysv_init_scripts,
    check_unnecessary_network_services,
    run_process_checks,
)


class TestCheckRunningServices:
    """Tests for check_running_services."""

    @patch("security_audit.phases.process.run_command")
    def test_running_services_found(self, mock_run):
        """Test when running services found."""
        mock_run.return_value = ("ssh.service\napache2.service", "", 0)
        findings = check_running_services()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-001"


class TestCheckDockerSocket:
    """Tests for check_docker_socket."""

    @patch("security_audit.phases.process.run_command")
    def test_docker_socket_exists(self, mock_run):
        """Test when Docker socket exists."""
        mock_run.return_value = ("srw-rw---- 1 root docker /var/run/docker.sock", "", 0)
        findings = check_docker_socket()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-003"


class TestCheckAppArmorStatus:
    """Tests for check_apparmor_status."""

    @patch("security_audit.phases.process.run_command")
    def test_apparmor_not_installed(self, mock_run):
        """Test when AppArmor not installed."""
        mock_run.return_value = ("not installed", "", 0)
        findings = check_apparmor_status()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-004"


class TestCheckSELinuxStatus:
    """Tests for check_selinux_status."""

    @patch("security_audit.phases.process.run_command")
    def test_selinux_disabled(self, mock_run):
        """Test when SELinux disabled."""
        mock_run.return_value = ("Disabled", "", 0)
        findings = check_selinux_status()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-006"

    @patch("security_audit.phases.process.run_command")
    def test_selinux_permissive(self, mock_run):
        """Test when SELinux permissive."""
        mock_run.return_value = ("Permissive", "", 0)
        findings = check_selinux_status()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-007"


class TestCheckServiceFilePermissions:
    """Tests for check_service_file_permissions."""

    @patch("security_audit.phases.process.run_command")
    def test_writable_service_files(self, mock_run):
        """Test when writable service files found."""
        mock_run.return_value = ("/etc/systemd/system/test.service", "", 0)
        findings = check_service_file_permissions()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-012"


class TestRunProcessChecks:
    """Tests for run_process_checks."""

    @patch("security_audit.phases.process.run_command")
    def test_run_process_checks_returns_list(self, mock_run):
        """Test that run_process_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_process_checks()
        assert isinstance(findings, list)


class TestCheckRkhunterInstallation:
    """Tests for check_rkhunter_installation."""

    @patch("security_audit.phases.process.run_command")
    def test_rkhunter_not_installed(self, mock_run):
        """Test when rkhunter is not installed."""
        mock_run.return_value = ("", "", 1)
        findings = check_rkhunter_installation()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-014"

    @patch("security_audit.phases.process.run_command")
    def test_rkhunter_installed(self, mock_run):
        """Test when rkhunter is installed."""
        mock_run.side_effect = [
            ("/usr/bin/rkhunter", "", 0),
            ("No threats found", "", 0),
        ]
        findings = check_rkhunter_installation()
        assert len(findings) == 0


class TestCheckUnnecessaryNetworkServices:
    """Tests for check_unnecessary_network_services."""

    @patch("security_audit.phases.process.run_command")
    def test_cups_running(self, mock_run):
        """Test when cups is running."""
        mock_run.return_value = ("active", "", 0)
        findings = check_unnecessary_network_services()
        assert any(f.title == "Unnecessary Service Running: cups" for f in findings)

    @patch("security_audit.phases.process.run_command")
    def test_bluetooth_running(self, mock_run):
        """Test when bluetooth is running."""
        mock_run.return_value = ("active", "", 0)
        findings = check_unnecessary_network_services()
        assert any(
            f.title == "Unnecessary Service Running: bluetooth" for f in findings
        )


class TestCheckSystemdTimers:
    """Tests for check_systemd_timers."""

    @patch("security_audit.phases.process.run_command")
    def test_timers_found(self, mock_run):
        """Test when timers are found."""
        mock_run.return_value = ("timer1.timer timer2.timer", "", 0)
        findings = check_systemd_timers()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-009"


class TestCheckSeccompStatus:
    """Tests for check_seccomp_status."""

    @patch("security_audit.phases.process.run_command")
    def test_seccomp_disabled(self, mock_run):
        """Test when seccomp is disabled."""
        mock_run.return_value = ("seccomp: 0 (disabled)", "", 0)
        findings = check_seccomp_status()
        assert len(findings) == 1


class TestCheckSysVInitScripts:
    """Tests for check_sysv_init_scripts."""

    @patch("security_audit.phases.process.run_command")
    def test_sysv_scripts_found(self, mock_run):
        """Test when SysV init scripts found."""
        mock_run.return_value = ("network\nfirewall", "", 0)
        findings = check_sysv_init_scripts()
        assert len(findings) == 1
        assert findings[0].check_id == "PROC-013"
