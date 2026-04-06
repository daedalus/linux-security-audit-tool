"""Tests for the kernel phase."""

import pytest
from unittest.mock import patch
from security_audit.phases.kernel import (
    check_aslr,
    check_dmesg_restrict,
    check_kptr_restrict,
    check_ptrace_scope,
    check_suid_dumpable,
    check_protected_symlinks,
    check_protected_hardlinks,
    check_kernel_module_blacklist,
    check_sysrq_status,
    check_vm_swappiness,
    check_user_namespaces,
    check_apparmor_sshd_enforce,
    check_ip_forwarding,
    check_rp_filter,
    check_icmp_redirects,
    check_tcp_syncookies,
    check_source_routing,
    check_log_martians,
    check_icmp_broadcasts,
    check_selinux_apparmor_enforcing,
    check_grub_password,
    check_fde,
    check_tpm_attestation,
    check_secureboot,
    run_kernel_checks,
)
from security_audit.core import Severity


class TestCheckASLR:
    """Tests for check_aslr."""

    @patch("security_audit.phases.kernel.run_command")
    def test_aslr_enabled(self, mock_run):
        """Test when ASLR is properly enabled."""
        mock_run.return_value = ("2", "", 0)
        findings = check_aslr()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_aslr_disabled(self, mock_run):
        """Test when ASLR is disabled."""
        mock_run.return_value = ("0", "", 0)
        findings = check_aslr()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-001"


class TestCheckKptrRestrict:
    """Tests for check_kptr_restrict."""

    @patch("security_audit.phases.kernel.run_command")
    def test_kptr_restrict_enabled(self, mock_run):
        """Test when kptr_restrict is properly set."""
        mock_run.return_value = ("2", "", 0)
        findings = check_kptr_restrict()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_kptr_restrict_disabled(self, mock_run):
        """Test when kptr_restrict is not set."""
        mock_run.return_value = ("0", "", 0)
        findings = check_kptr_restrict()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-003"


class TestCheckSysrqStatus:
    """Tests for check_sysrq_status."""

    @patch("security_audit.phases.kernel.run_command")
    def test_sysrq_disabled(self, mock_run):
        """Test when SysRq is disabled."""
        mock_run.return_value = ("0", "", 0)
        findings = check_sysrq_status()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_sysrq_enabled(self, mock_run):
        """Test when SysRq is enabled."""
        mock_run.return_value = ("1", "", 0)
        findings = check_sysrq_status()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-010"


class TestCheckVMSwappiness:
    """Tests for check_vm_swappiness."""

    @patch("security_audit.phases.kernel.run_command")
    def test_swappiness_ok(self, mock_run):
        """Test when swappiness is at optimal value."""
        mock_run.return_value = ("10", "", 0)
        findings = check_vm_swappiness()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_swappiness_high(self, mock_run):
        """Test when swappiness is too high."""
        mock_run.return_value = ("60", "", 0)
        findings = check_vm_swappiness()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-011"


class TestCheckTCPSyncookies:
    """Tests for check_tcp_syncookies."""

    @patch("security_audit.phases.kernel.run_command")
    def test_syncookies_enabled(self, mock_run):
        """Test when TCP SYN cookies are enabled."""
        mock_run.return_value = ("1", "", 0)
        findings = check_tcp_syncookies()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_syncookies_disabled(self, mock_run):
        """Test when TCP SYN cookies are disabled."""
        mock_run.return_value = ("0", "", 0)
        findings = check_tcp_syncookies()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-017"


class TestCheckIPForwarding:
    """Tests for check_ip_forwarding."""

    @patch("security_audit.phases.kernel.run_command")
    def test_ip_forwarding_disabled(self, mock_run):
        """Test when IP forwarding is disabled."""
        mock_run.return_value = ("0", "", 0)
        findings = check_ip_forwarding()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_ip_forwarding_enabled(self, mock_run):
        """Test when IP forwarding is enabled."""
        mock_run.return_value = ("1", "", 0)
        findings = check_ip_forwarding()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-014"


class TestCheckSourceRouting:
    """Tests for check_source_routing."""

    @patch("security_audit.phases.kernel.run_command")
    def test_source_routing_disabled(self, mock_run):
        """Test when source routing is disabled."""
        mock_run.return_value = ("0", "", 0)
        findings = check_source_routing()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_source_routing_enabled(self, mock_run):
        """Test when source routing is enabled."""
        mock_run.return_value = ("1", "", 0)
        findings = check_source_routing()
        assert len(findings) >= 1


class TestCheckICMPRedirects:
    """Tests for check_icmp_redirects."""

    @patch("security_audit.phases.kernel.run_command")
    def test_icmp_redirects_disabled(self, mock_run):
        """Test when ICMP redirects are disabled."""
        mock_run.return_value = ("0", "", 0)
        findings = check_icmp_redirects()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_icmp_redirects_enabled(self, mock_run):
        """Test when ICMP redirects are enabled."""
        mock_run.return_value = ("1", "", 0)
        findings = check_icmp_redirects()
        assert len(findings) >= 1


class TestCheckRPFilter:
    """Tests for check_rp_filter."""

    @patch("security_audit.phases.kernel.run_command")
    def test_rp_filter_enabled(self, mock_run):
        """Test when reverse path filter is enabled."""
        mock_run.return_value = ("1", "", 0)
        findings = check_rp_filter()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_rp_filter_disabled(self, mock_run):
        """Test when reverse path filter is disabled."""
        mock_run.return_value = ("0", "", 0)
        findings = check_rp_filter()
        assert len(findings) >= 1


class TestCheckSELinuxAppArmor:
    """Tests for check_selinux_apparmor_enforcing."""

    @patch("security_audit.phases.kernel.run_command")
    def test_selinux_enforcing(self, mock_run):
        """Test when SELinux is enforcing."""
        mock_run.return_value = ("Enforcing", "", 0)
        findings = check_selinux_apparmor_enforcing()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_selinux_permissive(self, mock_run):
        """Test when SELinux is permissive."""
        mock_run.return_value = ("Permissive", "", 0)
        findings = check_selinux_apparmor_enforcing()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-021"

    @patch("security_audit.phases.kernel.run_command")
    def test_no_mac(self, mock_run):
        """Test when neither SELinux nor AppArmor is enabled."""
        mock_run.return_value = ("", "", 1)
        findings = check_selinux_apparmor_enforcing()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-022"


class TestCheckGRUBPassword:
    """Tests for check_grub_password."""

    @patch("security_audit.phases.kernel.run_command")
    def test_grub_password_set(self, mock_run):
        """Test when GRUB password is set."""
        mock_run.return_value = ("password --md5 $1$xyz", "", 0)
        findings = check_grub_password()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_grub_password_not_set(self, mock_run):
        """Test when GRUB password is not set."""
        mock_run.return_value = ("", "", 1)
        findings = check_grub_password()
        assert len(findings) == 1
        assert findings[0].check_id == "KERN-023"


class TestCheckFDE:
    """Tests for check_fde."""

    @patch("security_audit.phases.kernel.run_command")
    def test_fde_present(self, mock_run):
        """Test when FDE is present."""
        mock_run.return_value = ("luks", "", 0)
        findings = check_fde()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_fde_not_present(self, mock_run):
        """Test when FDE is not present."""
        mock_run.return_value = ("no", "", 1)
        findings = check_fde()
        assert len(findings) >= 1


class TestCheckSecureBoot:
    """Tests for check_secureboot."""

    @patch("security_audit.phases.kernel.run_command")
    def test_secureboot_enabled(self, mock_run):
        """Test when SecureBoot is enabled."""
        mock_run.return_value = ("SecureBoot enabled", "", 0)
        findings = check_secureboot()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_secureboot_disabled(self, mock_run):
        """Test when SecureBoot is disabled."""
        mock_run.return_value = ("SecureBoot disabled", "", 0)
        findings = check_secureboot()
        assert len(findings) >= 1


class TestCheckTPMAttestation:
    """Tests for check_tpm_attestation."""

    @patch("security_audit.phases.kernel.run_command")
    def test_tpm_present(self, mock_run):
        """Test when TPM is present."""
        mock_run.return_value = ("TPM 2.0", "", 0)
        findings = check_tpm_attestation()
        assert len(findings) == 0

    @patch("security_audit.phases.kernel.run_command")
    def test_tpm_not_present(self, mock_run):
        """Test when TPM is not present."""
        mock_run.return_value = ("", "", 1)
        findings = check_tpm_attestation()
        assert len(findings) >= 1


class TestRunKernelChecks:
    """Tests for run_kernel_checks."""

    @patch("security_audit.phases.kernel.run_command")
    def test_run_kernel_checks_returns_list(self, mock_run):
        """Test that run_kernel_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_kernel_checks()
        assert isinstance(findings, list)
