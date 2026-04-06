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


class TestRunKernelChecks:
    """Tests for run_kernel_checks."""

    @patch("security_audit.phases.kernel.run_command")
    def test_run_kernel_checks_returns_list(self, mock_run):
        """Test that run_kernel_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_kernel_checks()
        assert isinstance(findings, list)
