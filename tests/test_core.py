"""Tests for the core module."""

import pytest
from unittest.mock import patch
from security_audit.core import Severity, Finding, AuditContext, run_command, check_root


class TestSeverity:
    """Tests for the Severity enum."""

    def test_severity_values(self):
        """Test that all severity levels exist."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"


class TestFinding:
    """Tests for the Finding dataclass."""

    def test_finding_creation(self, sample_finding):
        """Test that a Finding can be created with all required fields."""
        assert sample_finding.severity == Severity.HIGH
        assert sample_finding.check_id == "TEST-001"
        assert sample_finding.title == "Test Finding"
        assert sample_finding.description == "A test finding for unit tests"
        assert sample_finding.evidence == "test evidence"
        assert sample_finding.impact == "test impact"
        assert sample_finding.remediation == "test remediation"
        assert sample_finding.phase == "Test Phase"

    def test_finding_with_all_severities(self):
        """Test creating findings with all severity levels."""
        for severity in Severity:
            finding = Finding(
                severity=severity,
                check_id="TEST-001",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
            assert finding.severity == severity


class TestAuditContext:
    """Tests for the AuditContext dataclass."""

    def test_default_context(self):
        """Test default values for AuditContext."""
        context = AuditContext()
        assert context.hostname == ""
        assert context.os_release == ""
        assert context.kernel == ""
        assert context.uptime == ""
        assert context.virtualization == ""
        assert context.is_container is False
        assert context.is_server is True
        assert context.findings == []

    def test_context_with_values(self):
        """Test creating AuditContext with values."""
        from security_audit.core import Finding

        finding = Finding(
            severity=Severity.HIGH,
            check_id="TEST-001",
            title="Test",
            description="Test",
            evidence="Test",
            impact="Test",
            remediation="Test",
            phase="Test",
        )
        context = AuditContext(
            hostname="test-host",
            os_release="Test OS",
            kernel="5.0.0",
            uptime="1 day",
            virtualization="none",
            is_container=False,
            is_server=True,
            findings=[finding],
        )
        assert context.hostname == "test-host"
        assert context.os_release == "Test OS"
        assert context.kernel == "5.0.0"
        assert len(context.findings) == 1


class TestRunCommand:
    """Tests for the run_command function."""

    def test_run_command_success(self):
        """Test running a command successfully."""
        stdout, stderr, rc = run_command("echo hello")
        assert stdout == "hello"
        assert rc == 0

    def test_run_command_failure(self):
        """Test running a non-existent command."""
        stdout, stderr, rc = run_command("exit 1")
        assert rc == 1

    def test_run_command_timeout(self):
        """Test command timeout."""
        stdout, stderr, rc = run_command("sleep 10", timeout=1)
        assert rc == -1
        assert "timed out" in stderr.lower()


class TestCheckRoot:
    """Tests for the check_root function."""

    def test_check_root_not_root(self):
        """Test check_root returns False when not root."""
        with patch("os.geteuid", return_value=1000):
            assert check_root() is False

    def test_check_root_is_root(self):
        """Test check_root returns True when root."""
        with patch("os.geteuid", return_value=0):
            assert check_root() is True
