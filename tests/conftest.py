"""Pytest configuration and fixtures for security audit tests."""

import pytest
from unittest.mock import MagicMock, patch


@pytest.fixture
def mock_run_command():
    """Mock the run_command function."""
    with patch("security_audit.core.run_command") as mock:
        mock.return_value = ("", "", 0)
        yield mock


@pytest.fixture
def sample_finding():
    """Create a sample Finding for testing."""
    from security_audit.core import Finding, Severity

    return Finding(
        severity=Severity.HIGH,
        check_id="TEST-001",
        title="Test Finding",
        description="A test finding for unit tests",
        evidence="test evidence",
        impact="test impact",
        remediation="test remediation",
        phase="Test Phase",
    )


@pytest.fixture
def mock_root():
    """Mock running as root."""
    with patch("security_audit.core.check_root") as mock:
        mock.return_value = True
        yield mock
