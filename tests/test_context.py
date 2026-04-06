"""Tests for the context phase."""

import pytest
from unittest.mock import patch
from security_audit.phases.context import gather_context, get_system_info
from security_audit.core import AuditContext


class TestGatherContext:
    """Tests for gather_context function."""

    @patch("security_audit.phases.context.run_command")
    def test_gather_context_basic(self, mock_run):
        """Test basic context gathering."""
        mock_run.side_effect = [
            ("test-hostname", "", 0),
            ("5.15.0-generic", "", 0),
            ("Ubuntu 22.04", "", 0),
            ("12:00:00 up 1 day", "", 0),
            ("none", "", 0),
            ("", "", 1),
        ]
        context = gather_context()
        assert context.hostname == "test-hostname"
        assert context.kernel == "5.15.0-generic"

    @patch("security_audit.phases.context.run_command")
    def test_gather_context_container_detection(self, mock_run):
        """Test container detection."""
        mock_run.side_effect = [
            ("test-hostname", "", 0),
            ("5.15.0-generic", "", 0),
            ("Ubuntu 22.04", "", 0),
            ("12:00:00 up 1 day", "", 0),
            ("docker", "", 0),
            ("", "", 0),
        ]
        context = gather_context()
        assert context.is_container is True
        assert context.virtualization == "docker"


class TestGetSystemInfo:
    """Tests for get_system_info function."""

    @patch("security_audit.phases.context.run_command")
    def test_get_system_info(self, mock_run):
        """Test get_system_info returns dict."""
        mock_run.return_value = ("test", "", 0)
        info = get_system_info()
        assert isinstance(info, dict)
