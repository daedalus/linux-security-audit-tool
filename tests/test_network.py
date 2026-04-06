"""Tests for the network phase."""

import pytest
from unittest.mock import patch
from security_audit.phases.network import (
    check_listening_services,
    check_firewall_status,
    check_sysctl_network_hardening,
    check_unnecessary_services,
    check_ufw_firewall,
    check_firewalld,
    check_ipv6_hardening,
    check_icmp_broadcast,
    check_source_routing,
    check_open_proxy,
    check_open_relay,
    check_unwanted_network_services,
    run_network_checks,
)
from security_audit.core import Severity, Finding


class TestCheckListeningServices:
    """Tests for check_listening_services."""

    @patch("security_audit.phases.network.run_command")
    def test_no_listening_services(self, mock_run):
        """Test when no services listening on 0.0.0.0."""
        mock_run.return_value = ("", "", 1)
        findings = check_listening_services()
        assert len(findings) == 0


class TestCheckFirewallStatus:
    """Tests for check_firewall_status."""

    @patch("security_audit.phases.network.run_command")
    def test_firewall_default_accept(self, mock_run):
        """Test when firewall has ACCEPT policy."""
        mock_run.return_value = ("Chain INPUT (policy ACCEPT)", "", 0)
        findings = check_firewall_status()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-002"


class TestCheckSysctlNetworkHardening:
    """Tests for check_sysctl_network_hardening."""

    @patch("security_audit.phases.network.run_command")
    def test_all_params_hardened(self, mock_run):
        """Test when network params are properly hardened."""
        mock_run.side_effect = [
            ("0", "", 0),
            ("1", "", 0),
            ("0", "", 0),
            ("0", "", 0),
            ("0", "", 0),
            ("1", "", 0),
            ("1", "", 0),
        ]
        findings = check_sysctl_network_hardening()
        assert len(findings) == 0


class TestCheckUFWFirewall:
    """Tests for check_ufw_firewall."""

    @patch("security_audit.phases.network.run_command")
    def test_ufw_inactive(self, mock_run):
        """Test when UFW is inactive."""
        mock_run.return_value = ("Status: inactive", "", 0)
        findings = check_ufw_firewall()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-006"


class TestCheckFirewalld:
    """Tests for check_firewalld."""

    @patch("security_audit.phases.network.run_command")
    def test_firewalld_not_running(self, mock_run):
        """Test when firewalld is not running."""
        mock_run.return_value = ("inactive", "", 0)
        findings = check_firewalld()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-008"

    @patch("security_audit.phases.network.run_command")
    def test_firewalld_running(self, mock_run):
        """Test when firewalld is running."""
        mock_run.return_value = ("running", "", 0)
        findings = check_firewalld()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_firewalld_not_installed(self, mock_run):
        """Test when firewalld is not installed."""
        mock_run.return_value = ("", "", 1)
        findings = check_firewalld()
        assert len(findings) == 0


class TestRunNetworkChecks:
    """Tests for run_network_checks."""

    @patch("security_audit.phases.network.run_command")
    def test_run_network_checks_returns_list(self, mock_run):
        """Test that run_network_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_network_checks()
        assert isinstance(findings, list)


class TestCheckOpenProxy:
    """Tests for check_open_proxy."""

    @patch("security_audit.phases.network.run_command")
    def test_proxy_found(self, mock_run):
        """Test when proxy is found."""
        mock_run.return_value = (
            "LISTEN 0 128 *:3128 *:* users:(('squid',pid=1234,fd=5))",
            "",
            0,
        )
        findings = check_open_proxy()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-012"


class TestCheckOpenRelay:
    """Tests for check_open_relay."""

    @patch("security_audit.phases.network.run_command")
    def test_mail_on_25(self, mock_run):
        """Test when mail service on port 25."""
        mock_run.return_value = (
            "LISTEN 0 100 *:25 *:* users:(('postfix',pid=1234,fd=5))",
            "",
            0,
        )
        findings = check_open_relay()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-013"


class TestCheckUnwantedNetworkServices:
    """Tests for check_unwanted_network_services."""

    @patch("security_audit.phases.network.run_command")
    def test_telnet_found(self, mock_run):
        """Test when telnet is found."""
        mock_run.return_value = (
            "LISTEN 0 128 *:23 *:* users:(('telnetd',pid=1234,fd=5))",
            "",
            0,
        )
        findings = check_unwanted_network_services()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-014"


class TestCheckUnnecessaryServices:
    """Tests for check_unnecessary_services."""

    @patch("security_audit.phases.network.run_command")
    def test_telnet_running(self, mock_run):
        """Test when telnet is running."""
        mock_run.return_value = ("telnet.service loaded active running Telnetd", "", 0)
        findings = check_unnecessary_services()
        assert any(f.check_id == "NET-005" for f in findings)


class TestCheckIPv6Hardening:
    """Tests for check_ipv6_hardening."""

    @patch("security_audit.phases.network.run_command")
    def test_ipv6_accept_ra_enabled(self, mock_run):
        """Test when IPv6 accept_ra is enabled."""
        mock_run.side_effect = [
            ("1", "", 0),
            ("1", "", 0),
            ("1", "", 0),
            ("1", "", 0),
            ("1", "", 0),
            ("1", "", 0),
        ]
        findings = check_ipv6_hardening()
        assert len(findings) >= 1


class TestCheckICMPBroadcast:
    """Tests for check_icmp_broadcast."""

    @patch("security_audit.phases.network.run_command")
    def test_icmp_broadcast_disabled(self, mock_run):
        """Test when ICMP broadcast is not ignored."""
        mock_run.return_value = ("0", "", 0)
        findings = check_icmp_broadcast()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-010"


class TestCheckSourceRouting:
    """Tests for check_source_routing."""

    @patch("security_audit.phases.network.run_command")
    def test_source_routing_enabled(self, mock_run):
        """Test when source routing is enabled."""
        mock_run.return_value = ("1", "", 0)
        findings = check_source_routing()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-011"
