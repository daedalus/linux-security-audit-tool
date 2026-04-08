"""Tests for the network phase."""

from unittest.mock import patch

from security_audit.core import Severity
from security_audit.phases.network import (
    check_apache_insecure_config,
    check_firewall_status,
    check_firewalld,
    check_ftp_anonymous_access,
    check_listening_services,
    check_nfs_world_accessible_shares,
    check_nginx_insecure_config,
    check_ntp_sync,
    check_open_proxy,
    check_open_relay,
    check_samba_guest_access,
    check_sysctl_network_hardening,
    check_ufw_firewall,
    check_unnecessary_services,
    check_unwanted_network_services,
    run_network_checks,
)


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
            ("1", "", 0),
            ("0", "", 0),
            ("0", "", 0),
            ("1", "", 0),
            ("0", "", 0),
            ("0", "", 0),
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


class TestCheckNtpSync:
    """Tests for check_ntp_sync."""

    @patch("security_audit.phases.network.run_command")
    def test_systemd_timesyncd_active(self, mock_run):
        """Test when systemd-timesyncd is active."""
        mock_run.return_value = ("active", "", 0)
        findings = check_ntp_sync()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_chronyd_active(self, mock_run):
        """Test when chronyd is active (first service inactive, second active)."""
        mock_run.side_effect = [
            ("inactive", "", 1),
            ("active", "", 0),
        ]
        findings = check_ntp_sync()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_no_ntp_service(self, mock_run):
        """Test when no NTP service is active."""
        mock_run.return_value = ("inactive", "", 1)
        findings = check_ntp_sync()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-015"
        assert findings[0].severity == Severity.MEDIUM


class TestCheckFtpAnonymousAccess:
    """Tests for check_ftp_anonymous_access."""

    @patch("security_audit.phases.network.run_command")
    def test_vsftpd_anonymous_enabled(self, mock_run):
        """Test when vsftpd has anonymous_enable=YES."""
        mock_run.side_effect = [
            ("anonymous_enable=YES\nlocal_enable=YES\n", "", 0),  # vsftpd.conf
            ("", "", 1),  # proftpd /etc/proftpd/proftpd.conf not found
            ("", "", 1),  # proftpd /etc/proftpd.conf not found
            ("", "", 1),  # pure-ftpd NoAnonymous not found
        ]
        findings = check_ftp_anonymous_access()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-016"
        assert findings[0].severity == Severity.HIGH

    @patch("security_audit.phases.network.run_command")
    def test_vsftpd_anonymous_disabled(self, mock_run):
        """Test when vsftpd has anonymous_enable=NO."""
        mock_run.side_effect = [
            ("anonymous_enable=NO\nlocal_enable=YES\n", "", 0),  # vsftpd.conf
            ("", "", 1),  # proftpd.conf not found
            ("", "", 1),  # proftpd.conf alt not found
            ("", "", 1),  # pure-ftpd not found
        ]
        findings = check_ftp_anonymous_access()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_proftpd_anonymous_block(self, mock_run):
        """Test when proftpd has an <Anonymous> block."""
        mock_run.side_effect = [
            ("", "", 1),  # vsftpd.conf not found
            ("<Anonymous /ftp>\n  User ftp\n</Anonymous>", "", 0),  # proftpd.conf found
            # proftpd loop breaks after first match, goes to pure-ftpd
            ("", "", 1),  # pure-ftpd NoAnonymous not found
        ]
        findings = check_ftp_anonymous_access()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-016"
        assert findings[0].severity == Severity.HIGH

    @patch("security_audit.phases.network.run_command")
    def test_no_ftp_servers(self, mock_run):
        """Test when no FTP config files are present."""
        mock_run.return_value = ("", "", 1)
        findings = check_ftp_anonymous_access()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_pure_ftpd_anonymous_allowed(self, mock_run):
        """Test when pure-ftpd has NoAnonymous=no."""
        mock_run.side_effect = [
            ("", "", 1),  # vsftpd.conf not found
            ("", "", 1),  # proftpd /etc/proftpd/proftpd.conf not found
            ("", "", 1),  # proftpd /etc/proftpd.conf not found
            ("no\n", "", 0),  # /etc/pure-ftpd/conf/NoAnonymous
            ("/usr/sbin/pure-ftpd", "", 0),  # which pure-ftpd
        ]
        findings = check_ftp_anonymous_access()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-016"
        assert findings[0].severity == Severity.HIGH

    @patch("security_audit.phases.network.run_command")
    def test_pure_ftpd_anonymous_disabled(self, mock_run):
        """Test when pure-ftpd NoAnonymous=yes (anonymous disabled)."""
        mock_run.side_effect = [
            ("", "", 1),  # vsftpd.conf not found
            ("", "", 1),  # proftpd not found
            ("", "", 1),  # proftpd alt not found
            ("yes\n", "", 0),  # /etc/pure-ftpd/conf/NoAnonymous
        ]
        findings = check_ftp_anonymous_access()
        assert len(findings) == 0


class TestCheckNfsWorldAccessibleShares:
    """Tests for check_nfs_world_accessible_shares."""

    @patch("security_audit.phases.network.run_command")
    def test_no_exports_file(self, mock_run):
        """Test when /etc/exports does not exist."""
        mock_run.return_value = ("", "", 1)
        findings = check_nfs_world_accessible_shares()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_wildcard_export(self, mock_run):
        """Test when /etc/exports has a wildcard (world-accessible) share."""
        mock_run.return_value = ("/data *(rw,sync)\n", "", 0)
        findings = check_nfs_world_accessible_shares()
        assert any(f.check_id == "NET-017" for f in findings)
        titles = [f.title for f in findings]
        assert any("World" in t or "All Hosts" in t for t in titles)

    @patch("security_audit.phases.network.run_command")
    def test_no_root_squash_export(self, mock_run):
        """Test when /etc/exports has no_root_squash."""
        mock_run.return_value = ("/data 192.168.1.0/24(rw,no_root_squash)\n", "", 0)
        findings = check_nfs_world_accessible_shares()
        assert any(f.check_id == "NET-017" for f in findings)
        assert any("no_root_squash" in f.title for f in findings)

    @patch("security_audit.phases.network.run_command")
    def test_insecure_option(self, mock_run):
        """Test when /etc/exports has the insecure option."""
        mock_run.return_value = ("/data 192.168.1.0/24(rw,insecure)\n", "", 0)
        findings = check_nfs_world_accessible_shares()
        assert any(f.check_id == "NET-017" for f in findings)
        assert any("insecure" in f.title.lower() for f in findings)

    @patch("security_audit.phases.network.run_command")
    def test_secure_restricted_export(self, mock_run):
        """Test when /etc/exports has a properly restricted share."""
        mock_run.return_value = ("/data 192.168.1.100(ro,root_squash)\n", "", 0)
        findings = check_nfs_world_accessible_shares()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_comments_ignored(self, mock_run):
        """Test that comments in /etc/exports are ignored."""
        mock_run.return_value = ("# /data *(rw,sync)\n", "", 0)
        findings = check_nfs_world_accessible_shares()
        assert len(findings) == 0


class TestCheckSambaGuestAccess:
    """Tests for check_samba_guest_access."""

    @patch("security_audit.phases.network.run_command")
    def test_no_smb_conf(self, mock_run):
        """Test when /etc/samba/smb.conf does not exist."""
        mock_run.return_value = ("", "", 1)
        findings = check_samba_guest_access()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_share_level_security(self, mock_run):
        """Test when Samba uses share-level security (no authentication)."""
        smb_conf = "[global]\n   security = share\n"
        mock_run.return_value = (smb_conf, "", 0)
        findings = check_samba_guest_access()
        assert any(f.check_id == "NET-018" for f in findings)
        assert any(f.severity == Severity.CRITICAL for f in findings)

    @patch("security_audit.phases.network.run_command")
    def test_map_to_guest_bad_user(self, mock_run):
        """Test when Samba maps failed logins to guest."""
        smb_conf = "[global]\n   map to guest = bad user\n"
        mock_run.return_value = (smb_conf, "", 0)
        findings = check_samba_guest_access()
        assert any(f.check_id == "NET-018" for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    @patch("security_audit.phases.network.run_command")
    def test_share_with_guest_ok(self, mock_run):
        """Test when a Samba share has guest ok = yes."""
        smb_conf = "[global]\n   workgroup = WORKGROUP\n\n[public]\n   path = /srv/public\n   guest ok = yes\n"
        mock_run.return_value = (smb_conf, "", 0)
        findings = check_samba_guest_access()
        assert any(f.check_id == "NET-018" for f in findings)
        assert any("Guest Access" in f.title for f in findings)

    @patch("security_audit.phases.network.run_command")
    def test_share_with_guest_only(self, mock_run):
        """Test when a Samba share has guest only = yes."""
        smb_conf = "[global]\n   workgroup = WORKGROUP\n\n[files]\n   path = /srv/files\n   guest only = yes\n"
        mock_run.return_value = (smb_conf, "", 0)
        findings = check_samba_guest_access()
        assert any(f.check_id == "NET-018" for f in findings)
        assert any("Guest Only" in f.title for f in findings)

    @patch("security_audit.phases.network.run_command")
    def test_secure_samba_config(self, mock_run):
        """Test when Samba is configured securely (no guest access)."""
        smb_conf = "[global]\n   security = user\n   map to guest = never\n\n[homes]\n   browseable = no\n"
        mock_run.return_value = (smb_conf, "", 0)
        findings = check_samba_guest_access()
        assert len(findings) == 0


class TestCheckApacheInsecureConfig:
    """Tests for check_apache_insecure_config."""

    @patch("security_audit.phases.network.run_command")
    def test_no_apache_config(self, mock_run):
        """Test when no Apache config files are found."""
        mock_run.return_value = ("", "", 1)
        findings = check_apache_insecure_config()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_options_indexes_enabled(self, mock_run):
        """Test when Apache has Options Indexes enabled."""
        mock_run.side_effect = [
            ("/etc/apache2/apache2.conf", "", 0),  # find config files
            (
                "<Directory /var/www/html>\n    Options Indexes FollowSymLinks\n</Directory>",
                "",
                0,
            ),
        ]
        findings = check_apache_insecure_config()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-019"
        assert findings[0].severity == Severity.MEDIUM

    @patch("security_audit.phases.network.run_command")
    def test_options_indexes_disabled(self, mock_run):
        """Test when Apache has Options -Indexes (directory listing disabled)."""
        mock_run.side_effect = [
            ("/etc/apache2/apache2.conf", "", 0),
            (
                "<Directory /var/www/html>\n    Options -Indexes FollowSymLinks\n</Directory>",
                "",
                0,
            ),
        ]
        findings = check_apache_insecure_config()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_commented_options_indexes(self, mock_run):
        """Test that commented Options Indexes lines are not flagged."""
        mock_run.side_effect = [
            ("/etc/apache2/apache2.conf", "", 0),
            ("# Options Indexes FollowSymLinks\n", "", 0),
        ]
        findings = check_apache_insecure_config()
        assert len(findings) == 0


class TestCheckNginxInsecureConfig:
    """Tests for check_nginx_insecure_config."""

    @patch("security_audit.phases.network.run_command")
    def test_no_nginx_config(self, mock_run):
        """Test when no Nginx config files are found."""
        mock_run.return_value = ("", "", 1)
        findings = check_nginx_insecure_config()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_autoindex_on(self, mock_run):
        """Test when Nginx has autoindex on."""
        mock_run.side_effect = [
            ("/etc/nginx/sites-enabled/default", "", 0),
            ("server {\n    location / {\n        autoindex on;\n    }\n}", "", 0),
        ]
        findings = check_nginx_insecure_config()
        assert len(findings) == 1
        assert findings[0].check_id == "NET-020"
        assert findings[0].severity == Severity.MEDIUM

    @patch("security_audit.phases.network.run_command")
    def test_autoindex_off(self, mock_run):
        """Test when Nginx has autoindex off (secure)."""
        mock_run.side_effect = [
            ("/etc/nginx/nginx.conf", "", 0),
            ("server {\n    location / {\n        autoindex off;\n    }\n}", "", 0),
        ]
        findings = check_nginx_insecure_config()
        assert len(findings) == 0

    @patch("security_audit.phases.network.run_command")
    def test_commented_autoindex_on(self, mock_run):
        """Test that commented autoindex on lines are not flagged."""
        mock_run.side_effect = [
            ("/etc/nginx/nginx.conf", "", 0),
            ("# autoindex on;\n", "", 0),
        ]
        findings = check_nginx_insecure_config()
        assert len(findings) == 0
