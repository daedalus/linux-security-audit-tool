"""Phase 2 - Network Exposure module."""

import re

from ..core import Finding, Severity, cached_check, run_command


@cached_check("check_listening_services")
def check_listening_services() -> list[Finding]:
    """Check for listening services on the system."""
    findings = []

    stdout, _, rc = run_command("ss -tlnp 2>/dev/null")
    if rc == 0 and stdout:
        lines = stdout.strip().split("\n")
        for line in lines[1:]:
            if "0.0.0.0:" in line or "*:" in line:
                port_match = re.search(r":(\d+)\s", line)
                port = port_match.group(1) if port_match else "unknown"
                proto = (
                    "TCP"
                    if "tcp" in line.lower()
                    else "UDP"
                    if "udp" in line.lower()
                    else "TCP"
                )
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="NET-001",
                        title=f"Exposed Network Service (port {port})",
                        description=f"Service listening on all interfaces on port {port}/{proto}",
                        evidence=line,
                        impact="Service is accessible from network",
                        remediation="Bind to 127.0.0.1 or configure firewall",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_firewall_status")
def check_firewall_status() -> list[Finding]:
    """Check firewall status and rules."""
    findings = []

    stdout, _, rc = run_command("iptables -L -n 2>/dev/null")
    if rc != 0:
        stdout, _, rc = run_command("nft list ruleset 2>/dev/null")

    if rc == 0 and stdout:
        if "Chain INPUT (policy ACCEPT)" in stdout:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="NET-002",
                    title="Firewall Default Policy ACCEPT",
                    description="iptables INPUT chain has default ACCEPT policy",
                    evidence="Chain INPUT (policy ACCEPT)",
                    impact="No protection against unsolicited network traffic",
                    remediation="Set default INPUT policy to DROP",
                    phase="Phase 2",
                )
            )
    else:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="NET-003",
                title="No Firewall Rules Found",
                description="Unable to detect active firewall rules",
                evidence="No iptables/nftables rules detected",
                impact="System may have no network protection",
                remediation="Configure firewall with default DROP policy",
                phase="Phase 2",
            )
        )

    return findings


@cached_check("check_sysctl_network_hardening")
def check_sysctl_network_hardening() -> list[Finding]:
    """Check sysctl network hardening parameters (Phase 2 specific)."""
    findings = []

    params = {
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
    }

    for param, expected in params.items():
        stdout, _, rc = run_command(f"sysctl -n {param} 2>/dev/null")
        if rc == 0:
            actual = stdout.strip()
            if actual != expected:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        check_id="NET-004",
                        title=f"Suboptimal {param}",
                        description=f"Current value: {actual}, expected: {expected}",
                        evidence=f"{param} = {actual}",
                        impact="Network hardening gap",
                        remediation=f"Set {param} = {expected}",
                        phase="Phase 2",
                    )
                )

    ipv6_params = {
        "net.ipv6.conf.all.accept_redirects": "0",
        "net.ipv6.conf.all.accept_source_route": "0",
    }

    for param, expected in ipv6_params.items():
        stdout, _, rc = run_command(f"sysctl -n {param} 2>/dev/null")
        if rc == 0:
            actual = stdout.strip()
            if actual != expected:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        check_id="NET-004",
                        title=f"Suboptimal {param}",
                        description=f"Current value: {actual}, expected: {expected}",
                        evidence=f"{param} = {actual}",
                        impact="IPv6 network hardening gap",
                        remediation=f"Set {param} = {expected}",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_unnecessary_services")
def check_unnecessary_services() -> list[Finding]:
    """Check for unnecessary network services."""
    findings = []

    dangerous_services = [
        "telnet",
        "rsh",
        "rlogin",
        "rexec",
        "finger",
        "rpcbind",
    ]

    stdout, _, rc = run_command(
        "systemctl list-units --type=service --state=running 2>/dev/null"
    )
    if rc == 0 and stdout:
        for service in dangerous_services:
            if service in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="NET-005",
                        title=f"Running Dangerous Service: {service}",
                        description=f"Service {service} is running",
                        evidence=f"systemctl show {service}",
                        impact="Service provides insecure network access",
                        remediation=f"Disable {service}: systemctl stop {service} && systemctl disable {service}",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_ufw_firewall")
def check_ufw_firewall() -> list[Finding]:
    """Check UFW firewall status and rules."""
    findings = []

    stdout, _, rc = run_command("ufw status 2>/dev/null")
    if rc == 0 and stdout:
        if "Status: inactive" in stdout:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="NET-006",
                    title="UFW Firewall Inactive",
                    description="UFW firewall is not active",
                    evidence=stdout,
                    impact="No firewall protection enabled",
                    remediation="Enable UFW: sudo ufw enable",
                    phase="Phase 2",
                )
            )
        elif "Status: active" in stdout:
            if "Default deny (incoming)" not in stdout:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="NET-007",
                        title="UFW Default Policy Not Deny",
                        description="UFW is active but default incoming policy is not deny",
                        evidence=stdout,
                        impact="May allow unsolicited incoming connections",
                        remediation="Set default incoming policy: sudo ufw default deny incoming",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_firewalld")
def check_firewalld() -> list[Finding]:
    """Check firewalld firewall status and rules."""
    findings = []

    stdout, _, rc = run_command("firewall-cmd --state 2>/dev/null")
    if rc == 0:
        if "running" not in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="NET-008",
                    title="Firewalld Not Running",
                    description="Firewalld is not active",
                    evidence=stdout,
                    impact="No firewall protection enabled",
                    remediation="Enable firewalld: sudo systemctl enable --now firewalld",
                    phase="Phase 2",
                )
            )
    elif rc != 0:
        pass

    return findings


@cached_check("check_open_proxy")
def check_open_proxy() -> list[Finding]:
    """Check for open proxy services."""
    findings = []

    proxy_services = ["squid", "tinyproxy", "polipo", "varnish", "nginx"]

    stdout, _, rc = run_command("ss -tlnp 2>/dev/null")
    if rc == 0 and stdout:
        for service in proxy_services:
            if service in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="NET-012",
                        title=f"Proxy Service Detected: {service}",
                        description=f"Proxy service {service} is listening",
                        evidence=f"ss output contains {service}",
                        impact="Open proxy can be used for malicious traffic",
                        remediation=f"Configure {service} to require authentication or restrict access",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_open_relay")
def check_open_relay() -> list[Finding]:
    """Check for open SMTP relay."""
    findings = []

    mail_services = ["postfix", "sendmail", "exim", "dovecot"]

    stdout, _, rc = run_command("ss -tlnp 2>/dev/null")
    if rc == 0 and stdout:
        listening_on_25 = ":25 " in stdout or ":25/" in stdout
        if listening_on_25:
            for service in mail_services:
                if service in stdout.lower():
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            check_id="NET-013",
                            title=f"Mail Service Detected: {service}",
                            description=f"Mail service {service} is listening on port 25",
                            evidence=f"ss output shows {service} on port 25",
                            impact="May be configured as open relay for spam",
                            remediation=f"Configure {service} to reject unauthorized relay",
                            phase="Phase 2",
                        )
                    )
                    break

    return findings


@cached_check("check_unwanted_network_services")
def check_unwanted_network_services() -> list[Finding]:
    """Check for unwanted network services (FTP, Telnet, etc.)."""
    findings = []

    unwanted = ["vsftpd", "proftpd", "ftpd", "telnet", "rsh", "finger"]

    stdout, _, rc = run_command("ss -tlnp 2>/dev/null")
    if rc == 0 and stdout:
        for service in unwanted:
            if service in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="NET-014",
                        title=f"Unwanted Service: {service}",
                        description=f"Insecure service {service} is running",
                        evidence=f"ss output contains {service}",
                        impact="Service may have known vulnerabilities",
                        remediation=f"Disable {service}: systemctl stop {service} && systemctl disable {service}",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_ntp_sync")
def check_ntp_sync() -> list[Finding]:
    """Check if NTP time synchronization is configured and active."""
    findings: list[Finding] = []

    ntp_services = ["systemd-timesyncd", "chronyd", "ntp", "ntpd"]
    for service in ntp_services:
        stdout, _, rc = run_command(f"systemctl is-active {service} 2>/dev/null")
        if rc == 0 and stdout.strip() == "active":
            return findings

    findings.append(
        Finding(
            severity=Severity.MEDIUM,
            check_id="NET-015",
            title="NTP Not Configured",
            description="No active NTP daemon found (systemd-timesyncd, chronyd, or ntpd)",
            evidence="None of systemd-timesyncd, chronyd, ntp, ntpd reported active",
            impact="System clock may drift, affecting log timestamps and TLS certificate validation",
            remediation="Enable an NTP daemon: systemctl enable --now systemd-timesyncd",
            phase="Phase 2",
        )
    )

    return findings


@cached_check("check_ftp_anonymous_access")
def check_ftp_anonymous_access() -> list[Finding]:
    """Check FTP servers for anonymous/unauthenticated access."""
    findings: list[Finding] = []

    # Check vsftpd configuration
    stdout, _, rc = run_command("cat /etc/vsftpd.conf 2>/dev/null")
    if rc == 0 and stdout:
        for line in stdout.splitlines():
            stripped = line.strip().lower()
            if stripped.startswith("anonymous_enable") and "yes" in stripped:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="NET-016",
                        title="FTP Anonymous Access Enabled (vsftpd)",
                        description="vsftpd is configured to allow anonymous FTP logins",
                        evidence=line.strip(),
                        impact="Anyone can connect to the FTP server without credentials and access files",
                        remediation="Set anonymous_enable=NO in /etc/vsftpd.conf and restart vsftpd",
                        phase="Phase 2",
                    )
                )
                break

    # Check proftpd configuration
    for proftpd_conf in ["/etc/proftpd/proftpd.conf", "/etc/proftpd.conf"]:
        stdout, _, rc = run_command(f"cat {proftpd_conf} 2>/dev/null")
        if rc == 0 and stdout:
            if "<anonymous" in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="NET-016",
                        title="FTP Anonymous Access Enabled (proftpd)",
                        description=f"proftpd configuration at {proftpd_conf} contains an <Anonymous> block",
                        evidence=f"<Anonymous> block found in {proftpd_conf}",
                        impact="Anyone can connect to the FTP server without credentials and access files",
                        remediation=f"Remove or comment out the <Anonymous> block in {proftpd_conf} and restart proftpd",
                        phase="Phase 2",
                    )
                )
            break

    # Check pure-ftpd configuration
    stdout, _, rc = run_command("cat /etc/pure-ftpd/conf/NoAnonymous 2>/dev/null")
    if rc == 0:
        if stdout.strip().lower() != "yes":
            # Only flag if pure-ftpd is actually installed/running
            _, _, rc2 = run_command("which pure-ftpd 2>/dev/null")
            if rc2 == 0:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="NET-016",
                        title="FTP Anonymous Access Enabled (pure-ftpd)",
                        description="pure-ftpd NoAnonymous setting is not enabled",
                        evidence=f"/etc/pure-ftpd/conf/NoAnonymous = '{stdout.strip()}'",
                        impact="Anyone can connect to the FTP server without credentials and access files",
                        remediation="Set 'yes' in /etc/pure-ftpd/conf/NoAnonymous and restart pure-ftpd",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_nfs_world_accessible_shares")
def check_nfs_world_accessible_shares() -> list[Finding]:
    """Check NFS exports for world-accessible or insecure shares."""
    findings: list[Finding] = []

    stdout, _, rc = run_command("cat /etc/exports 2>/dev/null")
    if rc != 0 or not stdout.strip():
        return findings

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # A wildcard host (*) means the share is accessible by any host
        parts = stripped.split()
        if len(parts) >= 2:
            export_path = parts[0]
            clients_and_opts = stripped[len(export_path) :].strip()

            # Check for world-accessible exports (wildcard host)
            if re.search(r"(?:^|\s)\*(?:\s|\(|$)", clients_and_opts):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="NET-017",
                        title=f"NFS Share Accessible by All Hosts: {export_path}",
                        description=f"NFS export '{export_path}' uses wildcard (*) host, allowing any host to mount it",
                        evidence=stripped,
                        impact="Any system on the network can mount this NFS share without host-based restriction",
                        remediation=f"Restrict the NFS export to specific trusted hosts in /etc/exports: {export_path} trusted_host(options)",
                        phase="Phase 2",
                    )
                )

            # Check for no_root_squash (allows remote root to act as local root)
            if "no_root_squash" in clients_and_opts.lower():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="NET-017",
                        title=f"NFS Share with no_root_squash: {export_path}",
                        description=f"NFS export '{export_path}' has no_root_squash enabled, allowing remote root privilege escalation",
                        evidence=stripped,
                        impact="A remote root user can access the NFS share with root privileges on the server",
                        remediation=f"Remove no_root_squash from the export options in /etc/exports for {export_path}",
                        phase="Phase 2",
                    )
                )

            # Check for insecure option (allows non-privileged source ports)
            if re.search(
                r"(?:^|,|\()\s*insecure\s*(?:,|\)|$)", clients_and_opts.lower()
            ):
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="NET-017",
                        title=f"NFS Share with insecure Option: {export_path}",
                        description=f"NFS export '{export_path}' has the 'insecure' option, allowing connections from unprivileged ports",
                        evidence=stripped,
                        impact="Clients can connect from unprivileged source ports, weakening the security model",
                        remediation=f"Remove the 'insecure' option from the export in /etc/exports for {export_path}",
                        phase="Phase 2",
                    )
                )

    return findings


@cached_check("check_samba_guest_access")
def check_samba_guest_access() -> list[Finding]:
    """Check Samba/CIFS configuration for anonymous/guest access."""
    findings: list[Finding] = []

    stdout, _, rc = run_command("cat /etc/samba/smb.conf 2>/dev/null")
    if rc != 0 or not stdout:
        return findings

    current_share = None
    share_options: dict[str, str] = {}
    global_options: dict[str, str] = {}
    in_global = False

    for line in stdout.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        if stripped.startswith("["):
            # Process previous share if any
            if current_share and current_share.lower() not in (
                "[global]",
                "[printers]",
                "[homes]",
            ):
                _check_samba_share(current_share, share_options, findings)
            current_share = stripped
            share_options = {}
            in_global = stripped.lower() == "[global]"
        elif "=" in stripped:
            key, _, val = stripped.partition("=")
            key = key.strip().lower()
            val = val.strip().lower()
            if in_global:
                global_options[key] = val
            else:
                share_options[key] = val

    # Process the last share
    if current_share and current_share.lower() not in (
        "[global]",
        "[printers]",
        "[homes]",
    ):
        _check_samba_share(current_share, share_options, findings)

    # Check for global insecure settings
    security = global_options.get("security", "")
    if security == "share":
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                check_id="NET-018",
                title="Samba Using Share-Level Security (No Authentication)",
                description="Samba is configured with 'security = share', which does not require user authentication",
                evidence=f"security = {security}",
                impact="Any user can access Samba shares without providing valid credentials",
                remediation="Set 'security = user' in /etc/samba/smb.conf [global] section",
                phase="Phase 2",
            )
        )

    map_to_guest = global_options.get("map to guest", "")
    if map_to_guest in ("bad user", "bad password"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="NET-018",
                title="Samba Maps Authentication Failures to Guest",
                description=f"Samba global setting 'map to guest = {map_to_guest}' allows failed logins to fall back to guest access",
                evidence=f"map to guest = {map_to_guest}",
                impact="Users with invalid or unknown credentials will be granted guest access to shares",
                remediation="Set 'map to guest = never' in /etc/samba/smb.conf [global] section",
                phase="Phase 2",
            )
        )

    return findings


def _check_samba_share(
    share_name: str,
    share_options: dict[str, str],
    findings: list[Finding],
) -> None:
    """Evaluate a single Samba share for guest/anonymous access issues."""
    guest_ok = share_options.get("guest ok", share_options.get("public", ""))
    guest_only = share_options.get("guest only", "")

    if guest_ok in ("yes", "true", "1"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="NET-018",
                title=f"Samba Share Allows Guest Access: {share_name}",
                description=f"Samba share {share_name} has 'guest ok = yes', allowing unauthenticated access",
                evidence=f"[{share_name.strip('[]')}] guest ok = yes",
                impact="Anyone on the network can access this share without authentication",
                remediation=f"Set 'guest ok = no' for share {share_name} in /etc/samba/smb.conf",
                phase="Phase 2",
            )
        )

    if guest_only in ("yes", "true", "1"):
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="NET-018",
                title=f"Samba Share Restricted to Guest Only: {share_name}",
                description=f"Samba share {share_name} has 'guest only = yes', meaning all access is unauthenticated",
                evidence=f"[{share_name.strip('[]')}] guest only = yes",
                impact="All connections to this share are treated as the guest account",
                remediation=f"Remove 'guest only' and configure proper authentication for share {share_name}",
                phase="Phase 2",
            )
        )


@cached_check("check_apache_insecure_config")
def check_apache_insecure_config() -> list[Finding]:
    """Check Apache web server for insecure configuration (open directory listing, no auth)."""
    findings: list[Finding] = []

    # Locate Apache config files
    stdout, _, rc = run_command(
        "find /etc/apache2 /etc/httpd -name '*.conf' -type f 2>/dev/null"
    )
    if rc != 0 or not stdout.strip():
        return findings

    config_files = stdout.strip().splitlines()
    indexes_files: list[str] = []
    no_auth_files: list[str] = []

    for conf_file in config_files:
        content, _, frc = run_command(f"cat {conf_file} 2>/dev/null")
        if frc != 0 or not content:
            continue

        # Check for Options Indexes (directory listing enabled)
        for line in content.splitlines():
            stripped = line.strip()
            if re.search(r"Options\b.*\bIndexes\b", stripped, re.IGNORECASE):
                if not stripped.startswith("#") and not re.search(
                    r"-\s*Indexes\b", stripped, re.IGNORECASE
                ):
                    indexes_files.append(conf_file)
                    break

        # Check for locations/directories without any AuthType (unauthenticated access)
        in_location = False
        has_auth = False
        block_lines: list[str] = []
        for line in content.splitlines():
            stripped = line.strip()
            if re.search(r"<(Location|Directory|Files)\b", stripped, re.IGNORECASE):
                in_location = True
                has_auth = False
                block_lines = [stripped]
            elif re.search(r"</(Location|Directory|Files)>", stripped, re.IGNORECASE):
                if in_location and not has_auth:
                    # Only flag if it requires authentication context (has Require or auth directives)
                    block_text = "\n".join(block_lines)
                    if (
                        re.search(r"\bRequire\b", block_text, re.IGNORECASE) is None
                        and re.search(r"\bAuthType\b", block_text, re.IGNORECASE)
                        is None
                        and re.search(
                            r"\bOrder\s+deny,allow\b", block_text, re.IGNORECASE
                        )
                    ):
                        no_auth_files.append(conf_file)
                in_location = False
                block_lines = []
            elif in_location:
                block_lines.append(stripped)
                if re.search(r"\bAuthType\b", stripped, re.IGNORECASE):
                    has_auth = True

    if indexes_files:
        evidence = "\n".join(indexes_files)
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="NET-019",
                title="Apache Directory Listing Enabled (Options Indexes)",
                description="Apache is configured with 'Options Indexes', which enables automatic directory listing",
                evidence=evidence,
                impact="Directory contents are exposed to anyone who accesses a URL without an index file",
                remediation="Remove 'Indexes' from Options directives or use 'Options -Indexes' in the affected config files",
                phase="Phase 2",
            )
        )

    return findings


@cached_check("check_nginx_insecure_config")
def check_nginx_insecure_config() -> list[Finding]:
    """Check Nginx web server for insecure configuration (directory listing, no auth)."""
    findings: list[Finding] = []

    # Locate Nginx config files
    stdout, _, rc = run_command("find /etc/nginx -name '*.conf' -type f 2>/dev/null")
    if rc != 0 or not stdout.strip():
        return findings

    config_files = stdout.strip().splitlines()
    autoindex_files: list[str] = []

    for conf_file in config_files:
        content, _, frc = run_command(f"cat {conf_file} 2>/dev/null")
        if frc != 0 or not content:
            continue

        # Check for autoindex on (directory listing enabled)
        for line in content.splitlines():
            stripped = line.strip()
            if re.search(r"\bautoindex\s+on\b", stripped, re.IGNORECASE):
                if not stripped.startswith("#"):
                    autoindex_files.append(conf_file)
                    break

    if autoindex_files:
        evidence = "\n".join(autoindex_files)
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="NET-020",
                title="Nginx Directory Listing Enabled (autoindex on)",
                description="Nginx is configured with 'autoindex on', which enables automatic directory listing",
                evidence=evidence,
                impact="Directory contents are exposed to anyone who accesses a URL without an index file",
                remediation="Set 'autoindex off;' in the affected Nginx server/location blocks",
                phase="Phase 2",
            )
        )

    return findings


def run_network_checks() -> list[Finding]:
    """Run all network exposure checks."""
    findings = []

    findings.extend(check_listening_services())
    findings.extend(check_firewall_status())
    findings.extend(check_sysctl_network_hardening())
    findings.extend(check_unnecessary_services())
    findings.extend(check_ufw_firewall())
    findings.extend(check_firewalld())
    findings.extend(check_open_proxy())
    findings.extend(check_open_relay())
    findings.extend(check_unwanted_network_services())
    findings.extend(check_ntp_sync())
    findings.extend(check_ftp_anonymous_access())
    findings.extend(check_nfs_world_accessible_shares())
    findings.extend(check_samba_guest_access())
    findings.extend(check_apache_insecure_config())
    findings.extend(check_nginx_insecure_config())

    return findings
