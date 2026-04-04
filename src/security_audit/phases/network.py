"""Phase 2 - Network Exposure module."""

from ..core import Finding, Severity, run_command


def check_listening_services() -> list[Finding]:
    """Check for listening services on the system."""
    findings = []

    stdout, _, rc = run_command("ss -tlnp 2>/dev/null")
    if rc == 0 and stdout:
        lines = stdout.strip().split("\n")
        for line in lines[1:]:
            if "0.0.0.0:" in line or "*:" in line:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="NET-001",
                        title="Exposed Network Service",
                        description="Service listening on all interfaces",
                        evidence=line,
                        impact="Service is accessible from network",
                        remediation="Bind to 127.0.0.1 or configure firewall",
                        phase="Phase 2",
                    )
                )

    return findings


def check_firewall_status() -> list[Finding]:
    """Check firewall status and rules."""
    findings = []

    stdout, _, rc = run_command("sudo iptables -L -n 2>/dev/null")
    if rc != 0:
        stdout, _, rc = run_command("sudo nft list ruleset 2>/dev/null")

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


def check_sysctl_network_hardening() -> list[Finding]:
    """Check sysctl network hardening parameters."""
    findings = []

    params = {
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.rp_filter": "1",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.send_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "net.ipv4.tcp_syncookies": "1",
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

    return findings


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


def check_ufw_firewall() -> list[Finding]:
    """Check UFW firewall status and rules."""
    findings = []

    stdout, _, rc = run_command("sudo ufw status 2>/dev/null")
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


def check_firewalld() -> list[Finding]:
    """Check firewalld firewall status and rules."""
    findings = []

    stdout, _, rc = run_command("sudo firewall-cmd --state 2>/dev/null")
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


def check_ipv6_hardening() -> list[Finding]:
    """Check IPv6 hardening parameters."""
    findings = []

    params = {
        "net.ipv6.conf.all.accept_ra": "0",
        "net.ipv6.conf.default.accept_ra": "0",
        "net.ipv6.conf.all.accept_redirects": "0",
        "net.ipv6.conf.default.accept_redirects": "0",
        "net.ipv6.conf.all.accept_source_route": "0",
        "net.ipv6.conf.default.accept_source_route": "0",
    }

    for param, expected in params.items():
        stdout, _, rc = run_command(f"sysctl -n {param} 2>/dev/null")
        if rc == 0:
            actual = stdout.strip()
            if actual != expected:
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        check_id="NET-009",
                        title=f"Suboptimal IPv6 {param}",
                        description=f"Current value: {actual}, expected: {expected}",
                        evidence=f"{param} = {actual}",
                        impact="IPv6 security hardening gap",
                        remediation=f"Set {param} = {expected}",
                        phase="Phase 2",
                    )
                )

    return findings


def check_icmp_broadcast() -> list[Finding]:
    """Check ICMP broadcast protection."""
    findings = []

    stdout, _, rc = run_command("sysctl -n net.ipv4.icmp_ignore_broadcasts 2>/dev/null")
    if rc == 0:
        if stdout.strip() != "1":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="NET-010",
                    title="ICMP Broadcast Not Ignored",
                    description=f"Current value: {stdout.strip()}, expected: 1",
                    evidence=f"net.ipv4.icmp_ignore_broadcasts = {stdout.strip()}",
                    impact="System vulnerable to broadcast ping attacks",
                    remediation="Set net.ipv4.icmp_ignore_broadcasts = 1",
                    phase="Phase 2",
                )
            )

    return findings


def check_source_routing() -> list[Finding]:
    """Check source packet routing."""
    findings = []

    stdout, _, rc = run_command(
        "sysctl -n net.ipv4.conf.all.accept_source_route 2>/dev/null"
    )
    if rc == 0:
        if stdout.strip() != "0":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="NET-011",
                    title="Source Routing Enabled",
                    description=f"Current value: {stdout.strip()}, expected: 0",
                    evidence=f"net.ipv4.conf.all.accept_source_route = {stdout.strip()}",
                    impact="Allowing source routing enables IP spoofing attacks",
                    remediation="Set net.ipv4.conf.all.accept_source_route = 0",
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
    findings.extend(check_ipv6_hardening())
    findings.extend(check_icmp_broadcast())
    findings.extend(check_source_routing())

    return findings
