"""Phase 4 - Process & Service Posture module."""

from ..core import Finding, Severity, run_command


def check_running_services() -> list[Finding]:
    """Check running services on the system."""
    findings = []

    stdout, _, rc = run_command(
        "systemctl list-units --type=service --state=running 2>/dev/null"
    )
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="PROC-001",
                title="Running Services",
                description="List of running services",
                evidence=f"{len(stdout.split(chr(10)))} services running",
                impact="Each running service increases attack surface",
                remediation="Disable unnecessary services",
                phase="Phase 4",
            )
        )

    return findings


def check_enabled_services() -> list[Finding]:
    """Check services enabled at boot."""
    findings = []

    stdout, _, rc = run_command(
        "systemctl list-unit-files --type=service --state=enabled 2>/dev/null"
    )
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="PROC-002",
                title="Enabled Services",
                description="List of services enabled at boot",
                evidence=f"{len(stdout.split(chr(10)))} services enabled",
                impact="Services will restart after reboot",
                remediation="Disable services not needed at boot",
                phase="Phase 4",
            )
        )

    return findings


def check_docker_socket() -> list[Finding]:
    """Check for Docker socket access."""
    findings = []

    stdout, _, rc = run_command("ls -la /var/run/docker.sock 2>/dev/null")
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="PROC-003",
                title="Docker Socket Accessible",
                description="Docker socket is present on the system",
                evidence=stdout,
                impact="Docker group equivalent to root access",
                remediation="Restrict Docker socket access to docker group only",
                phase="Phase 4",
            )
        )

    return findings


def check_apparmor_status() -> list[Finding]:
    """Check AppArmor status."""
    findings = []

    stdout, _, rc = run_command(
        "aa-status 2>/dev/null || apparmor_status 2>/dev/null || echo 'not installed'"
    )
    if rc == 0:
        if "not installed" in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="PROC-004",
                    title="AppArmor Not Installed",
                    description="AppArmor is not installed on the system",
                    evidence=stdout,
                    impact="No mandatory access control framework",
                    remediation="Install and enable AppArmor",
                    phase="Phase 4",
                )
            )
        elif "enforce" not in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="PROC-005",
                    title="AppArmor Not Enforcing",
                    description="AppArmor is installed but not in enforce mode",
                    evidence=stdout,
                    impact="Limited MAC protection",
                    remediation="Enable AppArmor enforce mode",
                    phase="Phase 4",
                )
            )

    return findings


def check_selinux_status() -> list[Finding]:
    """Check SELinux status."""
    findings = []

    stdout, _, rc = run_command("getenforce 2>/dev/null")
    if rc == 0:
        if stdout.lower() == "disabled":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="PROC-006",
                    title="SELinux Disabled",
                    description="SELinux is disabled on the system",
                    evidence=stdout,
                    impact="No mandatory access control enforcement",
                    remediation="Enable SELinux in enforcing mode",
                    phase="Phase 4",
                )
            )
        elif stdout.lower() == "permissive":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="PROC-007",
                    title="SELinux Permissive",
                    description="SELinux is in permissive mode",
                    evidence=stdout,
                    impact="Policy violations logged but not enforced",
                    remediation="Set SELinux to enforcing mode",
                    phase="Phase 4",
                )
            )

    return findings


def check_unnecessary_network_services() -> list[Finding]:
    """Check for unnecessary network services."""
    findings = []

    dangerous_services = [
        "telnet",
        "rsh",
        "rlogin",
        "rexec",
        "finger",
        "rpcbind",
        "cups",
        "avahi-daemon",
        "bluetooth",
    ]

    for service in dangerous_services:
        stdout, _, rc = run_command(f"systemctl is-active {service} 2>/dev/null")
        if rc == 0 and stdout.strip() == "active":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="PROC-008",
                    title=f"Unnecessary Service Running: {service}",
                    description=f"Service {service} is running",
                    evidence=f"systemctl is-active {service}",
                    impact=f"{service} increases attack surface",
                    remediation=f"Disable: systemctl stop {service}; systemctl disable {service}",
                    phase="Phase 4",
                )
            )

    return findings


def run_process_checks() -> list[Finding]:
    """Run all process and service posture checks."""
    findings = []

    findings.extend(check_running_services())
    findings.extend(check_enabled_services())
    findings.extend(check_docker_socket())
    findings.extend(check_apparmor_status())
    findings.extend(check_selinux_status())
    findings.extend(check_unnecessary_network_services())

    return findings
