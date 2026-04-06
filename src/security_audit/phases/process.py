"""Phase 4 - Process & Service Posture module."""

from ..core import Finding, Severity, run_command


def check_running_services() -> list[Finding]:
    """Check running services on the system."""
    findings = []

    stdout, _, rc = run_command(
        "systemctl list-units --type=service --state=running 2>/dev/null"
    )
    if rc == 0 and stdout:
        lines = [
            l.strip()
            for l in stdout.strip().split("\n")
            if l.strip() and not l.startswith("UNITLoaded")
        ]
        count = len(lines)
        service_list = "\n".join(lines[:20])
        if count > 20:
            service_list += f"\n... and {count - 20} more"
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="PROC-001",
                title=f"Running Services ({count} services)",
                description=f"List of running services: {count} services",
                evidence=service_list,
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
        lines = [
            l.strip()
            for l in stdout.strip().split("\n")
            if l.strip() and not l.startswith("UNIT")
        ]
        count = len(lines)
        service_list = "\n".join(lines[:20])
        if count > 20:
            service_list += f"\n... and {count - 20} more"
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="PROC-002",
                title=f"Enabled Services ({count} services)",
                description=f"List of services enabled at boot: {count} services",
                evidence=service_list,
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


def check_systemd_timers() -> list[Finding]:
    """Check systemd timers."""
    findings = []

    stdout, _, rc = run_command("systemctl list-timers --all 2>/dev/null")
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="PROC-009",
                title="Systemd Timers Found",
                description="Systemd timers are scheduled",
                evidence=f"{len(stdout.split(chr(10)))} timer entries",
                impact="Timers can execute commands automatically",
                remediation="Review timers for legitimacy",
                phase="Phase 4",
            )
        )

    return findings


def check_seccomp_status() -> list[Finding]:
    """Check Seccomp profile status."""
    findings = []

    stdout, _, rc = run_command(
        "systemd-analyze security 2>/dev/null | grep -i seccomp"
    )
    if rc == 0 and stdout:
        if "0" in stdout or "disabled" in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="PROC-010",
                    title="Seccomp Not Enforced",
                    description="Seccomp filtering may not be enforced",
                    evidence=stdout,
                    impact="Limited syscall filtering protection",
                    remediation="Enable Seccomp in systemd service files",
                    phase="Phase 4",
                )
            )
    else:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="PROC-011",
                title="Seccomp Status Unclear",
                description="Unable to determine Seccomp status",
                evidence="systemd-analyze security returned no seccomp info",
                impact="Limited syscall filtering visibility",
                remediation="Check service files for Seccomp= settings",
                phase="Phase 4",
            )
        )

    return findings


def check_service_file_permissions() -> list[Finding]:
    """Check systemd service file permissions."""
    findings = []

    stdout, _, rc = run_command(
        "find /etc/systemd/system -name '*.service' -type f -perm -002 2>/dev/null"
    )
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="PROC-012",
                title="Writable Service Files Found",
                description="Service files with world-writable permissions",
                evidence=stdout,
                impact="Service files can be modified by any user",
                remediation="Fix permissions: chmod 644 on service files",
                phase="Phase 4",
            )
        )

    return findings


def check_sysv_init_scripts() -> list[Finding]:
    """Check for SysV init scripts."""
    findings = []

    stdout, _, rc = run_command("ls /etc/init.d/ 2>/dev/null")
    if rc == 0 and stdout and stdout.strip():
        lines = stdout.strip().split("\n")
        if len(lines) > 0:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    check_id="PROC-013",
                    title="SysV Init Scripts Found",
                    description=f"Found {len(lines)} SysV init scripts",
                    evidence=stdout[:500] + "..." if len(stdout) > 500 else stdout,
                    impact="Legacy init system may be in use",
                    remediation="Consider migrating to systemd",
                    phase="Phase 4",
                )
            )

    return findings


def check_rkhunter_installation() -> list[Finding]:
    """Check if rkhunter is installed and configured."""
    findings = []

    stdout, _, rc = run_command("which rkhunter 2>/dev/null")
    if rc != 0:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="PROC-014",
                title="rkhunter Not Installed",
                description="Rootkit Hunter is not installed on the system",
                evidence="rkhunter not found in PATH",
                impact="No automated rootkit detection in place",
                remediation="Install rkhunter: apt install rkhunter",
                phase="Phase 4",
            )
        )
    else:
        stdout, _, rc = run_command(
            "rkhunter --check --skip-keypress 2>/dev/null | tail -20"
        )
        if rc != 0:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="PROC-015",
                    title="rkhunter Check Failed",
                    description="rkhunter check completed with errors",
                    evidence=stdout[:500] if stdout else "No output",
                    impact="Possible rootkit detected or misconfiguration",
                    remediation="Run rkhunter --check manually and review output",
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
    findings.extend(check_systemd_timers())
    findings.extend(check_seccomp_status())
    findings.extend(check_service_file_permissions())
    findings.extend(check_sysv_init_scripts())
    findings.extend(check_rkhunter_installation())

    return findings
