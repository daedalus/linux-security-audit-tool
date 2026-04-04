"""Phase 6 - Logging & Monitoring module."""

from ..core import Finding, Severity, run_command


def check_auditd_status() -> list[Finding]:
    """Check if auditd is installed and running."""
    findings = []

    stdout, _, rc = run_command("systemctl is-active auditd 2>/dev/null")
    if rc != 0 or stdout.strip() != "active":
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="LOG-001",
                title="auditd Not Running",
                description="Audit daemon is not running",
                evidence=f"systemctl status auditd: {stdout}",
                impact="No audit trail for security events",
                remediation="Install and enable auditd",
                phase="Phase 6",
            )
        )

    return findings


def check_audit_rules() -> list[Finding]:
    """Check configured audit rules."""
    findings = []

    stdout, _, rc = run_command("auditctl -l 2>/dev/null")
    if rc == 0 and stdout and stdout.strip():
        pass
    else:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="LOG-002",
                title="No Audit Rules Configured",
                description="No audit rules found",
                evidence="auditctl -l returned no rules",
                impact="Limited security event monitoring",
                remediation="Configure audit rules for critical files",
                phase="Phase 6",
            )
        )

    return findings


def check_auth_log_permissions() -> list[Finding]:
    """Check auth log permissions."""
    findings = []

    log_paths = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]
    for log_path in log_paths:
        stdout, _, rc = run_command(f"ls -la {log_path} 2>/dev/null")
        if rc == 0 and stdout:
            parts = stdout.split()
            if len(parts) >= 1:
                perms = parts[0]
                if "w" in perms[1:]:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            check_id="LOG-003",
                            title=f"Log File World-Writable: {log_path}",
                            description="Log file has world-writable permissions",
                            evidence=stdout,
                            impact="Log files can be modified by any user",
                            remediation=f"Fix permissions: chmod 640 {log_path}",
                            phase="Phase 6",
                        )
                    )
            break

    return findings


def check_failed_logins() -> list[Finding]:
    """Check for failed login attempts."""
    findings = []

    log_paths = ["/var/log/auth.log", "/var/log/secure"]
    for log_path in log_paths:
        stdout, _, rc = run_command(
            f"grep -i 'failed\\|invalid\\|refused\\|authentication failure' {log_path} 2>/dev/null | tail -20"
        )
        if rc == 0 and stdout and stdout.strip():
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    check_id="LOG-004",
                    title="Failed Login Attempts Found",
                    description="There are failed login attempts in logs",
                    evidence=f"{len(stdout.split(chr(10)))} recent failed attempts",
                    impact="May indicate brute force attempts",
                    remediation="Review and consider rate limiting",
                    phase="Phase 6",
                )
            )
            break

    return findings


def check_logrotate_config() -> list[Finding]:
    """Check logrotate configuration."""
    findings = []

    stdout, _, rc = run_command(
        "ls -la /etc/logrotate.conf /etc/logrotate.d/ 2>/dev/null"
    )
    if rc == 0 and stdout:
        pass
    else:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="LOG-005",
                title="Logrotate Not Configured",
                description="No logrotate configuration found",
                evidence="Unable to read logrotate config",
                impact="Logs may grow unbounded",
                remediation="Configure logrotate",
                phase="Phase 6",
            )
        )

    return findings


def check_syslog_config() -> list[Finding]:
    """Check syslog configuration."""
    findings = []

    stdout, _, rc = run_command("cat /etc/rsyslog.conf 2>/dev/null | head -20")
    if rc != 0:
        stdout, _, rc = run_command(
            "cat /etc/syslog-ng/syslog-ng.conf 2>/dev/null | head -20"
        )

    if rc != 0:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="LOG-006",
                title="No Syslog Configuration Found",
                description="Unable to find syslog configuration",
                evidence="No rsyslog or syslog-ng config",
                impact="Limited log management",
                remediation="Configure syslog",
                phase="Phase 6",
            )
        )

    return findings


def check_journald_persistence() -> list[Finding]:
    """Check systemd journal persistence."""
    findings = []

    stdout, _, rc = run_command("journalctl --disk-usage 2>/dev/null")
    if rc == 0 and stdout:
        if "0 B" in stdout:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="LOG-007",
                    title="Journal Not Persistent",
                    description="Systemd journal is not configured for persistence",
                    evidence=stdout,
                    impact="Journal logs lost after reboot",
                    remediation="Configure Storage=persistent in /etc/systemd/journald.conf",
                    phase="Phase 6",
                )
            )

    return findings


def run_logging_checks() -> list[Finding]:
    """Run all logging and monitoring checks."""
    findings = []

    findings.extend(check_auditd_status())
    findings.extend(check_audit_rules())
    findings.extend(check_auth_log_permissions())
    findings.extend(check_failed_logins())
    findings.extend(check_logrotate_config())
    findings.extend(check_syslog_config())
    findings.extend(check_journald_persistence())

    return findings
