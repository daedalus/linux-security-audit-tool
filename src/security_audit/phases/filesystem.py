"""Phase 3 - File System & Permissions module."""

from ..core import Finding, Severity, run_command

EXPECTED_SUID = [
    "/usr/bin/passwd",
    "/usr/bin/su",
    "/usr/bin/sudo",
    "/usr/bin/newgrp",
    "/usr/bin/gpasswd",
    "/usr/bin/chfn",
    "/usr/bin/chsh",
    "/usr/bin/mount",
    "/usr/bin/umount",
    "/usr/bin/ping",
    "/usr/bin/pings",
]

DANGEROUS_SUID = [
    "/usr/bin/python",
    "/usr/bin/python3",
    "/usr/bin/perl",
    "/usr/bin/ruby",
    "/usr/bin/vim",
    "/usr/bin/nano",
    "/usr/bin/nc",
    "/usr/bin/netcat",
    "/usr/bin/nmap",
    "/usr/bin/bash",
    "/usr/bin/sh",
    "/bin/bash",
    "/bin/sh",
]


def check_suid_binaries() -> list[Finding]:
    """Check for SUID binaries on the system."""
    findings = []

    stdout, _, rc = run_command("find / -perm -4000 -type f 2>/dev/null | sort")
    if rc == 0 and stdout:
        for path in stdout.strip().split("\n"):
            if path in DANGEROUS_SUID:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="FS-001",
                        title="Dangerous SUID Binary",
                        description=f"Found dangerous SUID binary: {path}",
                        evidence=f"ls -la {path}",
                        impact="Can be used for privilege escalation",
                        remediation=f"Remove SUID bit: chmod u-s {path}",
                        phase="Phase 3",
                    )
                )

    return findings


def check_sgid_binaries() -> list[Finding]:
    """Check for SGID binaries on the system."""
    findings = []

    stdout, _, rc = run_command("find / -perm -2000 -type f 2>/dev/null | sort")
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="FS-002",
                title="SGID Binaries Found",
                description="Found SGID binaries on system",
                evidence=stdout,
                impact="May allow group privilege escalation",
                remediation="Review and remove unnecessary SGID bits",
                phase="Phase 3",
            )
        )

    return findings


def check_world_writable_files() -> list[Finding]:
    """Check for world-writable files."""
    findings = []

    stdout, _, rc = run_command(
        "find / -xdev -type f -perm -0002 -not -path '/proc/*' -not -path '/sys/*' 2>/dev/null | head -20"
    )
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="FS-003",
                title="World-Writable Files Found",
                description="Files with world-writable permissions",
                evidence=stdout,
                impact="Any user can modify these files",
                remediation="Remove world-writable: chmod o-w <file>",
                phase="Phase 3",
            )
        )

    return findings


def check_world_writable_dirs() -> list[Finding]:
    """Check for world-writable directories."""
    findings = []

    stdout, _, rc = run_command(
        "find / -xdev -type d -perm -0002 -not -sticky -not -path '/proc/*' 2>/dev/null | head -20"
    )
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="FS-004",
                title="World-Writable Directories (without sticky bit)",
                description="Directories without sticky bit are world-writable",
                evidence=stdout,
                impact="Users can delete files from shared directories",
                remediation="Add sticky bit: chmod +t <dir>",
                phase="Phase 3",
            )
        )

    return findings


def check_unowned_files() -> list[Finding]:
    """Check for unowned files."""
    findings = []

    stdout, _, rc = run_command(
        "find / -xdev \\( -nouser -o -nogroup \\) 2>/dev/null | head -20"
    )
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="FS-005",
                title="Unowned Files Found",
                description="Files without valid owner/group",
                evidence=stdout,
                impact="Files may be owned by deleted users or be compromised",
                remediation="Set ownership: chown <user>:<group> <file>",
                phase="Phase 3",
            )
        )

    return findings


def check_critical_file_permissions() -> list[Finding]:
    """Check permissions on critical system files."""
    findings = []

    critical_files = {
        "/etc/shadow": ("root", "shadow", "0600"),
        "/etc/gshadow": ("root", "root", "0600"),
        "/etc/sudoers": ("root", "root", "0440"),
    }

    for filepath, (owner, group, perms) in critical_files.items():
        stdout, _, rc = run_command(f"ls -la {filepath} 2>/dev/null")
        if rc == 0 and stdout:
            parts = stdout.split()
            if len(parts) >= 4:
                actual_perms = parts[0]

                if actual_perms != f"-{perms}" and actual_perms != "-rw------":
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            check_id="FS-006",
                            title=f"Weak {filepath} Permissions",
                            description=f"Current permissions: {actual_perms}",
                            evidence=stdout,
                            impact="Sensitive data may be readable by non-root users",
                            remediation=f"Set permissions: chmod {perms} {filepath}",
                            phase="Phase 3",
                        )
                    )

    return findings


def check_cron_jobs() -> list[Finding]:
    """Check for suspicious cron jobs."""
    findings = []

    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d/",
        "/etc/cron.daily/",
        "/etc/cron.weekly/",
        "/etc/cron.monthly/",
        "/var/spool/cron/",
    ]

    for path in cron_paths:
        stdout, _, rc = run_command(f"ls -la {path} 2>/dev/null")
        if rc == 0 and stdout:
            if "curl" in stdout.lower() or "wget" in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="FS-007",
                        title="Suspicious Cron Script",
                        description=f"Found curl/wget in {path}",
                        evidence=stdout,
                        impact="Cron may download and execute untrusted code",
                        remediation="Review and remove suspicious cron scripts",
                        phase="Phase 3",
                    )
                )

    stdout, _, rc = run_command("crontab -l 2>/dev/null")
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="FS-008",
                title="Root Cron Jobs Found",
                description="Root has cron jobs configured",
                evidence=stdout,
                impact="Cron can execute commands as root",
                remediation="Review root cron jobs for legitimacy",
                phase="Phase 3",
            )
        )

    return findings


def run_filesystem_checks() -> list[Finding]:
    """Run all file system and permissions checks."""
    findings = []

    findings.extend(check_suid_binaries())
    findings.extend(check_sgid_binaries())
    findings.extend(check_world_writable_files())
    findings.extend(check_world_writable_dirs())
    findings.extend(check_unowned_files())
    findings.extend(check_critical_file_permissions())
    findings.extend(check_cron_jobs())

    return findings
