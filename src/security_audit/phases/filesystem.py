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
        count = len(stdout.strip().split("\n"))
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="FS-003",
                title=f"World-Writable Files Found ({count} files)",
                description=f"Files with world-writable permissions: {count} files found",
                evidence=stdout[:1000],
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
        count = len(stdout.strip().split("\n"))
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="FS-005",
                title=f"Unowned Files Found ({count} files)",
                description=f"Files without valid owner/group: {count} files found",
                evidence=stdout[:1000],
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
                expected_perm = f"-{perms}"
                if actual_perms == expected_perm:
                    continue
                if filepath == "/etc/sudoers" and actual_perms in [
                    "-r--r-----",
                    "-rw-r-----",
                ]:
                    continue
                if filepath in ["/etc/shadow", "/etc/gshadow"] and actual_perms in [
                    "-rw-------"
                ]:
                    continue
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


def check_ssh_private_key_permissions() -> list[Finding]:
    """Check SSH private key file permissions."""
    findings = []

    stdout, _, _ = run_command(
        "find /home /root /etc/ssh -name 'ssh_host_*_key' -type f 2>/dev/null"
    )
    if stdout:
        for path in stdout.strip().split("\n"):
            perms, _, rc = run_command(f"stat -c '%a' {path} 2>/dev/null")
            if rc == 0 and perms.strip() != "600":
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="FS-009",
                        title=f"Weak SSH Private Key Permissions: {path}",
                        description=f"Current permissions: {perms.strip()}, expected: 600",
                        evidence=f"Permissions: {perms}",
                        impact="Private key may be readable by other users",
                        remediation=f"Set permissions: chmod 600 {path}",
                        phase="Phase 3",
                    )
                )

    return findings


def check_tmp_sensitive_files() -> list[Finding]:
    """Check for sensitive files in /tmp."""
    findings = []

    stdout, _, rc = run_command(
        "find /tmp -xdev -type f \\( -name '*.conf' -o -name '*.cnf' -o -name '*.key' -o -name '*.pem' -o -name '*.passwd' -o -name '*.shadow' \\) -perm -004 2>/dev/null | head -20"
    )
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="FS-010",
                title="Sensitive Files in /tmp",
                description="Sensitive files with world-readable permissions in /tmp",
                evidence=stdout,
                impact="Sensitive data may be accessible to other users",
                remediation="Move sensitive files to secure locations",
                phase="Phase 3",
            )
        )

    return findings


def check_backup_files() -> list[Finding]:
    """Check for backup files in /etc."""
    findings = []

    stdout, _, rc = run_command(
        "find /etc -xdev -type f \\( -name '*.bak' -o -name '*.old' -o -name '*.swp' -o -name '*~' \\) 2>/dev/null | head -20"
    )
    if rc == 0 and stdout and stdout.strip():
        count = len(stdout.strip().split("\n"))
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="FS-011",
                title=f"Backup Files Found in /etc ({count} files)",
                description=f"Backup files found in /etc directory: {count} files",
                evidence=stdout[:1000],
                impact="Backup files may contain sensitive information",
                remediation="Remove backup files from /etc",
                phase="Phase 3",
            )
        )

    return findings


def check_sudoers_integrity() -> list[Finding]:
    """Check sudoers file integrity."""
    findings = []

    stdout, _, rc = run_command("stat -c '%y %n' /etc/sudoers 2>/dev/null")
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="FS-012",
                title="/etc/sudoers Last Modified",
                description="Last modification time of /etc/sudoers",
                evidence=stdout,
                impact="Monitor for unauthorized sudoers changes",
                remediation="Review sudoers file changes",
                phase="Phase 3",
            )
        )

    stdout, _, rc = run_command("stat -c '%y %n' /etc/sudoers.d 2>/dev/null")
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="FS-013",
                title="/etc/sudoers.d Last Modified",
                description="Last modification time of /etc/sudoers.d",
                evidence=stdout,
                impact="Monitor for unauthorized sudoers.d changes",
                remediation="Review sudoers.d file changes",
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
    findings.extend(check_ssh_private_key_permissions())
    findings.extend(check_tmp_sensitive_files())
    findings.extend(check_backup_files())
    findings.extend(check_sudoers_integrity())

    return findings
