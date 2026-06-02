"""Phase 3 - File System & Permissions module."""

from ..core import Finding, Severity, cached_check, run_command

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

# Capabilities that grant full or near-full privilege escalation
# when set on any executable (effective+inheritable).
# See capabilities(7) for the full reference.
ESCALATION_CAPS = {
    "cap_setuid",  # spawn shell with arbitrary UID 0
    "cap_setgid",  # spawn shell with arbitrary GID 0
    "cap_sys_admin",  # mount, namespace, bpf — kernel-level access
    "cap_sys_ptrace",  # ptrace any process, read memory
    "cap_dac_override",  # bypass file permission checks
    "cap_dac_read_search",  # read any file
    "cap_fowner",  # change file ownership arbitrarily
    "cap_fsetid",  # set arbitrary GID on created files
    "cap_setpcap",  # grant capabilities to other processes
    "cap_net_admin",  # configure network (firewall, raw sockets)
    "cap_sys_module",  # load kernel modules
    "cap_sys_rawio",  # raw I/O, memory access
}

# Capabilities worth noting but lower severity
NOTEWORTHY_CAPS = {
    "cap_net_raw",  # raw sockets (ping, sniff)
    "cap_net_bind_service",  # bind to privileged ports <1024
    "cap_sys_boot",  # reboot
    "cap_sys_time",  # system clock manipulation
    "cap_kill",  # signal any process
    "cap_linux_immutable",  # set FS_APPEND_FL / FS_IMMUTABLE_FL
    "cap_ipc_lock",  # lock memory (side-channel, swap bypass)
    "cap_sys_nice",  # raise priority, set real-time scheduling
    "cap_audit_control",  # manipulate audit subsystem
}


@cached_check("check_suid_binaries")
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


@cached_check("check_capabilities")
def check_capabilities() -> list[Finding]:
    """Check for files with Linux capabilities(7).

    Capabilities are the modern, granular replacement for SUID.
    A binary with cap_setuid+ep is functionally equivalent to a
    SUID-root binary and must be audited with the same rigor.
    """
    findings: list[Finding] = []

    stdout, _, rc = run_command("getcap -r / 2>/dev/null | sort")
    if rc != 0 or not stdout:
        return findings

    for line in stdout.strip().split("\n"):
        line = line.strip()
        if not line or " = " not in line:
            continue

        parts = line.split(" = ", 1)
        path = parts[0]
        cap_part = parts[1]

        caps_found = set()
        for token in cap_part.replace(",", " ").split():
            cap_name = token.split("+")[0]
            caps_found.add(cap_name)

        escalation = caps_found & ESCALATION_CAPS
        noteworthy = caps_found & NOTEWORTHY_CAPS

        if escalation:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="FS-016",
                    title="Binary with Privilege-Escalation Capabilities",
                    description=f"{path} has escalation-capable capabilities: {', '.join(sorted(escalation))}",
                    evidence=line,
                    impact="Can be used for privilege escalation (equivalent to SUID root)",
                    remediation=f"Remove capabilities: setcap -r {path}",
                    phase="Phase 3",
                )
            )
        elif noteworthy:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="FS-016",
                    title="Binary with Notable Capabilities",
                    description=f"{path} has capabilities: {', '.join(sorted(noteworthy))}",
                    evidence=line,
                    impact="Expanded attack surface beyond traditional unprivileged execution",
                    remediation=f"Review and remove unnecessary capabilities: setcap -r {path}",
                    phase="Phase 3",
                )
            )

    return findings


@cached_check("check_sgid_binaries")
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


@cached_check("check_world_writable_files")
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


@cached_check("check_world_writable_dirs")
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


@cached_check("check_unowned_files")
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


@cached_check("check_critical_file_permissions")
def check_critical_file_permissions() -> list[Finding]:
    """Check permissions on critical system files."""
    findings = []

    critical_files = {
        "/etc/shadow": ("root", "shadow", "0600"),
        "/etc/gshadow": ("root", "root", "0600"),
        "/etc/sudoers": ("root", "root", "0440"),
        "/etc/passwd": ("root", "root", "0644"),
        "/etc/group": ("root", "root", "0644"),
    }

    for filepath, (_, _, perms) in critical_files.items():
        stdout, _, rc = run_command(["ls", "-la", filepath])
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
                if filepath in ["/etc/passwd", "/etc/group"] and actual_perms in [
                    "-rw-r--r--",
                    "-rw-rw-r--",
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


@cached_check("check_cron_jobs")
def _check_cron_file_perms(path: str, findings: list[Finding]) -> None:
    """Check ownership and permissions of cron files inside a directory."""
    files_out, _, frc = run_command(f"find {path} -type f 2>/dev/null")
    if frc != 0 or not files_out:
        return
    for fpath in files_out.strip().split("\n"):
        if not fpath:
            continue
        fstat, _, src = run_command(["stat", "-c", "%U %a", fpath])
        if src != 0 or not fstat:
            continue
        owner, perms = fstat.split()
        if owner != "root":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="FS-007",
                    title="Cron Script Not Owned by Root",
                    description=f"{fpath} owned by {owner}, expected root",
                    evidence=f"stat: {fstat}",
                    impact="Non-root user can modify cron script, leading to privilege escalation on execution",
                    remediation=f"chown root:root {fpath}",
                    phase="Phase 3",
                )
            )
        if len(perms) >= 3 and perms[-1] in ("2", "3", "6", "7"):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    check_id="FS-007",
                    title="World-Writable Cron Script",
                    description=f"{fpath} has permissions {perms}",
                    evidence=f"stat: {fstat}",
                    impact="Any user can modify this cron script to execute arbitrary code as the cron owner",
                    remediation=f"chmod o-w {fpath}",
                    phase="Phase 3",
                )
            )


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
        stdout, _, rc = run_command(["ls", "-la", path])
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

        if path.endswith("/"):
            _check_cron_file_perms(path, findings)

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


@cached_check("check_ssh_private_key_permissions")
def check_ssh_private_key_permissions() -> list[Finding]:
    """Check SSH private key file permissions."""
    findings = []

    stdout, _, _ = run_command(
        "find /home /root /etc/ssh -name 'ssh_host_*_key' -type f 2>/dev/null"
    )
    if stdout:
        for path in stdout.strip().split("\n"):
            perms, _, rc = run_command(["stat", "-c", "%a", path])
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


@cached_check("check_tmp_sensitive_files")
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


@cached_check("check_backup_files")
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


@cached_check("check_ld_preload")
def check_ld_preload() -> list[Finding]:
    """Check for writable ld.so preload configuration.

    A writable /etc/ld.so.preload lets an attacker inject a shared library
    into every setuid and non-setuid process on the system — a classic
    privilege-persistence vector.
    """
    findings: list[Finding] = []

    preload_files = [
        "/etc/ld.so.preload",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d/",
    ]

    for path in preload_files:
        stdout, _, rc = run_command(["ls", "-la", path])
        if rc != 0 or not stdout:
            continue
        parts = stdout.split()
        if len(parts) < 4:
            continue
        perms = parts[0]
        owner = parts[2]
        if owner != "root":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="FS-017",
                    title=f"{path} Not Owned by Root",
                    description=f"Owner is {owner}, expected root",
                    evidence=stdout,
                    impact="Non-root owner can modify dynamic linker configuration, enabling global code injection",
                    remediation=f"chown root:root {path}",
                    phase="Phase 3",
                )
            )
        # world-writable or group-writable is dangerous
        if "w" in perms[4:6] or "w" in perms[7:9]:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="FS-017",
                    title=f"Writable Dynamic Linker Config: {path}",
                    description=f"Permissions: {perms}",
                    evidence=stdout,
                    impact="Any user can modify dynamic linker configuration, enabling global code injection across all processes",
                    remediation=f"chmod go-w {path}",
                    phase="Phase 3",
                )
            )
        # Existence of /etc/ld.so.preload alone is suspicious unless intentional
        if path == "/etc/ld.so.preload" and rc == 0:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="FS-017",
                    title="/etc/ld.so.preload Exists",
                    description="Preload file exists — verify it is intentional",
                    evidence=stdout,
                    impact="Libraries listed here are loaded into every process; malicious additions affect the entire system",
                    remediation="Review contents and remove if unused: echo > /etc/ld.so.preload",
                    phase="Phase 3",
                )
            )

    return findings


SECRET_PATTERNS: dict[str, str] = {
    "AKIA[0-9A-Z]{16}": "AWS Access Key ID",
    "-----BEGIN RSA PRIVATE KEY-----": "RSA Private Key",
    "-----BEGIN EC PRIVATE KEY-----": "EC Private Key",
    "-----BEGIN OPENSSH PRIVATE KEY-----": "OpenSSH Private Key",
    "-----BEGIN DSA PRIVATE KEY-----": "DSA Private Key",
    "ghp_[0-9a-zA-Z]{36}": "GitHub Personal Access Token",
    "gho_[0-9a-zA-Z]{36}": "GitHub OAuth Token",
    "xox[bpsa]-[0-9a-zA-Z-]+": "Slack Token",
    "sk_live_[0-9a-z]+": "Stripe Live Secret Key",
    "pk_live_[0-9a-z]+": "Stripe Live Publishable Key",
}

SECRET_SCAN_PATHS = [
    "/root/.bash_history",
    "/root/.zsh_history",
    "/home/*/.bash_history",
    "/home/*/.zsh_history",
    "/root/.netrc",
    "/home/*/.netrc",
    "/root/.env",
    "/home/*/.env",
    "/etc/environment",
    "/etc/profile.d/*.sh",
]


@cached_check("check_exposed_secrets")
def check_exposed_secrets() -> list[Finding]:
    """Scan for exposed secrets and credentials in readable files.

    Checks shell histories, .env files, and configuration files for
    high-value credential patterns (AWS keys, API tokens, private keys).
    """
    findings: list[Finding] = []

    for pattern_path in SECRET_SCAN_PATHS:
        stdout, _, rc = run_command(f"ls -la {pattern_path} 2>/dev/null | head -5")
        if rc != 0 or not stdout:
            continue

        for line in stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) < 9:
                continue
            fpath = parts[-1]
            fperms = parts[0]
            # Only scan files readable by others or by group
            if "r" not in fperms[4:5] and "r" not in fperms[7:8]:
                continue

            content, _, crc = run_command(["cat", fpath])
            if crc != 0 or not content:
                continue

            for pattern, label in SECRET_PATTERNS.items():
                import re

                matches = re.findall(pattern, content, re.MULTILINE)
                if matches:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            check_id="FS-018",
                            title=f"Exposed Credential: {label}",
                            description=f"Found {len(matches)} match(es) of {label} in {fpath}",
                            evidence=f"File: {fpath}\nPermissions: {fperms}\nPattern: {label}",
                            impact="Exposed credentials can be used to access cloud services, source control, or payment systems",
                            remediation=f"Remove the credential from {fpath}. Rotate the compromised key immediately.",
                            phase="Phase 3",
                        )
                    )
                    break

    return findings


@cached_check("check_sudoers_integrity")
def check_sudoers_integrity() -> list[Finding]:
    """Check sudoers file integrity."""
    findings = []

    stdout, _, rc = run_command(["stat", "-c", "%y %n", "/etc/sudoers"])
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

    stdout, _, rc = run_command(["stat", "-c", "%y %n", "/etc/sudoers.d"])
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


@cached_check("check_at_jobs")
def check_at_jobs() -> list[Finding]:
    """Check for at jobs and at.allow restrictions."""
    findings: list[Finding] = []

    at_allow_exists = run_command("ls -la /etc/at.allow 2>/dev/null")[2] == 0
    at_deny_exists = run_command("ls -la /etc/at.deny 2>/dev/null")[2] == 0

    if not at_allow_exists and at_deny_exists:
        stdout, _, rc = run_command("stat -c '%a' /etc/at.deny 2>/dev/null")
        if rc == 0 and stdout.strip() not in ("", "660", "640", "600"):
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="FS-015",
                    title="Insecure /etc/at.deny Permissions",
                    description=f"/etc/at.deny has permissions {stdout.strip()}",
                    evidence=f"/etc/at.deny permissions: {stdout.strip()}",
                    impact="Users may be able to run at jobs they shouldn't",
                    remediation="Remove /etc/at.deny or restrict permissions to 640",
                    phase="Phase 3",
                )
            )
    return findings


@cached_check("check_mount_options")
def check_mount_options() -> list[Finding]:
    """Check security mount options for sensitive filesystems."""
    findings: list[Finding] = []

    stdout, _, rc = run_command("mount 2>/dev/null")
    if rc != 0 or not stdout:
        return findings

    # Map of mountpoint -> required security options
    required: dict[str, list[str]] = {
        "/tmp": ["noexec", "nosuid", "nodev"],
        "/var/tmp": ["noexec", "nosuid", "nodev"],
        "/dev/shm": ["noexec", "nosuid", "nodev"],
        "/home": ["nodev"],
    }

    for mountpoint, opts in required.items():
        for line in stdout.strip().split("\n"):
            parts = line.split()
            # mount output: <device> on <mountpoint> type <fs> (<options>)
            if len(parts) >= 3 and parts[1] == "on" and parts[2] == mountpoint:
                missing = [opt for opt in opts if opt not in line]
                if missing:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            check_id="FS-014",
                            title=f"Insecure Mount Options: {mountpoint}",
                            description=(
                                f"{mountpoint} is missing security mount options: "
                                + ", ".join(missing)
                            ),
                            evidence=line,
                            impact="Missing mount restrictions may allow privilege escalation or code execution",
                            remediation=(
                                f"Add {', '.join(missing)} to the {mountpoint} entry in /etc/fstab"
                            ),
                            phase="Phase 3",
                        )
                    )
                break

    return findings


@cached_check("check_nfs_exports")
def check_nfs_exports() -> list[Finding]:
    """Check NFS export (/etc/exports) for dangerous options.

    Insecure NFS exports allow privilege escalation and data access:
      - no_root_squash  → remote root can write as local root
      - insecure        → clients can connect from unprivileged ports
      - world-readable  → no subnet restriction
    """
    findings: list[Finding] = []

    stdout, _, rc = run_command(["cat", "/etc/exports"])
    if rc != 0 or not stdout:
        return findings

    for line in stdout.strip().split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "no_root_squash" in stripped:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    check_id="FS-019",
                    title="NFS Export With no_root_squash",
                    description=f"Dangerous export: {stripped}",
                    evidence=stripped,
                    impact="Remote root can write to the exported filesystem as local root, enabling privilege escalation across the network",
                    remediation='Remove "no_root_squash" from the export; use "root_squash" instead',
                    phase="Phase 3",
                )
            )
        if "insecure" in stripped:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="FS-019",
                    title="NFS Export With 'insecure' Option",
                    description=f"Export allows connections from unprivileged ports: {stripped}",
                    evidence=stripped,
                    impact="Non-root users on clients can mount NFS shares, widening the attack surface",
                    remediation='Replace "insecure" with "secure" in the export options',
                    phase="Phase 3",
                )
            )
        # No host restriction (world-accessible)
        parts = stripped.split()
        if len(parts) >= 2:
            clients = parts[1].split("(")[0]  # strip options like *(rw) → *
            if clients in ("*", "0.0.0.0/0", "::/0"):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="FS-019",
                        title="NFS Export World-Accessible",
                        description=f"Export is accessible to any client: {stripped}",
                        evidence=stripped,
                        impact="Anyone on the network can mount this NFS share",
                        remediation="Restrict the export to specific IP ranges or hostnames",
                        phase="Phase 3",
                    )
                )

    return findings


@cached_check("check_smb_config")
def check_smb_config() -> list[Finding]:
    """Check Samba configuration for security issues."""
    findings: list[Finding] = []

    stdout, _, rc = run_command(
        "grep -E '^\\s*security\\s*=' /etc/samba/smb.conf 2>/dev/null"
    )
    if rc == 0 and stdout and "security = user" not in stdout:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="FS-020",
                title="Samba Security Mode Not 'user'",
                description=f"Samba security mode is not 'user': {stdout.strip()}",
                evidence=stdout.strip(),
                impact="Weak Samba security modes can allow anonymous or share-level access",
                remediation="Set 'security = user' in /etc/samba/smb.conf and use local authentication",
                phase="Phase 3",
            )
        )

    stdout, _, rc = run_command(
        "grep -E '^\\s*guest\\s+ok\\s*=\\s*yes' /etc/samba/smb.conf 2>/dev/null"
    )
    if rc == 0 and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="FS-020",
                title="Samba Guest Access Enabled",
                description="Found shares with guest access enabled",
                evidence=stdout.strip()[:500],
                impact="Unauthenticated users can access Samba shares",
                remediation="Set 'guest ok = no' on all Samba shares",
                phase="Phase 3",
            )
        )

    return findings


def run_filesystem_checks() -> list[Finding]:
    """Run all file system and permissions checks."""
    findings = []

    findings.extend(check_suid_binaries())
    findings.extend(check_capabilities())
    findings.extend(check_sgid_binaries())
    findings.extend(check_world_writable_files())
    findings.extend(check_world_writable_dirs())
    findings.extend(check_unowned_files())
    findings.extend(check_critical_file_permissions())
    findings.extend(check_cron_jobs())
    findings.extend(check_ssh_private_key_permissions())
    findings.extend(check_tmp_sensitive_files())
    findings.extend(check_backup_files())
    findings.extend(check_ld_preload())
    findings.extend(check_exposed_secrets())
    findings.extend(check_sudoers_integrity())
    findings.extend(check_mount_options())
    findings.extend(check_nfs_exports())
    findings.extend(check_smb_config())

    return findings
