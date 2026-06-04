"""Phase 1 - Identity & Access Control module."""

import os

from ..config import config
from ..core import Finding, Severity, cached_check, check_root, run_command


@cached_check("check_uid_zero_accounts")
def check_uid_zero_accounts() -> list[Finding]:
    """Check for duplicate UID 0 accounts (skips the canonical root entry)."""
    findings = []

    stdout, _, rc = run_command("awk -F: '$3 == 0 {print}' /etc/passwd")
    if rc == 0 and stdout:
        extra = [
            e for e in stdout.strip().split("\n") if e and not e.startswith("root:")
        ]
        if extra:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    check_id="IDENT-001",
                    title=f"Duplicate UID 0 Accounts Found ({len(extra)})",
                    description="Additional UID-0 accounts beyond root: "
                    + ", ".join(e.split(":")[0] for e in extra),
                    evidence="awk -F: '$3 == 0 {print}' /etc/passwd\n"
                    + "\n".join(extra),
                    impact="Each additional UID-0 account has full root privileges",
                    remediation="Remove unauthorized UID 0 accounts with: userdel <username>",
                    phase="Phase 1",
                )
            )

    return findings


@cached_check("check_system_accounts_with_shells")
def check_system_accounts_with_shells() -> list[Finding]:
    """Check for system accounts with interactive shells."""
    findings = []

    stdout, _, rc = run_command(
        "awk -F: '$3 < 1000 && $7 !~ /nologin|false|\\/(sync|shutdown|halt|reboot)( |$)/ {print}' /etc/passwd"
    )
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="IDENT-002",
                title="System Accounts with Interactive Shells",
                description="System accounts should have nologin/false shells",
                evidence=f"awk -F: '$3 < 1000 && $7 !~ /nologin|false/ {print}' /etc/passwd\n{stdout}",
                impact="System accounts could be used for interactive access",
                remediation="Set shell to /usr/sbin/nologin or /bin/false",
                phase="Phase 1",
            )
        )

    return findings


@cached_check("check_passwordless_accounts")
def check_passwordless_accounts() -> list[Finding]:
    """Check for accounts with empty passwords."""
    if not check_root():
        return []

    findings = []

    stdout, _, rc = run_command(
        'awk -F: \'$2 == "" {print "NO PASSWORD:", $1}\' /etc/shadow'
    )
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                check_id="IDENT-003",
                title="Account with Empty Password",
                description="Accounts with empty passwords allow passwordless authentication",
                evidence=stdout,
                impact="Anyone can log in without providing a password",
                remediation="Set a password or lock the account",
                phase="Phase 1",
            )
        )

    return findings


@cached_check("check_sudo_nopasswd")
def check_sudo_nopasswd() -> list[Finding]:
    """Check for sudo NOPASSWD configurations."""
    findings = []

    sudoers_files = ["/etc/sudoers"] + [
        f"/etc/sudoers.d/{f}"
        for f in run_command("ls /etc/sudoers.d/ 2>/dev/null")[0].split("\n")
        if f
    ]

    all_nopasswd = []
    for f in sudoers_files:
        stdout, _, rc = run_command(f"grep -r NOPASSWD {f} 2>/dev/null")
        if rc == 0 and stdout:
            all_nopasswd.append(stdout)

    if all_nopasswd:
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                check_id="IDENT-004",
                title="NOPASSWD Sudo Configuration",
                description="Users can execute sudo without password authentication",
                evidence="\n".join(all_nopasswd),
                impact="Privilege escalation without authentication",
                remediation="Remove NOPASSWD or restrict to specific commands",
                phase="Phase 1",
            )
        )

    return findings


@cached_check("check_sudo_wildcard_abuse")
def check_sudo_wildcard_abuse() -> list[Finding]:
    """Check for dangerous sudo wildcard patterns."""
    findings = []

    dangerous_patterns = [
        "ALL=(ALL) /usr/bin/vi",
        "ALL=(ALL) /usr/bin/vim",
        "ALL=(ALL) /usr/bin/nano",
        "ALL=(ALL) /usr/bin/find",
        "ALL=(ALL) /usr/bin/python",
        "ALL=(ALL) /usr/bin/perl",
        "ALL=(ALL) /bin/cp",
        "ALL=(ALL) /bin/tar",
    ]

    stdout, _, rc = run_command("cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null")
    if rc == 0 and stdout:
        for pattern in dangerous_patterns:
            if pattern in stdout:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="IDENT-005",
                        title="Dangerous Sudo Wildcard Pattern",
                        description=f"Found dangerous sudo rule: {pattern}",
                        evidence=pattern,
                        impact="User can escape to shell or modify critical files",
                        remediation="Remove or restrict the sudo rule",
                        phase="Phase 1",
                    )
                )

    return findings


@cached_check("check_privileged_groups")
def check_privileged_groups() -> list[Finding]:
    """Check for users in privileged groups."""
    findings = []

    groups = ["sudo", "wheel", "adm", "docker", "lxd"]

    for group in groups:
        stdout, _, rc = run_command(f"getent group {group}")
        if rc == 0 and stdout:
            members = stdout.split(":")[-1]
            if members:
                severity = (
                    Severity.HIGH if group in ["docker", "lxd"] else Severity.MEDIUM
                )
                findings.append(
                    Finding(
                        severity=severity,
                        check_id="IDENT-006",
                        title=f"Users in {group} Group",
                        description=f"Members: {members}",
                        evidence=stdout,
                        impact=f"{group} group membership provides elevated privileges",
                        remediation=f"Review {group} group membership necessity",
                        phase="Phase 1",
                    )
                )

    return findings


@cached_check("check_ssh_root_login")
def check_ssh_root_login() -> list[Finding]:
    """Check if root can login via SSH."""
    findings = []

    stdout, _, rc = run_command("sshd -T 2>/dev/null | grep -i permitrootlogin")
    if rc == 0:
        if "yes" in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="IDENT-007",
                    title="Root Login Permitted via SSH",
                    description="Root login is allowed via SSH",
                    evidence=stdout,
                    impact="Attacker can attempt brute force on root account",
                    remediation="Set PermitRootLogin to 'no' or 'prohibit-password'",
                    phase="Phase 1",
                )
            )

    return findings


@cached_check("check_ssh_password_auth")
def check_ssh_password_auth() -> list[Finding]:
    """Check if password authentication is enabled."""
    findings = []

    stdout, _, rc = run_command("sshd -T 2>/dev/null | grep -i passwordauthentication")
    if rc == 0:
        if "yes" in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="IDENT-008",
                    title="Password Authentication Enabled",
                    description="Password authentication is enabled for SSH",
                    evidence=stdout,
                    impact="Vulnerable to brute force attacks",
                    remediation="Set PasswordAuthentication to 'no' for key-only auth",
                    phase="Phase 1",
                )
            )

    return findings


@cached_check("check_unauthorized_ssh_keys")
def check_unauthorized_ssh_keys() -> list[Finding]:
    """Check for unauthorized SSH authorized_keys."""
    findings = []

    stdout, _, _ = run_command("find /home /root -name authorized_keys 2>/dev/null")
    if stdout:
        for path in stdout.strip().split("\n"):
            key_content, _, _ = run_command(["cat", path])
            if key_content:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="IDENT-009",
                        title="SSH Authorized Keys Found",
                        description=f"Found authorized_keys at {path}",
                        evidence=f"Contains {len(key_content.split(chr(10)))} key(s)",
                        impact="User can access system without password",
                        remediation="Review and verify authorized keys are expected",
                        phase="Phase 1",
                    )
                )

    return findings


@cached_check("check_password_policy")
def check_password_policy() -> list[Finding]:
    """Check password policy settings."""
    findings = []

    stdout, _, rc = run_command(
        "grep -E '^PASS_MAX_DAYS|^PASS_MIN_DAYS|^PASS_WARN_AGE' /etc/login.defs 2>/dev/null"
    )
    if rc == 0 and stdout:
        lines = stdout.strip().split("\n")
        for line in lines:
            if "PASS_MAX_DAYS" in line:
                parts = line.split()
                if len(parts) > 1:
                    days = parts[1]
                    if int(days) > config.pass_max_days_threshold:
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                check_id="IDENT-010",
                                title="Excessive PASS_MAX_DAYS",
                                description=f"Password max age: {days} days (recommended <= {config.pass_max_days_threshold})",
                                evidence=line,
                                impact="Compromised passwords remain valid longer",
                                remediation=f"Set PASS_MAX_DAYS to {config.pass_max_days_threshold} or less in /etc/login.defs",
                                phase="Phase 1",
                            )
                        )
            elif "PASS_MIN_DAYS" in line:
                parts = line.split()
                if len(parts) > 1:
                    days = parts[1]
                    if int(days) < config.pass_min_days_threshold:
                        findings.append(
                            Finding(
                                severity=Severity.LOW,
                                check_id="IDENT-011",
                                title="PASS_MIN_DAYS Too Low",
                                description=f"Password min age: {days} days (recommended >= {config.pass_min_days_threshold})",
                                evidence=line,
                                impact="Users can change passwords too quickly",
                                remediation=f"Set PASS_MIN_DAYS to at least {config.pass_min_days_threshold} in /etc/login.defs",
                                phase="Phase 1",
                            )
                        )
            elif "PASS_WARN_AGE" in line:
                parts = line.split()
                if len(parts) > 1:
                    days = parts[1]
                    if int(days) < config.pass_warn_age_threshold:
                        findings.append(
                            Finding(
                                severity=Severity.LOW,
                                check_id="IDENT-012",
                                title="PASS_WARN_AGE Too Low",
                                description=f"Password warn age: {days} days (recommended >= {config.pass_warn_age_threshold})",
                                evidence=line,
                                impact="Users not warned early enough about expiring passwords",
                                remediation=f"Set PASS_WARN_AGE to {config.pass_warn_age_threshold} or more in /etc/login.defs",
                                phase="Phase 1",
                            )
                        )

    return findings


@cached_check("check_password_expiry")
def check_password_expiry() -> list[Finding]:
    """Check for expired passwords."""
    findings = []

    stdout, _, rc = run_command(
        "awk -F: '($1!~ /^root/ && $1!~ /^sync/ && $1!~ /^shutdown/ && $1!~ /^halt/ && $8~/^e/ && $7!~/nologin/) {print $1,$5,$6}' /etc/shadow 2>/dev/null"
    )
    if rc == 0 and stdout:
        import time

        current_time = int(time.time() / 86400)
        for line in stdout.strip().split("\n"):
            parts = line.split()
            if len(parts) >= 3:
                username, last_change, _ = parts[0], parts[1], parts[2]
                try:
                    last_change_day = int(last_change)
                    days_since_change = current_time - last_change_day
                    if days_since_change > 90:
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                check_id="IDENT-013",
                                title=f"Password Not Changed Recently: {username}",
                                description=f"Password last changed: {days_since_change} days ago",
                                evidence=f"User: {username}, Days since change: {days_since_change}",
                                impact="Account password may be compromised",
                                remediation="Require password change for this user",
                                phase="Phase 1",
                            )
                        )
                except ValueError:
                    pass

    return findings


@cached_check("check_locked_accounts_with_shells")
def check_locked_accounts_with_shells() -> list[Finding]:
    """Check for locked accounts that still have valid shells."""
    findings = []

    stdout, _, rc = run_command(
        "awk -F: '$2 ~ /^!|^\\*$/ && $7 !~ /nologin|false/ {print}' /etc/passwd 2>/dev/null"
    )
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="IDENT-014",
                title="Locked Accounts With Valid Shells",
                description="Accounts with locked passwords but valid shells",
                evidence=stdout,
                impact="Potential for unauthorized access if password is set",
                remediation="Set shell to /usr/sbin/nologin for locked accounts",
                phase="Phase 1",
            )
        )

    return findings


@cached_check("check_group_modifications")
def check_group_modifications() -> list[Finding]:
    """Check for recent modifications to /etc/group."""
    findings = []

    stdout, _, rc = run_command("stat -c '%y %n' /etc/group 2>/dev/null")
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="IDENT-015",
                title="/etc/group Last Modified",
                description="Last modification time of /etc/group",
                evidence=stdout,
                impact="Monitor for unauthorized group changes",
                remediation="Review group membership changes",
                phase="Phase 1",
            )
        )

    return findings


@cached_check("check_pam_faillock")
def check_pam_faillock() -> list[Finding]:
    """Check PAM account lockout configuration (pam_faillock or pam_tally2)."""
    findings: list[Finding] = []

    stdout, _, rc = run_command("grep -r 'pam_faillock' /etc/pam.d/ 2>/dev/null")
    if rc == 0 and stdout and stdout.strip():
        return findings

    stdout2, _, rc2 = run_command("grep -r 'pam_tally2' /etc/pam.d/ 2>/dev/null")
    if rc2 == 0 and stdout2 and stdout2.strip():
        return findings

    findings.append(
        Finding(
            severity=Severity.MEDIUM,
            check_id="IDENT-016",
            title="No PAM Account Lockout Configured",
            description="Neither pam_faillock nor pam_tally2 found in PAM configuration",
            evidence="grep -r 'pam_faillock\\|pam_tally2' /etc/pam.d/ returned no results",
            impact="No brute-force protection for local account authentication",
            remediation="Configure pam_faillock in /etc/pam.d/common-auth or /etc/pam.d/system-auth",
            phase="Phase 1",
        )
    )

    return findings


@cached_check("check_session_timeout")
def check_session_timeout() -> list[Finding]:
    """Check if an idle session timeout (TMOUT) is configured."""
    findings: list[Finding] = []

    configs = [
        "/etc/profile",
        "/etc/bashrc",
        "/etc/bash.bashrc",
        "/etc/profile.d/",
    ]

    for cfg in configs:
        stdout, _, rc = run_command(f"grep -r 'TMOUT' {cfg} 2>/dev/null")
        if rc == 0 and stdout and stdout.strip():
            return findings

    findings.append(
        Finding(
            severity=Severity.MEDIUM,
            check_id="IDENT-017",
            title="No Session Timeout Configured",
            description="TMOUT is not set in any shell configuration file",
            evidence="No TMOUT setting found in /etc/profile, /etc/bashrc, or /etc/profile.d/",
            impact="Idle sessions remain open indefinitely, increasing the risk of unauthorized access",
            remediation="Add 'TMOUT=900' (or less) to /etc/profile or /etc/profile.d/timeout.sh",
            phase="Phase 1",
        )
    )

    return findings


@cached_check("check_umask")
def check_umask() -> list[Finding]:
    """Check if a secure default umask (027 or 077) is configured."""
    findings: list[Finding] = []

    configs = [
        "/etc/login.defs",
        "/etc/profile",
        "/etc/bashrc",
        "/etc/bash.bashrc",
    ]

    for cfg in configs:
        stdout, _, rc = run_command(
            f"grep -E '^\\s*[Uu][Mm][Aa][Ss][Kk]' {cfg} 2>/dev/null"
        )
        if rc == 0 and stdout and stdout.strip():
            for line in stdout.strip().split("\n"):
                parts = line.split()
                if len(parts) >= 2:
                    umask_val = parts[-1].strip()
                    try:
                        val = int(umask_val, 8)
                        if val >= 0o027:
                            return findings
                    except ValueError:
                        pass

    findings.append(
        Finding(
            severity=Severity.MEDIUM,
            check_id="IDENT-018",
            title="Insecure Default Umask",
            description="Default umask is not set to a secure value (027 or more restrictive)",
            evidence="No secure umask found in /etc/login.defs, /etc/profile, or /etc/bashrc",
            impact="Newly created files may be world-readable or group-writable",
            remediation="Set 'UMASK 027' in /etc/login.defs or 'umask 027' in /etc/profile",
            phase="Phase 1",
        )
    )

    return findings


@cached_check("check_ssh_x11_forwarding")
def check_ssh_x11_forwarding() -> list[Finding]:
    """Check if SSH X11 forwarding is enabled."""
    findings: list[Finding] = []

    paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
    stdout, _, rc = run_command(f"grep -r '^X11Forwarding' {paths} 2>/dev/null")
    if rc != 0 or not stdout.strip():
        return findings
    if "X11Forwarding yes" in stdout:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="IDENT-019",
                title="SSH X11Forwarding Enabled",
                description="X11Forwarding is explicitly enabled in sshd_config",
                evidence=stdout.strip(),
                impact="X11 forwarding allows remote GUI access over SSH connections",
                remediation="Set 'X11Forwarding no' in /etc/ssh/sshd_config",
                phase="Phase 1",
            )
        )
    return findings


@cached_check("check_ssh_permit_empty_passwords")
def check_ssh_permit_empty_passwords() -> list[Finding]:
    """Check SSH PermitEmptyPasswords setting."""
    findings: list[Finding] = []

    paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
    stdout, _, rc = run_command(f"grep -r '^PermitEmptyPasswords' {paths} 2>/dev/null")
    if rc != 0 or not stdout.strip():
        return findings
    if "PermitEmptyPasswords yes" in stdout:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="IDENT-020",
                title="SSH PermitEmptyPasswords Enabled",
                description="SSH allows authentication with empty passwords",
                evidence=stdout.strip(),
                impact="Users with empty passwords can authenticate without providing password",
                remediation="Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config",
                phase="Phase 1",
            )
        )
    return findings


@cached_check("check_ssh_pubkey_auth")
def check_ssh_pubkey_auth() -> list[Finding]:
    """Check SSH PubkeyAuthentication setting."""
    findings: list[Finding] = []

    paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
    stdout, _, rc = run_command(f"grep -r '^PubkeyAuthentication' {paths} 2>/dev/null")
    if rc != 0 or "PubkeyAuthentication yes" not in stdout:
        stdout_disabled, _, _ = run_command(
            f"grep -r '^PubkeyAuthentication no' {paths} 2>/dev/null"
        )
        if stdout_disabled.strip():
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="IDENT-021",
                    title="SSH PubkeyAuthentication Disabled",
                    description="PubkeyAuthentication is disabled",
                    evidence=stdout_disabled.strip(),
                    impact="Passwordless authentication via SSH keys is not available",
                    remediation="Set 'PubkeyAuthentication yes' in /etc/ssh/sshd_config for key-based auth",
                    phase="Phase 1",
                )
            )
    return findings


@cached_check("check_ssh_max_auth_tries")
def check_ssh_max_auth_tries() -> list[Finding]:
    """Check SSH MaxAuthTries setting."""
    findings: list[Finding] = []

    paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
    stdout, _, rc = run_command(f"grep -r '^MaxAuthTries' {paths} 2>/dev/null")
    if rc == 0 and stdout.strip():
        for line in stdout.strip().split("\n"):
            if line.startswith("MaxAuthTries"):
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        val = int(parts[1])
                        if val > 3:
                            findings.append(
                                Finding(
                                    severity=Severity.MEDIUM,
                                    check_id="IDENT-022",
                                    title="SSH MaxAuthTries Too High",
                                    description=f"Current value: {val}, recommended: <= 3",
                                    evidence=line,
                                    impact="More login attempts allowed, brute force easier",
                                    remediation="Set 'MaxAuthTries 3' in /etc/ssh/sshd_config",
                                    phase="Phase 1",
                                )
                            )
                    except ValueError:
                        pass
    else:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="IDENT-022",
                title="SSH MaxAuthTries Not Set",
                description="MaxAuthTries is not explicitly set (default is 6)",
                evidence="No MaxAuthTries directive",
                impact="Default allows up to 6 authentication attempts",
                remediation="Set 'MaxAuthTries 3' in /etc/ssh/sshd_config",
                phase="Phase 1",
            )
        )
    return findings


@cached_check("check_ssh_agent_forwarding")
def check_ssh_agent_forwarding() -> list[Finding]:
    """Check if SSH AllowAgentForwarding is explicitly disabled."""
    findings: list[Finding] = []

    paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
    stdout, _, rc = run_command(f"grep -r '^AllowAgentForwarding' {paths} 2>/dev/null")
    if rc == 0 and stdout.strip():
        if "AllowAgentForwarding no" in stdout:
            return findings
        if "AllowAgentForwarding yes" in stdout:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="IDENT-023",
                    title="SSH Agent Forwarding Enabled",
                    description="AllowAgentForwarding is explicitly set to yes",
                    evidence=stdout.strip(),
                    impact="SSH agent forwarding can expose local SSH keys to remote hosts if the remote is compromised",
                    remediation="Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config",
                    phase="Phase 1",
                )
            )
            return findings

    findings.append(
        Finding(
            severity=Severity.MEDIUM,
            check_id="IDENT-023",
            title="SSH Agent Forwarding Not Explicitly Disabled",
            description="AllowAgentForwarding is not explicitly set (defaults to yes on many systems)",
            evidence=stdout.strip()
            if stdout.strip()
            else "No AllowAgentForwarding directive",
            impact="SSH agent forwarding may be enabled by default, exposing keys to remote hosts",
            remediation="Set 'AllowAgentForwarding no' in /etc/ssh/sshd_config",
            phase="Phase 1",
        )
    )
    return findings


@cached_check("check_ssh_tcp_forwarding")
def check_ssh_tcp_forwarding() -> list[Finding]:
    """Check if SSH AllowTcpForwarding is explicitly disabled."""
    findings: list[Finding] = []

    paths = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/*.conf"]
    stdout, _, rc = run_command(f"grep -r '^AllowTcpForwarding' {paths} 2>/dev/null")
    if rc == 0 and stdout.strip():
        if "AllowTcpForwarding no" in stdout:
            return findings
        if "AllowTcpForwarding yes" in stdout:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="IDENT-024",
                    title="SSH TCP Forwarding Enabled",
                    description="AllowTcpForwarding is explicitly set to yes",
                    evidence=stdout.strip(),
                    impact="TCP forwarding can be abused to tunnel out of restricted networks or access internal services",
                    remediation="Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config",
                    phase="Phase 1",
                )
            )
            return findings

    findings.append(
        Finding(
            severity=Severity.MEDIUM,
            check_id="IDENT-024",
            title="SSH TCP Forwarding Not Explicitly Disabled",
            description="AllowTcpForwarding is not explicitly set (defaults to yes on many systems)",
            evidence=stdout.strip()
            if stdout.strip()
            else "No AllowTcpForwarding directive",
            impact="TCP forwarding may be enabled by default, allowing port tunneling through SSH",
            remediation="Set 'AllowTcpForwarding no' in /etc/ssh/sshd_config",
            phase="Phase 1",
        )
    )
    return findings


@cached_check("check_weak_service_credentials")
def _check_mysql_creds(paths: list[str]) -> list[Finding]:
    """Check MySQL config files for plaintext passwords."""
    findings: list[Finding] = []
    for path in paths:
        stdout, _, rc = run_command(["cat", path])
        if rc != 0 or not stdout:
            continue
        for line in stdout.strip().split("\n"):
            if "password" in line.strip().lower():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="IDENT-025",
                        title="MySQL Credential in Plaintext Config",
                        description=f"Password found in {path}",
                        evidence=line.strip(),
                        impact="Credentials stored in plaintext can be read by any user with file access",
                        remediation=f"Remove password from {path}; use mysql_config_editor or socket auth instead",
                        phase="Phase 1",
                    )
                )
                break
    return findings


def _check_redis_auth() -> list[Finding]:
    """Check Redis requirepass configuration."""
    stdout, _, rc = run_command(
        "grep -E '^requirepass' /etc/redis/redis.conf 2>/dev/null"
    )
    if rc == 0 and stdout.strip():
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            check_id="IDENT-025",
            title="Redis Authentication Not Configured",
            description="requirepass is not set in /etc/redis/redis.conf",
            evidence="No requirepass directive found",
            impact="Redis is accessible without authentication, allowing remote code execution via Lua sandbox",
            remediation="Set requirepass in /etc/redis/redis.conf and restart redis-server",
            phase="Phase 1",
        )
    ]


def _check_pgsql_trust() -> list[Finding]:
    """Check PostgreSQL for trust authentication entries."""
    stdout, _, rc = run_command("grep -r 'trust' /etc/postgresql/ 2>/dev/null")
    if rc != 0 or not stdout.strip():
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            check_id="IDENT-025",
            title="PostgreSQL Trust Authentication Enabled",
            description="Found 'trust' authentication entries in pg_hba.conf",
            evidence=stdout.strip()[:500],
            impact="Trust authentication allows passwordless database access for matching entries",
            remediation="Replace 'trust' with 'md5' or 'scram-sha-256' in pg_hba.conf",
            phase="Phase 1",
        )
    ]


def _check_pgsql_passwd_file() -> list[Finding]:
    """Check PostgreSQL .pgpass file permissions."""
    stdout, _, rc = run_command(["ls", "-la", "/root/.pgpass"])
    if rc != 0 or not stdout:
        return []
    parts = stdout.split()
    if len(parts) < 1:
        return []
    perms = parts[0]
    if len(perms) < 9 or (perms[7] == "-" and perms[8] == "-"):
        return []
    return [
        Finding(
            severity=Severity.HIGH,
            check_id="IDENT-025",
            title="World-Readable PostgreSQL Password File",
            description=f"/root/.pgpass has permissions {perms}",
            evidence=stdout,
            impact="PostgreSQL credentials are readable by other users",
            remediation="Set permissions to 600: chmod 600 /root/.pgpass",
            phase="Phase 1",
        )
    ]


def check_weak_service_credentials() -> list[Finding]:
    """Check for weak or default credentials in common services."""
    findings: list[Finding] = []
    findings.extend(_check_mysql_creds(["/etc/mysql/my.cnf", "/root/.my.cnf"]))
    findings.extend(_check_redis_auth())
    findings.extend(_check_pgsql_trust())
    findings.extend(_check_pgsql_passwd_file())
    return findings


@cached_check("check_path_hijacking")
def check_path_hijacking() -> list[Finding]:
    """Check PATH for writable directories and systemd for relative ExecStart paths.

    A writable directory early in root's PATH lets an attacker intercept
    any command that is resolved without a full path.
    A relative ExecStart in a systemd unit lets an attacker control execution
    by planting a binary in the unit's working directory.
    """
    findings: list[Finding] = []

    path = os.environ.get("PATH", "")
    for i, directory in enumerate(path.split(":")):
        if not directory:
            continue
        stdout, _, rc = run_command(["ls", "-lad", directory])
        if rc != 0 or not stdout:
            continue
        parts = stdout.split()
        if len(parts) < 4:
            continue
        perms = parts[0]
        if len(perms) >= 9 and perms[8] == "w":
            pos = "early" if i < 3 else "later in"
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="IDENT-026",
                    title="World-Writable Directory in PATH",
                    description=f"{directory} is world-writable and appears {pos} PATH",
                    evidence=f"PATH element [{i}]: {directory}\n{stdout}",
                    impact="Attacker can plant a malicious binary with a common name, and root may execute it inadvertently",
                    remediation="Remove world-writable bit: chmod o-w {directory}, or move {directory} to the end of PATH",
                    phase="Phase 1",
                )
            )

    # Check systemd unit files for relative ExecStart paths
    stdout, _, rc = run_command(
        "grep -rh '^ExecStart=' /etc/systemd/system/ 2>/dev/null | "
        "grep -v '/bin/' | grep -v '/usr/' | grep -v '/sbin/' | "
        "grep -v '/opt/' | grep -v '/etc/' | sort -u | head -20"
    )
    if rc == 0 and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="IDENT-026",
                title="Systemd Units With Relative ExecStart",
                description="Found systemd units using relative paths in ExecStart",
                evidence=stdout.strip()[:500],
                impact="A malicious binary planted in the unit's working directory will be executed instead of the intended program",
                remediation="Replace relative ExecStart paths with absolute paths in all systemd unit files",
                phase="Phase 1",
            )
        )

    return findings


@cached_check("check_sudo_timestamp_timeout")
def check_sudo_timestamp_timeout() -> list[Finding]:
    """Check sudo timestamp_timeout — the window before sudo re-asks for a password.

    A long timestamp_timeout widens the reuse window: if a user walks away from
    a terminal with an active sudo session, an attacker can use the cached credential.
    """
    findings: list[Finding] = []

    stdout, _, rc = run_command(
        "grep -rh 'timestamp_timeout' /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
    )
    if rc == 0 and stdout.strip():
        for line in stdout.strip().split("\n"):
            if "timestamp_timeout=" in line:
                val_str = line.split("timestamp_timeout=", 1)[1].strip().split()[0]
                try:
                    val = float(val_str)
                    if val > 15:
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                check_id="IDENT-027",
                                title="Long sudo Timestamp Timeout",
                                description=(
                                    f"sudo timestamp_timeout is {val} minutes "
                                    f"(recommended <= 15)"
                                ),
                                evidence=line.strip(),
                                impact=(
                                    "Extended sudo credential caching increases the window for "
                                    "privilege escalation if a terminal is left unattended"
                                ),
                                remediation=(
                                    "Set 'Defaults timestamp_timeout=15' or less "
                                    "in /etc/sudoers"
                                ),
                                phase="Phase 1",
                            )
                        )
                    if val <= 0:
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                check_id="IDENT-027",
                                title="sudo Timestamp Timeout Disabled",
                                description=(
                                    f"sudo timestamp_timeout is {val} (credentials never expire)"
                                ),
                                evidence=line.strip(),
                                impact=(
                                    "Once authenticated with sudo, the credential never "
                                    "expires — a permanent escalation window"
                                ),
                                remediation=(
                                    "Remove 'timestamp_timeout=0' or set a positive value "
                                    "in /etc/sudoers"
                                ),
                                phase="Phase 1",
                            )
                        )
                except ValueError:
                    pass
    return findings


@cached_check("check_sudo_gtfobins")
def check_sudo_gtfobins() -> list[Finding]:
    """Check for dangerous sudo rules allowing GTFOBins command escape.

    Extends the 8 hardcoded patterns from check_sudo_wildcard_abuse with a
    comprehensive list of commands known to allow shell escape via
    sudo (see GTFOBins.github.io).  Every command on this list that can appear
    in sudoers with the form Cmnd_Alias /usr/bin/<cmd> or ALL=(ALL) <cmd>
    enables a non‑privileged user to obtain a root shell.
    """
    findings: list[Finding] = []

    gtfobins = [
        "/usr/bin/vi",
        "/usr/bin/vim",
        "/usr/bin/nano",
        "/usr/bin/emacs",
        "/usr/bin/find",
        "/usr/bin/python",
        "/usr/bin/python3",
        "/usr/bin/perl",
        "/usr/bin/ruby",
        "/usr/bin/lua",
        "/usr/bin/awk",
        "/usr/bin/mawk",
        "/usr/bin/gawk",
        "/usr/bin/sed",
        "/usr/bin/cp",
        "/usr/bin/mv",
        "/usr/bin/tar",
        "/usr/bin/zip",
        "/usr/bin/unzip",
        "/usr/bin/less",
        "/usr/bin/more",
        "/usr/bin/head",
        "/usr/bin/tail",
        "/usr/bin/htop",
        "/usr/bin/top",
        "/usr/bin/ftp",
        "/usr/bin/gdb",
        "/usr/bin/strace",
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "/usr/bin/rsync",
        "/usr/bin/git",
        "/usr/bin/env",
        "/usr/bin/expect",
        "/usr/bin/csplit",
        "/usr/bin/cut",
        "/usr/bin/paste",
        "/usr/bin/join",
        "/usr/bin/expand",
        "/usr/bin/uniq",
        "/usr/bin/run-parts",
        "/usr/bin/busybox",
        "/usr/bin/socat",
        "/usr/bin/nmap",
        "/usr/bin/nc",
        "/usr/bin/netcat",
        "/usr/bin/cat",
    ]

    stdout, _, rc = run_command("cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null")
    if rc != 0 or not stdout:
        return findings

    for cmd in gtfobins:
        if cmd in stdout:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="IDENT-028",
                    title="Dangerous Sudo GTFOBins Rule",
                    description=f"Found sudo rule referencing {cmd} — allows shell escape on execution",
                    evidence=f"sudoers contains: {cmd}",
                    impact="Privileged user can escape to a root shell via the GTFOBins technique for this command",
                    remediation=f"Remove {cmd} from sudo rules or restrict with specific arguments",
                    phase="Phase 1",
                )
            )

    return findings


def run_identity_checks() -> list[Finding]:
    """Run all identity and access control checks."""
    findings = []

    findings.extend(check_uid_zero_accounts())
    findings.extend(check_system_accounts_with_shells())
    findings.extend(check_passwordless_accounts())
    findings.extend(check_sudo_nopasswd())
    findings.extend(check_sudo_wildcard_abuse())
    findings.extend(check_privileged_groups())
    findings.extend(check_ssh_root_login())
    findings.extend(check_ssh_password_auth())
    findings.extend(check_unauthorized_ssh_keys())
    findings.extend(check_password_policy())
    findings.extend(check_password_expiry())
    findings.extend(check_locked_accounts_with_shells())
    findings.extend(check_group_modifications())
    findings.extend(check_pam_faillock())
    findings.extend(check_session_timeout())
    findings.extend(check_umask())
    findings.extend(check_ssh_x11_forwarding())
    findings.extend(check_ssh_permit_empty_passwords())
    findings.extend(check_ssh_pubkey_auth())
    findings.extend(check_ssh_max_auth_tries())
    findings.extend(check_ssh_agent_forwarding())
    findings.extend(check_ssh_tcp_forwarding())
    findings.extend(check_weak_service_credentials())
    findings.extend(check_path_hijacking())
    findings.extend(check_sudo_timestamp_timeout())
    findings.extend(check_sudo_gtfobins())

    return findings
