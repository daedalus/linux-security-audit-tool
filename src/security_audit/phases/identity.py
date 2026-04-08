"""Phase 1 - Identity & Access Control module."""

from ..core import Finding, Severity, cached_check, check_root, run_command


@cached_check("check_uid_zero_accounts")
def check_uid_zero_accounts() -> list[Finding]:
    """Check for duplicate UID 0 accounts."""
    findings = []

    stdout, _, rc = run_command("awk -F: '$3 == 0 {print}' /etc/passwd")
    if rc == 0 and stdout:
        lines = stdout.strip().split("\n")
        for line in lines:
            if line:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        check_id="IDENT-001",
                        title="UID 0 Account Found",
                        description=f"Found account with UID 0: {line}",
                        evidence=f"awk -F: '$3 == 0 {print}' /etc/passwd\n{stdout}",
                        impact="Account has full root privileges on the system",
                        remediation="Review and remove unauthorized UID 0 accounts",
                        phase="Phase 1",
                    )
                )

    return findings


@cached_check("check_system_accounts_with_shells")
def check_system_accounts_with_shells() -> list[Finding]:
    """Check for system accounts with interactive shells."""
    findings = []

    stdout, _, rc = run_command(
        "awk -F: '$3 < 1000 && $7 !~ /nologin|false/ {print}' /etc/passwd"
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
            key_content, _, _ = run_command(f"cat {path} 2>/dev/null")
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
                    if int(days) > 90:
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                check_id="IDENT-010",
                                title="Excessive PASS_MAX_DAYS",
                                description=f"Password max age: {days} days (recommended <= 90)",
                                evidence=line,
                                impact="Compromised passwords remain valid longer",
                                remediation="Set PASS_MAX_DAYS to 90 or less in /etc/login.defs",
                                phase="Phase 1",
                            )
                        )
            elif "PASS_MIN_DAYS" in line:
                parts = line.split()
                if len(parts) > 1:
                    days = parts[1]
                    if int(days) < 1:
                        findings.append(
                            Finding(
                                severity=Severity.LOW,
                                check_id="IDENT-011",
                                title="PASS_MIN_DAYS Too Low",
                                description=f"Password min age: {days} days (recommended >= 1)",
                                evidence=line,
                                impact="Users can change passwords too quickly",
                                remediation="Set PASS_MIN_DAYS to at least 1 in /etc/login.defs",
                                phase="Phase 1",
                            )
                        )
            elif "PASS_WARN_AGE" in line:
                parts = line.split()
                if len(parts) > 1:
                    days = parts[1]
                    if int(days) < 7:
                        findings.append(
                            Finding(
                                severity=Severity.LOW,
                                check_id="IDENT-012",
                                title="PASS_WARN_AGE Too Low",
                                description=f"Password warn age: {days} days (recommended >= 7)",
                                evidence=line,
                                impact="Users not warned early enough about expiring passwords",
                                remediation="Set PASS_WARN_AGE to 7 or more in /etc/login.defs",
                                phase="Phase 1",
                            )
                        )

    return findings


@cached_check("check_password_expiry")
def check_password_expiry() -> list[Finding]:
    """Check for expired passwords."""
    findings = []

    stdout, _, rc = run_command(
        "sudo awk -F: '($1!~ /^root/ && $1!~ /^sync/ && $1!~ /^shutdown/ && $1!~ /^halt/ && $8~/^e/ && $7!~/nologin/) {print $1,$5,$6}' /etc/shadow 2>/dev/null"
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

    for config in configs:
        stdout, _, rc = run_command(f"grep -r 'TMOUT' {config} 2>/dev/null")
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

    for config in configs:
        stdout, _, rc = run_command(
            f"grep -E '^\\s*[Uu][Mm][Aa][Ss][Kk]' {config} 2>/dev/null"
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
        stdout, _, rc = run_command(f"grep -r '^X11Forwarding no' {paths} 2>/dev/null")
        if rc == 0:
            return findings
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="IDENT-019",
                title="SSH X11Forwarding Not Explicitly Disabled",
                description="X11Forwarding is not explicitly disabled in sshd_config",
                evidence="No X11Forwarding directive found",
                impact="X11 forwarding may be enabled, allowing remote GUI access",
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
    if rc != 0 or "PermitEmptyPasswords no" not in stdout:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="IDENT-020",
                title="SSH PermitEmptyPasswords Not Disabled",
                description="SSH allows authentication with empty passwords",
                evidence=stdout.strip()
                if stdout.strip()
                else "No PermitEmptyPasswords directive",
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

    return findings
