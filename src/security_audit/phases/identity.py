"""Phase 1 - Identity & Access Control module."""

from ..core import Finding, Severity, check_root, run_command


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


def check_passwordless_accounts() -> list[Finding]:
    """Check for accounts with empty passwords."""
    if not check_root():
        return []

    findings = []

    stdout, _, rc = run_command(
        'sudo awk -F: \'$2 == "" {print "NO PASSWORD:", $1}\' /etc/shadow'
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

    return findings
