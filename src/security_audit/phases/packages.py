"""Phase 7 - Package & Update Hygiene module."""

from ..core import Finding, Severity, run_command


def check_pending_updates() -> list[Finding]:
    """Check for pending security updates."""
    findings = []

    stdout, _, rc = run_command("apt list --upgradable 2>/dev/null | grep -i security")
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="PKG-001",
                title="Pending Security Updates",
                description="Security updates available but not applied",
                evidence=stdout,
                impact="System vulnerable to known exploits",
                remediation="Run: apt update && apt upgrade",
                phase="Phase 7",
            )
        )

    stdout, _, rc = run_command("yum check-update 2>/dev/null | grep -i security")
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="PKG-001",
                title="Pending Security Updates (RHEL)",
                description="Security updates available but not applied",
                evidence=stdout,
                impact="System vulnerable to known exploits",
                remediation="Run: yum update",
                phase="Phase 7",
            )
        )

    return findings


def check_last_update() -> list[Finding]:
    """Check when system was last updated."""
    findings = []

    stdout, _, rc = run_command(
        "stat /var/cache/apt/pkgcache.bin 2>/dev/null | grep Modify"
    )
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="PKG-002",
                title="Last Package Cache Update",
                description=f"Package cache last modified: {stdout}",
                evidence=stdout,
                impact="May indicate stale package cache",
                remediation="Run apt update",
                phase="Phase 7",
            )
        )

    return findings


def check_untrusted_repos() -> list[Finding]:
    """Check for untrusted package repositories."""
    findings = []

    stdout, _, rc = run_command("apt-key list 2>/dev/null")
    if rc == 0 and stdout:
        if "expired" in stdout.lower() or "disabled" in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="PKG-003",
                    title="Expired/GPG Keys Found",
                    description="Some GPG keys are expired or disabled",
                    evidence=stdout,
                    impact="Package integrity cannot be verified",
                    remediation="Update or remove expired GPG keys",
                    phase="Phase 7",
                )
            )

    return findings


def check_unnecessary_packages() -> list[Finding]:
    """Check for unnecessary packages."""
    findings = []

    unnecessary = ["telnet", "xinetd", "rsh-server", "talk"]

    stdout, _, rc = run_command("dpkg -l 2>/dev/null")
    if rc == 0 and stdout:
        for pkg in unnecessary:
            if pkg in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="PKG-004",
                        title=f"Unnecessary Package: {pkg}",
                        description=f"Package {pkg} is installed",
                        evidence=f"dpkg -l | grep {pkg}",
                        impact="Unnecessary packages increase attack surface",
                        remediation=f"Remove: apt remove {pkg}",
                        phase="Phase 7",
                    )
                )

    return findings


def check_deprecated_packages() -> list[Finding]:
    """Check for deprecated/insecure packages."""
    findings = []

    deprecated = ["libssl1.0", "openssl-1.0"]

    stdout, _, rc = run_command("dpkg -l 2>/dev/null")
    if rc == 0 and stdout:
        for pkg in deprecated:
            if pkg in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="PKG-005",
                        title=f"Deprecated Package: {pkg}",
                        description=f"Package {pkg} is deprecated and may have vulnerabilities",
                        evidence=f"dpkg -l | grep {pkg}",
                        impact="Known vulnerabilities in deprecated software",
                        remediation="Upgrade to supported version",
                        phase="Phase 7",
                    )
                )

    return findings


def run_package_checks() -> list[Finding]:
    """Run all package and update hygiene checks."""
    findings = []

    findings.extend(check_pending_updates())
    findings.extend(check_last_update())
    findings.extend(check_untrusted_repos())
    findings.extend(check_unnecessary_packages())
    findings.extend(check_deprecated_packages())

    return findings
