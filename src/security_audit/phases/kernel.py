"""Phase 5 - Kernel & OS Hardening module."""

from ..core import Finding, Severity, run_command


def check_aslr() -> list[Finding]:
    """Check if ASLR is enabled."""
    findings = []

    stdout, _, rc = run_command("sysctl -n kernel.randomize_va_space 2>/dev/null")
    if rc == 0:
        if stdout.strip() != "2":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="KERN-001",
                    title="ASLR Not Fully Enabled",
                    description=f"Current value: {stdout.strip()}, expected: 2",
                    evidence=f"kernel.randomize_va_space = {stdout.strip()}",
                    impact="Memory addresses predictable, easier exploitation",
                    remediation="Set kernel.randomize_va_space = 2",
                    phase="Phase 5",
                )
            )

    return findings


def check_dmesg_restrict() -> list[Finding]:
    """Check dmesg restriction."""
    findings = []

    stdout, _, rc = run_command("sysctl -n kernel.dmesg_restrict 2>/dev/null")
    if rc == 0:
        if stdout.strip() != "1":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-002",
                    title="dmesg Not Restricted",
                    description=f"Current value: {stdout.strip()}, expected: 1",
                    evidence=f"kernel.dmesg_restrict = {stdout.strip()}",
                    impact="Kernel messages may leak sensitive information",
                    remediation="Set kernel.dmesg_restrict = 1",
                    phase="Phase 5",
                )
            )

    return findings


def check_kptr_restrict() -> list[Finding]:
    """Check kernel pointer restriction."""
    findings = []

    stdout, _, rc = run_command("sysctl -n kernel.kptr_restrict 2>/dev/null")
    if rc == 0:
        val = int(stdout.strip() or 0)
        if val < 2:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-003",
                    title="Kernel Pointers Exposed",
                    description=f"Current value: {val}, expected: >= 2",
                    evidence=f"kernel.kptr_restrict = {val}",
                    impact="Kernel pointers visible in /proc, aids exploitation",
                    remediation="Set kernel.kptr_restrict = 2",
                    phase="Phase 5",
                )
            )

    return findings


def check_ptrace_scope() -> list[Finding]:
    """Check ptrace scope."""
    findings = []

    stdout, _, rc = run_command("sysctl -n kernel.yama.ptrace_scope 2>/dev/null")
    if rc == 0:
        val = int(stdout.strip() or 0)
        if val > 1:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="KERN-004",
                    title="ptrace Scope Not Restricted",
                    description=f"Current value: {val}, expected: <= 1",
                    evidence=f"kernel.yama.ptrace_scope = {val}",
                    impact="Non-root can ptrace other processes",
                    remediation="Set kernel.yama.ptrace_scope = 1",
                    phase="Phase 5",
                )
            )

    return findings


def check_suid_dumpable() -> list[Finding]:
    """Check suid_dumpable setting."""
    findings = []

    stdout, _, rc = run_command("sysctl -n fs.suid_dumpable 2>/dev/null")
    if rc == 0:
        if stdout.strip() != "0":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-005",
                    title="SUID Programs Can Dump Core",
                    description=f"Current value: {stdout.strip()}, expected: 0",
                    evidence=f"fs.suid_dumpable = {stdout.strip()}",
                    impact="Core dumps may contain sensitive data",
                    remediation="Set fs.suid_dumpable = 0",
                    phase="Phase 5",
                )
            )

    return findings


def check_protected_symlinks() -> list[Finding]:
    """Check protected symlinks."""
    findings = []

    stdout, _, rc = run_command("sysctl -n fs.protected_symlinks 2>/dev/null")
    if rc == 0:
        if stdout.strip() != "1":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="KERN-006",
                    title="Symlinks Not Protected",
                    description=f"Current value: {stdout.strip()}, expected: 1",
                    evidence=f"fs.protected_symlinks = {stdout.strip()}",
                    impact="Symlink attacks possible",
                    remediation="Set fs.protected_symlinks = 1",
                    phase="Phase 5",
                )
            )

    return findings


def check_protected_hardlinks() -> list[Finding]:
    """Check protected hardlinks."""
    findings = []

    stdout, _, rc = run_command("sysctl -n fs.protected_hardlinks 2>/dev/null")
    if rc == 0:
        if stdout.strip() != "1":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="KERN-007",
                    title="Hardlinks Not Protected",
                    description=f"Current value: {stdout.strip()}, expected: 1",
                    evidence=f"fs.protected_hardlinks = {stdout.strip()}",
                    impact="Hardlink attacks possible",
                    remediation="Set fs.protected_hardlinks = 1",
                    phase="Phase 5",
                )
            )

    return findings


def check_kernel_module_blacklist() -> list[Finding]:
    """Check if dangerous kernel modules are blacklisted."""
    findings = []

    dangerous_modules = ["dccp", "sctp", "rds", "tipc", "usb-storage"]

    stdout, _, rc = run_command("cat /etc/modprobe.d/*.conf 2>/dev/null")
    if rc != 0 or not stdout:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="KERN-008",
                title="No Kernel Module Blacklist Configured",
                description="No blacklist configuration found in /etc/modprobe.d/",
                evidence="No config files found",
                impact="Dangerous modules can be loaded",
                remediation="Create blacklist config for unnecessary modules",
                phase="Phase 5",
            )
        )
    else:
        for module in dangerous_modules:
            if f"blacklist {module}" not in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.LOW,
                        check_id="KERN-009",
                        title=f"Kernel Module Not Blacklisted: {module}",
                        description=f"Module {module} not explicitly blacklisted",
                        evidence="grep blacklist in modprobe.d",
                        impact=f"Module {module} can be loaded",
                        remediation=f"Add 'blacklist {module}' to /etc/modprobe.d/blacklist.conf",
                        phase="Phase 5",
                    )
                )

    return findings


def check_sysrq_status() -> list[Finding]:
    """Check SysRq key status."""
    findings = []

    stdout, _, rc = run_command("sysctl -n kernel.sysrq 2>/dev/null")
    if rc == 0:
        if stdout.strip() != "0":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-010",
                    title="SysRq Key Enabled",
                    description=f"Current value: {stdout.strip()}, expected: 0",
                    evidence=f"kernel.sysrq = {stdout.strip()}",
                    impact="SysRq can be used for system control even if compromised",
                    remediation="Set kernel.sysrq = 0",
                    phase="Phase 5",
                )
            )

    return findings


def check_vm_swappiness() -> list[Finding]:
    """Check VM swappiness setting."""
    findings = []

    stdout, _, rc = run_command("sysctl -n vm.swappiness 2>/dev/null")
    if rc == 0:
        val = int(stdout.strip() or 0)
        if val > 10:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="KERN-011",
                    title="High VM Swappiness",
                    description=f"Current value: {val}, recommended: <= 10",
                    evidence=f"vm.swappiness = {val}",
                    impact="High swappiness may lead to swap usage affecting security",
                    remediation="Set vm.swappiness = 10 or lower",
                    phase="Phase 5",
                )
            )

    return findings


def check_user_namespaces() -> list[Finding]:
    """Check user namespace restrictions."""
    findings = []

    stdout, _, rc = run_command(
        "sysctl -n kernel.unprivileged_userns_clone 2>/dev/null"
    )
    if rc == 0:
        if stdout.strip() != "0":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="KERN-012",
                    title="User Namespaces Unrestricted",
                    description=f"Current value: {stdout.strip()}, recommended: 0",
                    evidence=f"kernel.unprivileged_userns_clone = {stdout.strip()}",
                    impact="Unprivileged users can create namespaces",
                    remediation="Set kernel.unprivileged_userns_clone = 0",
                    phase="Phase 5",
                )
            )

    return findings


def run_kernel_checks() -> list[Finding]:
    """Run all kernel and OS hardening checks."""
    findings = []

    findings.extend(check_aslr())
    findings.extend(check_dmesg_restrict())
    findings.extend(check_kptr_restrict())
    findings.extend(check_ptrace_scope())
    findings.extend(check_suid_dumpable())
    findings.extend(check_protected_symlinks())
    findings.extend(check_protected_hardlinks())
    findings.extend(check_kernel_module_blacklist())
    findings.extend(check_sysrq_status())
    findings.extend(check_vm_swappiness())
    findings.extend(check_user_namespaces())

    return findings
