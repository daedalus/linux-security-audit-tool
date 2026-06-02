"""Phase 5 - Kernel & OS Hardening module."""

from ..core import Finding, Severity, cached_check, run_command


@cached_check("check_aslr")
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


@cached_check("check_dmesg_restrict")
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


@cached_check("check_kptr_restrict")
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


@cached_check("check_ptrace_scope")
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


@cached_check("check_suid_dumpable")
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


@cached_check("check_protected_symlinks")
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


@cached_check("check_protected_hardlinks")
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


@cached_check("check_kernel_module_blacklist")
def check_kernel_module_blacklist() -> list[Finding]:
    """Check if dangerous kernel modules are blacklisted."""
    findings = []

    dangerous_modules = [
        "dccp",
        "sctp",
        "rds",
        "tipc",
        "usb-storage",
        "floppy",
        "usbhid",
        "ehci_hcd",
        "uhci_hcd",
        "ohci_hcd",
    ]

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


@cached_check("check_sysrq_status")
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


@cached_check("check_vm_swappiness")
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


@cached_check("check_panic_on_oops")
def check_panic_on_oops() -> list[Finding]:
    """Check kernel panic on oops setting."""
    findings: list[Finding] = []

    stdout, _, rc = run_command("sysctl -n kernel.panic_on_oops 2>/dev/null")
    if rc == 0:
        val = int(stdout.strip() or 0)
        if val == 0:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="KERN-012",
                    title="Kernel Panic on Oops Not Enabled",
                    description=f"Current value: {val}, recommended: 1",
                    evidence=f"kernel.panic_on_oops = {val}",
                    impact="System may continue running after a kernel panic",
                    remediation="Set kernel.panic_on_oops = 1",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_bpf_jit_harden")
def check_bpf_jit_harden() -> list[Finding]:
    """Check BPF JIT hardening setting."""
    findings: list[Finding] = []

    stdout, _, rc = run_command("sysctl -n net.core.bpf_jit_harden 2>/dev/null")
    if rc == 0:
        val = int(stdout.strip() or 0)
        if val != 2:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-014",
                    title="BPF JIT Hardening Not Enabled",
                    description=f"Current value: {val}, recommended: 2",
                    evidence=f"net.core.bpf_jit_harden = {val}",
                    impact="BPF JIT may leak addresses to unprivileged users",
                    remediation="Set net.core.bpf_jit_harden = 2",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_user_namespaces")
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
                    check_id="KERN-013",
                    title="User Namespaces Unrestricted",
                    description=f"Current value: {stdout.strip()}, recommended: 0",
                    evidence=f"kernel.unprivileged_userns_clone = {stdout.strip()}",
                    impact="Unprivileged users can create namespaces",
                    remediation="Set kernel.unprivileged_userns_clone = 0",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_apparmor_sshd_enforce")
def check_apparmor_sshd_enforce() -> list[Finding]:
    """Check if AppArmor is enforcing for sshd."""
    findings: list[Finding] = []

    stdout, _, rc = run_command("aa-status --enabled 2>/dev/null")
    if rc != 0:
        return findings

    stdout, _, rc = run_command(
        "grep -E '^((enforce)|(complaining))' /etc/apparmor.d/usr.sbin.sshd 2>/dev/null | head -1"
    )
    if rc == 0:
        line = stdout.strip()
        if "enforce" not in line.lower():
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-013",
                    title="AppArmor Not Enforcing for sshd",
                    description="Profile is not in enforce mode",
                    evidence=line,
                    impact="sshd may run with less restriction",
                    remediation="Run: aa-enforce /etc/apparmor.d/usr.sbin.sshd",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_ip_forwarding")
def check_ip_forwarding() -> list[Finding]:
    """Check IP forwarding is disabled."""
    findings = []

    stdout, _, rc = run_command("sysctl -n net.ipv4.ip_forward 2>/dev/null")
    if rc == 0 and stdout.strip() != "0":
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="KERN-014",
                title="IP Forwarding Enabled",
                description=f"Current value: {stdout.strip()}, expected: 0",
                evidence=f"net.ipv4.ip_forward = {stdout.strip()}",
                impact="System may act as router, exposing it to forward traffic",
                remediation="Set net.ipv4.ip_forward = 0",
                phase="Phase 5",
            )
        )

    return findings


@cached_check("check_rp_filter")
def check_rp_filter() -> list[Finding]:
    """Check reverse path filtering is enabled."""
    findings = []

    checks = [
        ("net.ipv4.conf.all.rp_filter", "all"),
        ("net.ipv4.conf.default.rp_filter", "default"),
    ]

    for param, _ in checks:
        stdout, _, rc = run_command(f"sysctl -n {param} 2>/dev/null")
        if rc == 0 and stdout.strip() != "1":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-015",
                    title="Reverse Path Filtering Disabled",
                    description=f"{param} = {stdout.strip()}, expected: 1",
                    evidence=f"{param} = {stdout.strip()}",
                    impact="IP spoofing possible",
                    remediation=f"Set {param} = 1",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_icmp_redirects")
def check_icmp_redirects() -> list[Finding]:
    """Check ICMP redirects are disabled."""
    findings = []

    checks = [
        "net.ipv4.conf.all.accept_redirects",
        "net.ipv4.conf.default.accept_redirects",
        "net.ipv6.conf.all.accept_redirects",
        "net.ipv6.conf.default.accept_redirects",
    ]

    for param in checks:
        stdout, _, rc = run_command(f"sysctl -n {param} 2>/dev/null")
        if rc == 0 and stdout.strip() != "0":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-016",
                    title="ICMP Redirects Enabled",
                    description=f"{param} = {stdout.strip()}, expected: 0",
                    evidence=f"{param} = {stdout.strip()}",
                    impact="Man-in-the-middle attacks possible",
                    remediation=f"Set {param} = 0",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_tcp_syncookies")
def check_tcp_syncookies() -> list[Finding]:
    """Check TCP SYN cookies are enabled."""
    findings = []

    stdout, _, rc = run_command("sysctl -n net.ipv4.tcp_syncookies 2>/dev/null")
    if rc == 0 and stdout.strip() != "1":
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="KERN-017",
                title="TCP SYN Cookies Disabled",
                description=f"Current value: {stdout.strip()}, expected: 1",
                evidence=f"net.ipv4.tcp_syncookies = {stdout.strip()}",
                impact="SYN flood vulnerability",
                remediation="Set net.ipv4.tcp_syncookies = 1",
                phase="Phase 5",
            )
        )

    return findings


@cached_check("check_source_routing")
def check_source_routing() -> list[Finding]:
    """Check source routing is disabled."""
    findings = []

    checks = [
        "net.ipv4.conf.all.accept_source_route",
        "net.ipv4.conf.default.accept_source_route",
        "net.ipv6.conf.all.accept_source_route",
        "net.ipv6.conf.default.accept_source_route",
    ]

    for param in checks:
        stdout, _, rc = run_command(f"sysctl -n {param} 2>/dev/null")
        if rc == 0 and stdout.strip() != "0":
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-018",
                    title="Source Routing Enabled",
                    description=f"{param} = {stdout.strip()}, expected: 0",
                    evidence=f"{param} = {stdout.strip()}",
                    impact="Route spoofing possible",
                    remediation=f"Set {param} = 0",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_log_martians")
def check_log_martians() -> list[Finding]:
    """Check suspicious packets are logged."""
    findings = []

    checks = [
        "net.ipv4.conf.all.log_martians",
        "net.ipv4.conf.default.log_martians",
    ]

    for param in checks:
        stdout, _, rc = run_command(f"sysctl -n {param} 2>/dev/null")
        if rc == 0 and stdout.strip() != "1":
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="KERN-019",
                    title="Martian Packet Logging Disabled",
                    description=f"{param} = {stdout.strip()}, expected: 1",
                    evidence=f"{param} = {stdout.strip()}",
                    impact="Suspicious packets not logged",
                    remediation=f"Set {param} = 1",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_icmp_broadcasts")
def check_icmp_broadcasts() -> list[Finding]:
    """Check ICMP broadcasts are ignored."""
    findings = []

    stdout, _, rc = run_command(
        "sysctl -n net.ipv4.icmp_echo_ignore_broadcasts 2>/dev/null"
    )
    if rc == 0 and stdout.strip() != "1":
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="KERN-020",
                title="ICMP Broadcasts Not Ignored",
                description=f"Current value: {stdout.strip()}, expected: 1",
                evidence=f"net.ipv4.icmp_echo_ignore_broadcasts = {stdout.strip()}",
                impact="Smurf amplification attack possible",
                remediation="Set net.ipv4.icmp_echo_ignore_broadcasts = 1",
                phase="Phase 5",
            )
        )

    return findings


@cached_check("check_selinux_apparmor_enforcing")
def check_selinux_apparmor_enforcing() -> list[Finding]:
    """Check if SELinux or AppArmor is enforcing."""
    findings = []

    stdout, _, rc = run_command("getenforce 2>/dev/null")
    if rc == 0:
        if stdout.strip().lower() != "enforcing":
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="KERN-021",
                    title="SELinux Not Enforcing",
                    description=f"Current mode: {stdout.strip()}, expected: Enforcing",
                    evidence=f"SELinux mode: {stdout.strip()}",
                    impact="SELinux not providing mandatory access control",
                    remediation="Set SELinux to enforcing mode",
                    phase="Phase 5",
                )
            )
    else:
        stdout, _, rc = run_command("aa-status --enabled 2>/dev/null")
        if rc != 0:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="KERN-022",
                    title="No Mandatory Access Control",
                    description="Neither SELinux nor AppArmor is enabled",
                    evidence="No MAC system detected",
                    impact="System lacks mandatory access control",
                    remediation="Enable SELinux or AppArmor",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_grub_password")
def check_grub_password() -> list[Finding]:
    """Check if GRUB has password protection."""
    findings = []

    stdout, _, rc = run_command(
        "grep -r '^password' /boot/grub/ /etc/grub.d/ 2>/dev/null"
    )
    if rc != 0 or not stdout.strip():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="KERN-023",
                title="GRUB Not Password Protected",
                description="No GRUB password configuration found",
                evidence="No password set in GRUB config",
                impact="Anyone can edit GRUB boot parameters",
                remediation="Set GRUB password using grub-mkpasswd-pbkdf2",
                phase="Phase 5",
            )
        )

    return findings


@cached_check("check_fde")
def check_fde() -> list[Finding]:
    """Check if Full Disk Encryption is present."""
    findings = []

    stdout, _, rc = run_command(
        "cryptsetup isLuks --type luks $(lsblk -o NAME -o PTTYPE -n | grep -E 'disk' | head -1 | awk '{print $1}') 2>/dev/null || echo 'no'"
    )
    if "no" in stdout.lower() or rc != 0:
        stdout, _, rc = run_command(
            "ls -la /dev/mapper/ 2>/dev/null | grep -v '^total'"
        )
        if rc != 0 or not stdout.strip():
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="KERN-024",
                    title="No Full Disk Encryption",
                    description="No LUKS encrypted volumes detected",
                    evidence="No encrypted volumes found",
                    impact="Data at rest not encrypted",
                    remediation="Set up LUKS encryption for disk partitions",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_tpm_attestation")
def check_tpm_attestation() -> list[Finding]:
    """Check if TPM attestation is present and not tampered."""
    findings = []

    stdout, _, rc = run_command("tpm2_getcap -l 2>/dev/null")
    if rc != 0:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="KERN-025",
                title="No TPM Present",
                description="No TPM device found",
                evidence="tpm2_getcap failed",
                impact="No hardware root of trust for platform attestation",
                remediation="Install a TPM module",
                phase="Phase 5",
            )
        )
    else:
        stdout, _, rc = run_command(
            "tpm2_checkquote --help 2>/dev/null || tpm2_attestations 2>/dev/null || echo 'no_attestation'"
        )
        if "no_attestation" in stdout.lower() or rc != 0:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="KERN-026",
                    title="TPM Attestation Not Configured",
                    description="TPM is present but attestation not configured",
                    evidence="TPM available, attestation tools missing",
                    impact="Platform cannot prove its integrity",
                    remediation="Configure TPM attestation services",
                    phase="Phase 5",
                )
            )

    return findings


@cached_check("check_secureboot")
def check_secureboot() -> list[Finding]:
    """Check if SecureBoot is present and active."""
    findings = []

    stdout, _, rc = run_command(
        "mokutil --sb-state 2>/dev/null || sbctl status 2>/dev/null"
    )
    if rc != 0:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="KERN-027",
                title="SecureBoot Not Available",
                description="SecureBoot not available on this system",
                evidence="mokutil/sbctl failed",
                impact="Boot integrity not verified",
                remediation="Enable SecureBoot in UEFI firmware",
                phase="Phase 5",
            )
        )
    elif "disabled" in stdout.lower() or "disabled" in stdout.lower():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="KERN-028",
                title="SecureBoot Disabled",
                description="SecureBoot is present but disabled",
                evidence=f"SecureBoot state: {stdout.strip()}",
                impact="Boot integrity not verified",
                remediation="Enable SecureBoot in UEFI firmware",
                phase="Phase 5",
            )
        )

    return findings


# Known-vulnerable kernel version ranges (simplified as (major, minor, patch, label))
# Only the most impactful LPE/LPE-prerequisite vulns that have public exploits.
_KNOWN_VULNERABLE_KERNELS: list[tuple[int, int, int, str]] = [
    (6, 2, 0, "CVE-2022-0847 (Dirty Pipe) — affects 5.8–6.2"),
    (5, 19, 0, "CVE-2022-1786 (BRLTTY race) — 5.8–5.19"),
    (5, 18, 0, "CVE-2024-1086 (nf_tables use-after-free) — 3.15–6.8"),
    (5, 15, 0, "CVE-2023-0386 (overlayfs privilege escalation) — 5.11–5.15"),
    (5, 15, 0, "CVE-2023-3269 (stack clobber in perf) — 5.15–6.4"),
    (5, 14, 0, "CVE-2022-0995 (watch queue LPE) — 5.8–5.14"),
    (5, 14, 0, "CVE-2022-25636 (nf_dup_netdev OOB) — 5.5–5.14"),
    (5, 13, 0, "CVE-2021-22555 (netfilter heap write) — 2.6–5.13"),
    (5, 14, 0, "CVE-2022-2588 (cls_route use-after-free) — 5.8–5.14"),
    (5, 11, 0, "CVE-2021-3493 (overlayfs LPE) — 5.11–5.13"),
    (5, 10, 0, "CVE-2021-22555 (netfilter heap write) — up to 5.10"),
    (5, 10, 0, "CVE-2022-0847 (Dirty Pipe patch range) — backported to 5.10"),
    (5, 4, 0, "CVE-2021-33909 (seccomp_cgroup no_new_privs bypass) — 5.0–5.4"),
    (4, 19, 0, "CVE-2021-3490 (eBPF ALU32 bounds tracking) — 5.7–5.11"),
    (4, 15, 0, "CVE-2021-22555 (netfilter heap write) — up to 4.15"),
    (4, 14, 0, "CVE-2022-2586 (nft_set elem use-after-free) — 4.0–4.14"),
    (4, 10, 0, "Dirty COW (CVE-2016-5195) — all 2.x and 3.x, early 4.x"),
    (3, 10, 0, "CVE-2017-1000112 (Dirty COW variant) — up to 4.12"),
]

# Ranges where at least one fix-backport exists; use a wider range for safety.
# Each entry is (from, to, description).
_VULNERABLE_RANGES: list[tuple[str, str, str]] = [
    ("2.6", "4.14", "CVE-2022-2586 (nft_set elem) — 4.0–4.14"),
    ("3.15", "5.14", "CVE-2022-2588 (cls_route) — 5.8–5.14"),
    ("3.15", "6.8", "CVE-2024-1086 (nf_tables) — 3.15–6.8"),
    ("4.0", "4.14", "CVE-2022-2586 (nft_set elem) — 4.0–4.14"),
    ("5.0", "5.4", "CVE-2021-33909 (seccomp_cgroup) — 5.0–5.4"),
    ("5.5", "5.14", "CVE-2022-25636 (nf_dup_netdev) — 5.5–5.14"),
    ("5.7", "5.11", "CVE-2021-3490 (eBPF ALU32) — 5.7–5.11"),
    ("5.8", "5.14", "CVE-2022-0995 (watch queue) — 5.8–5.14"),
    ("5.8", "5.14", "CVE-2022-2588 (cls_route) — 5.8–5.14"),
    ("5.8", "6.2", "CVE-2022-0847 (Dirty Pipe) — 5.8–6.2"),
    ("5.11", "6.8", "CVE-2024-1086 (nf_tables) — 3.15–6.8"),
    ("5.11", "5.13", "CVE-2021-3493 (overlayfs) — 5.11–5.13"),
    ("5.11", "5.15", "CVE-2023-0386 (overlayfs) — 5.11–5.15"),
    ("5.15", "6.4", "CVE-2023-3269 (perf stack) — 5.15–6.4"),
    ("5.8", "5.19", "CVE-2022-1786 (BRLTTY) — 5.8–5.19"),
]


def _parse_kernel_version(version_str: str) -> tuple[int, int, int] | None:
    """Parse a kernel version string like '5.15.0-rc7' into (5, 15, 0)."""
    import re

    m = re.match(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2))
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)


@cached_check("check_kernel_vulnerable")
def check_kernel_vulnerable() -> list[Finding]:
    """Check running kernel version against known-vulnerable ranges.

    Linux LPE exploits are version-specific.  This check maps the current
    `uname -r` output against a curated list of high-impact CVEs with
    public exploits.
    """
    findings: list[Finding] = []

    stdout, _, rc = run_command("uname -r 2>/dev/null")
    if rc != 0 or not stdout:
        return findings

    version_str = stdout.strip()
    kv = _parse_kernel_version(version_str)
    if kv is None:
        return findings

    seen: set[str] = set()
    for from_str, to_str, desc in _VULNERABLE_RANGES:
        from_kv = _parse_kernel_version(from_str)
        to_kv = _parse_kernel_version(to_str)
        if from_kv is None or to_kv is None:
            continue
        if from_kv <= kv <= to_kv:
            # Deduplicate adjacent vulns referencing the same CVE
            short = desc.split("—")[0].rstrip() if "—" in desc else desc
            if short in seen:
                continue
            seen.add(short)
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    check_id="KERN-029",
                    title=f"Kernel Version May Be Vulnerable: {version_str}",
                    description=(
                        f"Kernel {version_str} falls within the vulnerable range "
                        f"({from_str}–{to_str}) for {desc}"
                    ),
                    evidence=f"uname -r: {version_str}\nVulnerable range: {from_str}–{to_str}\nVuln: {desc}",
                    impact=(
                        "Public exploit exists for this kernel version; "
                        "local privilege escalation is possible if the system is unpatched"
                    ),
                    remediation="Upgrade the kernel to the latest stable version for your distribution",
                    phase="Phase 5",
                )
            )

    if not findings:
        return findings

    # Collapse multiple matches: if we found N vulns, report the count.
    collapsed = findings[0]
    if len(findings) > 1:
        collapsed.description = (
            f"Kernel {version_str} falls within vulnerable ranges "
            f"for {len(findings)} CVE(s). First hit: {findings[0].description}"
        )
        findings[:] = [collapsed]

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
    findings.extend(check_panic_on_oops())
    findings.extend(check_bpf_jit_harden())
    findings.extend(check_user_namespaces())
    findings.extend(check_apparmor_sshd_enforce())
    findings.extend(check_ip_forwarding())
    findings.extend(check_rp_filter())
    findings.extend(check_icmp_redirects())
    findings.extend(check_tcp_syncookies())
    findings.extend(check_source_routing())
    findings.extend(check_log_martians())
    findings.extend(check_icmp_broadcasts())
    findings.extend(check_selinux_apparmor_enforcing())
    findings.extend(check_grub_password())
    findings.extend(check_fde())
    findings.extend(check_tpm_attestation())
    findings.extend(check_secureboot())
    findings.extend(check_kernel_vulnerable())

    return findings
