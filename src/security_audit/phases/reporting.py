"""Phase 9 - Reporting & Remediation module."""

from datetime import datetime

from weasyprint import HTML

from ..core import AuditContext, Finding, Severity


def generate_pdf_report(
    context: AuditContext, findings: list[Finding], output_path: str
) -> None:
    """Generate a PDF executive report."""
    classified = classify_severity(findings)
    score = calculate_security_score(findings)

    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#0891b2",
        "INFO": "#4b5563",
    }

    findings_html = ""
    for severity_name, severity_list in [
        ("critical", classified["critical"]),
        ("high", classified["high"]),
        ("medium", classified["medium"]),
        ("low", classified["low"]),
        ("info", classified["info"]),
    ]:
        if severity_list:
            findings_html += f'<h2 style="color:{severity_colors.get(severity_name.upper(), "#000")}">{severity_name.upper()} Findings</h2>'
            for f in severity_list:
                findings_html += f"""
                <div class="finding">
                    <h3>{f.check_id}: {f.title}</h3>
                    <p><strong>Severity:</strong> <span class="severity {f.severity.value.lower()}">{f.severity.value}</span></p>
                    <p><strong>Description:</strong> {f.description}</p>
                    <p><strong>Remediation:</strong> {f.remediation}</p>
                </div>
                """

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Security Audit Report - {context.hostname}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; color: #1f2937; }}
            h1 {{ color: #1e40af; border-bottom: 2px solid #1e40af; padding-bottom: 10px; }}
            h2 {{ color: #374151; margin-top: 30px; }}
            .summary {{ background: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0; }}
            .score {{ font-size: 48px; font-weight: bold; color: #1e40af; }}
            .meta {{ color: #6b7280; font-size: 14px; }}
            .finding {{ background: #fff; border-left: 4px solid #374151; padding: 15px; margin: 15px 0; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
            .severity.critical {{ color: #dc2626; font-weight: bold; }}
            .severity.high {{ color: #ea580c; font-weight: bold; }}
            .severity.medium {{ color: #ca8a04; font-weight: bold; }}
            .severity.low {{ color: #0891b2; font-weight: bold; }}
            .severity.info {{ color: #4b5563; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }}
            th {{ background: #f9fafb; font-weight: 600; }}
        </style>
    </head>
    <body>
        <h1>Linux Security Audit Report</h1>
        <div class="meta">
            <p><strong>Hostname:</strong> {context.hostname or "Unknown"}</p>
            <p><strong>Date:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
            <p><strong>Kernel:</strong> {context.kernel or "Unknown"}</p>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="score">{score}/100</div>
            <table>
                <tr><th>Severity</th><th>Count</th></tr>
                <tr><td style="color:#dc2626">Critical</td><td>{len(classified["critical"])}</td></tr>
                <tr><td style="color:#ea580c">High</td><td>{len(classified["high"])}</td></tr>
                <tr><td style="color:#ca8a04">Medium</td><td>{len(classified["medium"])}</td></tr>
                <tr><td style="color:#0891b2">Low</td><td>{len(classified["low"])}</td></tr>
                <tr><td style="color:#4b5563">Info</td><td>{len(classified["info"])}</td></tr>
            </table>
        </div>

        {findings_html}
    </body>
    </html>
    """

    HTML(string=html_content).write_pdf(output_path)


def classify_severity(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Classify findings by severity."""
    classified = {"critical": [], "high": [], "medium": [], "low": [], "info": []}

    for f in findings:
        if f.severity == Severity.CRITICAL:
            classified["critical"].append(f)
        elif f.severity == Severity.HIGH:
            classified["high"].append(f)
        elif f.severity == Severity.MEDIUM:
            classified["medium"].append(f)
        elif f.severity == Severity.LOW:
            classified["low"].append(f)
        else:
            classified["info"].append(f)

    return classified


def generate_markdown_report(context: AuditContext, findings: list[Finding]) -> str:
    """Generate markdown security report."""
    classified = classify_severity(findings)

    report = f"""# Linux Security Audit Report

**Hostname:** {context.hostname or "Unknown"}
**Date:** {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
**Kernel:** {context.kernel or "Unknown"}

---

## Executive Summary

| Severity | Count |
|----------|-------|
| Critical | {len(classified["critical"])} |
| High | {len(classified["high"])} |
| Medium | {len(classified["medium"])} |
| Low | {len(classified["low"])} |
| Info | {len(classified["info"])} |

"""

    if classified["critical"]:
        report += "## Critical Findings\n\n"
        for f in classified["critical"]:
            report += format_finding(f)

    if classified["high"]:
        report += "## High Findings\n\n"
        for f in classified["high"]:
            report += format_finding(f)

    if classified["medium"]:
        report += "## Medium Findings\n\n"
        for f in classified["medium"]:
            report += format_finding(f)

    if classified["low"]:
        report += "## Low Findings\n\n"
        for f in classified["low"]:
            report += format_finding(f)

    if classified["info"]:
        report += "## Informational\n\n"
        for f in classified["info"]:
            report += format_finding(f)

    report += "\n## Remediation Checklist\n\n"
    for f in findings:
        if f.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
            report += f"- [{f.severity.value}] {f.check_id}: {f.remediation}\n"

    return report


def format_finding(f: Finding) -> str:
    """Format a single finding."""
    return f"""### {f.check_id}: {f.title}
- **Severity:** {f.severity.value}
- **Description:** {f.description}
- **Evidence:** ```
{f.evidence[:500]}
```
- **Impact:** {f.impact}
- **Remediation:** {f.remediation}

"""


def generate_remediation_script(findings: list[Finding]) -> str:
    """Generate a remediation script."""
    script = """#!/bin/bash
# Security Audit Remediation Script
# WARNING: Review before running
# Run as: sudo bash remediation.sh

set -euo pipefail

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
NC='\\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Backup function
backup_file() {
    local file="$1"
    if [ -f "$file" ]; then
        cp "$file" "${file}.bak.$(date +%Y%m%d%H%M%S)"
        log_info "Backed up $file"
    fi
}

# Get all findings
CRITICAL_FINDINGS=()
HIGH_FINDINGS=()
MEDIUM_FINDINGS=()

"""
    for f in findings:
        if f.severity == Severity.CRITICAL:
            script += f'CRITICAL_FINDINGS+=("{f.check_id}")\n'
        elif f.severity == Severity.HIGH:
            script += f'HIGH_FINDINGS+=("{f.check_id}")\n'
        elif f.severity == Severity.MEDIUM:
            script += f'MEDIUM_FINDINGS+=("{f.check_id}")\n'

    script += """
echo "========================================"
echo "Security Audit Remediation Script"
echo "========================================"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "Please run as root (sudo)"
    exit 1
fi

"""
    for f in findings:
        if f.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]:
            script += _generate_remediation_for_finding(f) + "\n"

    script += """
echo ""
log_info "Remediation complete. Please review the output above."
log_warn "Some changes may require a reboot to take effect."

# Summary
echo ""
echo "========================================"
echo "Summary"
echo "========================================"
echo "CRITICAL issues: ${#CRITICAL_FINDINGS[@]}"
echo "HIGH issues: ${#HIGH_FINDINGS[@]}"
echo "MEDIUM issues: ${#MEDIUM_FINDINGS[@]}"
"""

    return script


def _generate_remediation_for_finding(f: Finding) -> str:
    """Generate remediation commands for a specific finding."""

    # UID 0 accounts
    if f.check_id == "IDENT-001":
        return f"""
# {f.check_id}: {f.title}
# Find and remove unauthorized UID 0 accounts
echo "Checking for duplicate UID 0 accounts..."
awk -F: '$3 == 0 {{print}}' /etc/passwd | while read line; do
    user=$(echo "$line" | cut -d: -f1)
    if [ "$user" != "root" ]; then
        log_warn "Found UID 0 account: $user"
        echo "To remove: userdel -r $user"
    fi
done
"""

    # Empty passwords
    if f.check_id == "IDENT-003":
        return f"""
# {f.check_id}: {f.title}
# Lock accounts with empty passwords
echo "Locking accounts with empty passwords..."
for user in $(awk -F: '$2 == "" {{print $1}}' /etc/shadow 2>/dev/null); do
    log_warn "Locking account: $user"
    passwd -l "$user"
done
"""

    # NOPASSWD sudo
    if f.check_id == "IDENT-004":
        return f"""
# {f.check_id}: {f.title}
# Remove NOPASSWD from sudoers
echo "Checking for NOPASSWD sudo rules..."
for f in /etc/sudoers /etc/sudoers.d/*; do
    if [ -f "$f" ]; then
        if grep -q "NOPASSWD" "$f" 2>/dev/null; then
            backup_file "$f"
            log_warn "Found NOPASSWD in $f"
            echo "Review and manually remove NOPASSWD from: $f"
        fi
    fi
done
"""

    # SSH root login
    if f.check_id == "IDENT-007":
        return f"""
# {f.check_id}: {f.title}
# Disable root SSH login
echo "Disabling root SSH login..."
if [ -f /etc/ssh/sshd_config ]; then
    backup_file /etc/ssh/sshd_config
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    echo "Run 'systemctl restart sshd' to apply changes"
fi
"""

    # Password authentication
    if f.check_id == "IDENT-008":
        return f"""
# {f.check_id}: {f.title}
# Disable SSH password authentication
echo "Disabling SSH password authentication..."
if [ -f /etc/ssh/sshd_config ]; then
    backup_file /etc/ssh/sshd_config
    sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    echo "Run 'systemctl restart sshd' to apply changes"
fi
"""

    # Sudo wildcard abuse
    if f.check_id == "IDENT-005":
        return f"""
# {f.check_id}: {f.title}
# Remove dangerous sudo wildcard rules
echo "Checking for dangerous sudo rules..."
for rule in "vi" "vim" "nano" "find" "python" "perl" "cp" "tar"; do
    if grep -r "ALL=(ALL).*${rule}" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        log_warn "Dangerous sudo rule found involving: $rule"
    fi
done
echo "Manually review and remove dangerous sudo rules"
"""

    # System accounts with shells
    if f.check_id == "IDENT-002":
        return f"""
# {f.check_id}: {f.title}
# Set nologin shell for system accounts
echo "Setting nologin shell for system accounts..."
awk -F: '$3 < 1000 && $7 !~ /nologin|false/ {{print $1}}' /etc/passwd | while read user; do
    log_warn "Setting nologin for: $user"
    usermod -s /usr/sbin/nologin "$user" 2>/dev/null || echo "Could not modify $user"
done
"""

    # PASS_MAX_DAYS
    if f.check_id == "IDENT-010":
        return f"""
# {f.check_id}: {f.title}
# Set password max days to 90
echo "Setting PASS_MAX_DAYS to 90..."
if [ -f /etc/login.defs ]; then
    backup_file /etc/login.defs
    sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/' /etc/login.defs
fi
"""

    # PASS_MIN_DAYS
    if f.check_id == "IDENT-011":
        return f"""
# {f.check_id}: {f.title}
# Set password min days to 1
echo "Setting PASS_MIN_DAYS to 1..."
if [ -f /etc/login.defs ]; then
    backup_file /etc/login.defs
    sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS 1/' /etc/login.defs
fi
"""

    # PASS_WARN_AGE
    if f.check_id == "IDENT-012":
        return f"""
# {f.check_id}: {f.title}
# Set password warn age to 7
echo "Setting PASS_WARN_AGE to 7..."
if [ -f /etc/login.defs ]; then
    backup_file /etc/login.defs
    sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
fi
"""

    # Listening services
    if f.check_id == "NET-001":
        return f"""
# {f.check_id}: {f.title}
# Review and disable unnecessary listening services
echo "Reviewing listening services..."
echo "Check running services: systemctl list-units --type=service --state=running"
echo "Disable unnecessary services with: systemctl disable <service>"
"""

    # Firewall
    if f.check_id in ["NET-002", "NET-005", "NET-006"]:
        return f"""
# {f.check_id}: {f.title}
# Enable and configure firewall
echo "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw --force enable
    ufw default deny incoming
    ufw default allow outgoing
    log_info "UFW firewall enabled"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=https
    firewall-cmd --reload
    log_info "firewalld configured"
fi
"""

    # SUID binaries
    if f.check_id == "FS-001":
        return f"""
# {f.check_id}: {f.title}
# Review dangerous SUID binaries
echo "Reviewing SUID binaries..."
echo "Known dangerous SUID binaries: python, perl, bash, sh, nmap, vim, nano, etc."
echo "To remove SUID: chmod u-s <path>"
"""

    # World-writable files
    if f.check_id == "FS-003":
        return f"""
# {f.check_id}: {f.title}
# Fix world-writable files
echo "Finding world-writable files..."
find / -type f -perm -002 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -20
echo "To fix: chmod o-w <path>"
"""

    # Cron jobs
    if f.check_id == "FS-006":
        return f"""
# {f.check_id}: {f.title}
# Review cron jobs for malicious entries
echo "Reviewing cron jobs..."
ls -la /etc/cron.d/ /etc/cron.daily/ /etc/cron.hourly/ /etc/cron.monthly/ /etc/cron.weekly/ 2>/dev/null
echo "Check /var/spool/cron/ for user crons"
"""

    # Docker socket
    if f.check_id == "PROC-003":
        return f"""
# {f.check_id}: {f.title}
# Secure Docker socket
echo "Checking Docker socket permissions..."
if [ -S /var/run/docker.sock ]; then
    ls -la /var/run/docker.sock
    chmod 660 /var/run/docker.sock
    chown root:docker /var/run/docker.sock
fi
"""

    # AppArmor
    if f.check_id == "PROC-004":
        return f"""
# {f.check_id}: {f.title}
# Enable AppArmor
echo "Enabling AppArmor..."
if command -v aa-status &> /dev/null; then
    aa-status
    apparmor_parser -r /etc/apparmor.d/* 2>/dev/null
fi
"""

    # SELinux
    if f.check_id == "PROC-005":
        return f"""
# {f.check_id}: {f.title}
# Configure SELinux
echo "Configuring SELinux..."
if command -v getenforce &> /dev/null; then
    getenforce
    setenforce 1
    sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config 2>/dev/null
fi
"""

    # ASLR
    if f.check_id == "KERN-001":
        return f"""
# {f.check_id}: {f.title}
# Enable ASLR
echo "Enabling ASLR..."
echo 2 > /proc/sys/kernel/randomize_va_space
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
"""

    # dmesg restrict
    if f.check_id == "KERN-002":
        return f"""
# {f.check_id}: {f.title}
# Restrict dmesg
echo "Restricting dmesg access..."
echo 1 > /proc/sys/kernel/dmesg_restrict
echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.conf
"""

    # kptr restrict
    if f.check_id == "KERN-003":
        return f"""
# {f.check_id}: {f.title}
# Restrict kernel pointer visibility
echo "Restricting kernel pointers..."
echo 2 > /proc/sys/kernel/kptr_restrict
echo "kernel.kptr_restrict = 2" >> /etc/sysctl.conf
"""

    # ptrace scope
    if f.check_id == "KERN-004":
        return f"""
# {f.check_id}: {f.title}
# Restrict ptrace
echo "Restricting ptrace..."
echo 1 > /proc/sys/kernel/yama/ptrace_scope
echo "kernel.yama.ptrace_scope = 1" >> /etc/sysctl.conf
"""

    # auditd
    if f.check_id == "LOG-001":
        return f"""
# {f.check_id}: {f.title}
# Enable auditd
echo "Enabling auditd..."
if command -v systemctl &> /dev/null; then
    systemctl enable auditd
    systemctl start auditd
fi
"""

    # Remote logging
    if f.check_id == "LOG-013":
        return f"""
# {f.check_id}: {f.title}
# Configure remote logging
echo "Configuring remote logging..."
if [ -f /etc/rsyslog.conf ]; then
    backup_file /etc/rsyslog.conf
    echo "*.* @@logserver.example.com:514" >> /etc/rsyslog.conf
    systemctl restart rsyslog
fi
echo "Configure your syslog server address above"
"""

    # Pending updates
    if f.check_id == "PKG-001":
        return f"""
# {f.check_id}: {f.title}
# Apply pending security updates
echo "Applying security updates..."
apt update && apt upgrade -y
echo "Or for your distribution: yum update -y / dnf update -y"
"""

    # Untrusted repos
    if f.check_id == "PKG-003":
        return f"""
# {f.check_id}: {f.title}
# Review and remove untrusted repositories
echo "Checking package sources..."
ls -la /etc/apt/sources.list.d/ 2>/dev/null
cat /etc/apt/sources.list 2>/dev/null
echo "Remove untrusted repos: rm /etc/apt/sources.d/<file>"
"""

    # Weak SSH keys
    if f.check_id == "CRYPTO-001":
        return f"""
# {f.check_id}: {f.title}
# Regenerate weak SSH host keys
echo "Regenerating SSH host keys..."
ssh-keygen -A
systemctl restart sshd
"""

    # Default return for unhandled cases
    return f"""
# {f.check_id}: {f.title}
# Remediation: {f.remediation}
echo "Manual remediation needed for {f.check_id}"
echo "Finding: {f.title}"
echo "Remediation: {f.remediation}"
"""


def calculate_security_score(findings: list[Finding]) -> int:
    """Calculate a basic security score (0-100)."""
    if not findings:
        return 100

    deductions = {
        Severity.CRITICAL: 20,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }

    total_deduction = sum(deductions[f.severity] for f in findings)
    return max(0, 100 - total_deduction)


def run_reporting(context: AuditContext, findings: list[Finding]) -> dict:
    """Run reporting phase."""
    classified = classify_severity(findings)
    score = calculate_security_score(findings)

    return {
        "context": context,
        "findings": findings,
        "classified": classified,
        "score": score,
        "total_critical": len(classified["critical"]),
        "total_high": len(classified["high"]),
        "total_medium": len(classified["medium"]),
        "total_low": len(classified["low"]),
        "total_info": len(classified["info"]),
    }
