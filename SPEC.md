# SPEC.md — linux-security-audit-tool

## Purpose

A comprehensive CLI tool for auditing Linux system security posture. It performs security checks across 9 phases (identity, network, filesystem, process, kernel, logging, packages, crypto, reporting) and generates detailed security reports with findings classified by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO).

## Scope

### What IS in scope
- CLI interface with Rich console output
- 9-phase security audit (Phase 0-9)
- Finding classification and severity scoring
- Markdown report generation
- PDF executive report generation
- Remediation script generation
- Phase selection (run specific phases)
- Quiet mode for summary-only output
- Verbose mode for detailed output
- Debug mode for low-level command output
- Auto-remediation support (generation of remediation scripts)
- Check result caching with configurable TTL (default 3600s)

### What is NOT in scope
- GUI interface
- Web API
- Real-time monitoring
- Cloud security scanning (AWS/GCP/Azure)
- Network vulnerability scanning of external hosts

## Public API / Interface

### CLI Commands

```bash
security-audit [OPTIONS] COMMAND [ARGS]
```

#### audit command
```bash
security-audit audit [OPTIONS]
  --output, -o PATH          Output file for markdown report
  --json, -j PATH           Output file for JSON report
  --phases, -p TEXT         Specific phases to run (0-9), can repeat
  --quiet, -q               Suppress detailed output
  --verbose, -v             Show detailed output including descriptions and remediation
  --debug, -d               Show debug output with low-level commands being executed
  --remediate-all, -r       Apply automatic remediations for all findings
  --remediate-only-critical Apply automatic remediations for CRITICAL findings only
  --remediate-non-critical  Apply automatic remediations for non-CRITICAL findings
  --remediate-script PATH   Save remediation script to file
  --pdf, -pdf PATH          Generate PDF executive report
  --cache                   Enable caching of check results
  --cache-ttl INTEGER       Cache TTL in seconds (default: 3600)
```

#### version command
```bash
security-audit version
  Show version information
```

### Python API

```python
from security_audit import __version__
from security_audit.phases import (
    gather_context,
    run_identity_checks,
    run_network_checks,
    run_filesystem_checks,
    run_process_checks,
    run_kernel_checks,
    run_logging_checks,
    run_package_checks,
    run_crypto_checks,
    run_reporting,
    generate_markdown_report,
    generate_pdf_report,
    generate_json_report,
    generate_remediation_script,
    calculate_security_score,
    classify_severity,
)
from security_audit.core import Finding, Severity, AuditContext
```

### Data Structures

#### Finding
- `severity: Severity` - CRITICAL, HIGH, MEDIUM, LOW, INFO
- `check_id: str` - Unique identifier (e.g., "IDENT-001")
- `title: str` - Short title
- `description: str` - Detailed description
- `evidence: str` - Command output or evidence
- `impact: str` - Security impact
- `remediation: str` - Recommended fix
- `phase: str` - Phase name (e.g., "Phase 1")

#### Severity (Enum)
- CRITICAL - Direct root compromise
- HIGH - Easy privilege escalation
- MEDIUM - Increased attack surface
- LOW - Defense-in-depth gap
- INFO - Non-security hygiene

#### AuditContext
- `hostname: str`
- `os_release: str`
- `kernel: str`
- `uptime: str`
- `virtualization: str`
- `is_container: bool`
- `is_server: bool`
- `findings: List[Finding]`

## Data Formats

### Input
- System commands via subprocess
- File system reads (/etc/passwd, /etc/shadow, etc.)
- sysctl parameter queries

### Output
- Console output (Rich formatted)
- Markdown report (UTF-8)
- PDF report (via weasyprint)
- JSON report (optional)

## Edge Cases

1. **Root access not available**: Many checks require root; gracefully skip with warning
2. **Command timeout**: Long-running commands timeout after 30s
3. **File not found**: Skip checks for missing files (e.g., no auditd installed)
4. **Container environment**: Detect container and adjust checks appropriately
5. **Empty output**: Handle empty command output gracefully
6. **Permission denied**: Handle permission errors without crashing
7. **Unicode in output**: Handle non-ASCII characters in file content

## Performance & Constraints

- O(n) for file searches - limited to find with early termination
- Command timeout: 30 seconds max
- Memory: Minimal - streaming output, no large data structures
- Dependencies: click, rich, weasyprint only

## Audit Phases

### Phase 0: Context Gathering
- Hostname, OS release, kernel version
- Uptime, virtualization detection
- System role (server/workstation/container)

### Phase 1: Identity & Access Control (17 checks)
- UID 0 accounts
- System accounts with shells
- Empty passwords
- Sudo NOPASSWD rules
- Sudo wildcard abuse (vi, nano, find, etc.)
- SSH root login
- Password authentication
- Privileged groups (sudo, docker, lxd)
- Password policy (max days, min days, warn age)
- Password expiry status
- Locked accounts with valid shells
- SSH authorized keys
- /etc/group modification detection
- PAM account lockout policy (pam_faillock / pam_tally2)
- Idle session timeout (TMOUT)
- Default umask (should be 027 or more restrictive)
- SSH X11Forwarding configuration

### Phase 2: Network Exposure (15 checks)
- Listening services (ss/netstat)
- Firewall status (iptables/nftables/ufw/firewalld)
- UFW firewall status and rules
- Firewalld firewall status and rules
- sysctl network hardening (IPv4)
- sysctl network hardening (IPv6)
- Unnecessary services
- ICMP broadcast protection
- Source packet routing
- NTP time synchronization (systemd-timesyncd / chronyd / ntpd)
- Open proxy detection
- Open relay detection
- FTP anonymous access
- NFS world-accessible shares
- Samba guest access
- Apache insecure configuration
- Nginx insecure configuration

### Phase 3: File System & Permissions (13 checks)
- SUID/SGID binaries
- World-writable files/directories
- World-writable directories without sticky bit
- Unowned files
- Critical file permissions (/etc/shadow, /etc/sudoers, /etc/gshadow)
- Cron jobs
- SSH private key permissions
- Sensitive files in /tmp
- Backup files detection (.bak, .old, .swp)
- Sudoers file integrity
- Security mount options (/tmp, /var/tmp, /dev/shm, /home)
- at jobs permissions (/etc/at.allow, /etc/at.deny)

### Phase 4: Process & Service Posture (11 checks)
- Running services
- Enabled services at boot
- Docker socket
- AppArmor status
- SELinux status
- Unnecessary network services (telnet, rsh, finger, cups, avahi, bluetooth, ypbind, etc.)
- Systemd timers
- Seccomp profile status
- Service file permissions
- SysV init scripts
- rkhunter installation and configuration

### Phase 5: Kernel & OS Hardening (25 checks)
- ASLR (address space layout randomization)
- dmesg_restrict
- kptr_restrict
- ptrace_scope
- suid_dumpable
- protected_symlinks/hardlinks
- Kernel module blacklist
- SysRq key status
- ICMP broadcast ignore
- VM swappiness
- Kernel panic on oops
- User namespace restrictions
- AppArmor sshd profile enforcement
- IP forwarding (should be disabled)
- Reverse path filtering
- ICMP redirects (should be disabled)
- TCP SYN cookies (should be enabled)
- Source routing (should be disabled)
- Martian packet logging (should be enabled)
- SELinux/AppArmor enforcing mode
- GRUB password protection
- Full disk encryption (LUKS)
- TPM attestation
- SecureBoot status

### Phase 6: Logging & Monitoring (11 checks)
- auditd status
- Audit rules
- Audit rules for sensitive files (/etc/passwd, /etc/shadow)
- Log permissions (auth.log, secure)
- Log file ownership (should be root:adm)
- Failed logins
- Failed SSH attempts
- logrotate configuration
- syslog configuration (rsyslog/syslog-ng)
- Journald persistence
- Remote logging configuration (syslog forwarding to external system)

### Phase 7: Package & Update Hygiene (6 checks)
- Pending security updates
- Last package update time
- Last full system update
- Untrusted repositories
- Unnecessary packages
- Deprecated packages

### Phase 8: Cryptographic Posture (10 checks)
- SSH host key strength (RSA, DSA, ECDSA, Ed25519)
- SSH key exchange algorithms
- SSH ciphers and MACs
- TLS configuration and weak ciphers
- SSL certificate expiry
- Entropy availability
- GPG keys
- Password hashing algorithm
- Password quality (PAM configuration)
- Disk encryption status (LUKS)

### Phase 9: Reporting & Remediation
- Finding classification
- Security score calculation
- Markdown report generation
- PDF executive report generation
- JSON report generation
- Remediation script generation
- Remediation checklist