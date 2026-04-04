# SPEC.md — linux-security-audit-tool

## Purpose

A comprehensive CLI tool for auditing Linux system security posture. It performs security checks across 9 phases (identity, network, filesystem, process, kernel, logging, packages, crypto, reporting) and generates detailed security reports with findings classified by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO).

## Scope

### What IS in scope
- CLI interface with Rich console output
- 9-phase security audit (Phase 0-9)
- Finding classification and severity scoring
- Markdown report generation
- Phase selection (run specific phases)
- Quiet mode for summary-only output

### What is NOT in scope
- GUI interface
- Web API
- Auto-remediation (manual remediation only)
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
  --output, -o PATH    Output file for markdown report
  --phases, -p TEXT    Specific phases to run (0-9), can repeat
  --quiet, -q          Suppress detailed output
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
    calculate_security_score,
)
from security_audit.utils import Finding, Severity, AuditContext
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
- Dependencies: click, rich, jinja2, tabulate only

## Audit Phases

### Phase 0: Context Gathering
- Hostname, OS release, kernel version
- Uptime, virtualization detection
- System role (server/workstation/container)

### Phase 1: Identity & Access Control
- UID 0 accounts
- System accounts with shells
- Empty passwords
- Sudo NOPASSWD rules
- SSH root login
- Password authentication
- Privileged groups (sudo, docker, lxd)

### Phase 2: Network Exposure
- Listening services (ss/netstat)
- Firewall status (iptables/nftables/ufw/firewalld)
- sysctl network hardening
- Unnecessary services

### Phase 3: File System & Permissions
- SUID/SGID binaries
- World-writable files/directories
- Unowned files
- Critical file permissions (/etc/shadow, /etc/sudoers)
- Cron jobs

### Phase 4: Process & Service Posture
- Running services
- Docker socket
- AppArmor status
- SELinux status

### Phase 5: Kernel & OS Hardening
- ASLR (address space layout randomization)
- dmesg_restrict
- kptr_restrict
- ptrace_scope
- suid_dumpable
- protected_symlinks/hardlinks
- Kernel module blacklist

### Phase 6: Logging & Monitoring
- auditd status
- Audit rules
- Log permissions
- Failed logins
- logrotate configuration

### Phase 7: Package & Update Hygiene
- Pending security updates
- Last package update time
- Untrusted repositories
- Unnecessary packages
- Deprecated packages

### Phase 8: Cryptographic Posture
- SSH host key strength
- TLS configuration
- SSL certificate expiry
- Entropy availability
- GPG keys
- Password hashing

### Phase 9: Reporting & Remediation
- Finding classification
- Security score calculation
- Markdown report generation
- Remediation checklist