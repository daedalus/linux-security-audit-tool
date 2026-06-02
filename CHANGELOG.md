# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **FS-016**: Linux capabilities(7) audit via `getcap -r /`. Binaries with
  escalation-capable capabilities (cap_setuid, cap_sys_admin, cap_dac_override,
  etc.) are flagged HIGH; noteworthy capabilities (cap_net_raw,
  cap_net_bind_service, etc.) are flagged MEDIUM. This fills a blind spot where
  SUID-equivalent privilege granularity was invisible to the tool.
  See `ESCALATION_CAPS` and `NOTEWORTHY_CAPS` in `filesystem.py`.

### Fixed

- **IDENT-001**: Skip canonical `root` UID-0 entry; only flag additional UID-0
  accounts. Collapse multiple extra accounts into a single finding instead of
  duplicating the check_id per entry.
- **NET-001**: Differentiate severity by port. Well-known ports (22, 80, 443,
  8443\) produce INFO; sensitive ports (23, 514, 3306, 5432, 6379, 27017, 9200)
  produce HIGH; all others remain MEDIUM. Exposed as `EXPECTED_PORTS` /
  `SENSITIVE_PORTS` module-level sets for runtime overrides.
- **shell=True**: Added list-form argument support to `run_command`. User/machine
  supplied paths in `check_unauthorized_ssh_keys`, `check_ssh_private_key_permissions`,
  `check_apache_insecure_config`, `check_nginx_insecure_config`, and filesystem
  phase checks are now passed as argument lists (`shell=False`) to prevent
  shell injection on interpolated paths.
- **check_password_expiry**: Removed redundant `sudo` prefix — the tool already
  requires root, so `sudo awk ...` would break in environments without sudo
  configured for the root shell.

### Added

- **NET-001 tests**: Coverage for expected-port (INFO), sensitive-port (HIGH),
  and unknown-port (MEDIUM) severity tiers.
- **IDENT-001 tests**: Coverage for single-root (skipped) and multi-UID-0 (flagged)
  scenarios.
- **run_command list-args tests**: Coverage for `shell=False` path with special
  characters.

## [0.1.9] - 2026-06-02

### Added

- CIS/DISA hardening checks: SSH PermitEmptyPasswords, PubkeyAuthentication,
  MaxAuthTries, BPF JIT.

## [0.1.8] - 2026-06-01

### Added

- Various security checks; lint and type-error fixes; documentation updates.

## [0.1.7] - 2026-05-31

### Added

- `check_last_full_update`; duplicate sysctl check removal.
- Open-to-world service checks: FTP anonymous access, NFS world-accessible
  shares, Samba guest access, Apache/Nginx insecure configuration.

## [0.1.6] - 2026-05-30

### Added

- Network hardening checks; boot security checks; TPM checks.
- JSON report generation.

## [0.1.5] - 2026-05-29

### Added

- Caching support; remote logging check improvements; full remediation scripts.

## [0.1.4] - 2026-05-28

### Added

- PAM lockout checks; session timeout checks; umask checks; NTP checks;
  mount option checks.

## [0.1.3] - 2026-05-27

### Added

- Process analysis phase; kernel parameter auditing; filesystem permission checks.

## [0.1.2] - 2026-05-26

### Added

- Identity phase (user/group/SSH auditing); network exposure phase (port
  scanning, firewall checks); crypto policy checks; HTML/PDF reporting.

## [0.1.1] - 2026-05-25

### Added

- CLI interface with Click; Rich-based output formatting; package phase
  (vulnerability scanning).

## [0.1.0] - 2026-05-24

### Added

- Initial release: project scaffolding, core audit engine, `run_command`
  utility, `Finding`/`Severity` models.

[0.1.0]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.0
[0.1.1]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.1
[0.1.2]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.2
[0.1.3]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.3
[0.1.4]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.4
[0.1.5]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.5
[0.1.6]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.6
[0.1.7]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.7
[0.1.8]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.8
[0.1.9]: https://github.com/daedalus/linux-security-audit-tool/releases/tag/v0.1.9
