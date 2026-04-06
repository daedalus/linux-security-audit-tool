"""Phase 8 - Cryptographic Posture module."""

from ..core import Finding, Severity, cached_check, run_command


@cached_check("check_weak_ssh_keys")
def check_weak_ssh_keys() -> list[Finding]:
    """Check SSH host key strength."""
    findings = []

    stdout, _, rc = run_command(
        "ssh-keygen -l -f /etc/ssh/ssh_host_rsa_key.pub 2>/dev/null"
    )
    if rc == 0 and stdout:
        parts = stdout.split()
        if len(parts) >= 1:
            key_size = int(parts[0])
            if key_size < 2048:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="CRYPTO-001",
                        title="Weak SSH RSA Key",
                        description=f"RSA key size: {key_size} bits (minimum 2048)",
                        evidence=stdout,
                        impact="Key can be broken with modern computing resources",
                        remediation="Regenerate SSH host keys: ssh-keygen -t rsa -b 4096",
                        phase="Phase 8",
                    )
                )

    stdout, _, rc = run_command(
        "ssh-keygen -l -f /etc/ssh/ssh_host_dsa_key.pub 2>/dev/null"
    )
    if rc == 0 and stdout:
        findings.append(
            Finding(
                severity=Severity.HIGH,
                check_id="CRYPTO-002",
                title="DSA SSH Key In Use",
                description="DSA keys are deprecated",
                evidence=stdout,
                impact="DSA keys have known weaknesses",
                remediation="Regenerate with ECDSA or Ed25519",
                phase="Phase 8",
            )
        )

    stdout, _, rc = run_command(
        "ssh-keygen -l -f /etc/ssh/ssh_host_ecdsa_key.pub 2>/dev/null"
    )
    if rc == 0 and stdout:
        parts = stdout.split()
        if len(parts) >= 1:
            key_size = int(parts[0])
            if key_size < 256:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="CRYPTO-002A",
                        title="Weak SSH ECDSA Key",
                        description=f"ECDSA key size: {key_size} bits (minimum 256)",
                        evidence=stdout,
                        impact="Small ECDSA keys may be vulnerable",
                        remediation="Regenerate SSH host keys: ssh-keygen -t ecdsa -b 521",
                        phase="Phase 8",
                    )
                )

    stdout, _, rc = run_command(
        "ssh-keygen -l -f /etc/ssh/ssh_host_ed25519_key.pub 2>/dev/null"
    )
    if rc != 0:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="CRYPTO-002B",
                title="No SSH Ed25519 Key",
                description="No Ed25519 host key found",
                evidence="ssh_host_ed25519_key.pub not found",
                impact="Ed25519 is recommended for better security",
                remediation="Generate Ed25519 key: ssh-keygen -t ed25519",
                phase="Phase 8",
            )
        )

    return findings


@cached_check("check_tls_configuration")
def check_tls_configuration() -> list[Finding]:
    """Check for weak TLS configuration."""
    findings = []

    weak_protocols = ["ssl2", "ssl3", "tls1.0", "tls1.1"]

    stdout, _, rc = run_command(
        "grep -r 'SSLProtocol\\|TLSProtocol' /etc/apache2 /etc/nginx 2>/dev/null"
    )
    if rc == 0 and stdout:
        for proto in weak_protocols:
            if proto in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        check_id="CRYPTO-003",
                        title=f"Weak TLS Protocol Enabled: {proto}",
                        description=f"Weak TLS protocol {proto} is enabled",
                        evidence=stdout,
                        impact="Vulnerable to protocol downgrade attacks",
                        remediation="Disable weak protocols in web server config",
                        phase="Phase 8",
                    )
                )

    weak_ciphers = ["exp-null", "RC4", "3des", "aes128-md5", "aes256-md5"]

    stdout, _, rc = run_command(
        "grep -r 'SSLCipherSuite\\|ssl_ciphers' /etc/apache2 /etc/nginx 2>/dev/null"
    )
    if rc == 0 and stdout:
        for cipher in weak_ciphers:
            if cipher.lower() in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="CRYPTO-003A",
                        title=f"Weak TLS Cipher: {cipher}",
                        description=f"Weak TLS cipher {cipher} is configured",
                        evidence=stdout,
                        impact="Weak cryptographic cipher in use",
                        remediation="Use strong ciphers (e.g., AES-GCM, ChaCha20)",
                        phase="Phase 8",
                    )
                )

    return findings


@cached_check("check_ssl_certificates")
def check_ssl_certificates() -> list[Finding]:
    """Check SSL certificate expiry."""
    findings = []

    stdout, _, rc = run_command(
        "find /etc/ssl/certs -name '*.pem' -type f 2>/dev/null | head -10"
    )
    if rc == 0 and stdout:
        for cert in stdout.strip().split("\n"):
            expiry, _, _ = run_command(
                f"openssl x509 -noout -enddate -in {cert} 2>/dev/null"
            )
            if expiry and "notAfter" in expiry:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        check_id="CRYPTO-004",
                        title="SSL Certificate Info",
                        description=f"Certificate: {cert}",
                        evidence=expiry,
                        impact="Certificate expiration tracking",
                        remediation="Renew certificates before expiry",
                        phase="Phase 8",
                    )
                )

    return findings


@cached_check("check_entropy_available")
def check_entropy_available() -> list[Finding]:
    """Check available entropy."""
    findings = []

    stdout, _, rc = run_command("cat /proc/sys/kernel/random/entropy_avail 2>/dev/null")
    if rc == 0:
        entropy = int(stdout.strip() or 0)
        if entropy < 256:
            findings.append(
                Finding(
                    severity=Severity.LOW,
                    check_id="CRYPTO-005",
                    title="Low Entropy Available",
                    description=f"Available entropy: {entropy}",
                    evidence=f"entropy_avail = {entropy}",
                    impact="Cryptographic operations may use blocking /dev/random",
                    remediation="Install haveged or rng-tools",
                    phase="Phase 8",
                )
            )

    return findings


@cached_check("check_gpg_keys")
def check_gpg_keys() -> list[Finding]:
    """Check GPG keys on the system."""
    findings = []

    stdout, _, rc = run_command("gpg --list-keys 2>/dev/null | head -20")
    if rc == 0 and stdout and stdout.strip():
        findings.append(
            Finding(
                severity=Severity.INFO,
                check_id="CRYPTO-006",
                title="GPG Keys Found",
                description="GPG keys present on system",
                evidence=f"{len(stdout.split(chr(10)))} keys",
                impact="Review keys for security",
                remediation="Remove unnecessary GPG keys",
                phase="Phase 8",
            )
        )

    return findings


@cached_check("check_password_hashing")
def check_password_hashing() -> list[Finding]:
    """Check password hashing algorithm."""
    findings = []

    stdout, _, rc = run_command(
        "grep -E '^crypt_style|^ENCRYPT_METHOD' /etc/login.defs 2>/dev/null"
    )
    if rc == 0 and stdout:
        if "md5" in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    check_id="CRYPTO-007",
                    title="Weak Password Hashing",
                    description="MD5 password hashing detected",
                    evidence=stdout,
                    impact="Passwords vulnerable to rainbow table attacks",
                    remediation="Use SHA-512 hashing: SHA512_CRYPT_ABTERR in login.defs",
                    phase="Phase 8",
                )
            )

    return findings


@cached_check("check_ssh_key_exchange")
def check_ssh_key_exchange() -> list[Finding]:
    """Check SSH key exchange algorithms."""
    findings = []

    weak_kex = ["diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"]

    stdout, _, rc = run_command(
        "grep -r 'KexAlgorithms\\|Ciphers\\|MACs' /etc/ssh/sshd_config 2>/dev/null"
    )
    if rc == 0 and stdout:
        for alg in weak_kex:
            if alg in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="CRYPTO-008",
                        title=f"Weak SSH Key Exchange: {alg}",
                        description=f"Weak key exchange algorithm {alg} is configured",
                        evidence=stdout,
                        impact="Vulnerable to attacks on key exchange",
                        remediation="Remove weak key exchange algorithms from sshd_config",
                        phase="Phase 8",
                    )
                )
    else:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="CRYPTO-009",
                title="SSH Key Exchange Not Restricted",
                description="No explicit key exchange algorithm restrictions found",
                evidence="No KexAlgorithms in sshd_config",
                impact="May allow weak key exchange algorithms",
                remediation="Add KexAlgorithms to restrict key exchange",
                phase="Phase 8",
            )
        )

    return findings


@cached_check("check_ssh_ciphers")
def check_ssh_ciphers() -> list[Finding]:
    """Check SSH ciphers and MACs."""
    findings = []

    weak_ciphers = ["3des", "blowfish", "cast128", "arcfour"]

    stdout, _, rc = run_command(
        "grep -r 'Ciphers\\|MACs' /etc/ssh/sshd_config 2>/dev/null"
    )
    if rc == 0 and stdout:
        for cipher in weak_ciphers:
            if cipher in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        check_id="CRYPTO-010",
                        title=f"Weak SSH Cipher: {cipher}",
                        description=f"Weak cipher {cipher} is configured",
                        evidence=stdout,
                        impact="Weak cryptographic cipher in use",
                        remediation="Remove weak ciphers from sshd_config",
                        phase="Phase 8",
                    )
                )
    else:
        findings.append(
            Finding(
                severity=Severity.LOW,
                check_id="CRYPTO-011",
                title="SSH Ciphers Not Restricted",
                description="No explicit cipher restrictions found",
                evidence="No Ciphers in sshd_config",
                impact="May allow weak ciphers",
                remediation="Add Ciphers to restrict allowed ciphers",
                phase="Phase 8",
            )
        )

    return findings


@cached_check("check_password_quality")
def check_password_quality() -> list[Finding]:
    """Check password quality via PAM configuration."""
    findings = []

    stdout, _, rc = run_command(
        "grep -r -E 'password.*requisite|password.*required' /etc/pam.d/* 2>/dev/null | grep -iE 'pam_unix.so|pam_pwquality.so|pam_cracklib.so'"
    )
    if rc != 0 or not stdout:
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                check_id="CRYPTO-012",
                title="PAM Password Quality Not Enforced",
                description="No password quality checks in PAM configuration",
                evidence="No pwquality or cracklib in pam.d",
                impact="Users can set weak passwords",
                remediation="Configure pam_pwquality or pam_cracklib in PAM",
                phase="Phase 8",
            )
        )

    return findings


@cached_check("check_disk_encryption")
def check_disk_encryption() -> list[Finding]:
    """Check disk encryption status."""
    findings = []

    stdout, _, rc = run_command("cryptsetup luksDump /dev/sda2 2>/dev/null")
    if rc == 0 and stdout:
        if "is not LUKS" not in stdout:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    check_id="CRYPTO-013",
                    title="LUKS Encryption Detected",
                    description="Disk encryption (LUKS) is configured",
                    evidence="LUKS header found",
                    impact="Data protected at rest",
                    remediation="Ensure encryption is used for sensitive partitions",
                    phase="Phase 8",
                )
            )
    else:
        stdout, _, _ = run_command("ls -la /dev/mapper/ 2>/dev/null")
        if stdout and "crypt" in stdout.lower():
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    check_id="CRYPTO-014",
                    title="Encrypted Volumes Present",
                    description="Encrypted volume mappings found",
                    evidence=stdout,
                    impact="Some volumes are encrypted",
                    remediation="Ensure all sensitive data is encrypted",
                    phase="Phase 8",
                )
            )

    return findings


def run_crypto_checks() -> list[Finding]:
    """Run all cryptographic posture checks."""
    findings = []

    findings.extend(check_weak_ssh_keys())
    findings.extend(check_tls_configuration())
    findings.extend(check_ssl_certificates())
    findings.extend(check_entropy_available())
    findings.extend(check_gpg_keys())
    findings.extend(check_password_hashing())
    findings.extend(check_ssh_key_exchange())
    findings.extend(check_ssh_ciphers())
    findings.extend(check_password_quality())
    findings.extend(check_disk_encryption())

    return findings
