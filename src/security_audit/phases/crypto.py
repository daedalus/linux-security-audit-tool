"""Phase 8 - Cryptographic Posture module."""

from ..core import Finding, Severity, run_command


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

    return findings


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

    return findings


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


def run_crypto_checks() -> list[Finding]:
    """Run all cryptographic posture checks."""
    findings = []

    findings.extend(check_weak_ssh_keys())
    findings.extend(check_tls_configuration())
    findings.extend(check_ssl_certificates())
    findings.extend(check_entropy_available())
    findings.extend(check_gpg_keys())
    findings.extend(check_password_hashing())

    return findings
