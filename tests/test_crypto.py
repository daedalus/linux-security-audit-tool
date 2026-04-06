"""Tests for the crypto phase."""

import pytest
from unittest.mock import patch
from security_audit.phases.crypto import (
    check_weak_ssh_keys,
    check_tls_configuration,
    check_ssl_certificates,
    check_entropy_available,
    check_gpg_keys,
    check_password_hashing,
    check_ssh_key_exchange,
    check_ssh_ciphers,
    check_password_quality,
    check_disk_encryption,
    run_crypto_checks,
)
from security_audit.core import Severity


class TestCheckWeakSSHKeys:
    """Tests for check_weak_ssh_keys."""

    @patch("security_audit.phases.crypto.run_command")
    def test_weak_rsa_key(self, mock_run):
        """Test when weak RSA key found."""
        mock_run.return_value = ("1024 SHA256:abc123", "", 0)
        findings = check_weak_ssh_keys()
        assert len(findings) >= 1

    @patch("security_audit.phases.crypto.run_command")
    def test_dsa_key_found(self, mock_run):
        """Test when DSA key found."""
        mock_run.side_effect = [
            ("4096 SHA256:abc", "", 0),
            ("4096 SHA256:def", "", 0),
            ("", "", 1),
            ("256 SHA256:ghi", "", 0),
            ("", "", 1),
        ]
        findings = check_weak_ssh_keys()
        assert any(f.check_id == "CRYPTO-002" for f in findings)

    @patch("security_audit.phases.crypto.run_command")
    def test_weak_ecdsa_key(self, mock_run):
        """Test when weak ECDSA key found."""
        mock_run.side_effect = [
            ("4096 SHA256:abc", "", 0),
            ("", "", 1),
            ("128 SHA256:def", "", 0),
            ("", "", 1),
        ]
        findings = check_weak_ssh_keys()
        assert any(f.check_id == "CRYPTO-002A" for f in findings)

    @patch("security_audit.phases.crypto.run_command")
    def test_no_ed25519_key(self, mock_run):
        """Test when no Ed25519 key found."""
        mock_run.side_effect = [
            ("4096 SHA256:abc", "", 0),
            ("", "", 1),
            ("256 SHA256:def", "", 0),
            ("", "", 1),
        ]
        findings = check_weak_ssh_keys()
        assert any(f.check_id == "CRYPTO-002B" for f in findings)


class TestCheckTLSConfiguration:
    """Tests for check_tls_configuration."""

    @patch("security_audit.phases.crypto.run_command")
    def test_no_tls_config(self, mock_run):
        """Test when no TLS configuration found."""
        mock_run.side_effect = [
            ("", "", 1),
            ("", "", 1),
        ]
        findings = check_tls_configuration()
        assert len(findings) == 0

    @patch("security_audit.phases.crypto.run_command")
    def test_weak_tls_cipher(self, mock_run):
        """Test when weak TLS cipher found."""
        mock_run.side_effect = [
            ("", "", 1),
            ("SSLCipherSuite RC4", "", 0),
        ]
        findings = check_tls_configuration()
        assert any(f.check_id == "CRYPTO-003A" for f in findings)


class TestCheckEntropyAvailable:
    """Tests for check_entropy_available."""

    @patch("security_audit.phases.crypto.run_command")
    def test_low_entropy(self, mock_run):
        """Test when entropy is low."""
        mock_run.return_value = ("100", "", 0)
        findings = check_entropy_available()
        assert len(findings) == 1
        assert findings[0].check_id == "CRYPTO-005"

    @patch("security_audit.phases.crypto.run_command")
    def test_good_entropy(self, mock_run):
        """Test when entropy is good."""
        mock_run.return_value = ("256", "", 0)
        findings = check_entropy_available()
        assert len(findings) == 0


class TestCheckPasswordHashing:
    """Tests for check_password_hashing."""

    @patch("security_audit.phases.crypto.run_command")
    def test_weak_hash_md5(self, mock_run):
        """Test when MD5 hashing detected."""
        mock_run.return_value = ("ENCRYPT_METHOD md5", "", 0)
        findings = check_password_hashing()
        assert len(findings) == 1
        assert findings[0].check_id == "CRYPTO-007"


class TestRunCryptoChecks:
    """Tests for run_crypto_checks."""

    @patch("security_audit.phases.crypto.run_command")
    def test_run_crypto_checks_returns_list(self, mock_run):
        """Test that run_crypto_checks returns a list."""
        mock_run.return_value = ("", "", 1)
        findings = run_crypto_checks()
        assert isinstance(findings, list)
