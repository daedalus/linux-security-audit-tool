"""Tests for the reporting phase."""

import pytest
from security_audit.phases.reporting import (
    classify_severity,
    generate_markdown_report,
    calculate_security_score,
    generate_remediation_script,
)
from security_audit.core import Finding, Severity, AuditContext


class TestClassifySeverity:
    """Tests for classify_severity function."""

    def test_classify_critical(self):
        """Test classification of CRITICAL findings."""
        findings = [
            Finding(
                severity=Severity.CRITICAL,
                check_id="TEST-001",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
        ]
        result = classify_severity(findings)
        assert len(result["critical"]) == 1
        assert len(result["high"]) == 0
        assert len(result["medium"]) == 0
        assert len(result["low"]) == 0

    def test_classify_all_severities(self):
        """Test classification with all severity levels."""
        findings = [
            Finding(
                severity=severity,
                check_id=f"TEST-{i}",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
            for i, severity in enumerate(Severity)
        ]
        result = classify_severity(findings)
        assert len(result["critical"]) == 1
        assert len(result["high"]) == 1
        assert len(result["medium"]) == 1
        assert len(result["low"]) == 1
        assert len(result["info"]) == 1


class TestCalculateSecurityScore:
    """Tests for calculate_security_score function."""

    def test_empty_findings_returns_100(self):
        """Test that empty findings return score of 100."""
        score = calculate_security_score([])
        assert score == 100

    def test_critical_deductions(self):
        """Test that CRITICAL findings deduct 20 points."""
        findings = [
            Finding(
                severity=Severity.CRITICAL,
                check_id="TEST-001",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
        ]
        score = calculate_security_score(findings)
        assert score == 80

    def test_high_deductions(self):
        """Test that HIGH findings deduct 10 points."""
        findings = [
            Finding(
                severity=Severity.HIGH,
                check_id="TEST-001",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
        ]
        score = calculate_security_score(findings)
        assert score == 90

    def test_multiple_findings(self):
        """Test score with multiple findings."""
        findings = [
            Finding(
                severity=Severity.CRITICAL,
                check_id="TEST-001",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            ),
            Finding(
                severity=Severity.HIGH,
                check_id="TEST-002",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            ),
        ]
        score = calculate_security_score(findings)
        assert score == 70

    def test_score_capped_at_zero(self):
        """Test that score doesn't go below zero."""
        findings = [
            Finding(
                severity=Severity.CRITICAL,
                check_id=f"TEST-{i}",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
            for i in range(10)
        ]
        score = calculate_security_score(findings)
        assert score == 0


class TestGenerateMarkdownReport:
    """Tests for generate_markdown_report function."""

    def test_generate_report_empty(self):
        """Test generating report with no findings."""
        context = AuditContext(hostname="test-host")
        report = generate_markdown_report(context, [])
        assert "test-host" in report
        assert "Critical | 0" in report

    def test_generate_report_with_findings(self):
        """Test generating report with findings."""
        context = AuditContext(hostname="test-host")
        findings = [
            Finding(
                severity=Severity.CRITICAL,
                check_id="TEST-001",
                title="Test Finding",
                description="Test description",
                evidence="Test evidence",
                impact="Test impact",
                remediation="Test fix",
                phase="Test Phase",
            )
        ]
        report = generate_markdown_report(context, findings)
        assert "TEST-001" in report
        assert "Test Finding" in report
        assert "Critical | 1" in report


class TestGenerateRemediationScript:
    """Tests for generate_remediation_script function."""

    def test_generate_script_basic(self):
        """Test basic script generation."""
        findings = [
            Finding(
                severity=Severity.CRITICAL,
                check_id="TEST-001",
                title="Test",
                description="Test",
                evidence="Test",
                impact="Test",
                remediation="Test",
                phase="Test",
            )
        ]
        script = generate_remediation_script(findings)
        assert "#!/bin/bash" in script
        assert "Security Audit Remediation Script" in script
