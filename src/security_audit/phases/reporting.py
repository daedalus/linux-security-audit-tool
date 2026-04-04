"""Phase 9 - Reporting & Remediation module."""

from datetime import datetime

from ..core import AuditContext, Finding, Severity


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

set -euo pipefail

"""

    critical_fixes = [f for f in findings if f.severity == Severity.CRITICAL]

    for f in critical_fixes:
        if "NOPASSWD" in f.title:
            script += f"""
# {f.check_id}: {f.title}
# Review and remove NOPASSWD rules from sudoers
echo "Review sudoers for NOPASSWD rules"
"""

        if "Empty Password" in f.title:
            script += f"""
# {f.check_id}: {f.title}
# Set passwords for accounts with empty passwords
echo "Set passwords for accounts with empty passwords"
"""

        if "UID 0" in f.title:
            script += f"""
# {f.check_id}: {f.title}
# Remove duplicate UID 0 accounts
echo "Review and remove unauthorized UID 0 accounts"
"""

    script += """
echo "Review above items and apply manually as needed"
"""

    return script


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
