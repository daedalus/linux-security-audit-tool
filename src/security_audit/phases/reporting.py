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
