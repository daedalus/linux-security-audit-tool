"""Linux Security Audit Tool - Comprehensive security auditing and hardening."""

__version__ = "0.1.2"

from typing import TYPE_CHECKING

from .core import AuditContext, Finding, Severity
from .phases import (
    calculate_security_score,
    classify_severity,
    gather_context,
    generate_markdown_report,
    generate_remediation_script,
    get_system_info,
    run_crypto_checks,
    run_filesystem_checks,
    run_identity_checks,
    run_kernel_checks,
    run_logging_checks,
    run_network_checks,
    run_package_checks,
    run_process_checks,
    run_reporting,
)

if TYPE_CHECKING:
    from .cli import cli

__all__ = [
    "__version__",
    "AuditContext",
    "Finding",
    "Severity",
    "calculate_security_score",
    "classify_severity",
    "gather_context",
    "generate_markdown_report",
    "generate_remediation_script",
    "get_system_info",
    "run_crypto_checks",
    "run_filesystem_checks",
    "run_identity_checks",
    "run_kernel_checks",
    "run_logging_checks",
    "run_network_checks",
    "run_package_checks",
    "run_process_checks",
    "run_reporting",
]
