"""Security audit phases."""

from typing import TYPE_CHECKING

from .context import gather_context, get_system_info
from .crypto import run_crypto_checks
from .filesystem import run_filesystem_checks
from .identity import run_identity_checks
from .kernel import run_kernel_checks
from .logging import run_logging_checks
from .network import run_network_checks
from .packages import run_package_checks
from .process import run_process_checks
from .reporting import (
    calculate_security_score,
    classify_severity,
    generate_json_report,
    generate_markdown_report,
    generate_pdf_report,
    generate_remediation_script,
    run_reporting,
)

if TYPE_CHECKING:
    from ..core import AuditContext, Finding

__all__ = [
    "gather_context",
    "get_system_info",
    "run_identity_checks",
    "run_network_checks",
    "run_filesystem_checks",
    "run_process_checks",
    "run_kernel_checks",
    "run_logging_checks",
    "run_package_checks",
    "run_crypto_checks",
    "run_reporting",
    "generate_markdown_report",
    "generate_pdf_report",
    "generate_json_report",
    "generate_remediation_script",
    "calculate_security_score",
    "classify_severity",
]
