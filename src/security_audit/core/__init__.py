"""Security audit core models and utilities."""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Security finding severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Finding:
    """Represents a security finding from an audit check.

    Attributes:
        severity: The severity level of the finding.
        check_id: Unique identifier for the check (e.g., "IDENT-001").
        title: Short descriptive title of the finding.
        description: Detailed description of what was found.
        evidence: Command output or evidence supporting the finding.
        impact: Description of the security impact.
        remediation: Recommended remediation steps.
        phase: The audit phase where this finding was generated.
    """

    severity: Severity
    check_id: str
    title: str
    description: str
    evidence: str
    impact: str
    remediation: str
    phase: str


@dataclass
class AuditContext:
    """Context gathered during the audit.

    Attributes:
        hostname: System hostname.
        os_release: OS release information.
        kernel: Kernel version.
        uptime: System uptime.
        virtualization: Virtualization technology detected.
        is_container: Whether running in a container.
        is_server: Whether system is a server (vs workstation).
        findings: List of findings collected during audit.
    """

    hostname: str = ""
    os_release: str = ""
    kernel: str = ""
    uptime: str = ""
    virtualization: str = ""
    is_container: bool = False
    is_server: bool = True
    findings: list = field(default_factory=list)


def run_command(
    cmd: str,
    timeout: int = 30,
) -> tuple[str, str, int]:
    """Run a shell command and return stdout, stderr, and return code.

    Args:
        cmd: The command to execute.
        timeout: Maximum time to wait for command completion in seconds.

    Returns:
        A tuple of (stdout, stderr, returncode).
    """
    import subprocess

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip(), result.stderr.strip(), result.returncode
    except subprocess.TimeoutExpired:
        return "", f"Command timed out after {timeout}s", -1
    except Exception as e:
        return "", str(e), -1


def check_root() -> bool:
    """Check if the current process is running as root.

    Returns:
        True if running as root (UID 0), False otherwise.
    """
    import os

    return os.geteuid() == 0
