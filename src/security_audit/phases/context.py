"""Phase 0 - Context Gathering module."""

from ..core import AuditContext, run_command


def gather_context() -> AuditContext:
    """Gather basic system context for the audit."""
    context = AuditContext()

    stdout, _, rc = run_command("hostname")
    if rc == 0:
        context.hostname = stdout

    stdout, _, rc = run_command("uname -r")
    if rc == 0:
        context.kernel = stdout

    stdout, _, rc = run_command("cat /etc/os-release")
    if rc == 0:
        context.os_release = stdout

    stdout, _, rc = run_command("uptime")
    if rc == 0:
        context.uptime = stdout

    stdout, _, rc = run_command(
        "systemd-detect-virt 2>/dev/null || virt-what 2>/dev/null || echo 'none'"
    )
    if rc == 0 and stdout:
        context.virtualization = stdout
        context.is_container = stdout.strip() in ["docker", "lxc", "podman"]

    stdout, _, rc = run_command("systemd-detect-virt -c 2>/dev/null")
    context.is_container = rc == 0

    return context


def get_system_info() -> dict:
    """Get detailed system information."""
    info = {}

    cmds = {
        "hostname": "hostname",
        "os_release": "cat /etc/os-release",
        "kernel": "uname -r",
        "architecture": "uname -m",
        "uptime": "uptime",
        "last_boot": "who -b",
    }

    for key, cmd in cmds.items():
        stdout, _, rc = run_command(cmd)
        if rc == 0:
            info[key] = stdout

    virt, _, rc = run_command("systemd-detect-virt 2>/dev/null || echo 'none'")
    info["virtualization"] = virt if rc == 0 else "unknown"

    return info
