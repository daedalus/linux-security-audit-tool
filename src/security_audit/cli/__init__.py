"""Command-line interface for the Linux Security Audit Tool."""

from collections.abc import Callable
from typing import Any

import click
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from security_audit import __version__
from security_audit.config import load_config
from security_audit.core import (
    Finding,
    Severity,
    check_root,
    init_cache,
    run_command,
    set_debug,
)
from security_audit.phases import (
    calculate_security_score,
    gather_context,
    generate_json_report,
    generate_markdown_report,
    generate_pdf_report,
    generate_remediation_script,
    run_crypto_checks,
    run_filesystem_checks,
    run_identity_checks,
    run_kernel_checks,
    run_logging_checks,
    run_network_checks,
    run_package_checks,
    run_process_checks,
)

console = Console()


def print_finding(finding: Finding, verbose: bool = False) -> None:
    """Print a single finding with severity color.

    Args:
        finding: The Finding object to print.
        verbose: Whether to show description and remediation.
    """
    colors = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "blue",
    }
    color = colors.get(finding.severity, "white")
    rprint()
    rprint(f"[{color}]{finding.severity.value}[/{color}]")
    rprint(f"[{color}]{finding.check_id}: {finding.title}[/{color}]")
    if finding.evidence:
        rprint(f"  [dim]Evidence: {finding.evidence[:200]}[/dim]")
    if verbose:
        if finding.description:
            rprint(f"  {finding.description}")
        if finding.remediation:
            rprint(f"  [dim]Remediation: {finding.remediation}[/dim]")


def print_summary(findings: list[Finding]) -> None:
    """Print a summary table of findings.

    Args:
        findings: List of Finding objects.
    """
    from rich.table import Table

    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
    }
    for f in findings:
        counts[f.severity] += 1

    table = Table(title="Audit Summary")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")

    table.add_row("[red bold]CRITICAL[/red bold]", str(counts[Severity.CRITICAL]))
    table.add_row("[red]HIGH[/red]", str(counts[Severity.HIGH]))
    table.add_row("[yellow]MEDIUM[/yellow]", str(counts[Severity.MEDIUM]))
    table.add_row("[cyan]LOW[/cyan]", str(counts[Severity.LOW]))
    table.add_row("[blue]INFO[/blue]", str(counts[Severity.INFO]))

    console.print(table)


@click.group()
@click.version_option(version="0.1.0")
def cli() -> None:
    """Linux Security Audit Tool - Comprehensive security auditing and hardening."""


def _run_phase(
    progress: Progress,
    phase_num: int,
    selected_phases: list[int],
    description: str,
    run_fn: Callable[[], list[Finding]],
    all_findings: list[Finding],
    quiet: bool,
    verbose: bool,
) -> None:
    """Run a single audit phase with progress tracking."""
    if phase_num not in selected_phases:
        return
    task = progress.add_task(description, total=None)
    findings = run_fn()
    all_findings.extend(findings)
    if not quiet:
        console.print()
        for f in findings:
            print_finding(f, verbose=verbose)
    progress.update(task, completed=True)


_PHASE_DESCRIPTIONS: list[str] = [
    "Checking identity & access control...",
    "Checking network exposure...",
    "Checking file system & permissions...",
    "Checking process & service posture...",
    "Checking kernel & OS hardening...",
    "Checking logging & monitoring...",
    "Checking package hygiene...",
    "Checking cryptographic posture...",
]

_PHASE_NUMBERS: list[int] = [1, 2, 3, 4, 5, 6, 7, 8]


def _save_or_print_remediation(
    findings: list[Finding],
    remediate_script: str | None,
    label: str,
) -> None:
    """Generate and save or display a remediation script."""
    console.print(f"\n[bold yellow]Applying remediations ({label})...[/bold yellow]")
    script = generate_remediation_script(findings)
    if remediate_script:
        with open(remediate_script, "w", encoding="utf-8") as out_file:
            out_file.write(script)
        console.print(
            f"\n[green]Remediation script saved to {remediate_script}[/green]"
        )
        console.print("[dim]Run with: sudo bash " + remediate_script + "[/dim]")
    else:
        count_str = (
            f" ({len(findings)} {label} findings)" if "manual" not in label else ""
        )
        console.print(f"\n[dim]Generated remediation script{count_str}:[/dim]")
        console.print(f"[dim]{script[:500]}...[/dim]")
        console.print(
            "\n[yellow]Note: Automatic remediation is not yet fully implemented.[/yellow]"
        )
        console.print("[dim]Use --remediate-script <file> to save full script.[/dim]")


def _print_context_info(context: Any) -> None:
    """Print system context information."""
    console.print(f"  Hostname: {context.hostname}")
    console.print(f"  Kernel: {context.kernel}")
    stdout, _, _ = run_command("cat /etc/issue")
    if stdout:
        console.print(f"  OS: {stdout.split(chr(10))[0]}")


def _handle_audit_output(
    context: Any,
    all_findings: list[Finding],
    output: str | None,
    pdf: str | None,
    json: str | None,
    remediate_all: bool,
    remediate_only_critical: bool,
    remediate_non_critical: bool,
    remediate_script: str | None,
) -> None:
    """Handle audit output: summary, reports, and remediation."""
    console.print()
    print_summary(all_findings)

    if output:
        report = generate_markdown_report(context, all_findings)
        with open(output, "w", encoding="utf-8") as out_file:
            out_file.write(report)
        console.print(f"\n[green]Report saved to {output}[/green]")

    if pdf:
        generate_pdf_report(context, all_findings, pdf)
        console.print(f"\n[green]PDF report saved to {pdf}[/green]")

    if json:
        json_report = generate_json_report(context, all_findings)
        with open(json, "w", encoding="utf-8") as out_file:
            out_file.write(json_report)
        console.print(f"\n[green]JSON report saved to {json}[/green]")

    if remediate_all:
        _save_or_print_remediation(all_findings, remediate_script, "all")
    elif remediate_only_critical:
        critical = [f for f in all_findings if f.severity == Severity.CRITICAL]
        _save_or_print_remediation(critical, remediate_script, "CRITICAL only")
    elif remediate_non_critical:
        non_critical = [f for f in all_findings if f.severity != Severity.CRITICAL]
        _save_or_print_remediation(non_critical, remediate_script, "non-CRITICAL")


@cli.command()
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default=None,
    help="Output file for report",
)
@click.option(
    "--phases",
    "-p",
    multiple=True,
    help="Specific phases to run (0-9)",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress detailed output",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Show detailed output including descriptions and remediation",
)
@click.option(
    "--debug",
    "-d",
    is_flag=True,
    help="Show debug output with low-level commands being executed",
)
@click.option(
    "--remediate-all",
    "-r",
    "remediate_all",
    is_flag=True,
    help="Apply automatic remediations for all findings",
)
@click.option(
    "--remediate-only-critical",
    is_flag=True,
    help="Apply automatic remediations for CRITICAL findings only",
)
@click.option(
    "--remediate-non-critical",
    is_flag=True,
    help="Apply automatic remediations for non-CRITICAL findings",
)
@click.option(
    "--pdf",
    type=click.Path(),
    default=None,
    help="Generate PDF executive report",
)
@click.option(
    "--json",
    "-j",
    type=click.Path(),
    default=None,
    help="Output file for JSON report",
)
@click.option(
    "--remediate-script",
    type=click.Path(),
    default=None,
    help="Save remediation script to file",
)
@click.option(
    "--cache",
    is_flag=True,
    help="Enable caching of check results",
)
@click.option(
    "--cache-ttl",
    type=int,
    default=3600,
    help="Cache TTL in seconds (default: 3600)",
)
@click.option(
    "--config",
    type=click.Path(exists=True),
    default=None,
    help="Path to YAML configuration file",
)
def audit(
    output: str | None,
    phases: tuple[str, ...],
    quiet: bool,
    verbose: bool,
    debug: bool,
    remediate_all: bool,
    remediate_only_critical: bool,
    remediate_non_critical: bool,
    pdf: str | None,
    json: str | None,
    remediate_script: str | None,
    cache: bool,
    cache_ttl: int,
    config: str | None,
) -> None:
    """Run a full security audit."""
    if debug:
        set_debug(True)

    init_cache(enabled=cache, ttl=cache_ttl)
    load_config(config)

    if not check_root():
        console.print(
            "[yellow]Warning: This tool should be run as root for full functionality.[/yellow]"
        )
        console.print("[dim]Some checks may fail without root privileges.[/dim]")
        console.print()

    console.print(f"[bold blue]Linux Security Audit Tool v{__version__}[/bold blue]")
    console.print()

    all_findings: list[Finding] = []
    context = None

    if phases:
        selected_phases = [int(p) for p in phases]
    else:
        selected_phases = list(range(10))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        if 0 in selected_phases:
            task = progress.add_task("Gathering context...", total=None)
            context = gather_context()
            if not quiet:
                _print_context_info(context)
            progress.update(task, completed=True)

        phase_runners: list[Callable[[], list[Finding]]] = [
            run_identity_checks,
            run_network_checks,
            run_filesystem_checks,
            run_process_checks,
            run_kernel_checks,
            run_logging_checks,
            run_package_checks,
            run_crypto_checks,
        ]

        for pn, desc, runner in zip(_PHASE_NUMBERS, _PHASE_DESCRIPTIONS, phase_runners):
            _run_phase(
                progress,
                pn,
                selected_phases,
                desc,
                runner,
                all_findings,
                quiet,
                verbose,
            )

        if 9 in selected_phases:
            task = progress.add_task("Generating report...", total=None)
            if context is None:
                context = gather_context()
            score = calculate_security_score(all_findings)
            console.print(f"\n[bold]Security Score: {score}/100[/bold]")
            progress.update(task, completed=True)

    if context is None:
        context = gather_context()

    _handle_audit_output(
        context=context,
        all_findings=all_findings,
        output=output,
        pdf=pdf,
        json=json,
        remediate_all=remediate_all,
        remediate_only_critical=remediate_only_critical,
        remediate_non_critical=remediate_non_critical,
        remediate_script=remediate_script,
    )


@cli.command()
def version() -> None:
    """Show version information."""
    console.print(f"Linux Security Audit Tool v{__version__}")


def main() -> None:
    """Main entry point for the CLI."""
    cli()


if __name__ == "__main__":
    raise SystemExit(main())
