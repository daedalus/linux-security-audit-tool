"""Command-line interface for the Linux Security Audit Tool."""

import sys
from typing import Optional

import click
from rich import print as rprint
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from security_audit.core import (
    DEBUG,
    Finding,
    Severity,
    check_root,
    set_debug,
    run_command,
)
from security_audit.phases import (
    calculate_security_score,
    gather_context,
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
    pass


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
def audit(
    output: str | None,
    phases: tuple,
    quiet: bool,
    verbose: bool,
    debug: bool,
    remediate_all: bool,
    remediate_only_critical: bool,
    remediate_non_critical: bool,
    pdf: str | None,
) -> None:
    """Run a full security audit."""
    if debug:
        set_debug(True)

    if not check_root():
        console.print(
            "[yellow]Warning: This tool should be run as root for full functionality.[/yellow]"
        )
        console.print("[dim]Some checks may fail without root privileges.[/dim]")
        console.print()

    console.print("[bold blue]Linux Security Audit Tool v0.1.0[/bold blue]")
    console.print()

    all_findings = []
    context = None

    selected_phases = list(range(10)) if not phases else [int(p) for p in phases]

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        if 0 in selected_phases:
            task = progress.add_task("Gathering context...", total=None)
            context = gather_context()
            if not quiet:
                console.print(f"  Hostname: {context.hostname}")
                console.print(f"  Kernel: {context.kernel}")
                stdout, _, _ = run_command("cat /etc/issue")
                if stdout:
                    console.print(f"  OS: {stdout.split('\\n')[0]}")
            progress.update(task, completed=True)

        if 1 in selected_phases:
            task = progress.add_task(
                "Checking identity & access control...", total=None
            )
            findings = run_identity_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            for f in findings:
                if f.check_id == "IDENT-001" and f.severity == Severity.CRITICAL:
                    progress.update(
                        task,
                        description=f"Checking identity & access control...\n{f.severity.value} {f.check_id}: {f.title}",
                    )
            progress.update(task, completed=True)

        if 2 in selected_phases:
            task = progress.add_task("Checking network exposure...", total=None)
            findings = run_network_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            progress.update(task, completed=True)

        if 3 in selected_phases:
            task = progress.add_task(
                "Checking file system & permissions...", total=None
            )
            findings = run_filesystem_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            progress.update(task, completed=True)

        if 4 in selected_phases:
            task = progress.add_task(
                "Checking process & service posture...", total=None
            )
            findings = run_process_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            progress.update(task, completed=True)

        if 5 in selected_phases:
            task = progress.add_task("Checking kernel & OS hardening...", total=None)
            findings = run_kernel_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            progress.update(task, completed=True)

        if 6 in selected_phases:
            task = progress.add_task("Checking logging & monitoring...", total=None)
            findings = run_logging_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            progress.update(task, completed=True)

        if 7 in selected_phases:
            task = progress.add_task("Checking package hygiene...", total=None)
            findings = run_package_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            progress.update(task, completed=True)

        if 8 in selected_phases:
            task = progress.add_task("Checking cryptographic posture...", total=None)
            findings = run_crypto_checks()
            all_findings.extend(findings)
            if not quiet:
                console.print()
                for f in findings:
                    print_finding(f, verbose=verbose)
            progress.update(task, completed=True)

        if 9 in selected_phases:
            task = progress.add_task("Generating report...", total=None)
            if context is None:
                context = gather_context()
            score = calculate_security_score(all_findings)
            console.print(f"\n[bold]Security Score: {score}/100[/bold]")
            progress.update(task, completed=True)

    console.print()
    print_summary(all_findings)

    if output:
        report = generate_markdown_report(context, all_findings)
        with open(output, "w", encoding="utf-8") as f:
            f.write(report)
        console.print(f"\n[green]Report saved to {output}[/green]")

    if pdf:
        generate_pdf_report(context, all_findings, pdf)
        console.print(f"\n[green]PDF report saved to {pdf}[/green]")

    if remediate_all:
        console.print("\n[bold yellow]Applying remediations (all)...[/bold yellow]")
        script = generate_remediation_script(all_findings)
        console.print(f"\n[dim]Generated remediation script:[/dim]")
        console.print(f"[dim]{script[:500]}...[/dim]")
        console.print(
            "\n[yellow]Note: Automatic remediation is not yet fully implemented.[/yellow]"
        )
        console.print(
            "[dim]Please review the remediation script and apply manually.[/dim]"
        )
    elif remediate_only_critical:
        from security_audit.core import Severity

        critical = [f for f in all_findings if f.severity == Severity.CRITICAL]
        console.print(
            f"\n[bold yellow]Applying remediations (CRITICAL only)...[/bold yellow]"
        )
        script = generate_remediation_script(critical)
        console.print(
            f"\n[dim]Generated remediation script for {len(critical)} critical findings:[/dim]"
        )
        console.print(f"[dim]{script[:500]}...[/dim]")
        console.print(
            "\n[yellow]Note: Automatic remediation is not yet fully implemented.[/yellow]"
        )
        console.print(
            "[dim]Please review the remediation script and apply manually.[/dim]"
        )
    elif remediate_non_critical:
        from security_audit.core import Severity

        non_critical = [f for f in all_findings if f.severity != Severity.CRITICAL]
        console.print(
            f"\n[bold yellow]Applying remediations (non-CRITICAL)...[/bold yellow]"
        )
        script = generate_remediation_script(non_critical)
        console.print(
            f"\n[dim]Generated remediation script for {len(non_critical)} non-critical findings:[/dim]"
        )
        console.print(f"[dim]{script[:500]}...[/dim]")
        console.print(
            "\n[yellow]Note: Automatic remediation is not yet fully implemented.[/yellow]"
        )
        console.print(
            "[dim]Please review the remediation script and apply manually.[/dim]"
        )


@cli.command()
def version() -> None:
    """Show version information."""
    console.print("Linux Security Audit Tool v0.1.0")


def main() -> int:
    """Main entry point for the CLI."""
    return cli()


if __name__ == "__main__":
    raise SystemExit(main())
