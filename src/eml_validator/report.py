"""Rich-formatted output for validation reports."""

from __future__ import annotations

import json
from typing import Literal

from rich.console import Console
from rich.table import Table

from eml_validator.models import CheckResult, Severity, ValidationReport

OutputFormat = Literal["rich", "json", "summary"]

console = Console()

SEVERITY_ICONS = {
    Severity.OK: "[green]✅[/green]",
    Severity.WARNING: "[yellow]⚠️[/yellow] ",
    Severity.ERROR: "[red]❌[/red]",
    Severity.CRITICAL: "[bold red]💥[/bold red]",
}

SEVERITY_COLORS = {
    Severity.OK: "green",
    Severity.WARNING: "yellow",
    Severity.ERROR: "red",
    Severity.CRITICAL: "bold red",
}


def print_report(
    report: ValidationReport,
    fmt: OutputFormat = "rich",
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Print a validation report to stdout."""
    if fmt == "json":
        print_json(report)
    elif fmt == "summary":
        print_summary(report)
    else:
        print_rich(report, verbose=verbose, quiet=quiet)


def print_rich(
    report: ValidationReport,
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Print a rich-formatted report."""
    console.print()
    console.rule(f"[bold]📧 EML Validator — {report.filename}[/bold]")

    categories = [
        ("RFC 5322 Compliance", report.rfc_checks),
        ("MIME Structure", report.mime_checks),
        ("DKIM Signature", report.dkim_checks),
        ("Authentication Results", report.auth_checks),
    ]

    for title, checks in categories:
        if not checks:
            continue
        _print_category(title, checks, verbose=verbose, quiet=quiet)

    # Summary footer
    console.rule()
    errors = report.error_count()
    warnings = report.warning_count()

    if errors == 0 and warnings == 0:
        console.print(" [bold green]Result: All checks passed ✅[/bold green]")
    elif errors == 0:
        console.print(f" [bold yellow]Result: {warnings} warning(s), 0 errors[/bold yellow]")
    else:
        console.print(f" [bold red]Result: {errors} error(s), {warnings} warning(s)[/bold red]")

    console.rule()
    console.print()


def _print_category(
    title: str,
    checks: list[CheckResult],
    verbose: bool = False,
    quiet: bool = False,
) -> None:
    """Print a single check category."""
    total = len(checks)
    passed = sum(1 for c in checks if c.severity == Severity.OK)
    has_errors = any(c.severity in (Severity.ERROR, Severity.CRITICAL) for c in checks)
    has_warnings = any(c.severity == Severity.WARNING for c in checks)

    # Section header with score
    if has_errors:
        status_icon = "[red]❌[/red]"
        score_color = "red"
    elif has_warnings:
        status_icon = "[yellow]⚠️[/yellow] "
        score_color = "yellow"
    else:
        status_icon = "[green]✅[/green]"
        score_color = "green"

    score_str = f"[{score_color}]{passed}/{total}[/{score_color}]"
    console.print(f"\n[bold]{title}[/bold]  {score_str} {status_icon}")
    console.print("─" * 50)

    for check in checks:
        if quiet and check.severity not in (Severity.ERROR, Severity.CRITICAL):
            continue
        if not verbose and check.severity == Severity.OK:
            continue

        icon = SEVERITY_ICONS[check.severity]
        color = SEVERITY_COLORS[check.severity]
        console.print(f" {icon} [{color}]{check.message}[/{color}]")

        if check.details and (verbose or check.severity != Severity.OK):
            for line in check.details.splitlines():
                console.print(f"     [dim]→ {line}[/dim]")

        if check.rfc_ref and verbose:
            console.print(f"     [dim italic]{check.rfc_ref}[/dim italic]")

    # In verbose mode, show OK checks too
    if verbose:
        ok_checks = [c for c in checks if c.severity == Severity.OK]
        for check in ok_checks:
            icon = SEVERITY_ICONS[check.severity]
            color = SEVERITY_COLORS[check.severity]
            console.print(f" {icon} [{color}]{check.message}[/{color}]")
            if check.rfc_ref:
                console.print(f"     [dim italic]{check.rfc_ref}[/dim italic]")


def print_summary(report: ValidationReport) -> None:
    """Print a concise summary (pass/fail per category)."""
    table = Table(title=f"EML Validator — {report.filename}", show_header=True)
    table.add_column("Category", style="bold")
    table.add_column("Result")
    table.add_column("Errors")
    table.add_column("Warnings")

    categories = [
        ("RFC 5322", report.rfc_checks),
        ("MIME", report.mime_checks),
        ("DKIM", report.dkim_checks),
        ("Auth", report.auth_checks),
    ]

    for name, checks in categories:
        if not checks:
            continue
        errors = sum(1 for c in checks if c.severity in (Severity.ERROR, Severity.CRITICAL))
        warnings = sum(1 for c in checks if c.severity == Severity.WARNING)
        result = "[green]PASS[/green]" if errors == 0 else "[red]FAIL[/red]"
        table.add_row(name, result, str(errors) if errors else "-", str(warnings) if warnings else "-")

    console.print(table)


def print_json(report: ValidationReport) -> None:
    """Print the report as JSON."""
    def check_to_dict(c: CheckResult) -> dict:
        return {
            "name": c.name,
            "severity": c.severity.value,
            "message": c.message,
            "rfc_ref": c.rfc_ref,
            "details": c.details,
        }

    data = {
        "filename": report.filename,
        "has_errors": report.has_errors,
        "error_count": report.error_count(),
        "warning_count": report.warning_count(),
        "rfc_checks": [check_to_dict(c) for c in report.rfc_checks],
        "mime_checks": [check_to_dict(c) for c in report.mime_checks],
        "dkim_checks": [check_to_dict(c) for c in report.dkim_checks],
        "auth_checks": [check_to_dict(c) for c in report.auth_checks],
    }
    print(json.dumps(data, indent=2))


def print_error(message: str) -> None:
    """Print an error message to the console."""
    console.print(f"[bold red]Error:[/bold red] {message}")
