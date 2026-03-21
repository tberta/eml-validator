"""CLI entry point for eml-validator."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from eml_validator.models import ValidationReport
from eml_validator.report import print_error, print_report
from eml_validator.validators.auth_validator import validate_auth
from eml_validator.validators.dkim_validator import validate_dkim
from eml_validator.validators.mime_validator import validate_mime
from eml_validator.validators.rfc_validator import validate_rfc

VALID_VALIDATORS = {"rfc", "mime", "dkim", "auth"}


def _collect_files(paths: tuple[str, ...], recursive: bool) -> list[Path]:
    """Collect .eml files from the given paths."""
    files: list[Path] = []
    for path_str in paths:
        p = Path(path_str)
        if p.is_dir():
            if recursive:
                files.extend(sorted(p.rglob("*.eml")))
            else:
                files.extend(sorted(p.glob("*.eml")))
        elif p.is_file():
            files.append(p)
        else:
            # Could be a glob pattern already expanded by shell, or non-existent
            # Try as literal path
            print_error(f"Path not found: {path_str}")

    return files


def _parse_validator_list(val: str) -> set[str]:
    """Parse a comma-separated list of validator names."""
    parts = {v.strip().lower() for v in val.split(",")}
    unknown = parts - VALID_VALIDATORS
    if unknown:
        raise click.BadParameter(
            f"Unknown validator(s): {', '.join(sorted(unknown))}. "
            f"Valid: {', '.join(sorted(VALID_VALIDATORS))}"
        )
    return parts


@click.group()
@click.version_option(package_name="eml-validator")
def main() -> None:
    """EML Validator — validate .eml files for RFC compliance, MIME structure, and DKIM."""


@main.command()
@click.argument("paths", nargs=-1, required=True)
@click.option("-r", "--recursive", is_flag=True, help="Recursively search directories for .eml files")
@click.option(
    "--only",
    default=None,
    metavar="VALIDATORS",
    help="Only run specific validators (comma-separated: rfc,mime,dkim,auth)",
)
@click.option(
    "--skip",
    default=None,
    metavar="VALIDATORS",
    help="Skip specific validators (comma-separated: rfc,mime,dkim,auth)",
)
@click.option(
    "--format",
    "fmt",
    default="rich",
    type=click.Choice(["rich", "json", "summary"]),
    help="Output format (default: rich)",
)
@click.option("-v", "--verbose", is_flag=True, help="Show all checks including OK results")
@click.option("-q", "--quiet", is_flag=True, help="Only show errors")
@click.option(
    "--canonicalization-matrix",
    is_flag=True,
    help="Test all 4 canonicalization combinations for DKIM",
)
@click.option("--check-auth", is_flag=True, help="Perform live DKIM/DMARC validation via authheaders")
@click.option("--dns-server", default=None, metavar="IP", help="Use a custom DNS server for lookups")
@click.option("--no-dns", is_flag=True, help="Skip DNS lookups (useful in air-gapped environments)")
def check(
    paths: tuple[str, ...],
    recursive: bool,
    only: str | None,
    skip: str | None,
    fmt: str,
    verbose: bool,
    quiet: bool,
    canonicalization_matrix: bool,
    check_auth: bool,
    dns_server: str | None,
    no_dns: bool,
) -> None:
    """Validate one or more .eml files.

    PATHS can be individual .eml files, directories, or glob patterns.
    """
    # Determine which validators to run
    if only is not None:
        try:
            enabled = _parse_validator_list(only)
        except click.BadParameter as e:
            raise click.UsageError(str(e)) from e
    else:
        enabled = set(VALID_VALIDATORS)

    if skip is not None:
        try:
            to_skip = _parse_validator_list(skip)
        except click.BadParameter as e:
            raise click.UsageError(str(e)) from e
        enabled -= to_skip

    # Configure DNS server if requested
    if dns_server and not no_dns:
        _configure_dns_server(dns_server)

    # Collect files
    files = _collect_files(paths, recursive)
    if not files:
        print_error("No .eml files found in the given paths.")
        sys.exit(1)

    # Process files
    overall_exit_code = 0
    for eml_file in files:
        try:
            raw = eml_file.read_bytes()
        except OSError as exc:
            print_error(f"Cannot read {eml_file}: {exc}")
            overall_exit_code = 2
            continue

        report = ValidationReport(filename=str(eml_file))

        if "rfc" in enabled:
            report.rfc_checks = validate_rfc(raw)

        if "mime" in enabled:
            report.mime_checks = validate_mime(raw)

        if "dkim" in enabled:
            report.dkim_checks = validate_dkim(
                raw,
                no_dns=no_dns,
                canonicalization_matrix=canonicalization_matrix,
            )

        if "auth" in enabled:
            report.auth_checks = validate_auth(raw, check_auth=check_auth)

        print_report(report, fmt=fmt, verbose=verbose, quiet=quiet)  # type: ignore[arg-type]

        if report.has_errors:
            overall_exit_code = 1

    sys.exit(overall_exit_code)


def _configure_dns_server(server: str) -> None:
    """Configure dnspython to use a custom DNS server."""
    try:
        import dns.resolver

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [server]
        dns.resolver.default_resolver = resolver
    except ImportError:
        pass  # dnspython not available, ignore


if __name__ == "__main__":
    main()
