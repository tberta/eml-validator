"""Data models for validation results."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Severity level for a check result."""

    OK = "ok"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class CheckResult:
    """Result of a single validation check."""

    name: str
    severity: Severity
    message: str
    rfc_ref: str = ""
    details: str = ""


@dataclass
class ValidationReport:
    """Full validation report for a single .eml file."""

    filename: str
    rfc_checks: list[CheckResult] = field(default_factory=list)
    mime_checks: list[CheckResult] = field(default_factory=list)
    dkim_checks: list[CheckResult] = field(default_factory=list)
    auth_checks: list[CheckResult] = field(default_factory=list)

    @property
    def has_errors(self) -> bool:
        """Return True if any check is ERROR or CRITICAL."""
        all_checks = self.rfc_checks + self.mime_checks + self.dkim_checks + self.auth_checks
        return any(c.severity in (Severity.ERROR, Severity.CRITICAL) for c in all_checks)

    @property
    def all_checks(self) -> list[CheckResult]:
        """Return all checks from all categories."""
        return self.rfc_checks + self.mime_checks + self.dkim_checks + self.auth_checks

    def error_count(self) -> int:
        """Count checks with ERROR or CRITICAL severity."""
        return sum(1 for c in self.all_checks if c.severity in (Severity.ERROR, Severity.CRITICAL))

    def warning_count(self) -> int:
        """Count checks with WARNING severity."""
        return sum(1 for c in self.all_checks if c.severity == Severity.WARNING)
