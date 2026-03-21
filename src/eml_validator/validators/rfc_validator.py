"""RFC 5322 / 2045 compliance validator."""

from __future__ import annotations

import email
import email.policy
import re
from email.message import Message
from email.utils import parsedate_to_datetime

from eml_validator.models import CheckResult, Severity

# Headers that must appear at most once per RFC 5322 §3.6
SINGULAR_HEADERS = {"from", "sender", "reply-to", "to", "cc", "subject", "message-id", "date"}

# Headers that are required per RFC 5322 §3.6
REQUIRED_HEADERS = {"from", "date"}

# Recommended headers
RECOMMENDED_HEADERS = {"message-id"}

# Valid address headers
ADDRESS_HEADERS = {"from", "to", "cc", "reply-to", "sender", "bcc"}


def _ok(name: str, message: str, rfc_ref: str = "") -> CheckResult:
    return CheckResult(name=name, severity=Severity.OK, message=message, rfc_ref=rfc_ref)


def _warn(name: str, message: str, rfc_ref: str = "", details: str = "") -> CheckResult:
    return CheckResult(
        name=name, severity=Severity.WARNING, message=message, rfc_ref=rfc_ref, details=details
    )


def _error(name: str, message: str, rfc_ref: str = "", details: str = "") -> CheckResult:
    return CheckResult(
        name=name, severity=Severity.ERROR, message=message, rfc_ref=rfc_ref, details=details
    )


def validate_rfc(raw: bytes) -> list[CheckResult]:
    """Run all RFC 5322 / 2045 checks on raw email bytes."""
    results: list[CheckResult] = []

    try:
        msg = email.message_from_bytes(raw, policy=email.policy.default)
    except Exception as exc:
        return [
            CheckResult(
                name="RFC5322-Parse",
                severity=Severity.CRITICAL,
                message=f"Failed to parse email: {exc}",
                rfc_ref="RFC 5322",
            )
        ]

    results.extend(_check_required_headers(msg))
    results.extend(_check_singular_headers(msg))
    results.extend(_check_date_format(msg))
    results.extend(_check_address_syntax(msg))
    results.extend(_check_line_lengths(raw))
    results.extend(_check_mime_version(msg))
    results.extend(_check_content_type(msg))
    results.extend(_check_8bit_headers(raw))
    results.extend(_check_header_folding(raw))

    return results


def _check_required_headers(msg: Message) -> list[CheckResult]:
    results: list[CheckResult] = []

    for header in REQUIRED_HEADERS:
        if msg[header] is None:
            results.append(
                _error(
                    f"RFC5322-{header.title()}-Header",
                    f"Missing required header: {header.title()}",
                    rfc_ref="RFC 5322 §3.6",
                )
            )
        else:
            results.append(
                _ok(
                    f"RFC5322-{header.title()}-Header",
                    f"{header.title()} header present",
                    rfc_ref="RFC 5322 §3.6",
                )
            )

    for header in RECOMMENDED_HEADERS:
        if msg[header] is None:
            results.append(
                _warn(
                    f"RFC5322-{header.title()}-Header",
                    f"Missing recommended header: {header.title()}",
                    rfc_ref="RFC 5322 §3.6",
                )
            )
        else:
            results.append(
                _ok(
                    f"RFC5322-{header.title()}-Header",
                    f"{header.title()} header present",
                    rfc_ref="RFC 5322 §3.6",
                )
            )

    return results


def _check_singular_headers(msg: Message) -> list[CheckResult]:
    results: list[CheckResult] = []
    for header in SINGULAR_HEADERS:
        values = msg.get_all(header, [])
        if len(values) > 1:
            results.append(
                _error(
                    f"RFC5322-{header.title()}-Unique",
                    f"Header '{header.title()}' appears {len(values)} times (must be unique)",
                    rfc_ref="RFC 5322 §3.6",
                    details=f"Found {len(values)} occurrences",
                )
            )
        elif len(values) == 1:
            results.append(
                _ok(
                    f"RFC5322-{header.title()}-Unique",
                    f"{header.title()} header is unique",
                    rfc_ref="RFC 5322 §3.6",
                )
            )
    return results


def _check_date_format(msg: Message) -> list[CheckResult]:
    date_val = msg.get("date")
    if date_val is None:
        return []  # Already reported as missing

    try:
        parsedate_to_datetime(str(date_val))
        return [_ok("RFC5322-Date-Format", "Date header format is valid", rfc_ref="RFC 5322 §3.3")]
    except Exception as exc:
        return [
            _error(
                "RFC5322-Date-Format",
                f"Date header format is invalid: {exc}",
                rfc_ref="RFC 5322 §3.3",
                details=f"Value: {date_val!r}",
            )
        ]


def _check_address_syntax(msg: Message) -> list[CheckResult]:
    results: list[CheckResult] = []

    for header in ADDRESS_HEADERS:
        value = msg.get(header)
        if value is None:
            continue

        try:
            # Check via the email policy's address validation
            raw_value = str(value)
            # Basic RFC 5322 address format check
            if not _is_valid_address_field(raw_value):
                results.append(
                    _warn(
                        f"RFC5322-{header.title()}-Address",
                        f"Potentially invalid address in {header.title()} header",
                        rfc_ref="RFC 5322 §3.4",
                        details=f"Value: {raw_value[:100]}",
                    )
                )
            else:
                results.append(
                    _ok(
                        f"RFC5322-{header.title()}-Address",
                        f"{header.title()} address syntax valid",
                        rfc_ref="RFC 5322 §3.4",
                    )
                )
        except Exception as exc:
            results.append(
                _error(
                    f"RFC5322-{header.title()}-Address",
                    f"Failed to parse {header.title()} address: {exc}",
                    rfc_ref="RFC 5322 §3.4",
                )
            )

    return results


def _is_valid_address_field(value: str) -> bool:
    """Basic validation that an address field looks plausible."""
    # Check for at least one @ sign in the value (very loose check)
    # More thorough validation would use a full RFC 5322 parser
    stripped = value.strip()
    if not stripped:
        return False
    # Allow display names like "Foo Bar <foo@bar.com>" or just "foo@bar.com"
    # Check that any bare tokens have @ or are in angle brackets
    # This is intentionally lenient to avoid false positives
    parts = [p.strip() for p in stripped.split(",") if p.strip()]
    for part in parts:
        # Extract email from angle brackets if present
        angle_match = re.search(r"<([^>]+)>", part)
        if angle_match:
            addr = angle_match.group(1)
        else:
            addr = part
        # Remove any display name tokens
        addr = addr.strip().strip('"').strip()
        if addr and "@" not in addr and not addr.startswith("("):
            return False
    return True


def _check_line_lengths(raw: bytes) -> list[CheckResult]:
    results: list[CheckResult] = []
    lines = raw.splitlines()
    long_lines = []
    warn_lines = []

    in_header = True
    for i, line in enumerate(lines, 1):
        if in_header:
            if line == b"":
                in_header = False
                continue
            length = len(line)
            if length > 998:
                long_lines.append((i, length))
            elif length > 78:
                warn_lines.append((i, length))

    if long_lines:
        details = "; ".join(f"line {i}: {length} chars" for i, length in long_lines[:5])
        results.append(
            _error(
                "RFC5322-Line-Length",
                f"{len(long_lines)} header line(s) exceed 998 characters (hard limit)",
                rfc_ref="RFC 5322 §2.1.1",
                details=details,
            )
        )
    elif warn_lines:
        results.append(
            _warn(
                "RFC5322-Line-Length",
                f"{len(warn_lines)} header line(s) exceed 78 characters (recommended max)",
                rfc_ref="RFC 5322 §2.1.1",
                details=f"First occurrence at line {warn_lines[0][0]}",
            )
        )
    else:
        results.append(
            _ok("RFC5322-Line-Length", "Header line lengths within limits", rfc_ref="RFC 5322 §2.1.1")
        )

    return results


def _check_mime_version(msg: Message) -> list[CheckResult]:
    """Check MIME-Version header presence for MIME messages."""
    content_type = msg.get_content_type()
    is_mime = (
        content_type.startswith("multipart/")
        or content_type != "text/plain"
        or msg.get("content-transfer-encoding") is not None
        or msg.get("content-type") is not None
    )

    mime_version = msg.get("mime-version")

    if is_mime:
        if mime_version is None:
            return [
                _warn(
                    "RFC2045-MIME-Version",
                    "Missing MIME-Version header for MIME message",
                    rfc_ref="RFC 2045 §4",
                )
            ]
        elif str(mime_version).strip() != "1.0":
            return [
                _error(
                    "RFC2045-MIME-Version",
                    f"Invalid MIME-Version value: {mime_version!r} (expected '1.0')",
                    rfc_ref="RFC 2045 §4",
                )
            ]
        else:
            return [_ok("RFC2045-MIME-Version", "MIME-Version: 1.0 present", rfc_ref="RFC 2045 §4")]
    else:
        if mime_version is not None:
            return [
                _ok("RFC2045-MIME-Version", "MIME-Version: 1.0 present", rfc_ref="RFC 2045 §4")
            ]
    return []


def _check_content_type(msg: Message) -> list[CheckResult]:
    """Validate Content-Type header syntax."""
    ct_raw = msg.get("content-type")
    if ct_raw is None:
        return []

    ct_str = str(ct_raw).strip()

    # Must have type/subtype
    if "/" not in ct_str.split(";")[0]:
        return [
            _error(
                "RFC2045-Content-Type",
                f"Invalid Content-Type format: {ct_str[:80]!r}",
                rfc_ref="RFC 2045 §5.1",
            )
        ]

    # Check type/subtype token validity
    main_part = ct_str.split(";")[0].strip()
    type_part, _, subtype_part = main_part.partition("/")
    if not type_part.strip() or not subtype_part.strip():
        return [
            _error(
                "RFC2045-Content-Type",
                f"Invalid Content-Type: missing type or subtype in {ct_str[:80]!r}",
                rfc_ref="RFC 2045 §5.1",
            )
        ]

    return [
        _ok(
            "RFC2045-Content-Type",
            f"Content-Type syntax valid: {main_part.strip()}",
            rfc_ref="RFC 2045 §5.1",
        )
    ]


def _check_8bit_headers(raw: bytes) -> list[CheckResult]:
    """Detect non-ASCII characters in headers without RFC 2047 encoding."""
    try:
        header_section, _, _ = raw.partition(b"\r\n\r\n")
        if not header_section:
            header_section, _, _ = raw.partition(b"\n\n")
    except Exception:
        return []

    # Find lines with non-ASCII bytes that are not RFC 2047 encoded words
    encoded_word_pattern = re.compile(rb"=\?[^?]+\?[BbQq]\?[^?]+\?=")
    problem_headers: list[str] = []

    for line in header_section.splitlines():
        # Skip continuation lines that are part of folded headers
        if line and line[0:1] in (b" ", b"\t"):
            line = line.lstrip()

        try:
            line.decode("ascii")
        except UnicodeDecodeError:
            # Has non-ASCII bytes — check if they're in encoded words
            cleaned = encoded_word_pattern.sub(b"", line)
            try:
                cleaned.decode("ascii")
            except UnicodeDecodeError:
                header_name = line.split(b":")[0].decode("ascii", errors="replace")
                problem_headers.append(header_name)

    if problem_headers:
        return [
            _error(
                "RFC2047-Header-Encoding",
                f"Non-ASCII characters in headers without RFC 2047 encoding: {', '.join(problem_headers[:5])}",
                rfc_ref="RFC 2047",
                details="Use =?charset?encoding?text?= format for non-ASCII header values",
            )
        ]
    return [
        _ok(
            "RFC2047-Header-Encoding",
            "No unencoded non-ASCII characters in headers",
            rfc_ref="RFC 2047",
        )
    ]


def _check_header_folding(raw: bytes) -> list[CheckResult]:
    """Verify that folded headers use proper whitespace continuation."""
    try:
        header_section, _, _ = raw.partition(b"\r\n\r\n")
        if not header_section:
            header_section, _, _ = raw.partition(b"\n\n")
    except Exception:
        return []

    lines = header_section.splitlines()
    problems: list[int] = []

    for i, line in enumerate(lines[1:], 2):  # Skip first line, count from 2
        # A continuation line (folded header) must start with space or tab
        # A new header must start with a non-whitespace token followed by ':'
        # If a line starts with neither, it's malformed
        if not line:
            continue
        first_byte = line[0:1]
        if first_byte not in (b" ", b"\t") and b":" not in line:
            problems.append(i)

    if problems:
        return [
            _warn(
                "RFC5322-Header-Folding",
                f"Suspicious header folding at line(s): {', '.join(str(p) for p in problems[:5])}",
                rfc_ref="RFC 5322 §2.2.3",
            )
        ]
    return [
        _ok(
            "RFC5322-Header-Folding",
            "Header folding appears correct",
            rfc_ref="RFC 5322 §2.2.3",
        )
    ]
