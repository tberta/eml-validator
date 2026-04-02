"""MIME structure validator."""

from __future__ import annotations

import base64
import binascii
import email
import email.policy
import quopri
import re
from email.message import Message

from eml_validator.models import CheckResult, Severity


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


VALID_CTE_VALUES = {"7bit", "8bit", "binary", "quoted-printable", "base64"}

_TEMPLATE_PLACEHOLDER_RE = re.compile(r"<#[A-Z0-9_]+#>")

# Extend this dict to add future aliases — do not replace with an external registry.
# Keys: non-IANA types seen in real EML corpora. Values: correct IANA-registered type.
# Source: https://www.iana.org/assignments/media-types/
NONSTANDARD_CONTENT_TYPES: dict[str, str] = {
    "image/jpg": "image/jpeg",  # very common tool/browser mistake
    "image/jfif": "image/jpeg",  # JFIF container, not a registered subtype
    "image/pjpeg": "image/jpeg",  # old IE progressive JPEG alias
    "image/x-png": "image/png",  # legacy pre-PNG-RFC alias
}


def validate_mime(raw: bytes) -> list[CheckResult]:
    """Run all MIME structure checks on raw email bytes."""
    results: list[CheckResult] = []

    results.extend(_check_headers_raw(raw))
    results.extend(_check_content_type_raw(raw))
    results.extend(_check_content_type_fold_semicolon(raw))
    results.extend(_check_multipart_boundary_raw(raw))
    results.extend(_check_multipart_boundary_terminator(raw))
    results.extend(_check_charset_cte_mismatch(raw))
    results.extend(_check_cte_on_multipart_or_message(raw))
    results.extend(_check_experimental_media_type(raw))

    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:
        return results + [
            CheckResult(
                name="MIME-Parse",
                severity=Severity.CRITICAL,
                message=f"Failed to parse email for MIME validation: {exc}",
                rfc_ref="RFC 2045",
            )
        ]

    seen_boundaries: set[str] = set()
    results.extend(_check_part(msg, depth=0, seen_boundaries=seen_boundaries, path="root"))
    return results


def _check_headers_raw(raw: bytes) -> list[CheckResult]:
    """Byte-level checks on the raw header section."""
    results: list[CheckResult] = []

    # Split header section from body (stop at the blank line)
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            header_bytes, _, _ = raw.partition(sep)
            break
    else:
        header_bytes = raw

    lines = re.split(rb"\r\n|\n", header_bytes)
    for lineno, line in enumerate(lines, start=1):
        # 2a: Header line > 998 chars (RFC 2822 §2.1.1)
        if len(line) > 998:
            results.append(
                _error(
                    "MIME-HeaderLineTooLong",
                    f"Header line {lineno} exceeds 998 characters ({len(line)} chars)",
                    rfc_ref="RFC 2822 §2.1.1",
                    details=f"Line starts with: {line[:80].decode(errors='replace')!r}",
                )
            )

        # Only check header lines (not folded continuation lines)
        if b":" in line and line[:1] not in (b" ", b"\t"):
            # 2b: Space between header name and colon (breaks DKIM simple canonicalization)
            if re.match(rb"^[A-Za-z0-9-]+ :", line):
                header_name = line.split(b":")[0].decode(errors="replace")
                results.append(
                    _warn(
                        "MIME-HeaderSpaceBeforeColon",
                        f"Header '{header_name}' has a space before the colon",
                        rfc_ref="RFC 2822 §2.2",
                        details="Breaks DKIM 'simple' canonicalization (RFC 6376 §3.4.1)",
                    )
                )

        # 2c: Bare CR or bare LF in header line
        # (already split on \r\n and \n, so a remaining \r in a line is bare)
        if b"\r" in line:
            results.append(
                _error(
                    "MIME-HeaderBareCRLF",
                    f"Bare carriage return in header line {lineno}",
                    rfc_ref="RFC 2822 §2.2",
                    details="Bare CR in headers is not permitted",
                )
            )

    return results


def _check_content_type_raw(raw: bytes) -> list[CheckResult]:
    """Raw-byte scan for Content-Type issues that survive parser failure (e.g. folded continuation lines).

    Unfolding per RFC 2822 §2.2.3 before extracting the type and charset parameter catches
    cases like:
        Content-Type: image/jpg
        \tcharset="UTF-8"
    which Python's email parser misreads as a single malformed type string.
    """
    results: list[CheckResult] = []

    for ct_match in re.finditer(rb"(?mi)^content-type\s*:[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*", raw):
        raw_header = ct_match.group(0)
        # Unfold: collapse CRLF/LF + whitespace continuation into a single line
        unfolded = re.sub(rb"\r?\n[ \t]", b" ", raw_header)

        type_match = re.match(
            rb"(?i)content-type\s*:\s*([a-zA-Z0-9!#$&\-^_]+/[a-zA-Z0-9!#$&\-^_.+]+)",
            unfolded,
        )
        if type_match is None:
            continue
        content_type = type_match.group(1).decode("ascii", errors="replace").lower()

        # Check against known non-standard types
        correct = NONSTANDARD_CONTENT_TYPES.get(content_type)
        if correct is not None:
            results.append(
                _warn(
                    "MIME-NonstandardType-raw",
                    f"Content-Type '{content_type}' is not IANA-registered; use '{correct}' instead",
                    rfc_ref="RFC 2046 §5",
                    details=f"'{content_type}' is a common alias; '{correct}' is the registered subtype",
                )
            )

        # Check for charset on non-text, non-multipart types (ERROR)
        if not content_type.startswith("text/") and not content_type.startswith("multipart/"):
            charset_match = re.search(rb'(?i)charset\s*=\s*"?([^"\s;]+)"?', unfolded)
            if charset_match is not None:
                charset = charset_match.group(1).decode("ascii", errors="replace")
                results.append(
                    _error(
                        "MIME-CharsetOnNonText-raw",
                        f"charset parameter found on non-text Content-Type '{content_type}'",
                        rfc_ref="RFC 2046 §4.1",
                        details=f"charset='{charset}' is defined only for text/* types; remove it from '{content_type}'",
                    )
                )

        # Check for charset on multipart/* types (WARNING — undefined by RFC 2046 §5.1)
        elif content_type.startswith("multipart/"):
            charset_match = re.search(rb'(?i)charset\s*=\s*"?([^"\s;]+)"?', unfolded)
            if charset_match is not None:
                charset = charset_match.group(1).decode("ascii", errors="replace")
                results.append(
                    _warn(
                        "MIME-CharsetOnMultipart-raw",
                        f"charset parameter found on multipart Content-Type '{content_type}'",
                        rfc_ref="RFC 2046 §5.1",
                        details=f"charset='{charset}' is not defined for multipart/* types; remove it",
                    )
                )

    return results


def _check_content_type_fold_semicolon(raw: bytes) -> list[CheckResult]:
    """Detect Content-Type headers where a folded continuation line is not preceded by a semicolon."""
    results: list[CheckResult] = []
    for ct_match in re.finditer(rb"(?mi)^content-type\s*:([^\r\n]*)(\r?\n[ \t][^\r\n]*)+", raw):
        raw_hdr = ct_match.group(0)
        fold_lines = re.split(rb"\r?\n", raw_hdr)
        for i, line in enumerate(fold_lines[:-1]):
            stripped = line.rstrip(b" \t")
            next_part = fold_lines[i + 1].lstrip(b" \t")
            if next_part and stripped and stripped[-1:] != b";":
                results.append(
                    _error(
                        "MIME-ContentTypeMissingSemicolon-raw",
                        "Content-Type header is missing a semicolon before a folded parameter",
                        rfc_ref="RFC 2045 §5.1",
                        details=(
                            f"Line ends with {stripped[-20:].decode(errors='replace')!r} "
                            f"before continuation {next_part[:30].decode(errors='replace')!r}"
                        ),
                    )
                )
                break  # one error per header is enough
    return results


def _check_multipart_boundary_raw(raw: bytes) -> list[CheckResult]:
    """Parser-independent check: every declared multipart boundary must appear as '--<boundary>' in the body."""
    results: list[CheckResult] = []

    # Locate the body (everything after the first blank line)
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            _, _, body = raw.partition(sep)
            break
    else:
        body = b""

    # Find all Content-Type headers declaring multipart/* anywhere in the raw message
    # (covers both the top-level header and sub-part headers embedded in the body)
    for ct_match in re.finditer(
        rb"(?i)content-type\s*:[^\r\n]*multipart/[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*", raw
    ):
        ct_line = ct_match.group(0)
        b_match = re.search(rb'(?i)boundary\s*=\s*"?([^"\s;]+)"?', ct_line)
        if b_match is None:
            continue
        boundary = b_match.group(1)
        delimiter = b"--" + boundary
        if delimiter not in body:
            results.append(
                _warn(
                    "MIME-BoundaryMismatch-raw",
                    f"Content-Type declares boundary='{boundary.decode(errors='replace')}' "
                    f"but '--{boundary.decode(errors='replace')}' was not found in the message body",
                    rfc_ref="RFC 2046 §5.1.1",
                    details="The boundary delimiter line must be '--' followed immediately by the boundary value",
                )
            )

    return results


def _check_multipart_boundary_terminator(raw: bytes) -> list[CheckResult]:
    """Detect multipart sections that are missing the closing '--boundary--' terminator.

    RFC 2046 §5.1.1 requires each multipart body to end with '--<boundary>--'.
    The email library silently treats unterminated multiparts as valid; we check raw bytes.
    msglint.c:3139-3148
    """
    results: list[CheckResult] = []

    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            _, _, body = raw.partition(sep)
            break
    else:
        body = b""

    for ct_match in re.finditer(
        rb"(?i)content-type\s*:[^\r\n]*multipart/[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*", raw
    ):
        ct_line = ct_match.group(0)
        b_match = re.search(rb'(?i)boundary\s*=\s*"?([^"\s;]+)"?', ct_line)
        if b_match is None:
            continue
        boundary = b_match.group(1)
        terminator = b"--" + boundary + b"--"
        if b"--" + boundary in body and terminator not in body:
            results.append(
                _error(
                    "MIME-BoundaryUnterminated",
                    f"Multipart boundary '{boundary.decode(errors='replace')}' has no closing "
                    f"'--{boundary.decode(errors='replace')}--' terminator",
                    rfc_ref="RFC 2046 §5.1.1",
                    details="Each multipart body must end with '--<boundary>--'",
                )
            )

    return results


# 7-bit-only charsets: us-ascii and the common ISO charsets that define only ASCII-range
# values in their lower 128 positions — pairing these with 8bit CTE is non-conformant.
_7BIT_CHARSETS = frozenset({
    "us-ascii", "ascii",
    "iso-8859-1", "iso-8859-2", "iso-8859-3", "iso-8859-4", "iso-8859-5",
    "iso-8859-6", "iso-8859-7", "iso-8859-8", "iso-8859-9", "iso-8859-10",
    "iso-8859-13", "iso-8859-14", "iso-8859-15",
})


def _check_charset_cte_mismatch(raw: bytes) -> list[CheckResult]:
    """Detect charset / Content-Transfer-Encoding mismatches in raw headers.

    - us-ascii charset with 8bit or binary CTE is an error (RFC 2045 §6.4).
    - Any 7-bit-only charset (ISO-8859-*) with 8bit CTE is suspicious (warning).

    msglint.c:3039-3047
    """
    results: list[CheckResult] = []

    # Scan each MIME part header block: look for Content-Type + Content-Transfer-Encoding
    # together.  We scan the entire raw message for pairs of these two headers that appear
    # close together (within the same part header block).
    #
    # Strategy: find every Content-Type that declares a charset, then look for a
    # Content-Transfer-Encoding in the same header block (delimited by blank lines).
    part_blocks: list[bytes] = []
    # Split into blocks by blank lines
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            part_blocks = re.split(re.escape(sep), raw)
            break
    if not part_blocks:
        part_blocks = [raw]

    for block in part_blocks:
        ct_match = re.search(
            rb"(?mi)^content-type\s*:[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*", block
        )
        cte_match = re.search(
            rb"(?mi)^content-transfer-encoding\s*:\s*([^\r\n]+)", block
        )
        if ct_match is None or cte_match is None:
            continue

        ct_raw = re.sub(rb"\r?\n[ \t]", b" ", ct_match.group(0))
        charset_m = re.search(rb'(?i)charset\s*=\s*"?([^"\s;]+)"?', ct_raw)
        if charset_m is None:
            continue
        charset = charset_m.group(1).decode("ascii", errors="replace").lower().strip()
        cte = cte_match.group(1).decode("ascii", errors="replace").lower().strip()

        if charset in ("us-ascii", "ascii") and cte in ("8bit", "binary"):
            results.append(
                _error(
                    "MIME-CharsetCTEMismatch",
                    f"Charset '{charset}' is 7-bit-only but Content-Transfer-Encoding is '{cte}'",
                    rfc_ref="RFC 2045 §6.4",
                    details=(
                        f"us-ascii content must use '7bit', 'quoted-printable', or 'base64' CTE; "
                        f"'{cte}' implies 8-bit content"
                    ),
                )
            )
        elif charset in _7BIT_CHARSETS and cte == "8bit":
            results.append(
                _warn(
                    "MIME-CharsetCTEMismatch",
                    f"Charset '{charset}' typically uses 7-bit encoding but CTE is '8bit'",
                    rfc_ref="RFC 2045 §6.4",
                    details=(
                        f"If the content truly contains 8-bit bytes, consider 'quoted-printable' "
                        f"or 'base64' for better interoperability"
                    ),
                )
            )

    return results


def _check_cte_on_multipart_or_message(raw: bytes) -> list[CheckResult]:
    """Detect quoted-printable or base64 CTE applied to multipart/* or message/rfc822 parts.

    RFC 2045 §6.4 forbids qp/base64 on these composite types; only 7bit/8bit/binary are allowed.
    msglint.c:3026-3029
    """
    results: list[CheckResult] = []

    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            part_blocks = re.split(re.escape(sep), raw)
            break
    else:
        part_blocks = [raw]

    for block in part_blocks:
        ct_match = re.search(
            rb"(?mi)^content-type\s*:[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*", block
        )
        cte_match = re.search(
            rb"(?mi)^content-transfer-encoding\s*:\s*([^\r\n]+)", block
        )
        if ct_match is None or cte_match is None:
            continue

        ct_raw = re.sub(rb"\r?\n[ \t]", b" ", ct_match.group(0))
        type_m = re.match(
            rb"(?i)content-type\s*:\s*([a-zA-Z0-9!#$&\-^_]+/[a-zA-Z0-9!#$&\-^_.+]+)",
            ct_raw,
        )
        if type_m is None:
            continue

        content_type = type_m.group(1).decode("ascii", errors="replace").lower()
        cte = cte_match.group(1).decode("ascii", errors="replace").lower().strip()

        if (
            content_type.startswith("multipart/") or content_type == "message/rfc822"
        ) and cte in ("quoted-printable", "base64"):
            results.append(
                _error(
                    "MIME-CTEOnCompositeType",
                    f"Content-Transfer-Encoding '{cte}' is not allowed on '{content_type}'",
                    rfc_ref="RFC 2045 §6.4",
                    details=(
                        f"Only '7bit', '8bit', or 'binary' are permitted for composite types; "
                        f"'{cte}' applies only to leaf parts"
                    ),
                )
            )

    return results


def _check_experimental_media_type(raw: bytes) -> list[CheckResult]:
    """Warn when the top-level Content-Type uses an experimental 'x-' type or subtype.

    RFC 2046 §6 permits x- prefixes but discourages their use in production mail.
    msglint.c:2694-2698
    """
    results: list[CheckResult] = []

    # Only examine the top-level header block (before the first blank line)
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            top_headers = raw.partition(sep)[0]
            break
    else:
        top_headers = raw

    ct_match = re.search(
        rb"(?mi)^content-type\s*:[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*", top_headers
    )
    if ct_match is None:
        return results

    ct_raw = re.sub(rb"\r?\n[ \t]", b" ", ct_match.group(0))
    type_m = re.match(
        rb"(?i)content-type\s*:\s*([a-zA-Z0-9!#$&\-^_]+)/([a-zA-Z0-9!#$&\-^_.+]+)",
        ct_raw,
    )
    if type_m is None:
        return results

    media_type = type_m.group(1).decode("ascii", errors="replace").lower()
    media_subtype = type_m.group(2).decode("ascii", errors="replace").lower()

    if media_type.startswith("x-") or media_subtype.startswith("x-"):
        results.append(
            _warn(
                "MIME-ExperimentalMediaType",
                f"Top-level Content-Type uses experimental 'x-' prefix: "
                f"'{media_type}/{media_subtype}'",
                rfc_ref="RFC 2046 §6",
                details=(
                    "Experimental 'x-' types are not registered with IANA and may not be "
                    "understood by all mail clients; use a registered type when possible"
                ),
            )
        )

    return results


def _check_part(
    msg: Message,
    depth: int,
    seen_boundaries: set[str],
    path: str,
) -> list[CheckResult]:
    """Recursively check MIME parts."""
    results: list[CheckResult] = []
    content_type = msg.get_content_type()

    # Non-Content-* headers check only applies to sub-parts (depth > 0)
    if depth > 0:
        results.extend(_check_non_content_headers(msg, path))

    if msg.is_multipart():
        results.extend(_check_multipart(msg, depth, seen_boundaries, path))
    elif content_type.startswith("multipart/"):
        # Declared as multipart but not parsed as such — likely missing boundary
        boundary = msg.get_param("boundary")
        if boundary is None:
            results.append(
                _error(
                    f"MIME-Boundary-{path}",
                    f"Content-Type declares '{content_type}' but no boundary parameter is set",
                    rfc_ref="RFC 2046 §5.1",
                )
            )
        else:
            results.extend(_check_leaf_part(msg, path))
    else:
        results.extend(_check_leaf_part(msg, path))

    return results


def _check_multipart(
    msg: Message,
    depth: int,
    seen_boundaries: set[str],
    path: str,
) -> list[CheckResult]:
    results: list[CheckResult] = []
    content_type = msg.get_content_type()

    # Check boundary parameter
    boundary = msg.get_param("boundary")
    if boundary is None:
        results.append(
            _error(
                f"MIME-Boundary-{path}",
                f"multipart part at '{path}' missing boundary parameter",
                rfc_ref="RFC 2046 §5.1",
            )
        )
        return results

    # Check for boundary collision
    boundary_lower = boundary.lower()
    if boundary_lower in seen_boundaries:
        results.append(
            _error(
                f"MIME-Boundary-Conflict-{path}",
                f"Boundary '{boundary}' conflicts with a boundary at another nesting level",
                rfc_ref="RFC 2046 §5.1",
                details="Boundary values must be unique across all nesting levels",
            )
        )
    else:
        seen_boundaries.add(boundary_lower)
        results.append(
            _ok(
                f"MIME-Boundary-{path}",
                f"Boundary defined for {content_type} part at '{path}'",
                rfc_ref="RFC 2046 §5.1",
            )
        )

    # Check multipart/alternative has text/plain or text/html
    if content_type == "multipart/alternative":
        results.extend(_check_multipart_alternative(msg, path))

    # Recurse into sub-parts
    subparts = msg.get_payload()
    if isinstance(subparts, list):
        for i, part in enumerate(subparts):
            sub_path = f"{path}.{i}"
            if isinstance(part, Message):
                # Handle message/rfc822
                if part.get_content_type() == "message/rfc822":
                    inner = part.get_payload()
                    if isinstance(inner, list) and inner:
                        results.extend(
                            _check_part(inner[0], depth + 1, seen_boundaries, f"{sub_path}[rfc822]")
                        )
                else:
                    results.extend(_check_part(part, depth + 1, seen_boundaries, sub_path))

    return results


def _check_multipart_alternative(msg: Message, path: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    subparts = msg.get_payload()
    if not isinstance(subparts, list):
        return results

    content_types = {p.get_content_type() for p in subparts if isinstance(p, Message)}

    has_text = "text/plain" in content_types
    has_html = "text/html" in content_types

    if not has_text and not has_html:
        results.append(
            _warn(
                f"MIME-Alt-Content-{path}",
                "multipart/alternative has no text/plain or text/html part",
                rfc_ref="RFC 2046 §5.1.4",
                details="RFC 2046 recommends including a plain text alternative",
            )
        )
    elif not has_text:
        results.append(
            _warn(
                f"MIME-Alt-PlainText-{path}",
                "multipart/alternative missing text/plain part",
                rfc_ref="RFC 2046 §5.1.4",
                details="RFC 2046 recommends including a plain text alternative",
            )
        )
    else:
        results.append(
            _ok(
                f"MIME-Alt-Content-{path}",
                "multipart/alternative contains appropriate content types",
                rfc_ref="RFC 2046 §5.1.4",
            )
        )

    return results


def _check_leaf_part(msg: Message, path: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    # Check Content-Transfer-Encoding
    cte = msg.get("content-transfer-encoding")
    if cte is not None:
        results.extend(_check_cte(msg, cte, path))

    # Bare CR/LF check on decoded body for all text/* parts
    content_type = msg.get_content_type()
    if content_type.startswith("text/"):
        decoded = msg.get_payload(decode=True)
        if isinstance(decoded, bytes) and decoded:
            results.extend(_check_body_line_endings(decoded, path))

    # Check charset
    charset = msg.get_param("charset")
    if charset is not None:
        if content_type.startswith("text/"):
            results.extend(_check_charset(msg, charset, path))
        else:
            results.extend(_check_charset_on_nontext(msg, path))

    # Check attachment Content-Disposition consistency
    disposition = msg.get("content-disposition")
    if disposition is not None:
        results.extend(_check_disposition(msg, disposition, path))

    # Check for empty body
    payload = msg.get_payload(decode=False)
    if payload is not None:
        if isinstance(payload, str) and not payload.strip():
            results.append(
                _warn(
                    f"MIME-Empty-Part-{path}",
                    f"MIME part at '{path}' has an empty body",
                    rfc_ref="RFC 2046",
                )
            )

    # Structural checks
    results.extend(_check_content_type_name_param(msg, path))
    results.extend(_check_octet_misspelling(msg, path))
    results.extend(_check_nonstandard_content_type(msg, path))
    results.extend(_check_duplicate_mime_headers(msg, path))
    results.extend(_check_content_id(msg, path))
    results.extend(_check_template_placeholders(msg, path))

    return results


def _check_cte(msg: Message, cte: str, path: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    cte_lower = cte.strip().lower()

    if cte_lower not in VALID_CTE_VALUES:
        return [
            _error(
                f"MIME-CTE-{path}",
                f"Invalid Content-Transfer-Encoding value: {cte!r}",
                rfc_ref="RFC 2045 §6",
                details=f"Valid values: {', '.join(sorted(VALID_CTE_VALUES))}",
            )
        ]

    results.append(
        _ok(
            f"MIME-CTE-Valid-{path}",
            f"Content-Transfer-Encoding '{cte_lower}' is valid",
            rfc_ref="RFC 2045 §6",
        )
    )

    # Verify content matches declared encoding
    raw_payload = msg.get_payload(decode=False)
    if isinstance(raw_payload, str) and raw_payload:
        if cte_lower == "base64":
            results.extend(_check_base64_payload(raw_payload, path))
        elif cte_lower == "quoted-printable":
            results.extend(_check_qp_payload(raw_payload, path))
        elif cte_lower == "7bit":
            results.extend(_check_7bit_payload(raw_payload, path))

    return results


def _check_base64_payload(raw_payload: str, path: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    # 1d: Check each encoded line length (<= 76 chars per RFC 2045 pg 25)
    leading_space_count = 0
    leading_space_first: int | None = None
    for lineno, line in enumerate(raw_payload.splitlines(), start=1):
        line_stripped = line.strip()
        if not line_stripped:
            continue
        if len(line) > 76:
            results.append(
                _warn(
                    f"MIME-B64-LineTooLong-{path}",
                    f"Base64 line {lineno} exceeds 76 characters ({len(line)} chars)",
                    rfc_ref="RFC 2045 pg 25",
                    details="Long base64 lines may be re-wrapped by MTAs, breaking the body hash",
                )
            )
        if line.startswith(" "):
            leading_space_count += 1
            if leading_space_first is None:
                leading_space_first = lineno

    if leading_space_count > 0:
        results.append(
            _warn(
                f"MIME-B64-LeadingSpace-{path}",
                f"{leading_space_count} base64 line(s) start with a space character",
                rfc_ref="RFC 2045 §6.8",
                details=(
                    f"First occurrence at line {leading_space_first}. "
                    "A space prefix indicates the encoder split a line with a space instead of CRLF, "
                    "producing malformed line boundaries"
                ),
            )
        )

    # 1e: Validate entire base64 block
    cleaned = "".join(raw_payload.split())
    try:
        base64.b64decode(cleaned, validate=True)
        results.append(
            _ok(
                f"MIME-CTE-Content-{path}",
                "Base64 content is valid",
                rfc_ref="RFC 2045 §6.8",
            )
        )
    except (binascii.Error, ValueError) as exc:
        err_msg = str(exc)
        # Distinguish incomplete block from other errors
        if len(cleaned) % 4 != 0:
            results.append(
                _error(
                    f"MIME-B64-Incomplete-{path}",
                    "Incomplete base64 block (length not a multiple of 4)",
                    rfc_ref="RFC 2045 §6.8",
                    details=err_msg,
                )
            )
        else:
            results.append(
                _error(
                    f"MIME-CTE-Content-{path}",
                    "Content declared as base64 but contains invalid base64 data",
                    rfc_ref="RFC 2045 §6.8",
                    details=err_msg,
                )
            )

    # 1e: Check for excess characters after padding
    pad_match = re.search(r"={1,2}([A-Za-z0-9+/=]+)", cleaned)
    if pad_match:
        excess = pad_match.group(1).replace("=", "")
        if excess:
            results.append(
                _warn(
                    f"MIME-B64-ExcessPadding-{path}",
                    "Excess characters found after base64 padding",
                    rfc_ref="RFC 2045 §6.8",
                    details=f"Unexpected data after '=': {excess[:20]!r}",
                )
            )

    return results


def _check_qp_payload(raw_payload: str, path: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    has_error = False

    for lineno, line in enumerate(raw_payload.splitlines(), start=1):
        # 1c: Encoded line length > 76 chars (RFC 2045 §6.7(5))
        # Soft line break (=\r\n or =\n) ends the logical line, so check up to that
        logical_line = line.rstrip("\r\n")
        if logical_line.endswith("="):
            logical_line = logical_line[:-1]  # soft line break marker
        if len(logical_line) > 76:
            results.append(
                _error(
                    f"MIME-QP-LineTooLong-{path}",
                    f"Quoted-printable line {lineno} exceeds 76 characters ({len(logical_line)} chars)",
                    rfc_ref="RFC 2045 §6.7(5)",
                    details="Long QP lines violate RFC 2045 and may be re-encoded by MTAs",
                )
            )
            has_error = True

        # 1b: Encoded CRLF (=0D=0A) is forbidden in QP (RFC 2045 §6.7)
        if re.search(r"=0[Dd]=0[Aa]", logical_line):
            results.append(
                _error(
                    f"MIME-QP-EncodedCRLF-{path}",
                    f"Quoted-printable line {lineno} contains encoded CRLF (=0D=0A)",
                    rfc_ref="RFC 2045 §6.7",
                    details="Encoding CRLF in QP is forbidden; use a real line break",
                )
            )
            has_error = True

    if not has_error:
        try:
            quopri.decodestring(raw_payload.encode())
            results.append(
                _ok(
                    f"MIME-CTE-Content-{path}",
                    "Quoted-printable content is valid",
                    rfc_ref="RFC 2045 §6.7",
                )
            )
        except Exception as exc:
            results.append(
                _warn(
                    f"MIME-CTE-Content-{path}",
                    "Content declared as quoted-printable may have issues",
                    rfc_ref="RFC 2045 §6.7",
                    details=str(exc),
                )
            )

    return results


def _check_7bit_payload(raw_payload: str, path: str) -> list[CheckResult]:
    """Check that a 7bit-declared part contains no 8-bit bytes."""
    results: list[CheckResult] = []
    try:
        raw_bytes = raw_payload.encode("ascii")
    except UnicodeEncodeError:
        # Contains non-ASCII; check encoded bytes
        raw_bytes = raw_payload.encode("latin-1", errors="replace")

    for i, byte in enumerate(raw_bytes):
        if byte >= 0x80:
            results.append(
                _error(
                    f"MIME-8BitIn7Bit-{path}",
                    "Content-Transfer-Encoding is '7bit' but body contains 8-bit bytes",
                    rfc_ref="RFC 2045 §6.2",
                    details=f"First 8-bit byte (0x{byte:02x}) found at byte offset {i}",
                )
            )
            break

    return results


def _check_body_line_endings(decoded_body: bytes, path: str) -> list[CheckResult]:
    """Check for bare CR or bare LF in decoded body bytes."""
    results: list[CheckResult] = []
    bare_cr = False
    bare_lf = False

    i = 0
    while i < len(decoded_body):
        b = decoded_body[i]
        if b == 0x0D:  # CR
            if i + 1 >= len(decoded_body) or decoded_body[i + 1] != 0x0A:
                bare_cr = True
        elif b == 0x0A:  # LF
            if i == 0 or decoded_body[i - 1] != 0x0D:
                bare_lf = True
        i += 1

    if bare_cr:
        results.append(
            _error(
                f"MIME-BareCR-{path}",
                "Body contains bare carriage return (CR not followed by LF)",
                rfc_ref="RFC 2822 §2.2",
                details="Bare CRs alter the DKIM body hash and may be stripped by MTAs",
            )
        )
    if bare_lf:
        results.append(
            _error(
                f"MIME-BareLF-{path}",
                "Body contains bare line feed (LF not preceded by CR)",
                rfc_ref="RFC 2822 §2.2",
                details="Bare LFs alter the DKIM body hash; use CRLF line endings",
            )
        )

    return results


def _check_charset_on_nontext(msg: Message, path: str) -> list[CheckResult]:
    content_type = msg.get_content_type()
    charset = msg.get_param("charset")
    if charset is None or content_type.startswith("text/"):
        return []
    return [
        _error(
            f"MIME-CharsetOnNonText-{path}",
            f"charset parameter found on non-text Content-Type '{content_type}'",
            rfc_ref="RFC 2046 §4.1",
            details=f"charset='{charset}' is defined only for text/* types; remove it from '{content_type}'",
        )
    ]


def _check_charset(msg: Message, charset: str, path: str) -> list[CheckResult]:
    results: list[CheckResult] = []

    import codecs

    try:
        codecs.lookup(charset)
    except LookupError:
        return [
            _error(
                f"MIME-Charset-{path}",
                f"Unknown charset: {charset!r}",
                rfc_ref="RFC 2045 §5.1",
            )
        ]

    # Try to decode the payload with the declared charset
    try:
        payload_bytes = msg.get_payload(decode=True)
        if payload_bytes:
            payload_bytes.decode(charset)
            results.append(
                _ok(
                    f"MIME-Charset-{path}",
                    f"Content successfully decoded with charset '{charset}'",
                    rfc_ref="RFC 2045 §5.1",
                )
            )
            # 3d: Warn if charset is non-ASCII but content is pure ASCII
            import codecs as _codecs

            ascii_name = _codecs.lookup("us-ascii").name
            declared_name = _codecs.lookup(charset).name
            if declared_name != ascii_name and all(b < 0x80 for b in payload_bytes):
                results.append(
                    _warn(
                        f"MIME-CharsetOverspecified-{path}",
                        f"Charset '{charset}' declared but content is pure ASCII; 'us-ascii' suffices",
                        rfc_ref="RFC 2045 §5.1",
                        details="Overly broad charset declarations can mislead decoders",
                    )
                )
    except (UnicodeDecodeError, LookupError) as exc:
        results.append(
            _error(
                f"MIME-Charset-{path}",
                f"Content cannot be decoded with declared charset '{charset}'",
                rfc_ref="RFC 2045 §5.1",
                details=str(exc),
            )
        )
    except Exception:
        pass  # Skip if we can't get payload

    return results


def _check_disposition(msg: Message, disposition: str, path: str) -> list[CheckResult]:
    results: list[CheckResult] = []
    disp_lower = disposition.strip().lower().split(";")[0].strip()

    valid_dispositions = {"inline", "attachment"}
    if disp_lower not in valid_dispositions:
        return [
            _warn(
                f"MIME-Disposition-{path}",
                f"Unusual Content-Disposition value: {disp_lower!r}",
                rfc_ref="RFC 2183",
                details=f"Expected one of: {', '.join(sorted(valid_dispositions))}",
            )
        ]

    # For attachments, check filename consistency with Content-Type
    if disp_lower == "attachment":
        filename = msg.get_filename()
        content_type = msg.get_content_type()
        results.append(
            _ok(
                f"MIME-Attachment-{path}",
                f"Attachment '{filename or '(no filename)'}' with Content-Type '{content_type}'",
                rfc_ref="RFC 2183",
            )
        )
    elif disp_lower == "inline":
        filename = msg.get_filename()
        if filename is not None:
            results.append(
                _warn(
                    f"MIME-InlineWithFilename-{path}",
                    f"Content-Disposition 'inline' carries a filename parameter ('{filename}')",
                    rfc_ref="RFC 2183 §2.1",
                    details=(
                        "RFC 2183 §2.1 defines 'filename' for 'attachment' disposition only; "
                        "using it with 'inline' may cause inconsistent client behavior"
                    ),
                )
            )

    return results


def _check_content_id(msg: Message, path: str) -> list[CheckResult]:
    cid = msg.get("content-id")
    if cid is None:
        return []
    stripped = cid.strip()
    if not (stripped.startswith("<") and stripped.endswith(">")):
        return [
            _warn(
                f"MIME-ContentIDFormat-{path}",
                f"Content-ID value {stripped!r} is not wrapped in angle brackets",
                rfc_ref="RFC 2045 §7",
                details="Content-ID must be a msg-id: <local-part@domain>",
            )
        ]
    inner = stripped[1:-1]
    if "@" not in inner:
        return [
            _warn(
                f"MIME-ContentIDFormat-{path}",
                f"Content-ID value {stripped!r} is missing '@' — not a valid msg-id",
                rfc_ref="RFC 2045 §7",
                details="Content-ID must follow msg-id format: <local-part@domain>",
            )
        ]
    return []


def _check_template_placeholders(msg: Message, path: str) -> list[CheckResult]:
    """Warn if the decoded body contains unresolved template placeholders."""
    content_type = msg.get_content_type()
    if not content_type.startswith("text/"):
        return []
    try:
        payload = msg.get_payload(decode=True)
    except Exception:
        return []
    if not isinstance(payload, bytes) or not payload:
        return []
    try:
        text = payload.decode("utf-8", errors="replace")
    except Exception:
        return []
    found = _TEMPLATE_PLACEHOLDER_RE.findall(text)
    if not found:
        return []
    unique = sorted(set(found))
    return [
        _warn(
            f"MIME-TemplatePlaceholder-{path}",
            f"Body contains {len(unique)} unresolved template placeholder(s)",
            rfc_ref="",
            details=f"Found: {', '.join(unique[:5])}{'...' if len(unique) > 5 else ''}",
        )
    ]


def _check_content_type_name_param(msg: Message, path: str) -> list[CheckResult]:
    """Warn if Content-Type carries a 'name=' parameter (deprecated in favour of Content-Disposition filename=)."""
    results: list[CheckResult] = []
    name_param = msg.get_param("name")
    if name_param is not None:
        results.append(
            _warn(
                f"MIME-ContentTypeNameParam-{path}",
                "Content-Type 'name' parameter is deprecated; use Content-Disposition 'filename' instead",
                rfc_ref="RFC 2183",
                details=f"Found name={name_param!r} in Content-Type",
            )
        )
    return results


def _check_octet_misspelling(msg: Message, path: str) -> list[CheckResult]:
    """Warn if content-type looks like a misspelling of 'application/octet-stream'."""
    results: list[CheckResult] = []
    maintype = msg.get_content_maintype()
    subtype = msg.get_content_subtype()
    if maintype == "application" and subtype.startswith("octet") and subtype != "octet-stream":
        results.append(
            _warn(
                f"MIME-OctetMisspelling-{path}",
                f"Content-Type 'application/{subtype}' looks like a misspelling of 'application/octet-stream'",
                rfc_ref="RFC 2046 §6",
                details="Did you mean 'application/octet-stream'?",
            )
        )
    return results


def _check_nonstandard_content_type(msg: Message, path: str) -> list[CheckResult]:
    content_type = msg.get_content_type()
    correct = NONSTANDARD_CONTENT_TYPES.get(content_type)
    if correct is None:
        return []
    return [
        _warn(
            f"MIME-NonstandardType-{path}",
            f"Content-Type '{content_type}' is not IANA-registered; use '{correct}' instead",
            rfc_ref="RFC 2046 §5",
            details=f"'{content_type}' is a common alias; '{correct}' is the registered subtype",
        )
    ]


_MIME_ONLY_HEADERS = {
    "content-type",
    "content-transfer-encoding",
    "content-id",
    "content-description",
    "content-disposition",
    "mime-version",
}


def _check_duplicate_mime_headers(msg: Message, path: str) -> list[CheckResult]:
    """Error if MIME-specific headers appear more than once in a single part."""
    results: list[CheckResult] = []
    seen: dict[str, int] = {}
    for key in msg.keys():
        lower = key.lower()
        if lower in _MIME_ONLY_HEADERS:
            seen[lower] = seen.get(lower, 0) + 1

    for header, count in seen.items():
        if count > 1:
            results.append(
                _error(
                    f"MIME-DuplicateHeader-{path}",
                    f"Header '{header}' appears {count} times in MIME part at '{path}'",
                    rfc_ref="RFC 2045 §3",
                    details="Duplicate MIME headers cause ambiguous DKIM header signing",
                )
            )
    return results


def _check_non_content_headers(msg: Message, path: str) -> list[CheckResult]:
    """Warn on non-Content-* headers inside MIME sub-parts (except MIME-Version)."""
    results: list[CheckResult] = []
    allowed_prefixes = ("content-", "mime-version")
    for key in msg.keys():
        lower = key.lower()
        if not any(lower.startswith(p) for p in allowed_prefixes):
            results.append(
                _warn(
                    f"MIME-NonContentHeader-{path}",
                    f"Non-MIME header '{key}' found inside MIME part at '{path}'",
                    rfc_ref="RFC 2045 §3",
                    details="Only Content-* and MIME-Version headers are defined for MIME body parts",
                )
            )
    return results
