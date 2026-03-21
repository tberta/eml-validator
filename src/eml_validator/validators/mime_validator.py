"""MIME structure validator."""

from __future__ import annotations

import base64
import binascii
import email
import email.policy
import quopri
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


def validate_mime(raw: bytes) -> list[CheckResult]:
    """Run all MIME structure checks on raw email bytes."""
    results: list[CheckResult] = []

    try:
        msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    except Exception as exc:
        return [
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


def _check_part(
    msg: Message,
    depth: int,
    seen_boundaries: set[str],
    path: str,
) -> list[CheckResult]:
    """Recursively check MIME parts."""
    results: list[CheckResult] = []
    content_type = msg.get_content_type()

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

    # Check charset
    charset = msg.get_param("charset")
    if charset is not None:
        results.extend(_check_charset(msg, charset, path))

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
            # Strip whitespace and check if it's valid base64
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
                results.append(
                    _error(
                        f"MIME-CTE-Content-{path}",
                        "Content declared as base64 but contains invalid base64 data",
                        rfc_ref="RFC 2045 §6.8",
                        details=str(exc),
                    )
                )
        elif cte_lower == "quoted-printable":
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

    return results
