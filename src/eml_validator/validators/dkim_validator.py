"""DKIM signature validator using dkimpy."""

from __future__ import annotations

import base64
import email
import email.policy
import hashlib
import re
from collections.abc import Callable
from typing import Any

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


# Critical headers that should be signed per best practices
CRITICAL_HEADERS = {"from", "subject", "date", "to", "content-type"}

# Minimum recommended RSA key sizes
RSA_KEY_MIN_BITS = 1024
RSA_KEY_RECOMMENDED_BITS = 2048


def validate_dkim(
    raw: bytes,
    dns_override: dict[str, bytes] | None = None,
    no_dns: bool = False,
    canonicalization_matrix: bool = False,
) -> list[CheckResult]:
    """Run all DKIM checks on raw email bytes."""
    results: list[CheckResult] = []

    # Check for DKIM-Signature header presence
    msg = email.message_from_bytes(raw, policy=email.policy.compat32)
    dkim_sig = msg.get("dkim-signature")

    if dkim_sig is None:
        results.append(
            _warn(
                "DKIM-Signature-Present",
                "No DKIM-Signature header found",
                rfc_ref="RFC 6376 §3.5",
            )
        )
        return results

    results.append(
        _ok(
            "DKIM-Signature-Present",
            "DKIM-Signature header present",
            rfc_ref="RFC 6376 §3.5",
        )
    )

    # Parse signature tags
    sig_params = _parse_dkim_tag_value(str(dkim_sig))
    results.extend(_check_signature_params(sig_params))

    # Check expiration
    results.extend(_check_expiration(sig_params))

    # Try to verify the signature
    if not no_dns:
        dnsfunc = _build_dns_func(dns_override)
        results.extend(_verify_signature(raw, dnsfunc))

        # Check key size via DNS
        results.extend(_check_key_size(sig_params, dnsfunc))
    else:
        results.append(
            _warn(
                "DKIM-Verify-Skipped",
                "DKIM signature verification skipped (--no-dns mode)",
                rfc_ref="RFC 6376",
            )
        )

    # Verify body hash independently
    results.extend(_check_body_hash(raw, sig_params))

    # Check signed headers
    results.extend(_check_signed_headers(sig_params))

    # Canonicalization matrix
    if canonicalization_matrix:
        results.extend(_check_canonicalization_matrix(raw, sig_params))

    return results


def _parse_dkim_tag_value(sig: str) -> dict[str, str]:
    """Parse DKIM tag=value pairs from a DKIM-Signature header."""
    params: dict[str, str] = {}
    # Remove whitespace and split by semicolons
    for part in sig.split(";"):
        part = part.strip()
        if "=" in part:
            tag, _, value = part.partition("=")
            params[tag.strip()] = value.strip()
    return params


def _check_signature_params(params: dict[str, str]) -> list[CheckResult]:
    """Check that required DKIM signature tags are present and valid."""
    results: list[CheckResult] = []

    required_tags = {"v", "a", "d", "s", "h", "bh", "b"}
    for tag in required_tags:
        if tag not in params:
            results.append(
                _error(
                    f"DKIM-Tag-{tag}",
                    f"Missing required DKIM tag: {tag}=",
                    rfc_ref="RFC 6376 §3.5",
                )
            )

    # Check version
    if params.get("v") == "1":
        results.append(_ok("DKIM-Version", "DKIM version 1 (correct)", rfc_ref="RFC 6376 §3.5"))
    elif "v" in params:
        results.append(
            _error(
                "DKIM-Version",
                f"Unexpected DKIM version: v={params['v']}",
                rfc_ref="RFC 6376 §3.5",
            )
        )

    # Check algorithm
    algo = params.get("a", "")
    if algo == "rsa-sha256":
        results.append(
            _ok("DKIM-Algorithm", "Signature algorithm: rsa-sha256 (secure)", rfc_ref="RFC 6376 §3.3")
        )
    elif algo == "ed25519-sha256":
        results.append(
            _ok(
                "DKIM-Algorithm",
                "Signature algorithm: ed25519-sha256 (secure)",
                rfc_ref="RFC 6376 §3.3",
            )
        )
    elif algo == "rsa-sha1":
        results.append(
            _warn(
                "DKIM-Algorithm",
                "Signature algorithm rsa-sha1 is deprecated and considered insecure",
                rfc_ref="RFC 8301",
                details="Use rsa-sha256 or ed25519-sha256 instead",
            )
        )
    elif algo:
        results.append(
            _warn(
                "DKIM-Algorithm",
                f"Unknown/unusual DKIM algorithm: {algo}",
                rfc_ref="RFC 6376 §3.3",
            )
        )

    # Check canonicalization
    canon = params.get("c", "simple/simple")
    valid_canon = {"simple", "relaxed"}
    parts = canon.split("/")
    header_canon = parts[0] if parts else ""
    body_canon = parts[1] if len(parts) > 1 else "simple"

    if header_canon not in valid_canon or body_canon not in valid_canon:
        results.append(
            _error(
                "DKIM-Canonicalization",
                f"Invalid canonicalization: c={canon}",
                rfc_ref="RFC 6376 §3.4",
            )
        )
    else:
        results.append(
            _ok(
                "DKIM-Canonicalization",
                f"Canonicalization: {canon}",
                rfc_ref="RFC 6376 §3.4",
            )
        )

    return results


def _check_expiration(params: dict[str, str]) -> list[CheckResult]:
    """Check if DKIM signature has expired."""
    import time

    x_tag = params.get("x")
    if x_tag is None:
        return []

    try:
        expiry = int(x_tag)
        now = int(time.time())
        if now > expiry:
            import datetime

            exp_dt = datetime.datetime.fromtimestamp(expiry, tz=datetime.UTC)
            return [
                _error(
                    "DKIM-Expiration",
                    f"DKIM signature has expired at {exp_dt.isoformat()}",
                    rfc_ref="RFC 6376 §3.5",
                )
            ]
        else:
            return [
                _ok(
                    "DKIM-Expiration",
                    "DKIM signature has not expired",
                    rfc_ref="RFC 6376 §3.5",
                )
            ]
    except (ValueError, TypeError) as exc:
        return [
            _warn(
                "DKIM-Expiration",
                f"Could not parse DKIM expiration tag: {exc}",
                rfc_ref="RFC 6376 §3.5",
            )
        ]


def _build_dns_func(
    dns_override: dict[str, bytes] | None,
) -> Callable[[str, str], list[bytes]] | None:
    """Build a DNS lookup function, optionally with override records."""
    if dns_override is None:
        return None

    def dnsfunc(name: str | bytes, timeout: int = 5, **kwargs: object) -> bytes | None:
        # dkimpy passes name as bytes; normalize to str for lookup
        if isinstance(name, bytes):
            name_str = name.decode("ascii", errors="replace")
        else:
            name_str = name
        record = dns_override.get(name_str) or dns_override.get(name_str.rstrip("."))
        return record

    return dnsfunc


def _verify_signature(
    raw: bytes,
    dnsfunc: Callable | None,
) -> list[CheckResult]:
    """Verify DKIM signature using dkimpy."""
    try:
        import dkim

        kwargs: dict[str, Any] = {}
        if dnsfunc is not None:
            kwargs["dnsfunc"] = dnsfunc

        result = dkim.verify(raw, **kwargs)

        if result:
            return [
                _ok(
                    "DKIM-Verify",
                    "DKIM signature verification: PASS",
                    rfc_ref="RFC 6376",
                )
            ]
        else:
            return [
                _error(
                    "DKIM-Verify",
                    "DKIM signature verification: FAIL",
                    rfc_ref="RFC 6376",
                    details="The signature does not match the message content",
                )
            ]
    except ImportError:
        return [
            _warn(
                "DKIM-Verify",
                "dkimpy not installed — DKIM verification skipped",
                rfc_ref="RFC 6376",
            )
        ]
    except Exception as exc:
        return [
            _error(
                "DKIM-Verify",
                f"DKIM verification error: {exc}",
                rfc_ref="RFC 6376",
                details=str(exc),
            )
        ]


def _check_key_size(
    params: dict[str, str],
    dnsfunc: Callable | None,
) -> list[CheckResult]:
    """Fetch the public key from DNS and check its size."""
    domain = params.get("d", "")
    selector = params.get("s", "")
    algo = params.get("a", "")

    if not domain or not selector:
        return []

    if not algo.startswith("rsa"):
        # Ed25519 keys are always 256-bit, inherently secure
        return [
            _ok(
                "DKIM-Key-Size",
                "Ed25519 key (256-bit equivalent security) — adequate",
                rfc_ref="RFC 8463",
            )
        ]

    dns_name = f"{selector}._domainkey.{domain}"

    try:
        if dnsfunc is not None:
            records = dnsfunc(dns_name, "TXT")
        else:
            import dns.resolver

            answers = dns.resolver.resolve(dns_name, "TXT")
            records = [b"".join(rdata.strings) for rdata in answers]

        if not records:
            return [
                _warn(
                    "DKIM-Key-Size",
                    f"No DNS TXT record found for {dns_name}",
                    rfc_ref="RFC 6376 §3.6",
                )
            ]

        dns_record = records[0].decode("ascii", errors="replace")
        key_data = _extract_public_key(dns_record)

        if key_data is None:
            return [
                _warn(
                    "DKIM-Key-Size",
                    "Could not extract public key from DNS record",
                    rfc_ref="RFC 6376 §3.6",
                )
            ]

        key_bits = _get_rsa_key_bits(key_data)
        if key_bits is None:
            return [
                _warn(
                    "DKIM-Key-Size",
                    "Could not determine RSA key size",
                    rfc_ref="RFC 6376",
                )
            ]

        if key_bits < RSA_KEY_MIN_BITS:
            return [
                _error(
                    "DKIM-Key-Size",
                    f"RSA key size {key_bits} bits is below minimum of {RSA_KEY_MIN_BITS} bits",
                    rfc_ref="RFC 8301",
                )
            ]
        elif key_bits < RSA_KEY_RECOMMENDED_BITS:
            return [
                _warn(
                    "DKIM-Key-Size",
                    f"RSA key size: {key_bits} bits (recommended: ≥ {RSA_KEY_RECOMMENDED_BITS})",
                    rfc_ref="RFC 8301",
                    details=f"Key is {key_bits} bits; {RSA_KEY_RECOMMENDED_BITS} bits recommended",
                )
            ]
        else:
            return [
                _ok(
                    "DKIM-Key-Size",
                    f"RSA key size: {key_bits} bits (adequate)",
                    rfc_ref="RFC 8301",
                )
            ]

    except Exception as exc:
        return [
            _warn(
                "DKIM-Key-Size",
                f"Could not check key size: {exc}",
                rfc_ref="RFC 6376 §3.6",
            )
        ]


def _extract_public_key(dns_record: str) -> bytes | None:
    """Extract base64-encoded public key from a DKIM DNS TXT record."""
    match = re.search(r"p=([A-Za-z0-9+/=]+)", dns_record)
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1))
    except Exception:
        return None


def _get_rsa_key_bits(der_bytes: bytes) -> int | None:
    """Return the RSA key size in bits from DER-encoded SubjectPublicKeyInfo."""
    try:
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        from cryptography.hazmat.primitives.serialization import load_der_public_key

        key = load_der_public_key(der_bytes)
        if isinstance(key, RSAPublicKey):
            return key.key_size
        return None
    except Exception:
        return None


def _check_body_hash(raw: bytes, params: dict[str, str]) -> list[CheckResult]:
    """Recalculate the body hash independently and compare with bh= tag."""
    bh_declared = params.get("bh", "")
    canon = params.get("c", "simple/simple")
    algo = params.get("a", "rsa-sha256")

    if not bh_declared:
        return [_error("DKIM-Body-Hash", "Missing bh= tag in DKIM-Signature", rfc_ref="RFC 6376 §3.5")]

    # Determine body canonicalization
    canon_parts = canon.split("/")
    body_canon = canon_parts[1] if len(canon_parts) > 1 else "simple"

    # Extract body from raw message
    body = _extract_body(raw)
    if body is None:
        return [
            _warn(
                "DKIM-Body-Hash",
                "Could not extract message body for hash verification",
                rfc_ref="RFC 6376 §3.4",
            )
        ]

    # Canonicalize the body
    if body_canon == "relaxed":
        canonicalized_body = _canonicalize_body_relaxed(body)
    else:
        canonicalized_body = _canonicalize_body_simple(body)

    # Determine hash algorithm
    if "sha256" in algo:
        digest = hashlib.sha256(canonicalized_body).digest()
    elif "sha1" in algo:
        digest = hashlib.sha1(canonicalized_body).digest()  # noqa: S324
    else:
        return [
            _warn(
                "DKIM-Body-Hash",
                f"Unknown hash algorithm in {algo}, cannot verify body hash",
                rfc_ref="RFC 6376 §3.3",
            )
        ]

    # Truncate if l= tag is present
    l_tag = params.get("l")
    if l_tag:
        try:
            l_val = int(l_tag)
            canonicalized_body = canonicalized_body[:l_val]
            if "sha256" in algo:
                digest = hashlib.sha256(canonicalized_body).digest()
            elif "sha1" in algo:
                digest = hashlib.sha1(canonicalized_body).digest()  # noqa: S324
        except ValueError:
            pass

    computed_bh = base64.b64encode(digest).decode("ascii")

    # Normalize both for comparison (strip whitespace)
    declared_clean = "".join(bh_declared.split())
    computed_clean = "".join(computed_bh.split())

    if declared_clean == computed_clean:
        return [
            _ok(
                "DKIM-Body-Hash",
                "Body hash (bh=) matches computed value",
                rfc_ref="RFC 6376 §3.4.4",
            )
        ]
    else:
        return [
            _error(
                "DKIM-Body-Hash",
                "Body hash (bh=) does not match computed value — body may have been modified",
                rfc_ref="RFC 6376 §3.4.4",
                details=f"Declared: {declared_clean[:40]}...\nComputed: {computed_clean[:40]}...",
            )
        ]


def _extract_body(raw: bytes) -> bytes | None:
    """Extract the body from raw email bytes."""
    # Try CRLF separator first, then LF
    for sep in (b"\r\n\r\n", b"\n\n"):
        if sep in raw:
            _, _, body = raw.partition(sep)
            return body
    return None


def _canonicalize_body_simple(body: bytes) -> bytes:
    """Apply simple body canonicalization per RFC 6376 §3.4.3."""
    # Normalize line endings to CRLF
    body = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    body = body.replace(b"\n", b"\r\n")

    # Remove trailing empty CRLF lines
    while body.endswith(b"\r\n\r\n"):
        body = body[:-2]

    if not body.endswith(b"\r\n"):
        body += b"\r\n"

    return body


def _canonicalize_body_relaxed(body: bytes) -> bytes:
    """Apply relaxed body canonicalization per RFC 6376 §3.4.4."""
    lines = body.replace(b"\r\n", b"\n").replace(b"\r", b"\n").split(b"\n")
    result_lines: list[bytes] = []

    for line in lines:
        # Reduce all whitespace sequences to a single space
        line = re.sub(rb"[ \t]+", b" ", line)
        # Remove trailing whitespace
        line = line.rstrip(b" \t")
        result_lines.append(line)

    result = b"\r\n".join(result_lines)

    # Strip trailing empty lines
    while result.endswith(b"\r\n\r\n"):
        result = result[:-2]

    if not result.endswith(b"\r\n"):
        result += b"\r\n"

    return result


def _check_signed_headers(params: dict[str, str]) -> list[CheckResult]:
    """Check that critical headers are included in h= tag."""
    h_tag = params.get("h", "")
    signed_headers = {h.strip().lower() for h in h_tag.split(":")}

    missing = CRITICAL_HEADERS - signed_headers
    if missing:
        return [
            _warn(
                "DKIM-Signed-Headers",
                f"Critical header(s) not in DKIM h= list: {', '.join(sorted(missing))}",
                rfc_ref="RFC 6376 §5.4",
                details=f"Signed headers: {h_tag}\nMissing: {', '.join(sorted(missing))}",
            )
        ]
    return [
        _ok(
            "DKIM-Signed-Headers",
            f"Critical headers signed: {', '.join(sorted(CRITICAL_HEADERS))}",
            rfc_ref="RFC 6376 §5.4",
        )
    ]


def _check_canonicalization_matrix(
    raw: bytes,
    params: dict[str, str],
) -> list[CheckResult]:
    """Test all 4 canonicalization combinations and report body hash results."""
    results: list[CheckResult] = []
    algo = params.get("a", "rsa-sha256")
    bh_declared = "".join(params.get("bh", "").split())

    if not bh_declared:
        return [
            _warn(
                "DKIM-Canon-Matrix",
                "Cannot test canonicalization matrix: missing bh= tag",
                rfc_ref="RFC 6376 §3.4",
            )
        ]

    body = _extract_body(raw)
    if body is None:
        return [
            _warn(
                "DKIM-Canon-Matrix",
                "Cannot test canonicalization matrix: could not extract body",
                rfc_ref="RFC 6376 §3.4",
            )
        ]

    combos = [
        ("simple", "simple"),
        ("simple", "relaxed"),
        ("relaxed", "simple"),
        ("relaxed", "relaxed"),
    ]

    if "sha256" in algo:
        hash_fn = hashlib.sha256
    elif "sha1" in algo:
        hash_fn = hashlib.sha1
    else:
        return [
            _warn(
                "DKIM-Canon-Matrix",
                f"Cannot test canonicalization matrix: unknown algorithm {algo}",
                rfc_ref="RFC 6376 §3.4",
            )
        ]

    for header_canon, body_canon in combos:
        if body_canon == "relaxed":
            canon_body = _canonicalize_body_relaxed(body)
        else:
            canon_body = _canonicalize_body_simple(body)

        computed = base64.b64encode(hash_fn(canon_body).digest()).decode("ascii")
        body_match = computed == bh_declared

        results.append(
            CheckResult(
                name=f"DKIM-Canon-{header_canon}-{body_canon}",
                severity=Severity.OK if body_match else Severity.WARNING,
                message=f"Canon {header_canon}/{body_canon}: body hash {'matches' if body_match else 'does NOT match'}",
                rfc_ref="RFC 6376 §3.4",
                details=f"header={header_canon}, body={body_canon}, bh_match={body_match}",
            )
        )

    return results
