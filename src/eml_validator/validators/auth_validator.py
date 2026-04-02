"""Authentication-Results header parser and optional DKIM/DMARC validator."""

from __future__ import annotations

import email
import email.policy
import re

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


def validate_auth(
    raw: bytes,
    check_auth: bool = False,
    dns_override: dict[str, bytes] | None = None,
) -> list[CheckResult]:
    """Run authentication header checks."""
    results: list[CheckResult] = []

    msg = email.message_from_bytes(raw, policy=email.policy.compat32)

    # Parse existing Authentication-Results headers
    auth_results = msg.get_all("authentication-results", [])

    if auth_results:
        for i, ar in enumerate(auth_results):
            results.extend(_parse_authentication_results(str(ar), index=i))
    else:
        results.append(
            _warn(
                "Auth-Results-Present",
                "No Authentication-Results header found",
                rfc_ref="RFC 7601",
                details="This header is added by receiving MTAs after authentication checks",
            )
        )

    # Optionally perform live DKIM/DMARC validation via authheaders
    if check_auth:
        results.extend(_run_authheaders_check(raw, dns_override))

    return results


def _parse_authentication_results(ar_value: str, index: int = 0) -> list[CheckResult]:
    """Parse and report an Authentication-Results header value."""
    results: list[CheckResult] = []
    prefix = f"Auth-Results-{index}"

    # Basic structure: authserv-id ; method=result ...
    parts = [p.strip() for p in ar_value.split(";")]
    if not parts:
        return [_warn(f"{prefix}", "Empty Authentication-Results header", rfc_ref="RFC 7601")]

    authserv_id = parts[0].strip()
    results.append(
        _ok(
            f"{prefix}-AuthServId",
            f"Authentication-Results from: {authserv_id}",
            rfc_ref="RFC 7601",
        )
    )

    # Parse each method result
    for part in parts[1:]:
        part = part.strip()
        if not part:
            continue
        method_result = _parse_method_result(part)
        if method_result:
            method, result_val, props = method_result
            severity = _severity_for_auth_result(method, result_val)
            results.append(
                CheckResult(
                    name=f"{prefix}-{method.upper()}",
                    severity=severity,
                    message=f"{method}={result_val}",
                    rfc_ref="RFC 7601",
                    details="; ".join(f"{k}={v}" for k, v in props.items()) if props else "",
                )
            )

    return results


def _parse_method_result(
    part: str,
) -> tuple[str, str, dict[str, str]] | None:
    """Parse a single method=result [props...] part."""
    # Match method=result
    match = re.match(r"^([\w-]+)\s*=\s*([\w-]+)(.*)?$", part, re.DOTALL)
    if not match:
        return None

    method = match.group(1).lower()
    result_val = match.group(2).lower()
    remainder = match.group(3) or ""

    # Parse additional properties
    props: dict[str, str] = {}
    for prop_match in re.finditer(r"([\w.]+)\s*=\s*([\S]+)", remainder):
        props[prop_match.group(1)] = prop_match.group(2)

    return method, result_val, props


def _severity_for_auth_result(method: str, result: str) -> Severity:
    """Determine severity based on method and result value."""
    pass_results = {"pass"}
    fail_results = {"fail", "hardfail", "none"}
    warn_results = {"softfail", "neutral", "temperror", "permerror", "policy"}

    if result in pass_results:
        return Severity.OK
    elif result in fail_results:
        return Severity.ERROR
    elif result in warn_results:
        return Severity.WARNING
    else:
        return Severity.WARNING


def _run_authheaders_check(
    raw: bytes,
    dns_override: dict[str, bytes] | None,
) -> list[CheckResult]:
    """Use authheaders library to perform DKIM/DMARC validation."""
    try:
        import authheaders

        # authheaders.check_message returns an Authentication-Results header
        # We'll parse that result
        try:
            # Build a DNS function if needed
            if dns_override:

                def dnsfunc(name: str, rdtype: str = "TXT") -> list[bytes]:
                    record = dns_override.get(name)
                    return [record] if record is not None else []
            else:
                dnsfunc = None

            result_header = authheaders.check_message(
                raw,
                "localhost",
                "127.0.0.1",
                "localhost",
                dnsfunc=dnsfunc,
            )

            if result_header:
                # Parse the returned header
                # It's in the form: Authentication-Results: authserv; method=result
                _, _, value = result_header.partition(":")
                return _parse_authentication_results(value.strip(), index=99)
            else:
                return [
                    _warn(
                        "Auth-Check-Result",
                        "authheaders returned no Authentication-Results",
                        rfc_ref="RFC 7601",
                    )
                ]

        except Exception as exc:
            return [
                _warn(
                    "Auth-Check-Error",
                    f"authheaders check failed: {exc}",
                    rfc_ref="RFC 7601",
                    details=str(exc),
                )
            ]

    except ImportError:
        return [
            _warn(
                "Auth-Check-Skipped",
                "authheaders not installed — live auth check skipped",
                rfc_ref="RFC 7601",
            )
        ]
