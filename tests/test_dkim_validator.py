"""Tests for DKIM validator."""

from __future__ import annotations

from eml_validator.models import Severity
from eml_validator.validators.dkim_validator import (
    _canonicalize_body_relaxed,
    _canonicalize_body_simple,
    _parse_dkim_tag_value,
    validate_dkim,
)


def _has_severity(results, name_prefix: str, severity: Severity) -> bool:
    return any(r.severity == severity for r in results if r.name.startswith(name_prefix))


def _find(results, name: str):
    return next((r for r in results if r.name == name), None)


class TestDkimSignaturePresence:
    def test_no_signature_is_warning(self, valid_simple_eml):
        results = validate_dkim(valid_simple_eml, no_dns=True)
        assert _has_severity(results, "DKIM-Signature-Present", Severity.WARNING)

    def test_signature_present_is_ok(self, dkim_signed_eml):
        raw, dns_override = dkim_signed_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        assert _has_severity(results, "DKIM-Signature-Present", Severity.OK)


class TestDkimVerification:
    def test_valid_signature_passes(self, dkim_signed_eml):
        raw, dns_override = dkim_signed_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        verify_result = _find(results, "DKIM-Verify")
        assert verify_result is not None
        assert verify_result.severity == Severity.OK, f"Expected PASS, got: {verify_result.message}"

    def test_tampered_body_fails(self, dkim_broken_eml):
        raw, dns_override = dkim_broken_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        # Should have either DKIM-Verify failure or DKIM-Body-Hash failure
        verify_result = _find(results, "DKIM-Verify")
        body_hash_result = _find(results, "DKIM-Body-Hash")
        failed = (verify_result and verify_result.severity == Severity.ERROR) or (
            body_hash_result and body_hash_result.severity == Severity.ERROR
        )
        assert failed, "Expected verification failure for tampered email"

    def test_no_dns_skips_verification(self, dkim_signed_eml):
        raw, _ = dkim_signed_eml
        results = validate_dkim(raw, no_dns=True)
        assert _has_severity(results, "DKIM-Verify-Skipped", Severity.WARNING)


class TestDkimSignatureParams:
    def test_algorithm_rsa_sha256_ok(self, dkim_signed_eml):
        raw, dns_override = dkim_signed_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        assert _has_severity(results, "DKIM-Algorithm", Severity.OK)

    def test_rsa_sha1_is_warning(self):
        """Test that rsa-sha1 algorithm is flagged as warning."""
        raw = (
            b"DKIM-Signature: v=1; a=rsa-sha1; d=example.com; s=test;\r\n"
            b" h=from:to:subject; bh=abc123; b=sig\r\n"
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: Test\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_dkim(raw, no_dns=True)
        assert _has_severity(results, "DKIM-Algorithm", Severity.WARNING)

    def test_version_tag_ok(self, dkim_signed_eml):
        raw, dns_override = dkim_signed_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        assert _has_severity(results, "DKIM-Version", Severity.OK)


class TestDkimSignedHeaders:
    def test_critical_headers_signed(self, dkim_signed_eml):
        raw, dns_override = dkim_signed_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        assert _has_severity(results, "DKIM-Signed-Headers", Severity.OK)

    def test_missing_critical_header_warning(self):
        """DKIM-Signature with h= missing 'from' should warn."""
        raw = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test;\r\n"
            b" c=relaxed/relaxed; h=to:subject; bh=abc; b=sig\r\n"
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: Test\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_dkim(raw, no_dns=True)
        assert _has_severity(results, "DKIM-Signed-Headers", Severity.WARNING)


class TestDkimBodyHash:
    def test_valid_body_hash_matches(self, dkim_signed_eml):
        raw, dns_override = dkim_signed_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        bh_result = _find(results, "DKIM-Body-Hash")
        assert bh_result is not None
        assert bh_result.severity == Severity.OK

    def test_tampered_body_fails_hash(self, dkim_broken_eml):
        raw, dns_override = dkim_broken_eml
        results = validate_dkim(raw, dns_override=dns_override, no_dns=False)
        bh_result = _find(results, "DKIM-Body-Hash")
        if bh_result:
            assert bh_result.severity == Severity.ERROR


class TestCanonicalization:
    def test_simple_body_canon(self):
        body = b"Hello World\r\n\r\n\r\n"
        result = _canonicalize_body_simple(body)
        assert result.endswith(b"\r\n")
        # Trailing empty lines should be stripped
        assert not result.endswith(b"\r\n\r\n")

    def test_relaxed_body_canon_whitespace(self):
        body = b"Hello    World  \r\n"
        result = _canonicalize_body_relaxed(body)
        assert b"Hello World" in result
        # No trailing whitespace on line
        for line in result.split(b"\r\n"):
            assert not line.endswith(b" "), f"Line has trailing space: {line!r}"

    def test_relaxed_body_canon_crlf(self):
        body = b"Line 1\nLine 2\n"
        result = _canonicalize_body_relaxed(body)
        assert b"\r\n" in result

    def test_canonicalization_matrix(self, dkim_signed_eml):
        raw, dns_override = dkim_signed_eml
        results = validate_dkim(
            raw,
            dns_override=dns_override,
            no_dns=False,
            canonicalization_matrix=True,
        )
        matrix_results = [r for r in results if r.name.startswith("DKIM-Canon-")]
        assert len(matrix_results) == 4, f"Expected 4 matrix results, got {len(matrix_results)}"


class TestTagValueParsing:
    def test_parse_basic(self):
        sig = "v=1; a=rsa-sha256; d=example.com; s=sel"
        params = _parse_dkim_tag_value(sig)
        assert params["v"] == "1"
        assert params["a"] == "rsa-sha256"
        assert params["d"] == "example.com"
        assert params["s"] == "sel"

    def test_parse_with_whitespace(self):
        sig = "v = 1 ; a = rsa-sha256"
        params = _parse_dkim_tag_value(sig)
        assert params["v"] == "1"
        assert params["a"] == "rsa-sha256"


class TestExpiration:
    def test_no_expiry_tag_no_result(self, valid_simple_eml):
        # A message without DKIM signature won't have expiry checks
        results = validate_dkim(valid_simple_eml, no_dns=True)
        expiry_results = [r for r in results if r.name == "DKIM-Expiration"]
        assert not expiry_results

    def test_expired_signature_error(self):
        # x=1 (expired in 1970)
        raw = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test;\r\n"
            b" c=relaxed/relaxed; x=1; h=from:to:subject:date:content-type;\r\n"
            b" bh=abc; b=sig\r\n"
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: Test\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_dkim(raw, no_dns=True)
        expiry_results = [r for r in results if r.name == "DKIM-Expiration"]
        assert expiry_results
        assert expiry_results[0].severity == Severity.ERROR


class TestDKIMHeaderOversigning:
    def test_duplicate_h_headers_is_warning(self):
        raw = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test;\r\n"
            b" c=relaxed/relaxed; h=from:to:from;\r\n"
            b" bh=abc; b=sig\r\n"
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: Test\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_dkim(raw, no_dns=True)
        warns = [r for r in results if "H-Oversigning" in r.name and r.severity == Severity.WARNING]
        assert warns, "Expected warning for duplicate header name in DKIM h= tag"
        assert any("from ×2" in r.details for r in warns)

    def test_unique_h_headers_no_warning(self):
        raw = (
            b"DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test;\r\n"
            b" c=relaxed/relaxed; h=from:to:subject;\r\n"
            b" bh=abc; b=sig\r\n"
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Subject: Test\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_dkim(raw, no_dns=True)
        assert not any("H-Oversigning" in r.name for r in results)
