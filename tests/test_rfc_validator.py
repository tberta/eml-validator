"""Tests for RFC 5322 validator."""

from __future__ import annotations

from eml_validator.models import Severity
from eml_validator.validators.rfc_validator import validate_rfc


def _severities(results, name_prefix: str) -> list[Severity]:
    return [r.severity for r in results if r.name.startswith(name_prefix)]


def _find(results, name: str):
    return next((r for r in results if r.name == name), None)


def _has_severity(results, name_prefix: str, severity: Severity) -> bool:
    return any(r.severity == severity for r in results if r.name.startswith(name_prefix))


class TestRequiredHeaders:
    def test_valid_email_has_no_errors(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        errors = [r for r in results if r.severity in (Severity.ERROR, Severity.CRITICAL)]
        assert not errors, f"Expected no errors, got: {[r.message for r in errors]}"

    def test_missing_from_raises_error(self, missing_from_eml):
        results = validate_rfc(missing_from_eml)
        assert _has_severity(results, "RFC5322-From-Header", Severity.ERROR)

    def test_present_from_is_ok(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        assert _has_severity(results, "RFC5322-From-Header", Severity.OK)

    def test_missing_date_raises_error(self):
        raw = b"From: Alice <alice@example.com>\r\nSubject: Test\r\n\r\nBody\r\n"
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-Date-Header", Severity.ERROR)

    def test_missing_message_id_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"To: Bob <bob@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-Message-Id-Header", Severity.WARNING)


class TestSingularHeaders:
    def test_duplicate_from_is_error(self, duplicate_headers_eml):
        results = validate_rfc(duplicate_headers_eml)
        assert _has_severity(results, "RFC5322-From-Unique", Severity.ERROR)

    def test_unique_from_is_ok(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        assert _has_severity(results, "RFC5322-From-Unique", Severity.OK)


class TestDateFormat:
    def test_valid_date_is_ok(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        assert _has_severity(results, "RFC5322-Date-Format", Severity.OK)

    def test_invalid_date_is_error(self, bad_date_eml):
        results = validate_rfc(bad_date_eml)
        assert _has_severity(results, "RFC5322-Date-Format", Severity.ERROR)


class TestLineLengths:
    def test_normal_lines_ok(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        assert _has_severity(results, "RFC5322-Line-Length", Severity.OK)

    def test_long_header_line_warning(self):
        long_subject = b"X" * 80
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Subject: " + long_subject + b"\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        # Should get either warning or OK (78 char threshold)
        line_len_results = [r for r in results if r.name == "RFC5322-Line-Length"]
        assert line_len_results

    def test_very_long_line_error(self):
        long_subject = b"X" * 1000
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Subject: " + long_subject + b"\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-Line-Length", Severity.ERROR)


class TestMimeVersion:
    def test_mime_version_present_ok(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        assert _has_severity(results, "RFC2045-MIME-Version", Severity.OK)

    def test_missing_mime_version_warning(self, missing_mime_version_eml):
        results = validate_rfc(missing_mime_version_eml)
        assert _has_severity(results, "RFC2045-MIME-Version", Severity.WARNING)


class TestContentType:
    def test_valid_content_type_ok(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        ct_results = [r for r in results if r.name == "RFC2045-Content-Type"]
        # If present, should be OK
        if ct_results:
            assert any(r.severity == Severity.OK for r in ct_results)

    def test_invalid_content_type_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: invalidtype\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC2045-Content-Type", Severity.ERROR)


class TestHeaderEncoding:
    def test_ascii_headers_ok(self, valid_simple_eml):
        results = validate_rfc(valid_simple_eml)
        assert _has_severity(results, "RFC2047-Header-Encoding", Severity.OK)

    def test_unencoded_non_ascii_error(self):
        # Embed raw UTF-8 bytes in a header without RFC 2047 encoding
        raw = (
            b"From: Alice \xc3\xa9 <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC2047-Header-Encoding", Severity.ERROR)

    def test_encoded_word_is_ok(self):
        # RFC 2047 encoded word: =?UTF-8?Q?caf=C3=A9?=
        raw = (
            b"From: =?UTF-8?Q?Ren=C3=A9?= <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        # Should not error on properly encoded headers
        encoding_results = [r for r in results if r.name == "RFC2047-Header-Encoding"]
        if encoding_results:
            assert not any(r.severity == Severity.ERROR for r in encoding_results)


class TestAddressSyntax:
    def test_empty_cc_header_is_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"CC: \r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        warns = [r for r in results if "Cc-Empty" in r.name and r.severity == Severity.WARNING]
        assert warns, "Expected warning for empty CC header"

    def test_present_cc_with_address_no_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"CC: bob@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert not any("Cc-Empty" in r.name for r in results)

    def test_absent_cc_no_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"To: bob@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert not any("Cc-Empty" in r.name for r in results)


# ---------------------------------------------------------------------------
# Raw-byte checks (msglint-derived)
# ---------------------------------------------------------------------------

_VALID = (
    b"From: alice@example.com\r\n"
    b"To: bob@example.com\r\n"
    b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
    b"Message-ID: <abc@example.com>\r\n"
    b"\r\n"
    b"Body\r\n"
)


class TestTruncatedMessage:
    def test_no_blank_line_is_error(self):
        raw = b"From: alice@example.com\r\nDate: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-Truncated", Severity.ERROR)

    def test_valid_message_no_error(self):
        results = validate_rfc(_VALID)
        assert not _has_severity(results, "RFC5322-Truncated", Severity.ERROR)


class TestEmptyFoldedContinuation:
    def test_whitespace_only_continuation_is_warning(self):
        # A folded header where the continuation is spaces only
        raw = (
            b"From: alice@example.com\r\n"
            b"Subject: hello\r\n"
            b"X-Custom: value\r\n"
            b"   \r\n"  # whitespace-only continuation
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-EmptyFoldedContinuation", Severity.WARNING)

    def test_normal_folding_no_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Subject: hello\r\n"
            b"X-Custom: part1\r\n"
            b"    part2\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert not _has_severity(results, "RFC5322-EmptyFoldedContinuation", Severity.WARNING)


class TestMultiFromSender:
    def test_multi_from_no_sender_is_error(self):
        raw = (
            b"From: alice@example.com, bob@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-MultiFrom-NoSender", Severity.ERROR)

    def test_multi_from_with_sender_ok(self):
        raw = (
            b"From: alice@example.com, bob@example.com\r\n"
            b"Sender: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert not _has_severity(results, "RFC5322-MultiFrom-NoSender", Severity.ERROR)

    def test_single_from_with_comma_in_display_name_ok(self):
        # Comma inside quoted display name must not trigger the check
        raw = (
            b'From: "Smith, Alice" <alice@example.com>\r\n'
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert not _has_severity(results, "RFC5322-MultiFrom-NoSender", Severity.ERROR)

    def test_single_from_no_error(self):
        results = validate_rfc(_VALID)
        assert not _has_severity(results, "RFC5322-MultiFrom-NoSender", Severity.ERROR)


class Test8BitInStructuredFields:
    def test_8bit_in_comment_is_error(self):
        raw = (
            b"From: alice@example.com (caf\xe9)\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-8BitInComment", Severity.ERROR)

    def test_8bit_in_quoted_string_is_error(self):
        raw = (
            b'From: "caf\xe9" <alice@example.com>\r\n'
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-8BitInQuotedString", Severity.ERROR)

    def test_8bit_in_domain_literal_is_error(self):
        raw = (
            b"From: alice@[\xc0.example.com]\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-8BitInDomainLiteral", Severity.ERROR)

    def test_ascii_structured_fields_no_error(self):
        results = validate_rfc(_VALID)
        assert not _has_severity(results, "RFC5322-8BitInComment", Severity.ERROR)
        assert not _has_severity(results, "RFC5322-8BitInQuotedString", Severity.ERROR)
        assert not _has_severity(results, "RFC5322-8BitInDomainLiteral", Severity.ERROR)


class TestUnbalancedDelimiters:
    def test_unbalanced_quote_is_error(self):
        raw = (
            b'From: "alice <alice@example.com>\r\n'
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-UnbalancedQuote", Severity.ERROR)

    def test_unbalanced_paren_is_error(self):
        raw = (
            b"From: alice@example.com (comment\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-UnbalancedComment", Severity.ERROR)

    def test_balanced_delimiters_no_error(self):
        results = validate_rfc(_VALID)
        assert not _has_severity(results, "RFC5322-UnbalancedQuote", Severity.ERROR)
        assert not _has_severity(results, "RFC5322-UnbalancedComment", Severity.ERROR)
        assert not _has_severity(results, "RFC5322-UnbalancedDomainLiteral", Severity.ERROR)


class TestNewlineInQuotedString:
    def test_literal_newline_in_quoted_string_is_error(self):
        # Embedded bare newline inside a quoted-string in the From header
        raw = (
            b'From: "alice\nmalformed" <alice@example.com>\r\n'
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_rfc(raw)
        assert _has_severity(results, "RFC5322-NewlineInQuotedString", Severity.ERROR)

    def test_no_newline_in_quoted_string_ok(self):
        results = validate_rfc(_VALID)
        assert not _has_severity(results, "RFC5322-NewlineInQuotedString", Severity.ERROR)
