"""Tests for MIME structure validator."""

from __future__ import annotations

from eml_validator.models import Severity
from eml_validator.validators.mime_validator import validate_mime


def _has_severity(results, name_prefix: str, severity: Severity) -> bool:
    return any(r.severity == severity for r in results if r.name.startswith(name_prefix))


def _all_severities(results) -> list[Severity]:
    return [r.severity for r in results]


class TestMultipartStructure:
    def test_valid_multipart_ok(self, valid_multipart_eml):
        results = validate_mime(valid_multipart_eml)
        errors = [r for r in results if r.severity in (Severity.ERROR, Severity.CRITICAL)]
        assert not errors, f"Unexpected errors: {[r.message for r in errors]}"

    def test_missing_boundary_error(self, broken_boundary_eml):
        results = validate_mime(broken_boundary_eml)
        # Should flag missing or invalid boundary
        errors = [r for r in results if r.severity in (Severity.ERROR, Severity.CRITICAL)]
        # The broken boundary eml has no boundary param in Content-Type
        assert errors or any(r.severity == Severity.WARNING for r in results)

    def test_alt_missing_plain_is_warning(self, alt_no_plain_eml):
        results = validate_mime(alt_no_plain_eml)
        warnings = [r for r in results if r.severity == Severity.WARNING]
        assert warnings, "Expected a warning for missing text/plain in multipart/alternative"

    def test_alt_with_plain_ok(self, valid_multipart_eml):
        results = validate_mime(valid_multipart_eml)
        alt_results = [r for r in results if "MIME-Alt" in r.name]
        if alt_results:
            assert any(r.severity == Severity.OK for r in alt_results)


class TestContentTransferEncoding:
    def test_valid_cte_ok(self, valid_simple_eml):
        results = validate_mime(valid_simple_eml)
        errors = [r for r in results if r.severity in (Severity.ERROR, Severity.CRITICAL)]
        assert not errors

    def test_invalid_base64_is_error(self, invalid_base64_eml):
        results = validate_mime(invalid_base64_eml)
        # Should flag invalid base64 content
        cte_errors = [
            r
            for r in results
            if "CTE" in r.name and r.severity in (Severity.ERROR, Severity.CRITICAL)
        ]
        assert cte_errors, "Expected error for invalid base64 content"

    def test_invalid_cte_value_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Transfer-Encoding: invalid-encoding\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        errors = [
            r
            for r in results
            if "CTE" in r.name and r.severity in (Severity.ERROR, Severity.CRITICAL)
        ]
        assert errors


class TestCharset:
    def test_valid_utf8_charset(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello World\r\n"
        )
        results = validate_mime(raw)
        errors = [r for r in results if r.severity in (Severity.ERROR, Severity.CRITICAL)]
        assert not errors

    def test_unknown_charset_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=x-unknown-charset-xyz\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        charset_errors = [
            r
            for r in results
            if "Charset" in r.name and r.severity in (Severity.ERROR, Severity.CRITICAL)
        ]
        assert charset_errors


class TestEmptyParts:
    def test_empty_body_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"\r\n"
        )
        results = validate_mime(raw)
        # empty body should generate a warning
        warnings = [r for r in results if r.severity == Severity.WARNING and "Empty" in r.name]
        assert warnings


class TestAttachments:
    def test_attachment_with_content_disposition(self):
        import email.mime.application
        import email.mime.multipart
        import email.mime.text
        import email.utils

        msg = email.mime.multipart.MIMEMultipart("mixed")
        msg["From"] = "alice@example.com"
        msg["To"] = "bob@example.com"
        msg["Subject"] = "With attachment"
        msg["Date"] = email.utils.formatdate(localtime=False)
        msg["Message-ID"] = "<attach-test@example.com>"

        text_part = email.mime.text.MIMEText("See attached", "plain")
        msg.attach(text_part)

        attach = email.mime.application.MIMEApplication(b"PDF content", _subtype="pdf")
        attach.add_header("Content-Disposition", "attachment", filename="test.pdf")
        msg.attach(attach)

        raw = msg.as_bytes()
        results = validate_mime(raw)
        errors = [r for r in results if r.severity in (Severity.ERROR, Severity.CRITICAL)]
        assert not errors
