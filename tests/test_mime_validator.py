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


class TestMultipartBoundaryRaw:
    def test_mismatched_boundary_delimiter_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=testbound\r\n"
            b"\r\n"
            b"--wrongbound\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hello\r\n"
            b"--wrongbound--\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "BoundaryMismatch" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning when declared boundary is missing from body"

    def test_correct_boundary_no_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=testbound\r\n"
            b"\r\n"
            b"--testbound\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hello\r\n"
            b"--testbound--\r\n"
        )
        results = validate_mime(raw)
        assert not any("BoundaryMismatch" in r.name for r in results)

    def test_non_multipart_no_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert not any("BoundaryMismatch" in r.name for r in results)


class TestContentTransferEncoding:
    def test_valid_cte_ok(self, valid_simple_eml):
        results = validate_mime(valid_simple_eml)
        errors = [r for r in results if r.severity in (Severity.ERROR, Severity.CRITICAL)]
        assert not errors

    def test_invalid_base64_is_error(self, invalid_base64_eml):
        results = validate_mime(invalid_base64_eml)
        # Should flag invalid base64 content (may appear as CTE-Content or B64-* check)
        cte_errors = [
            r
            for r in results
            if ("CTE" in r.name or "B64" in r.name)
            and r.severity in (Severity.ERROR, Severity.CRITICAL)
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


class TestCharsetOnNonText:
    def test_charset_on_image_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: image/jpeg; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        errors = [
            r for r in results if "CharsetOnNonText" in r.name and r.severity == Severity.ERROR
        ]
        assert errors, "Expected error for charset on image/jpeg"

    def test_charset_on_application_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: application/pdf; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        errors = [
            r for r in results if "CharsetOnNonText" in r.name and r.severity == Severity.ERROR
        ]
        assert errors, "Expected error for charset on application/pdf"

    def test_charset_on_text_plain_no_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert not any("CharsetOnNonText" in r.name for r in results)


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


class TestBodyLineEndings:
    def test_crlf_body_ok(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Line one\r\nLine two\r\n"
        )
        results = validate_mime(raw)
        bare_errors = [r for r in results if "BareCR" in r.name or "BareLF" in r.name]
        assert not bare_errors

    def test_bare_lf_body_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Line one\nLine two\n"
        )
        results = validate_mime(raw)
        errors = [r for r in results if "BareLF" in r.name and r.severity == Severity.ERROR]
        assert errors, "Expected BareLF error for bare LF body"

    def test_bare_cr_body_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Line one\rLine two\r"
        )
        results = validate_mime(raw)
        errors = [r for r in results if "BareCR" in r.name and r.severity == Severity.ERROR]
        assert errors, "Expected BareCR error for bare CR body"


class TestQPBodyChecks:
    def test_qp_encoded_crlf_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"Hello=0D=0AWorld\r\n"
        )
        results = validate_mime(raw)
        errors = [r for r in results if "QP-EncodedCRLF" in r.name and r.severity == Severity.ERROR]
        assert errors, "Expected error for encoded CRLF in QP body"

    def test_qp_line_too_long_is_error(self):
        long_line = b"A" * 77 + b"\r\n"
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n" + long_line
        )
        results = validate_mime(raw)
        errors = [r for r in results if "QP-LineTooLong" in r.name and r.severity == Severity.ERROR]
        assert errors, "Expected error for QP encoded line > 76 chars"

    def test_valid_qp_ok(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"Hello =C3=A9 World\r\n"
        )
        results = validate_mime(raw)
        qp_errors = [
            r
            for r in results
            if ("QP" in r.name or "CTE" in r.name) and r.severity == Severity.ERROR
        ]
        assert not qp_errors


class TestBase64BodyChecks:
    def test_base64_line_too_long_is_warning(self):
        import base64 as b64

        # Build a base64 payload with one long line (> 76 chars)
        data = b"x" * 100
        long_b64 = b64.b64encode(data).decode()  # 136 chars, no line breaks
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n" + long_b64.encode() + b"\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "B64-LineTooLong" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for base64 line > 76 chars"

    def test_incomplete_base64_is_error(self):
        # A base64 string whose length % 4 != 0 (invalid)
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8\r\n"  # 7 chars, not multiple of 4
        )
        results = validate_mime(raw)
        errors = [
            r
            for r in results
            if ("B64-Incomplete" in r.name or "CTE-Content" in r.name)
            and r.severity == Severity.ERROR
        ]
        assert errors, "Expected error for incomplete base64 block"

    def test_valid_base64_ok(self):
        import base64 as b64

        data = b"Hello, World!"
        # Standard 76-char wrapped base64
        encoded = b64.encodebytes(data).decode()
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n" + encoded.encode()
        )
        results = validate_mime(raw)
        b64_errors = [
            r
            for r in results
            if ("B64" in r.name or "CTE-Content" in r.name) and r.severity == Severity.ERROR
        ]
        assert not b64_errors


class TestEightBitIn7Bit:
    def test_8bit_content_with_7bit_cte_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 7bit\r\n"
            b"\r\n"
            b"Caf\xc3\xa9\r\n"  # UTF-8 é = 0xc3 0xa9
        )
        results = validate_mime(raw)
        errors = [r for r in results if "8BitIn7Bit" in r.name and r.severity == Severity.ERROR]
        assert errors, "Expected error for 8-bit content with 7bit CTE"

    def test_ascii_content_with_7bit_cte_ok(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 7bit\r\n"
            b"\r\n"
            b"Hello, World!\r\n"
        )
        results = validate_mime(raw)
        errors = [r for r in results if "8BitIn7Bit" in r.name and r.severity == Severity.ERROR]
        assert not errors


class TestRawHeaderChecks:
    def test_header_line_too_long_is_error(self):
        long_value = "x" * 990
        raw = (
            f"From: Alice <alice@example.com>\r\n"
            f"Subject: {long_value}\r\n"
            f"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            f"\r\n"
            f"Body\r\n"
        ).encode()
        results = validate_mime(raw)
        errors = [
            r for r in results if "HeaderLineTooLong" in r.name and r.severity == Severity.ERROR
        ]
        assert errors, "Expected error for header line > 998 chars"

    def test_header_line_ok_length(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Subject: Short subject\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_mime(raw)
        errors = [r for r in results if "HeaderLineTooLong" in r.name]
        assert not errors

    def test_space_before_colon_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Subject : Space before colon\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r
            for r in results
            if "HeaderSpaceBeforeColon" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for space before colon in header"

    def test_no_space_before_colon_ok(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Subject: Normal header\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_mime(raw)
        warns = [r for r in results if "HeaderSpaceBeforeColon" in r.name]
        assert not warns

    def test_bare_cr_in_header_is_error(self):
        # Construct raw bytes with a bare CR in a header line
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Subject: Bad\rheader\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_mime(raw)
        errors = [r for r in results if "HeaderBareCRLF" in r.name and r.severity == Severity.ERROR]
        assert errors, "Expected error for bare CR in header"


class TestMIMEStructuralChecks:
    def test_content_type_name_param_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b'Content-Type: application/pdf; name="report.pdf"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r
            for r in results
            if "ContentTypeNameParam" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for Content-Type name= parameter"

    def test_octet_misspelling_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: application/octet\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "OctetMisspelling" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for application/octet misspelling"

    def test_non_content_header_in_subpart_is_warning(self):
        # Build a multipart message with a non-Content-* header inside a sub-part
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=bound\r\n"
            b"\r\n"
            b"--bound\r\n"
            b"Content-Type: text/plain\r\n"
            b"X-Custom-Header: should-warn\r\n"
            b"\r\n"
            b"Hello\r\n"
            b"--bound--\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "NonContentHeader" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for non-Content-* header in MIME sub-part"

    def test_duplicate_content_type_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=bound\r\n"
            b"\r\n"
            b"--bound\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Type: text/html\r\n"
            b"\r\n"
            b"Hello\r\n"
            b"--bound--\r\n"
        )
        results = validate_mime(raw)
        errors = [
            r for r in results if "DuplicateHeader" in r.name and r.severity == Severity.ERROR
        ]
        assert errors, "Expected error for duplicate Content-Type in MIME sub-part"

    def test_charset_overspecified_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello World\r\n"  # pure ASCII
        )
        results = validate_mime(raw)
        warns = [
            r
            for r in results
            if "CharsetOverspecified" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for utf-8 charset on pure-ASCII content"

    def test_charset_needed_for_non_ascii_ok(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"Caf\xc3\xa9\r\n"  # UTF-8 é
        )
        results = validate_mime(raw)
        warns = [r for r in results if "CharsetOverspecified" in r.name]
        assert not warns


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


class TestInlineDispositionWithFilename:
    def test_inline_with_filename_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=bound\r\n"
            b"\r\n"
            b"--bound\r\n"
            b"Content-Type: image/jpeg\r\n"
            b'Content-Disposition: inline; filename="photo.jpg"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
            b"--bound--\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "InlineWithFilename" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for inline disposition with filename"

    def test_inline_without_filename_no_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=bound\r\n"
            b"\r\n"
            b"--bound\r\n"
            b"Content-Type: text/plain\r\n"
            b"Content-Disposition: inline\r\n"
            b"\r\n"
            b"Hello\r\n"
            b"--bound--\r\n"
        )
        results = validate_mime(raw)
        assert not any("InlineWithFilename" in r.name for r in results)

    def test_attachment_with_filename_no_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=bound\r\n"
            b"\r\n"
            b"--bound\r\n"
            b"Content-Type: application/pdf\r\n"
            b'Content-Disposition: attachment; filename="doc.pdf"\r\n'
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
            b"--bound--\r\n"
        )
        results = validate_mime(raw)
        assert not any("InlineWithFilename" in r.name for r in results)


class TestContentTypeFoldSemicolon:
    def test_missing_semicolon_before_fold_is_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: image/jpg\r\n"
            b'\tcharset="UTF-8"\r\n'
            b"\r\n"
            b"body\r\n"
        )
        results = validate_mime(raw)
        errors = [
            r
            for r in results
            if "ContentTypeMissingSemicolon" in r.name and r.severity == Severity.ERROR
        ]
        assert errors, "Expected error for missing semicolon before folded Content-Type parameter"

    def test_semicolon_before_fold_no_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/html;\r\n"
            b'\tcharset="UTF-8"\r\n'
            b"\r\n"
            b"<p>Hello</p>\r\n"
        )
        results = validate_mime(raw)
        assert not any("ContentTypeMissingSemicolon" in r.name for r in results)

    def test_single_line_ct_no_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert not any("ContentTypeMissingSemicolon" in r.name for r in results)


class TestCharsetOnMultipart:
    def test_charset_on_multipart_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=b; charset=utf-8\r\n"
            b"\r\n"
            b"--b\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hi\r\n"
            b"--b--\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "CharsetOnMultipart" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for charset on multipart/mixed"

    def test_charset_on_multipart_no_error(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=b; charset=utf-8\r\n"
            b"\r\n"
            b"--b\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hi\r\n"
            b"--b--\r\n"
        )
        results = validate_mime(raw)
        errors = [
            r for r in results if "CharsetOnMultipart" in r.name and r.severity == Severity.ERROR
        ]
        assert not errors


class TestContentID:
    def _make_multipart_with_cid(self, cid_line: bytes | None) -> bytes:
        sub_headers = b"Content-Type: application/octet-stream\r\n"
        if cid_line is not None:
            sub_headers += cid_line
        return (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=bound\r\n"
            b"\r\n"
            b"--bound\r\n" + sub_headers + b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
            b"--bound--\r\n"
        )

    def test_content_id_missing_at_is_warning(self):
        raw = self._make_multipart_with_cid(b"Content-ID: <Attach_X6WZ4Z_1>\r\n")
        results = validate_mime(raw)
        warns = [
            r for r in results if "ContentIDFormat" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for Content-ID missing '@'"

    def test_content_id_valid_no_warning(self):
        raw = self._make_multipart_with_cid(b"Content-ID: <attach.1@example.com>\r\n")
        results = validate_mime(raw)
        assert not any("ContentIDFormat" in r.name for r in results)

    def test_no_content_id_no_warning(self):
        raw = self._make_multipart_with_cid(None)
        results = validate_mime(raw)
        assert not any("ContentIDFormat" in r.name for r in results)


class TestTemplatePlaceholders:
    def _make_text_part(self, content_type: str, body: bytes) -> bytes:
        ct = content_type.encode()
        return (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: " + ct + b"\r\n"
            b"\r\n" + body
        )

    def test_placeholder_in_html_body_is_warning(self):
        raw = self._make_text_part("text/html", b"<p>Click <#TP_URL#></p>\r\n")
        results = validate_mime(raw)
        warns = [
            r for r in results if "TemplatePlaceholder" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for unresolved template placeholder in text/html"

    def test_no_placeholder_no_warning(self):
        raw = self._make_text_part("text/html", b"<p>Hello World</p>\r\n")
        results = validate_mime(raw)
        assert not any("TemplatePlaceholder" in r.name for r in results)

    def test_placeholder_in_non_text_no_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: application/pdf\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        assert not any("TemplatePlaceholder" in r.name for r in results)


class TestBase64LeadingSpace:
    def test_base64_leading_space_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"SGVsbG8=\r\n"
            b" d29ybGQ=\r\n"  # leading space
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "B64-LeadingSpace" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for base64 line with leading space"

    def test_base64_no_leading_space_ok(self):
        import base64 as b64

        data = b"Hello World"
        encoded = b64.encodebytes(data).decode()
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: application/octet-stream\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n" + encoded.encode()
        )
        results = validate_mime(raw)
        assert not any("B64-LeadingSpace" in r.name for r in results)


class TestNonstandardContentType:
    def test_image_jpg_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: image/jpg\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "NonstandardType" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for non-IANA type image/jpg"

    def test_image_pjpeg_is_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: image/pjpeg\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        warns = [
            r for r in results if "NonstandardType" in r.name and r.severity == Severity.WARNING
        ]
        assert warns, "Expected warning for non-IANA type image/pjpeg"

    def test_image_jpeg_no_warning(self):
        raw = (
            b"From: Alice <alice@example.com>\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: image/jpeg\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        assert not any("NonstandardType" in r.name for r in results)


# ---------------------------------------------------------------------------
# Raw-byte checks (msglint-derived)
# ---------------------------------------------------------------------------

_VALID_MULTIPART = (
    b"From: alice@example.com\r\n"
    b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: multipart/mixed; boundary=frontier\r\n"
    b"\r\n"
    b"--frontier\r\n"
    b"Content-Type: text/plain\r\n"
    b"\r\n"
    b"Hello\r\n"
    b"--frontier--\r\n"
)


class TestMultipartBoundaryTerminator:
    def test_missing_terminator_is_error(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=frontier\r\n"
            b"\r\n"
            b"--frontier\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hello\r\n"
            # missing --frontier-- terminator
        )
        results = validate_mime(raw)
        assert _has_severity(results, "MIME-BoundaryUnterminated", Severity.ERROR)

    def test_correct_terminator_no_error(self):
        results = validate_mime(_VALID_MULTIPART)
        assert not _has_severity(results, "MIME-BoundaryUnterminated", Severity.ERROR)

    def test_non_multipart_no_error(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert not _has_severity(results, "MIME-BoundaryUnterminated", Severity.ERROR)


class TestCharsetCTEMismatch:
    def test_ascii_charset_with_8bit_cte_is_error(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=us-ascii\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert _has_severity(results, "MIME-CharsetCTEMismatch", Severity.ERROR)

    def test_ascii_charset_with_7bit_cte_no_error(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=us-ascii\r\n"
            b"Content-Transfer-Encoding: 7bit\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert not _has_severity(results, "MIME-CharsetCTEMismatch", Severity.ERROR)

    def test_iso8859_with_8bit_cte_is_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=iso-8859-1\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert _has_severity(results, "MIME-CharsetCTEMismatch", Severity.WARNING)

    def test_utf8_with_8bit_cte_no_issue(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: 8bit\r\n"
            b"\r\n"
            b"Hello\r\n"
        )
        results = validate_mime(raw)
        assert not _has_severity(results, "MIME-CharsetCTEMismatch", Severity.ERROR)
        assert not _has_severity(results, "MIME-CharsetCTEMismatch", Severity.WARNING)


class TestCTEOnCompositeType:
    def test_qp_on_multipart_is_error(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: multipart/mixed; boundary=frontier\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n"
            b"\r\n"
            b"--frontier\r\n"
            b"Content-Type: text/plain\r\n"
            b"\r\n"
            b"Hello\r\n"
            b"--frontier--\r\n"
        )
        results = validate_mime(raw)
        assert _has_severity(results, "MIME-CTEOnCompositeType", Severity.ERROR)

    def test_base64_on_message_rfc822_is_error(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: message/rfc822\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"From: inner@example.com\r\n"
            b"\r\n"
            b"Inner body\r\n"
        )
        results = validate_mime(raw)
        assert _has_severity(results, "MIME-CTEOnCompositeType", Severity.ERROR)

    def test_7bit_on_multipart_no_error(self):
        results = validate_mime(_VALID_MULTIPART)
        assert not _has_severity(results, "MIME-CTEOnCompositeType", Severity.ERROR)

    def test_base64_on_leaf_part_no_error(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: image/png\r\n"
            b"Content-Transfer-Encoding: base64\r\n"
            b"\r\n"
            b"AAAA\r\n"
        )
        results = validate_mime(raw)
        assert not _has_severity(results, "MIME-CTEOnCompositeType", Severity.ERROR)


class TestExperimentalMediaType:
    def test_x_prefix_type_is_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: x-custom/data\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_mime(raw)
        assert _has_severity(results, "MIME-ExperimentalMediaType", Severity.WARNING)

    def test_x_prefix_subtype_is_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: application/x-custom\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_mime(raw)
        assert _has_severity(results, "MIME-ExperimentalMediaType", Severity.WARNING)

    def test_standard_type_no_warning(self):
        raw = (
            b"From: alice@example.com\r\n"
            b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n"
            b"Body\r\n"
        )
        results = validate_mime(raw)
        assert not _has_severity(results, "MIME-ExperimentalMediaType", Severity.WARNING)

    def test_valid_multipart_no_warning(self):
        results = validate_mime(_VALID_MULTIPART)
        assert not _has_severity(results, "MIME-ExperimentalMediaType", Severity.WARNING)
