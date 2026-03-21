"""Test fixtures and helpers for eml-validator tests."""

from __future__ import annotations

import base64
import email.mime.base
import email.mime.multipart
import email.mime.text
import email.utils
from pathlib import Path

import pytest

# ─── Helper to build raw bytes ────────────────────────────────────────────────

def msg_to_bytes(msg) -> bytes:
    return msg.as_bytes()


# ─── Fixture: valid simple message ────────────────────────────────────────────

@pytest.fixture
def valid_simple_eml() -> bytes:
    """A minimal, RFC-compliant plain-text email."""
    raw = (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Hello\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <unique-id-001@example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: 7bit\r\n"
        b"\r\n"
        b"Hello, World!\r\n"
    )
    return raw


@pytest.fixture
def valid_simple_eml_file(tmp_path: Path, valid_simple_eml: bytes) -> Path:
    f = tmp_path / "valid_simple.eml"
    f.write_bytes(valid_simple_eml)
    return f


# ─── Fixture: valid multipart message ─────────────────────────────────────────

@pytest.fixture
def valid_multipart_eml() -> bytes:
    """A valid multipart/alternative email."""
    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["From"] = "Alice <alice@example.com>"
    msg["To"] = "Bob <bob@example.com>"
    msg["Subject"] = "Multipart Test"
    msg["Date"] = email.utils.formatdate(localtime=False)
    msg["Message-ID"] = "<unique-id-002@example.com>"

    text_part = email.mime.text.MIMEText("Hello, World!", "plain", "utf-8")
    html_part = email.mime.text.MIMEText("<p>Hello, World!</p>", "html", "utf-8")
    msg.attach(text_part)
    msg.attach(html_part)

    return msg.as_bytes()


@pytest.fixture
def valid_multipart_eml_file(tmp_path: Path, valid_multipart_eml: bytes) -> Path:
    f = tmp_path / "valid_multipart.eml"
    f.write_bytes(valid_multipart_eml)
    return f


# ─── Fixture: missing From header ─────────────────────────────────────────────

@pytest.fixture
def missing_from_eml() -> bytes:
    return (
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Hello\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <unique-id-003@example.com>\r\n"
        b"\r\n"
        b"Body\r\n"
    )


# ─── Fixture: duplicate headers ───────────────────────────────────────────────

@pytest.fixture
def duplicate_headers_eml() -> bytes:
    return (
        b"From: Alice <alice@example.com>\r\n"
        b"From: Eve <eve@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Hello\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <unique-id-004@example.com>\r\n"
        b"\r\n"
        b"Body\r\n"
    )


# ─── Fixture: bad Date format ─────────────────────────────────────────────────

@pytest.fixture
def bad_date_eml() -> bytes:
    return (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Hello\r\n"
        b"Date: not-a-date\r\n"
        b"Message-ID: <unique-id-005@example.com>\r\n"
        b"\r\n"
        b"Body\r\n"
    )


# ─── Fixture: missing MIME-Version ────────────────────────────────────────────

@pytest.fixture
def missing_mime_version_eml() -> bytes:
    return (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Hello\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <unique-id-006@example.com>\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"\r\n"
        b"<p>Hello</p>\r\n"
    )


# ─── Fixture: broken boundary ─────────────────────────────────────────────────

@pytest.fixture
def broken_boundary_eml() -> bytes:
    """multipart message missing the closing boundary."""
    return (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Broken\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <unique-id-007@example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: multipart/alternative\r\n"
        b"\r\n"
        b"--boundary\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Hello\r\n"
    )


# ─── Fixture: multipart/alternative without text/plain ───────────────────────

@pytest.fixture
def alt_no_plain_eml() -> bytes:
    """multipart/alternative with only text/html (no text/plain)."""
    msg = email.mime.multipart.MIMEMultipart("alternative")
    msg["From"] = "Alice <alice@example.com>"
    msg["To"] = "Bob <bob@example.com>"
    msg["Subject"] = "HTML Only"
    msg["Date"] = email.utils.formatdate(localtime=False)
    msg["Message-ID"] = "<unique-id-008@example.com>"
    html_part = email.mime.text.MIMEText("<p>Hello</p>", "html", "utf-8")
    msg.attach(html_part)
    return msg.as_bytes()


# ─── Fixture: invalid base64 ─────────────────────────────────────────────────

@pytest.fixture
def invalid_base64_eml() -> bytes:
    return (
        b"From: Alice <alice@example.com>\r\n"
        b"To: Bob <bob@example.com>\r\n"
        b"Subject: Bad Base64\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <unique-id-009@example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Transfer-Encoding: base64\r\n"
        b"\r\n"
        b"this is not valid base64 !!!\r\n"
    )


# ─── DKIM fixture helpers ─────────────────────────────────────────────────────

def generate_dkim_test_keypair():
    """Generate an RSA key pair for DKIM testing."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_key = private_key.public_key()
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_der


@pytest.fixture(scope="session")
def dkim_keypair():
    """Session-scoped RSA key pair for DKIM tests."""
    return generate_dkim_test_keypair()


@pytest.fixture
def dkim_signed_eml(dkim_keypair) -> tuple[bytes, dict[str, bytes]]:
    """A DKIM-signed email with a test key pair. Returns (raw_bytes, dns_override)."""
    private_pem, public_der = dkim_keypair

    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: DKIM Test\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <dkim-test-001@example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Test message body.\r\n"
    )

    try:
        import dkim

        selector = b"test"
        domain = b"example.com"

        sig_header = dkim.sign(
            raw,
            selector,
            domain,
            private_pem,
            include_headers=[b"from", b"to", b"subject", b"date", b"content-type"],
        )
        signed = sig_header + raw

        # Build DNS override: selector._domainkey.domain → TXT record
        public_b64 = base64.b64encode(public_der).decode("ascii")
        dns_record = f"v=DKIM1; k=rsa; p={public_b64}".encode()
        # dkimpy appends a trailing dot to DNS names
        dns_override = {
            "test._domainkey.example.com.": dns_record,
            "test._domainkey.example.com": dns_record,
        }

        return signed, dns_override

    except ImportError:
        pytest.skip("dkimpy not installed")


@pytest.fixture
def dkim_broken_eml(dkim_keypair) -> tuple[bytes, dict[str, bytes]]:
    """A DKIM-signed email with the body tampered after signing."""
    private_pem, public_der = dkim_keypair

    raw = (
        b"From: alice@example.com\r\n"
        b"To: bob@example.com\r\n"
        b"Subject: DKIM Broken\r\n"
        b"Date: Mon, 01 Jan 2024 12:00:00 +0000\r\n"
        b"Message-ID: <dkim-broken-001@example.com>\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain\r\n"
        b"\r\n"
        b"Original body.\r\n"
    )

    try:
        import dkim

        selector = b"test"
        domain = b"example.com"

        sig_header = dkim.sign(
            raw,
            selector,
            domain,
            private_pem,
            include_headers=[b"from", b"to", b"subject", b"date", b"content-type"],
        )
        signed_raw = sig_header + raw

        # Tamper: replace body content
        tampered = signed_raw.replace(b"Original body.\r\n", b"Tampered body.\r\n")

        public_b64 = base64.b64encode(public_der).decode("ascii")
        dns_record = f"v=DKIM1; k=rsa; p={public_b64}".encode()
        dns_override = {
            "test._domainkey.example.com.": dns_record,
            "test._domainkey.example.com": dns_record,
        }

        return tampered, dns_override

    except ImportError:
        pytest.skip("dkimpy not installed")
