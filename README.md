# eml-validator

A CLI tool to validate `.eml` files for RFC compliance, MIME structure, and DKIM signatures.

## Features

- **RFC 5322 Compliance**: Required headers, date format, address syntax, line lengths
- **MIME Validation**: Multipart boundaries, Content-Transfer-Encoding, charset validation
- **DKIM Verification**: Signature verification, body hash, canonicalization matrix
- **Authentication Results**: Parse existing `Authentication-Results` headers

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Validate a single file
eml-validator check message.eml

# Validate multiple files
eml-validator check *.eml

# Validate a directory recursively
eml-validator check --recursive ./maildir/

# Only run specific validators
eml-validator check --only rfc,mime message.eml

# Skip a validator
eml-validator check --skip auth message.eml

# Test all 4 DKIM canonicalization modes
eml-validator check --canonicalization-matrix message.eml

# Output as JSON (for CI/pipelines)
eml-validator check --format json message.eml

# Verbose mode (show all checks including OK)
eml-validator check -v message.eml

# Quiet mode (errors only)
eml-validator check -q message.eml

# Skip DNS lookups (air-gapped environments)
eml-validator check --no-dns message.eml
```

## Development

```bash
make install    # Install with dev dependencies
make lint       # Run ruff linter
make fmt        # Format code with ruff
make test       # Run tests
make coverage   # Run tests with coverage report
```
