.PHONY: install lint fmt test run clean

# Install in editable mode with dev dependencies
install:
	pip install -e ".[dev]"

# Lint with ruff
lint:
	ruff check src/ tests/

# Format with ruff
fmt:
	ruff format src/ tests/
	ruff check --fix src/ tests/

# Run tests
test:
	pytest -v

# Run tests with coverage
coverage:
	pytest -v --cov=eml_validator --cov-report=term-missing

# Run the CLI (pass FILE=path/to/message.eml)
run:
	eml-validator check $(FILE)

# Clean Python cache files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
