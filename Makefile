.PHONY: install dev test test-cov lint format check

VENV ?= .venv
PYTHON ?= $(VENV)/bin/python
PIP ?= $(VENV)/bin/pip

install: ## Create venv and install the package
	$(VENV)/bin/python -m venv $(VENV) || python3 -m venv $(VENV)
	$(PIP) install -e ".[dev]"

test: ## Run the test suite
	$(PYTHON) -m pytest

test-cov: ## Run tests with a coverage report
	$(PYTHON) -m pytest --cov --cov-report=term-missing

lint: ## Lint with ruff
	$(VENV)/bin/ruff check aegisrecon tests

format: ## Auto-format with ruff
	$(VENV)/bin/ruff format aegisrecon tests
	$(VENV)/bin/ruff check --fix aegisrecon tests

check: lint test ## Lint then test

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-12s %s\n", $$1, $$2}'
