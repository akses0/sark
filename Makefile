.PHONY: install check format test harness-up harness-down full-e2e clean

PYTHON ?= python3
COMPOSE := $(shell command -v podman >/dev/null 2>&1 && echo "podman compose" || echo "docker compose")

install:
	@command -v uv >/dev/null 2>&1 && uv venv --allow-existing .venv || $(PYTHON) -m venv .venv
	@command -v uv >/dev/null 2>&1 && uv pip install --python .venv/bin/python -e '.[dev]' \
		|| .venv/bin/pip install -e '.[dev]'
	@echo "dev env ready: source .venv/bin/activate"

check:
	.venv/bin/ruff format --check src tests
	.venv/bin/ruff check src tests
	.venv/bin/mypy src

format:
	.venv/bin/ruff format src tests
	.venv/bin/ruff check --fix src tests

test:
	.venv/bin/pytest tests --ignore=tests/e2e -q

harness-up:
	cd tests/harness && $(COMPOSE) up -d

harness-down:
	cd tests/harness && $(COMPOSE) down -v --remove-orphans

e2e:
	SARK_E2E=1 .venv/bin/pytest tests/e2e -q

full-e2e: harness-up e2e harness-down

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache dist *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
