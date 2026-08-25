.PHONY: install check format test harness e2e clean

PYTHON ?= python3

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
	.venv/bin/pytest -q

harness:
	@echo "redis harness variants land in M1 (tests/harness)"

e2e:
	@echo "golden-file e2e suite lands in M1"

clean:
	rm -rf .venv .pytest_cache .mypy_cache .ruff_cache dist *.egg-info src/*.egg-info
	find . -name __pycache__ -type d -exec rm -rf {} +
