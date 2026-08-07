.PHONY: install test test-verbose run seed keygen clean lint

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

install:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev]"

test:
	$(PY) -m pytest -q

test-verbose:
	$(PY) -m pytest -v

run:
	EHEALTH_ADMIN_API_KEY=$${EHEALTH_ADMIN_API_KEY:-local-development-admin-key-0123456789} \
	$(PY) -m uvicorn ehealth.main:app --reload --port 8000

seed:
	$(PY) -m ehealth.scripts.seed

keygen:
	@$(PY) -c "from ehealth.config import generate_root_key; print(generate_root_key())"

clean:
	rm -rf .pytest_cache **/__pycache__ ehealth.db ehealth.db-wal ehealth.db-shm
