# SPDX-License-Identifier: AGPL-3.0-or-later
.PHONY: install test test-verbose run seed keygen clean version verify-version release \
        migrate migration migrate-status

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

# Exported to every recipe so the targets work in a plain checkout, not only
# after `make install`. Matches the pythonpath pytest already uses.
export PYTHONPATH := src

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

## Bring the database up to the latest migration.
migrate:
	$(VENV)/bin/alembic upgrade head

## Show where the database is versus the migrations.
migrate-status:
	@$(VENV)/bin/alembic current
	@$(VENV)/bin/alembic heads

## Generate a migration from model changes:
##   make migration name="add allergy table"
##
## Always read what it produced. Autogenerate does not see data migrations,
## renames (it emits drop+add, which loses the data), or anything outside the
## table definitions.
migration:
	@test -n "$(name)" || { echo 'usage: make migration name="what changed"'; exit 1; }
	$(VENV)/bin/alembic revision --autogenerate -m "$(name)"
	@echo
	@echo "Now: read the generated file, bump SCHEMA_VERSION in src/ehealth/version.py,"
	@echo "and call stamp_schema_version() at the end of its upgrade()."

## Print the release identity of this checkout, exactly as /version reports it.
version:
	@$(PY) -c "import json; from ehealth.version import release_identity; \
	print(json.dumps(release_identity().as_dict(), indent=2))"

## Version numbers agree across version.py, pyproject.toml and CHANGELOG.md.
verify-version:
	@$(PY) -m pytest tests/test_versioning.py -q

## Cut a release: make release VERSION=0.2.0
##
## Refuses on a dirty tree, a version mismatch, a missing CHANGELOG section or
## an existing tag — a tag, once pushed, is a claim that must stay true.
release: verify-version
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=x.y.z"; exit 1; }
	@test -z "$$(git status --porcelain)" || { \
	  echo "refusing to release from a dirty working tree"; exit 1; }
	@actual=$$($(PY) -c "from ehealth.version import __version__; print(__version__)"); \
	  test "$$actual" = "$(VERSION)" || { \
	  echo "version.py says $$actual, you asked for $(VERSION)"; exit 1; }
	@grep -q "^## \[$(VERSION)\]" CHANGELOG.md || { \
	  echo "CHANGELOG.md has no section for $(VERSION)"; exit 1; }
	@! git rev-parse "v$(VERSION)" >/dev/null 2>&1 || { \
	  echo "tag v$(VERSION) already exists; tags are never moved"; exit 1; }
	$(PY) -m pytest -q
	git tag -a "v$(VERSION)" -m "swiss-ehealth $(VERSION)"
	@echo "tagged v$(VERSION) — push with: git push origin main --follow-tags"

clean:
	rm -rf .pytest_cache **/__pycache__ ehealth.db ehealth.db-wal ehealth.db-shm \
	       ehealth-demo.db ehealth-demo.db-wal ehealth-demo.db-shm
