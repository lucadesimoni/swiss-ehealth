# SPDX-License-Identifier: AGPL-3.0-or-later
.PHONY: install test test-verbose run seed keygen clean version verify-version release \
        record-release releases migrate migration migrate-status

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

## Version numbers agree across version.py, pyproject.toml and CHANGELOG.md,
## and every entry in RELEASES.json still matches the commit it names.
verify-version:
	@$(PY) -m pytest tests/test_versioning.py tests/test_releases.py -q

## Print the release ledger: version, commit and compatibility numbers.
releases:
	@$(PY) -c "from ehealth.releases import load_manifest; \
	print(f'{\"version\":9} {\"commit\":8} {\"date\":11} api  schema  payload'); \
	[print(f'{r.version:9} {r.short_commit:8} {r.date:11} {r.api_version:4} \
	{r.schema_version:^6}  {r.audit_payload_version:^7}') for r in load_manifest()]"

## Append the current commit to RELEASES.json. Run straight after the release
## commit exists, so the recorded SHA is the release itself and not the commit
## that records it — you cannot know a commit's hash before you have made it.
record-release:
	$(PY) -m ehealth.scripts.record_release

## Cut a release: make release VERSION=0.5.0
##
## Refuses on a dirty tree, a version mismatch, a missing CHANGELOG section or
## an existing tag — a tag, once published, is a claim that must stay true.
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
	@$(PY) -c "from ehealth.releases import find_release; import sys; \
	sys.exit(0 if find_release('$(VERSION)') is None else 1)" || { \
	  echo "RELEASES.json already records $(VERSION); the ledger is append-only"; \
	  exit 1; }
	$(PY) -m pytest -q
	git tag -a "v$(VERSION)" -m "swiss-ehealth $(VERSION)"
	@echo
	@echo "tagged v$(VERSION) at $$(git rev-parse --short HEAD). Now:"
	@echo "  make record-release"
	@echo "  git commit -m 'Record release $(VERSION) in the ledger' RELEASES.json"
	@echo "  git push -u origin main"
	@echo "  git push origin v$(VERSION)"
	@echo
	@echo "The tag push is the one step that can be refused by a restricted"
	@echo "network or a protected-ref rule. RELEASES.json is an ordinary file"
	@echo "in the tree, so the release stays recorded either way."

clean:
	rm -rf .pytest_cache **/__pycache__ ehealth.db ehealth.db-wal ehealth.db-shm \
	       ehealth-demo.db ehealth-demo.db-wal ehealth-demo.db-shm
