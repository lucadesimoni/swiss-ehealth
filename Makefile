# SPDX-License-Identifier: AGPL-3.0-or-later
.PHONY: install test test-verbose test-postgres lint format run seed keygen clean \
        version verify-version release record-release releases restore-tags \
        components release-component record-component-release \
        migrate migration migrate-status reindex-demographics retention \
        restore-rehearsal load-test

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

## The same suite against PostgreSQL, which is what production runs.
##
##   make test-postgres PGURL=postgresql+psycopg://ehealth:pw@localhost:5432/ehealth
##
## Each test gets its own schema in that database, created and dropped around
## it. SQLite cannot see a JSONB mismatch, a reserved word, or PostgreSQL's
## stricter transactional rules, so a green SQLite run is not evidence that a
## deployment will work.
test-postgres:
	@test -n "$(PGURL)" || { \
	  echo 'usage: make test-postgres PGURL=postgresql+psycopg://user:pw@host:5432/db'; \
	  exit 1; }
	EHEALTH_TEST_DATABASE_URL="$(PGURL)" $(PY) -m pytest -q

lint:
	$(PY) -m ruff check src tests migrations
	$(PY) -m ruff format --check src tests migrations

format:
	$(PY) -m ruff check --fix src tests migrations
	$(PY) -m ruff format src tests migrations

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

## Back up SOURCE, restore into the empty TARGET, and prove the copy whole:
## row counts, schema version, every ledger chain, and (DOCS=dir) every
## stored document against its hash.
restore-rehearsal:
	@test -n "$(SOURCE)" -a -n "$(TARGET)" || { \
	  echo "usage: make restore-rehearsal SOURCE=postgresql+psycopg://… TARGET=… [DOCS=dir]"; exit 1; }
	$(PY) -m ehealth.scripts.restore_rehearsal --source "$(SOURCE)" --target "$(TARGET)" \
	    $(if $(DOCS),--documents "$(DOCS)",)

## Drive the real app over HTTP against DB (empty, migrated) and report
## latency per operation; fails on any error or a ledger that no longer verifies.
load-test:
	@test -n "$(DB)" || { echo "usage: make load-test DB=postgresql+psycopg://…"; exit 1; }
	$(PY) -m ehealth.scripts.load_test --database-url "$(DB)" \
	    --patients $(or $(PATIENTS),50) --workers $(or $(WORKERS),16) --seconds $(or $(SECONDS),30)

## Destroy health data whose retention period has passed (EPDV art. 10).
## Dry run by default; `make retention APPLY=1` destroys.
retention:
	$(PY) -m ehealth.scripts.apply_retention $(if $(APPLY),--apply,)

## Fill the demographic search index for people registered before schema 5.
## Needs the application's root key, which is why the migration cannot do it.
reindex-demographics:
	$(PY) -m ehealth.scripts.reindex_demographics

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
## every entry in RELEASES.json still matches the commit it names, and the
## component registry and COMPONENTS.json still describe this tree.
verify-version:
	@$(PY) -m pytest tests/test_versioning.py tests/test_releases.py \
	    tests/test_components.py -q

## Print the release ledger: version, commit and compatibility numbers.
releases:
	@$(PY) -c "from ehealth.releases import load_manifest; \
	print(f'{\"version\":9} {\"commit\":8} {\"date\":11} api  schema  payload'); \
	[print(f'{r.version:9} {r.short_commit:8} {r.date:11} {r.api_version:4} \
	{r.schema_version:^6}  {r.audit_payload_version:^7}') for r in load_manifest()]"

## Print the component registry: tier, version, tag, and whether the declared
## version has been cut yet.
components:
	@$(PY) -c "from ehealth.components import components_by_tier, latest_release_of; \
	print(f'{\"tier\":9} {\"component\":11} {\"version\":8} {\"released\":9} tag'); \
	[print(f'{c.tier:9} {c.name:11} {c.version:8} \
	{(\"yes\" if (r := latest_release_of(c.name)) and r.version == c.version else \"not yet\"):9} \
	{c.tag}') for c in components_by_tier()]"

## Cut a component release: make release-component COMPONENT=persons
##
## The version comes from COMPONENT_VERSIONS in src/ehealth/components.py —
## bump it there first. Refuses on a dirty tree, an unknown component, an
## existing tag, or a version already in the ledger.
release-component: verify-version
	@test -n "$(COMPONENT)" || { \
	  echo "usage: make release-component COMPONENT=<name>"; \
	  echo "known:"; $(MAKE) --no-print-directory components; exit 1; }
	@test -z "$$(git status --porcelain)" || { \
	  echo "refusing to release from a dirty working tree"; exit 1; }
	@$(PY) -c "from ehealth.components import find_component; import sys; \
	sys.exit(0 if find_component('$(COMPONENT)') else 1)" || { \
	  echo "'$(COMPONENT)' is not a component of this system"; exit 1; }
	@tag=$$($(PY) -c "from ehealth.components import find_component; \
	print(find_component('$(COMPONENT)').tag)"); \
	! git rev-parse "$$tag" >/dev/null 2>&1 || { \
	  echo "tag $$tag already exists; tags are never moved"; exit 1; }
	@$(PY) -c "from ehealth.components import find_component, \
	find_component_release; import sys; c = find_component('$(COMPONENT)'); \
	sys.exit(0 if find_component_release(c.name, c.version) is None else 1)" || { \
	  echo "COMPONENTS.json already records that version; the ledger is append-only"; \
	  exit 1; }
	$(PY) -m pytest -q
	@tag=$$($(PY) -c "from ehealth.components import find_component; \
	print(find_component('$(COMPONENT)').tag)"); \
	version=$$($(PY) -c "from ehealth.components import find_component; \
	print(find_component('$(COMPONENT)').version)"); \
	git tag -a "$$tag" -m "swiss-ehealth $(COMPONENT) $$version"; \
	echo; echo "tagged $$tag at $$(git rev-parse --short HEAD). Now:"; \
	echo "  make record-component-release COMPONENT=$(COMPONENT)"; \
	echo "  git commit -m 'Record $(COMPONENT) $$version in the ledger' COMPONENTS.json"; \
	echo "  git push -u origin main && git push origin $$tag"

## Append component versions to COMPONENTS.json. With COMPONENT= set, records
## just that one; with no argument, records every component whose declared
## version is not in the ledger yet — which is what cutting the baseline needs.
record-component-release:
	$(PY) -m ehealth.scripts.record_component_release \
	    $(if $(COMPONENT),--component $(COMPONENT),)

## Append the current commit to RELEASES.json. Run straight after the release
## commit exists, so the recorded SHA is the release itself and not the commit
## that records it — you cannot know a commit's hash before you have made it.
record-release:
	$(PY) -m ehealth.scripts.record_release

## Recreate every release and component tag from RELEASES.json and
## COMPONENTS.json, then publish them:
##   make restore-tags && git push origin --tags
##
## For a clone that has the ledgers but not the tags — which is every clone
## while tags cannot be pushed from where releases are cut. Each tag is
## annotated, points at the commit its ledger entry records, and carries that
## commit's date as its tagger date rather than the day it was rebuilt. An
## existing tag is left alone if it already points at the right commit and is
## refused if it points anywhere else: tags are never moved.
restore-tags:
	$(PY) -m ehealth.scripts.restore_tags

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
