DB_CONTAINER ?= traust-postgres
DB_IMAGE ?= docker.io/library/postgres:16
DB_PORT ?= 5432
DB_USER ?= traust
DB_PASSWORD ?= traust-test-only
DB_NAME ?= traust_test
TRAUST_TEST_DATABASE_URL ?= postgresql+psycopg://$(DB_USER):$(DB_PASSWORD)@127.0.0.1:$(DB_PORT)/$(DB_NAME)
export TRAUST_TEST_DATABASE_URL


.PHONY: help setup sync lint lint-fix test test-integration coverage coverage-html coverage-all db-up db-down

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup            — uv sync (run once per clone)"
	@echo "  make lint             — ruff check + format --check"
	@echo "  make lint-fix         — ruff --fix + format"
	@echo "  make test             — unit tests (no integration)"
	@echo "  make test-integration — integration tests against Postgres (make db-up first)"
	@echo "  make coverage         — unit tests with coverage (term)"
	@echo "  make coverage-html    — unit tests with coverage (term + htmlcov/)"
	@echo "  make coverage-all     — unit + integration with coverage (needs make db-up)"
	@echo "  make db-up / db-down  — shared Postgres container ($(DB_CONTAINER)), same as contracts and ledger"

setup: sync

sync:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

test:
	uv run pytest tests/ -q -m "not integration"

test-integration:
	uv run --extra postgres pytest tests/ -q -m integration

coverage:
	uv run pytest tests/ --cov=traust_core --cov-report=term-missing -q -m "not integration"

coverage-html:
	uv run pytest tests/ --cov=traust_core --cov-report=term-missing --cov-report=html -q -m "not integration"

coverage-all:
	uv run --extra postgres pytest tests/ --cov=traust_core --cov-report=term-missing --cov-report=html -q
	@echo "Full report: open htmlcov/index.html"

db-up:
	@if podman container exists $(DB_CONTAINER) 2>/dev/null; then \
		echo "$(DB_CONTAINER) already running"; \
	else \
		podman run --name $(DB_CONTAINER) --rm -d \
			-e POSTGRES_USER=$(DB_USER) \
			-e POSTGRES_PASSWORD=$(DB_PASSWORD) \
			-e POSTGRES_DB=$(DB_NAME) \
			-p 127.0.0.1:$(DB_PORT):5432 \
			-v traust-postgres-data:/var/lib/postgresql/data \
			$(DB_IMAGE); \
		echo "waiting for database..."; \
		for i in $$(seq 1 30); do \
			podman exec $(DB_CONTAINER) pg_isready -U $(DB_USER) -q 2>/dev/null && break; \
			sleep 1; \
		done; \
		echo "$(DB_CONTAINER) ready on port $(DB_PORT)"; \
	fi
	@echo "TRAUST_TEST_DATABASE_URL=$(TRAUST_TEST_DATABASE_URL)"

db-down:
	@podman stop $(DB_CONTAINER) 2>/dev/null || true

