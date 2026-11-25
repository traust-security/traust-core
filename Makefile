DB_CONTAINER ?= traust-postgres
DB_IMAGE ?= docker.io/library/postgres:16
DB_PORT ?= 5432
DB_USER ?= traust
DB_PASSWORD ?= traust-test-only
DB_NAME ?= traust_test
TRAUST_TEST_DATABASE_URL ?= postgresql+psycopg://$(DB_USER):$(DB_PASSWORD)@127.0.0.1:$(DB_PORT)/$(DB_NAME)
export TRAUST_TEST_DATABASE_URL


PYTHON ?= python3
LOCAL ?= .local
LOCAL_CONFIG ?= $(LOCAL)/traust.yaml
K6_VERSION ?= v0.54.0
K6 ?= .perf/bin/k6

.PHONY: help setup sync hooks lint lint-fix test test-changed test-integration test-repositories coverage coverage-html coverage-all perf perf-api perf-api-baseline perf-api-breakpoint k6 api-check api-diff openapi serve local-config serve-local token db-up db-down

help:
	@echo "Targets ($(notdir $(CURDIR))):"
	@echo "  make setup            — uv sync + install git hooks (run once per clone)"
	@echo "  make lint             — ruff check + format --check"
	@echo "  make lint-fix         — ruff --fix + format"
	@echo "  make test             — unit tests, no integration (parallel via pytest-xdist)"
	@echo "  make test-changed     — testmon-selected unit tests (first run builds .testmondata)"
	@echo "  make test-integration — integration tests against Postgres (make db-up first)"
	@echo "  make test-repositories — repository layer on SQLite and Postgres (make db-up first)"
	@echo "  make coverage         — unit tests with coverage (term), fails under 80%"
	@echo "  make coverage-html    — unit tests with coverage (term + htmlcov/)"
	@echo "  make coverage-all     — unit + integration with coverage (needs make db-up)"
	@echo "  make perf             — query plans at production volume on Postgres (make db-up first)"
	@echo "  make perf-api         — k6 load over the REST API at fixture volume (make db-up first)"
	@echo "  make perf-api-baseline — run perf-api and overwrite perf/api/baseline.json"
	@echo "  make perf-api-breakpoint — reader ramp to find where the API stops holding (not gated)"
	@echo "  make k6               — fetch the pinned k6 binary into .perf/bin (perf-api dep)"
	@echo "  make api-check        — build the REST API's OpenAPI document (.openapi/openapi.json)"
	@echo "  make api-diff BASE=…   — fail on breaking OpenAPI changes vs BASE's merge-base (ALLOW_BREAKING=1 to allow)"
	@echo "  make openapi          — build the OpenAPI document and show where Swagger UI serves it"
	@echo "  make serve            — traust-server on 127.0.0.1:8080 (CONFIG=path for a config file)"
	@echo "  make serve-local      — traust-server with a local development config ($(LOCAL_CONFIG), SQLite)"
	@echo "  make token NAME=…     — a token for serve-local into $(LOCAL)/NAME.token (MACHINE=1 for a runner)"
	@echo "  make db-up / db-down  — shared Postgres container ($(DB_CONTAINER)), same as contracts and ledger"

setup: sync hooks
	@echo "ready — git hooks enabled (.githooks): lint on commit, conventional subject, lint + testmon-selected tests on push (FULL=1 for the complete suite; coverage gate in CI)"

hooks:
	git config core.hooksPath .githooks
	@chmod +x .githooks/* 2>/dev/null || true

sync:
	uv sync

lint:
	uv run ruff check .
	uv run ruff format --check .

lint-fix:
	uv run ruff check --fix .
	uv run ruff format .

test:
	uv run pytest tests/ -q -n auto -m "not integration"

test-changed:
	uv run pytest tests/ -q -n auto -m "not integration" --testmon-forceselect

test-integration:
	uv run --extra postgres pytest tests/ -q -n auto -m integration

test-repositories:
	uv run --extra postgres pytest tests/v1/repositories/tables -q -n auto -m "integration or not integration"

coverage:
	uv run pytest tests/ --cov=traust_core --cov-report=term-missing -q -n auto --dist worksteal -m "not integration"

coverage-html:
	uv run pytest tests/ --cov=traust_core --cov-report=term-missing --cov-report=html -q -m "not integration"

perf:
	uv run --extra postgres pytest perf/ -q
	@echo "Plans for the PR: .perf/report.md"

k6: $(K6)
$(K6):
	@mkdir -p $(dir $(K6))
	@os=$$(uname -s | tr '[:upper:]' '[:lower:]'); arch=$$(uname -m); \
		case "$$arch" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; esac; \
		case "$$os" in darwin) os=macos; ext=zip;; linux) os=linux; ext=tar.gz;; \
			*) echo "unsupported OS: $$os"; exit 1;; esac; \
		pkg=k6-$(K6_VERSION)-$$os-$$arch; \
		url=https://github.com/grafana/k6/releases/download/$(K6_VERSION)/$$pkg.$$ext; \
		echo "fetching $$url"; tmp=$$(mktemp -d); \
		curl -sSL -o "$$tmp/k6.$$ext" "$$url"; \
		if [ "$$ext" = zip ]; then unzip -q "$$tmp/k6.$$ext" -d "$$tmp"; \
		else tar -xzf "$$tmp/k6.$$ext" -C "$$tmp"; fi; \
		mv "$$tmp/$$pkg/k6" "$(K6)"; chmod +x "$(K6)"; rm -rf "$$tmp"; \
		"$(K6)" version

perf-api: k6
	uv run --extra postgres --extra rest $(PYTHON) -m perf.api.run

perf-api-baseline: k6
	uv run --extra postgres --extra rest $(PYTHON) -m perf.api.run --update-baseline

perf-api-breakpoint: k6
	uv run --extra postgres --extra rest $(PYTHON) -m perf.api.run --breakpoint

coverage-all:
	uv run --extra postgres pytest tests/ --cov=traust_core --cov-report=term-missing --cov-report=html -q
	@echo "Full report: open htmlcov/index.html"

db-up:
	@if podman container exists $(DB_CONTAINER) 2>/dev/null; then \
		echo "$(DB_CONTAINER) already running"; \
	else \
		podman run --name $(DB_CONTAINER) --rm -d --shm-size=256m \
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

api-check:
	@mkdir -p .openapi
	uv run python -c "import json, tempfile; from pathlib import Path; from traust_core.v1.context import Config, Context; from traust_core.v1.rest.app import create_app; spec = create_app(Context(Config(home=Path(tempfile.mkdtemp())))).openapi(); assert spec['paths'], 'no routes'; Path('.openapi/openapi.json').write_text(json.dumps(spec, indent=2)); print(f\"{len(spec['paths'])} paths -> .openapi/openapi.json\")"

openapi: api-check
	@echo "Swagger UI: 'make serve', then http://127.0.0.1:$${PORT:-8080}/docs (ReDoc /redoc, raw /openapi.json)"

BASE ?= origin/development
OASDIFF_VERSION ?= 1.41.0
OASDIFF ?= .openapi/oasdiff/$(OASDIFF_VERSION)/oasdiff
UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_S),Darwin)
OASDIFF_PLATFORM := Darwin
OASDIFF_ASSET := oasdiff_$(OASDIFF_VERSION)_darwin_all.tar.gz
else ifeq ($(UNAME_S)-$(UNAME_M),Linux-x86_64)
OASDIFF_PLATFORM := Linux-x86_64
OASDIFF_ASSET := oasdiff_$(OASDIFF_VERSION)_linux_amd64.tar.gz
else ifeq ($(UNAME_S)-$(UNAME_M),Linux-aarch64)
OASDIFF_PLATFORM := Linux-aarch64
OASDIFF_ASSET := oasdiff_$(OASDIFF_VERSION)_linux_arm64.tar.gz
endif
# per-platform release checksums: https://github.com/oasdiff/oasdiff/releases/tag/v$(OASDIFF_VERSION)
OASDIFF_SHA256_Darwin := 0452671a98a290ab7c5e49b274fdc77b34c5cdb595b4305cfdb64ae011f7f1ee
OASDIFF_SHA256_Linux-x86_64 := 96365453163118e6503eb71742643d9ee67f91aedbaadd1a1ce9c6213e3b71c7
OASDIFF_SHA256_Linux-aarch64 := 8d4b8ddd467440885675db918e229ab8db330111c6428eb864e7eb766a7f4071
OASDIFF_SHA256 := $(OASDIFF_SHA256_$(OASDIFF_PLATFORM))

$(OASDIFF):
	@test -n "$(OASDIFF_ASSET)" || { echo "api-diff: unsupported platform $(UNAME_S)/$(UNAME_M)" >&2; exit 2; }
	@mkdir -p $(dir $(OASDIFF))
	@tmp=$$(mktemp -d); curl -fsSL -o "$$tmp/$(OASDIFF_ASSET)" https://github.com/oasdiff/oasdiff/releases/download/v$(OASDIFF_VERSION)/$(OASDIFF_ASSET); \
	if command -v sha256sum >/dev/null 2>&1; then sum="sha256sum"; args=""; else sum="shasum"; args="-a 256"; fi; \
	echo "$(OASDIFF_SHA256)  $$tmp/$(OASDIFF_ASSET)" | $$sum $$args -c -; \
	tar -xzf "$$tmp/$(OASDIFF_ASSET)" -C $(dir $(OASDIFF)) oasdiff && rm -rf "$$tmp"; \
	$(OASDIFF) --version

api-diff: $(OASDIFF)
	@set -e; \
	git rev-parse --verify -q $(BASE)^{commit} >/dev/null || { echo "api-diff: unknown ref $(BASE)" >&2; exit 2; }; \
	MB=$$(git merge-base HEAD $(BASE)); \
	echo "api-diff: merge-base of HEAD and $(BASE): $$MB"; \
	$(MAKE) --no-print-directory api-check; \
	WT=$$(mktemp -d "$${TMPDIR:-/tmp}/traust-api-diff.XXXXXX"); \
	git worktree add --detach --quiet "$$WT" "$$MB"; \
	trap 'rm -rf "$$WT"; git worktree prune' EXIT; \
	( cd "$$WT" && $(MAKE) --no-print-directory api-check ); \
	$(OASDIFF) breaking --fail-on ERR "$$WT/.openapi/openapi.json" .openapi/openapi.json && st=0 || st=$$?; \
	if [ "$$st" = 1 ] && [ "$(ALLOW_BREAKING)" = 1 ]; then \
		echo "api-diff: breaking changes above allowed (ALLOW_BREAKING=1)"; \
	elif [ "$$st" = 1 ]; then \
		echo "api-diff: breaking changes against $(BASE) — /v1 only grows; make the change additive or set ALLOW_BREAKING=1" >&2; exit 1; \
	elif [ "$$st" != 0 ]; then exit "$$st"; fi

serve:
	uv run traust-server $(if $(CONFIG),--config $(CONFIG)) $(if $(WORKERS),--workers $(WORKERS))

# Development only: SQLite under $(LOCAL)/home and this machine's local issuer trusted.
local-config:
	@test -f $(LOCAL_CONFIG) || { mkdir -p $(LOCAL) && printf 'home: %s\nidentity: { trust_local: true }\n' "$(abspath $(LOCAL))/home" > $(LOCAL_CONFIG) && echo "wrote $(LOCAL_CONFIG)"; }

serve-local: local-config
	uv run traust-server --config $(LOCAL_CONFIG) $(if $(WORKERS),--workers $(WORKERS))

token: local-config
	@test -n "$(NAME)" || { echo "usage: make token NAME=me@example.com (a person) | NAME=runner-1 MACHINE=1 (a runner)" >&2; exit 2; }
	@uv run traust-server --config $(LOCAL_CONFIG) token "$(NAME)" $(if $(MACHINE),--machine) > $(LOCAL)/$(NAME).token
	@echo "$(LOCAL)/$(NAME).token"


perf-load:
	TRAUST_PERF_LOAD=1 uv run --extra postgres --extra rest pytest perf/test_load.py -q -s
