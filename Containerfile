# ── Builder stage ───────────────────────────────────────────────────
# Hardened, RPM-based Python builder image from a public registry
# (registry.access.redhat.com needs no credentials). Pinned by digest.
#
# MUST stay on the same Python minor as the runtime stage below: the .venv
# built here is copied wholesale into the runtime, and native-extension .so
# files are ABI-pinned per minor while the venv's script shebangs hardcode
# the builder's interpreter path.
FROM registry.access.redhat.com/hi/python:3.12.16-builder@sha256:370dac28b556bdc990f9d04fc8d4ff5896bc5c412e49885f5e788b4c913b75f0 AS builder

ARG UV_VERSION=0.7

USER 0

# git is required for uv to resolve the git-commit dependency pins
# (traust-contracts, traust-ledger). Installed via dnf (the base image
# is RPM-based). Both pins are public repositories and resolve without
# credentials.
RUN dnf install -y git ca-certificates \
  && dnf clean all

RUN pip install --no-cache-dir "uv>=${UV_VERSION}"

WORKDIR /app

# Dependency layer first — cache-friendly when only source changes.
COPY pyproject.toml uv.lock ./

# The lock pins rest (fastapi, uvicorn) and postgres (psycopg) extras for
# the REST adapter; everything else core needs is in the main dependency set.
RUN uv sync --frozen --extra rest --extra postgres --no-install-project

COPY src/ ./src/
RUN uv build --wheel --out-dir /app/dist

# Install the built wheel into the venv so the runtime stage gets a
# single self-contained tree (traust-server console script included).
RUN uv pip install --no-deps /app/dist/*.whl

# ── cosign source ───────────────────────────────────────────────────
# Take the cosign binary from a digest-pinned hardened image rather than
# downloading a release at build time: no network fetch in the build.
# Ledger signing (Config.ledger) shells out to it; deployments without
# signing never execute it.
FROM registry.access.redhat.com/hi/cosign:latest@sha256:a8b792557cb6180a43122deca8d1edcf97e4efa5c7e917b7812924fb713d8323 AS cosign

# ── Runtime stage ───────────────────────────────────────────────────
# Minimal hardened Python runtime. Runs as a non-root user (UID 65532) by
# default and ships no package manager, so nothing is installed here.
# Python minor must match the builder stage above (see note there).
FROM registry.access.redhat.com/hi/python:3.12.16@sha256:92e83dcf087d5ef02e6edaf218ab40c297227b8845da97db8f6766b698703d74

# OCI labels. SOURCE_REVISION and VERSION are supplied by the build.
ARG SOURCE_REVISION=unknown
ARG VERSION=unknown
LABEL org.opencontainers.image.source="https://github.com/traust-security/traust-core" \
      org.opencontainers.image.revision="${SOURCE_REVISION}" \
      org.opencontainers.image.title="traust-core" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0" \
      name="traust-core" \
      version="${VERSION}" \
      release="1" \
      vendor="Red Hat, Inc." \
      url="https://github.com/traust-security/traust-core" \
      summary="traust platform API server" \
      description="traust-core's REST adapter (traust-server): domain services over the contract tables, bearer-token identity, one unit of work per request." \
      distribution-scope="public" \
      com.redhat.component="traust-core" \
      io.k8s.description="traust platform API server (traust-server)." \
      io.k8s.display-name="Traust Core Server" \
      maintainer="Traust maintainers <traust@redhat.com>"

# cosign for ledger signing when a deployment configures it; the key never
# ships here.
COPY --from=cosign /usr/bin/cosign /usr/local/bin/cosign
# No LICENSE file ships yet (pyproject declares Apache-2.0); add one under
# /licenses when the repository gains it.

COPY --from=builder /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

ARG APP_PORT=8080
EXPOSE ${APP_PORT}

# Liveness is /v1/healthz (no auth, no database); Kubernetes probes call it.
# Run as the base image's non-root user, matching the file ownership above.
USER 65532

# The deployment passes --config /etc/traust/traust.yaml (and may override
# host/port); defaults serve on all interfaces at the exposed port.
ENTRYPOINT ["traust-server", "--host", "0.0.0.0", "--port", "8080"]
