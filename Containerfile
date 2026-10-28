# ── Builder stage ───────────────────────────────────────────────────
# Hardened, RPM-based Python builder image from a public registry
# (registry.access.redhat.com needs no credentials). Pinned by digest.
#
# MUST stay on the same Python minor as the runtime stage below: the .venv
# built here is copied wholesale into the runtime, and native-extension .so
# files are ABI-pinned per minor while the venv's script shebangs hardcode
# the builder's interpreter path.
FROM registry.access.redhat.com/hi/python:3.12-builder@sha256:08a3af100c8c595e348dac3a2a0ff96e3265bd63d0d17f2fe53504ae0b75f189 AS builder

ARG UV_VERSION=0.7

USER 0

# git is required for uv to resolve the git-commit dependency pins
# (traust-contracts, traust-ledger). Installed via microdnf (the base image
# is RPM-based). Both pins are public repositories and resolve without
# credentials.
RUN microdnf install -y git ca-certificates \
    && microdnf clean all

RUN pip install --no-cache-dir "uv>=${UV_VERSION}"

WORKDIR /build

# Dependency layer first — cache-friendly when only source changes.
COPY pyproject.toml uv.lock ./

# The lock pins rest (fastapi, uvicorn) and postgres (psycopg) extras for
# the REST adapter; everything else core needs is in the main dependency set.
RUN uv sync --frozen --extra rest --extra postgres --no-install-project

COPY . .
RUN uv build --wheel --out-dir /build/dist

# Install the built wheel into the venv so the runtime stage gets a
# single self-contained tree (traust-server console script included).
RUN uv pip install --no-deps /build/dist/*.whl

# ── cosign source ───────────────────────────────────────────────────
# Take the cosign binary from a digest-pinned hardened image rather than
# downloading a release at build time: no network fetch in the build.
# Ledger signing (Config.ledger) shells out to it; deployments without
# signing never execute it.
FROM registry.access.redhat.com/hi/cosign:latest@sha256:b093a3ec46fab423d25333ca1a9466ccf21799c94008eaf1b9fdbd23e7ee25a2 AS cosign

# ── Runtime stage ───────────────────────────────────────────────────
# Minimal hardened Python runtime. Runs as a non-root user (UID 65532) by
# default and ships no package manager, so nothing is installed here.
# Python minor must match the builder stage above (see note there).
FROM registry.access.redhat.com/hi/python:3.12@sha256:14ce8115a8eb67f602070b85bee19e22856a760454e74afed17a23d41cc1ddc2 AS runtime

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

# --chown: the runtime base image runs as a non-root UID (65532) and the
# rewire RUN below executes as that user, so it must own the copied files.
COPY --from=builder --chown=65532:65532 /build/.venv /app/.venv

# The venv was created at /build/.venv in the builder stage, so its
# console-script shebangs (traust-server, uvicorn, etc.) and `python`
# symlinks point at builder paths that do not exist in the runtime image.
# Rewire them to the runtime location. The runtime image ships no shell or
# package manager, so this runs python (by absolute path, since the venv's
# own symlinks are broken until fixed).
RUN ["/usr/bin/python3.12", "-c", "import glob, os\nvenv_bin = '/app/.venv/bin'\nfor link, target in (('python3.12', '/usr/bin/python3.12'), ('python3', 'python3.12'), ('python', 'python3.12')):\n    path = os.path.join(venv_bin, link)\n    if os.path.lexists(path):\n        os.remove(path)\n    os.symlink(target, path)\nold = '#!/build/.venv/bin/python'\nnew = '#!/app/.venv/bin/python'\nfor script in glob.glob(os.path.join(venv_bin, '*')):\n    if not os.path.isfile(script) or os.path.islink(script):\n        continue\n    with open(script, 'rb+') as fh:\n        head = fh.read(len(old) + 8)\n        if head.startswith(old.encode()):\n            fh.seek(0)\n            fh.write(new.encode() + head[len(old):]"]

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
