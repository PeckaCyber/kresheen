# syntax=docker/dockerfile:1
# Minimal runtime image: no shell, no package manager, no pip, non-root,
# every base pinned by digest (the tag is in the comment). Build args choose the base so another base can be compared
# them from one file; the builder's Python minor version MUST match the runtime's (compiled wheels and .pyc).
#   default:  builder python:3.13-slim-trixie  +  runtime gcr.io/distroless/python3-debian13:nonroot (Python 3.13.5)
#   Debian 12: --build-arg BUILDER_IMAGE=python:3.11-slim-bookworm@sha256:2333bd33... \
#              --build-arg RUNTIME_IMAGE=gcr.io/distroless/python3-debian12:nonroot@sha256:7d1042ce...
# Debugging without a shell (docker debug / kubectl debug).
# The defaults are the two stages below (named so Dependabot can track and update their digests); a build arg can name any other image.
ARG BUILDER_IMAGE=builder-default
ARG RUNTIME_IMAGE=runtime-default

# python:3.13-slim-trixie
FROM python:3.13-slim-trixie@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS builder-default
# gcr.io/distroless/python3-debian13:nonroot (Python 3.13.5)
FROM gcr.io/distroless/python3-debian13:nonroot@sha256:ed91505d162119a1e46552bc7f471c77737729a525269a7e9b60646807564601 AS runtime-default

# Node build image, pinned by tag and digest. Runs on the build host's platform (the built files are the same for every architecture).
FROM --platform=$BUILDPLATFORM node:24-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS frontend-builder
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

# Official uv image, pinned by tag and digest. Only used to export uv.lock; it never reaches the runtime.
FROM ghcr.io/astral-sh/uv:0.13.4@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b AS uv

FROM ${BUILDER_IMAGE} AS builder
WORKDIR /build
COPY --from=uv /uv /usr/local/bin/uv
COPY pyproject.toml README.md uv.lock ./
COPY src ./src
# Install into a plain directory (not a venv): only site-packages reaches the runtime, so pip, setuptools and the
# build tooling never do. Bytecode is precompiled because the runtime root filesystem is read-only.
# uv.lock is the only lock file. It is exported to a hashed requirements list at build time and pip installs that with
# --require-hashes, so anything not in the lock is refused. The app itself goes in last.
RUN uv export --frozen --no-dev --no-emit-project --format requirements-txt --no-header -o /tmp/requirements.txt \
    && pip install --no-cache-dir --require-hashes --target /opt/site-packages -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt \
    && pip install --no-cache-dir --no-deps --target /opt/site-packages . \
    && rm -rf /opt/site-packages/bin \
    && find /opt/site-packages -type d \( -name tests -o -name test \) -prune -exec rm -rf {} + \
    && find /opt/site-packages -name '*.pyi' -delete \
    && python -m compileall -q /opt/site-packages \
    && mkdir -p /rootfs/data /rootfs/var/cache/grype /rootfs/tmp \
    && printf '#!/usr/bin/python3\nfrom kresheen.cli.main import cli\ncli()\n' > /rootfs/kresheen

# Official Grype image, pinned by tag and digest (a static Go binary)
FROM anchore/grype:v0.121.0@sha256:621d56d1d68106b787022c81546f7e0a36202a25d1239f0c20195fab8c16f7ea AS grype

FROM ${RUNTIME_IMAGE}
COPY --from=builder /opt/site-packages /opt/site-packages
COPY --from=grype /grype /usr/local/bin/grype
# `kresheen` on PATH for `kubectl exec` / `docker exec` (pip's script was dropped: its shebang names the builder's Python).
COPY --from=builder --chmod=0755 /rootfs/kresheen /usr/local/bin/kresheen
COPY --from=frontend-builder /build/frontend/dist /app/frontend/dist
COPY LICENSE NOTICE /app/
# Writable places only: the database volume, the Grype vulnerability DB cache, /tmp (also mount tmpfs/emptyDir there).
COPY --from=builder --chown=65532:65532 /rootfs/data /data
COPY --from=builder --chown=65532:65532 /rootfs/var/cache/grype /var/cache/grype
COPY --from=builder --chown=65532:65532 --chmod=1777 /rootfs/tmp /tmp
# Grype downloads its vulnerability DB on first use (outbound access once), or mount a pre-populated
# GRYPE_DB_CACHE_DIR for air-gapped installs.
ENV PYTHONPATH=/opt/site-packages \
    PYTHONDONTWRITEBYTECODE=1 \
    KRESHEEN_FRONTEND_DIST=/app/frontend/dist \
    KRESHEEN_DB_URL=sqlite:////data/kresheen.db \
    GRYPE_DB_CACHE_DIR=/var/cache/grype \
    GRYPE_CHECK_FOR_APP_UPDATE=false \
    HOME=/tmp
WORKDIR /app
USER 65532:65532
EXPOSE 8000
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/usr/bin/python3", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=3).status == 200 else 1)"]
ENTRYPOINT ["/usr/bin/python3", "-c", "from kresheen.cli.main import cli; cli()"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
