# Multi-stage Dockerfile for EmberVault Portal service
FROM ghcr.io/astral-sh/uv:latest AS uv-bin
FROM python:3.12-slim-bookworm AS base

# Install uv from official image
COPY --from=uv-bin /uv /uvx /bin/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

# Create unprivileged non-root user
RUN groupadd -g 10001 embervault && \
    useradd -u 10001 -g embervault -m -d /home/embervault -s /bin/bash embervault && \
    mkdir -p /app /home/embervault/.cache/uv && \
    chown -R embervault:embervault /app /home/embervault

USER embervault
WORKDIR /app

# Copy root workspace and package manifests for caching
COPY --chown=embervault:embervault pyproject.toml uv.lock README.md ./
COPY --chown=embervault:embervault packages/embervault-common/pyproject.toml packages/embervault-common/README.md packages/embervault-common/
COPY --chown=embervault:embervault packages/embervault-db/pyproject.toml packages/embervault-db/README.md packages/embervault-db/
COPY --chown=embervault:embervault services/app/pyproject.toml services/app/README.md services/app/
COPY --chown=embervault:embervault services/orchestrator/pyproject.toml services/orchestrator/README.md services/orchestrator/
COPY --chown=embervault:embervault services/proxy/pyproject.toml services/proxy/README.md services/proxy/
COPY --chown=embervault:embervault services/portal/pyproject.toml services/portal/README.md services/portal/

# Install dependencies (only for portal and its dependencies, excluding workspace source packages)
RUN --mount=type=cache,target=/home/embervault/.cache/uv,uid=10001,gid=10001 \
    uv sync --frozen --no-dev --no-install-workspace --package embervault-portal

# Copy portal source code
COPY --chown=embervault:embervault README.md ./
COPY --chown=embervault:embervault services/portal services/portal
COPY --chown=embervault:embervault deploy/scripts/healthcheck.py deploy/scripts/healthcheck.py

# Re-sync to install the workspace package sources
RUN --mount=type=cache,target=/home/embervault/.cache/uv,uid=10001,gid=10001 \
    uv sync --frozen --no-dev --package embervault-portal

EXPOSE 8083

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 /app/deploy/scripts/healthcheck.py --service portal --port 8083

CMD ["gunicorn", "--bind", "0.0.0.0:8083", "--workers", "2", "--threads", "8", "--timeout", "120", "--access-logfile", "-", "embervault_portal.factory:create_app()"]

