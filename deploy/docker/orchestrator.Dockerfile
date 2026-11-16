# Multi-stage Dockerfile for EmberVault Orchestrator service
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

# Create unprivileged non-root user and shared directories upfront with correct ownership
RUN groupadd -g 10001 embervault && \
    useradd -u 10001 -g embervault -m -d /home/embervault -s /bin/bash embervault && \
    mkdir -p /app /backups /home/embervault/.cache/uv && \
    chown -R embervault:embervault /app /backups /home/embervault && \
    chmod 775 /backups

USER embervault
WORKDIR /app

# Copy root workspace and package manifests for caching
COPY --chown=embervault:embervault pyproject.toml uv.lock README.md ./
COPY --chown=embervault:embervault packages/embervault-common/pyproject.toml packages/embervault-common/README.md packages/embervault-common/
COPY --chown=embervault:embervault packages/embervault-db/pyproject.toml packages/embervault-db/README.md packages/embervault-db/
COPY --chown=embervault:embervault services/app/pyproject.toml services/app/README.md services/app/
COPY --chown=embervault:embervault services/orchestrator/pyproject.toml services/orchestrator/README.md services/orchestrator/
COPY --chown=embervault:embervault services/proxy/pyproject.toml services/proxy/README.md services/proxy/

# Install dependencies for orchestrator (caching external dependencies layer)
RUN --mount=type=cache,target=/home/embervault/.cache/uv,uid=10001,gid=10001 \
    uv sync --frozen --no-dev --no-install-workspace --package embervault-orchestrator

# Copy application source code
COPY --chown=embervault:embervault README.md ./
COPY --chown=embervault:embervault packages/embervault-common packages/embervault-common
COPY --chown=embervault:embervault packages/embervault-db packages/embervault-db
COPY --chown=embervault:embervault services/orchestrator services/orchestrator
COPY --chown=embervault:embervault deploy/scripts/healthcheck.py deploy/scripts/healthcheck.py

# Re-sync to install workspace package sources
RUN --mount=type=cache,target=/home/embervault/.cache/uv,uid=10001,gid=10001 \
    uv sync --frozen --no-dev --package embervault-orchestrator

EXPOSE 8081 9091

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 /app/deploy/scripts/healthcheck.py --service orchestrator

CMD ["gunicorn", "--bind", "0.0.0.0:8081", "--workers", "1", "--threads", "4", "embervault_orchestrator.factory:create_orchestrator_app()"]
