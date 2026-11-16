# Multi-stage Dockerfile for EmberVault Hook Runner sidecar service (M8/M9 Hardening)
FROM ghcr.io/astral-sh/uv:latest AS uv-bin
FROM python:3.12-slim-bookworm AS base

# Install uv from official image
COPY --from=uv-bin /uv /uvx /bin/

# Install bash, curl, coreutils, jq for shell scripts execution in the hook environment
RUN apt-get update && \
    apt-get install -y --no-install-recommends bash curl coreutils jq ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PATH="/app/.venv/bin:$PATH"

# Create unprivileged non-root user and app directory upfront with correct ownership
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

# Install dependencies needed by runner_service (Flask, Gunicorn, embervault-common)
# Using embervault-proxy dependencies (which contains Flask + Gunicorn + embervault-common without DB)
RUN --mount=type=cache,target=/home/embervault/.cache/uv,uid=10001,gid=10001 \
    uv sync --frozen --no-dev --no-install-workspace --package embervault-proxy

# Copy common library, proxy package (for workspace resolution), and healthcheck
COPY --chown=embervault:embervault README.md ./
COPY --chown=embervault:embervault packages/embervault-common packages/embervault-common
COPY --chown=embervault:embervault services/proxy services/proxy
COPY --chown=embervault:embervault deploy/scripts/healthcheck.py deploy/scripts/healthcheck.py

# Re-sync workspace packages
RUN --mount=type=cache,target=/home/embervault/.cache/uv,uid=10001,gid=10001 \
    uv sync --frozen --no-dev --package embervault-proxy

EXPOSE 8082

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD python3 /app/deploy/scripts/healthcheck.py --service hook-runner

CMD ["gunicorn", "--bind", "0.0.0.0:8082", "--workers", "1", "--threads", "4", "embervault_common.hooks.runner_service:create_hook_runner_app()"]
