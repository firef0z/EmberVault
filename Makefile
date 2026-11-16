.PHONY: help sync lint format format-check typecheck arch-check test check smoke clean up down ps logs up-prod down-prod test-e2e

COMPOSE_DEV = docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.dev.yml
COMPOSE_PROD = docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.prod.yml

help:
	@echo "EmberVault Development Commands:"
	@echo "  make sync        - Sync dependencies with uv"
	@echo "  make lint        - Run ruff linter"
	@echo "  make format      - Format code with ruff"
	@echo "  make typecheck   - Run mypy type checker"
	@echo "  make arch-check  - Run import-linter architectural checks"
	@echo "  make test        - Run unit test suite"
	@echo "  make smoke       - Run baseline smoke verification suite"
	@echo "  make check       - Run lint, format check, typecheck, arch-check, and tests"
	@echo "  make up          - Start development stack with docker compose"
	@echo "  make down        - Stop development stack and remove volumes"
	@echo "  make up-prod     - Start hardened production stack with docker compose"
	@echo "  make down-prod   - Stop production stack"
	@echo "  make ps          - View running compose services status"
	@echo "  make logs        - Follow compose services logs"
	@echo "  make test-e2e    - Run e2e tests (verifying compose health & isolation)"
	@echo "  make clean       - Remove cache and temporary files"

sync:
	uv sync

lint:
	uv run ruff check .

format:
	uv run ruff format .

format-check:
	uv run ruff format --check .

typecheck:
	uv run mypy packages services tests

arch-check:
	uv run lint-imports

test:
	uv run pytest tests -v

smoke:
	uv run python deploy/scripts/smoke.py

check: lint format-check typecheck arch-check test smoke

up:
	$(COMPOSE_DEV) up -d --build

down:
	$(COMPOSE_DEV) down -v

up-prod:
	$(COMPOSE_PROD) up -d --build

down-prod:
	$(COMPOSE_PROD) down -v

ps:
	$(COMPOSE_DEV) ps

logs:
	$(COMPOSE_DEV) logs -f

test-e2e:
	uv run pytest tests/e2e -v

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache .import_linter_cache .hypothesis .coverage htmlcov site
