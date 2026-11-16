# EmberVault — Distributed Backup Orchestration System

[![Documentation](https://img.shields.io/badge/docs-docs.embervault.eu-orange.svg)](https://docs.embervault.eu/)
[![Live Demo](https://img.shields.io/badge/demo-demo.embervault.eu-success.svg)](https://demo.embervault.eu/)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Docker Compose](https://img.shields.io/badge/deploy-Docker%20Compose-2496ED.svg)](https://docs.docker.com/compose/)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-red.svg)](#)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: mypy](https://img.shields.io/badge/type%20checked-mypy-blue.svg)](https://mypy-lang.org/)

EmberVault is a distributed platform for backup, replication, and data synchronization orchestration powered by **Rclone**, designed for heterogeneous multi-node environments with encryption at rest and native network isolation.

> 📖 **Official Documentation**: For complete guides, detailed architectural specifications, tutorials, reverse proxy configurations, and API references, visit **[https://docs.embervault.eu/](https://docs.embervault.eu/)**.  
> 🌐 **Live Demo**: Experience EmberVault in real time without installation at **[https://demo.embervault.eu/](https://demo.embervault.eu/)**.

> [!NOTE]
> ### 🤖 Development Model & Contribution Guidelines
> **EmberVault** is developed using an **AI-assisted software development** methodology: all system architecture, design patterns, security controls, and engineering workflows are designed and directed by human engineering, with AI assisting during implementation and test authoring.
>
> - 🐛 **Bug Reports**: Community feedback is very welcome! If you encounter an unexpected behavior or defect, please open a GitHub Issue with reproduction steps and logs.
> - 🚫 **Pull Requests & Feature Requests**: At this stage, external Pull Requests (PRs) and requests for new feature developments are **not accepted or contemplated**. The project roadmap is maintained and evolved strictly according to internal design specifications.

---

## Table of Contents

1. [Quick Deployment Guide](#1-quick-deployment-guide)
   - [Option A: Guided Automated Deployment (Recommended on Linux)](#option-a-guided-automated-deployment-recommended-on-linux)
   - [Option B: Manual Deployment with Docker Compose (Production)](#option-b-manual-deployment-with-docker-compose-production)
   - [Option C: Remote Node Deployment (Proxy & Public Portal)](#option-c-remote-node-deployment-proxy--public-portal)
   - [Option D: Local Development Environment (Dev)](#option-d-local-development-environment-dev)
2. [Post-Installation Configuration](#2-post-installation-configuration)
   - [Switching from Setup Mode to Production](#switching-from-setup-mode-to-production)
   - [Proxy Registration and TOFU Verification](#proxy-registration-and-tofu-verification)
   - [Proxy SSL Certificate Renewal](#proxy-ssl-certificate-renewal)
   - [Reverse Proxy & Disaster Recovery](#reverse-proxy--disaster-recovery)
3. [System Architecture](#3-system-architecture)
4. [Repository Structure](#4-repository-structure)
5. [Configuration & Environment Variables](#5-configuration--environment-variables)
6. [Monitoring & Prometheus Metrics](#6-monitoring--prometheus-metrics)
7. [Make Commands & Quality Assurance](#7-make-commands--quality-assurance)
8. [Security](#8-security)
9. [Documentation](#9-documentation)

---

## 1. Quick Deployment Guide

EmberVault can be deployed on a single host (all-in-one) or distributed across multiple servers by separating the **Primary Host (Core)**, the **Remote Execution Proxies**, and the **Public Portal**.

### Option A: Guided Automated Deployment (Recommended on Linux)

The [`deploy/embervault_sync_and_deploy.sh`](deploy/embervault_sync_and_deploy.sh) script automates installation and updates on Linux (Debian/Ubuntu, RHEL/Rocky, Arch Linux):
- Installs prerequisites (`git`, `docker`, and `docker compose`) if missing.
- Synchronizes the repository to `/opt/embervault/app` and manages secrets in `/opt/embervault/secrets` (`0600` permissions).
- Guides role selection and persists choices in `/opt/embervault/secrets/.last_deploy_choices`.

#### Launching the Script
```bash
curl -fsSL https://raw.githubusercontent.com/firef0z/EmberVault/refs/heads/master/deploy/embervault_sync_and_deploy.sh | sudo bash
```
*Or locally:* `bash deploy/embervault_sync_and_deploy.sh`

Select the role:
1. **Primary Host**: Deploys core services (`app`, `postgres`, `orchestrator`, `hook-runner`), optional local Public Portal, and local Proxies.
2. **External Proxy**: Installs standalone Rclone worker agent (HTTPS port `8443`). *Shortcut*: `bash deploy/embervault_sync_and_deploy_proxy.sh`
3. **External Public Portal**: Installs DMZ file sharing portal (port `8083`). *Shortcut*: `bash deploy/embervault_sync_and_deploy_portal.sh`

#### Unattended / Non-Interactive Execution
```bash
# Setup mode (EMBERVAULT_DEV_NOAUTH=true)
DEPLOY_ROLE=1 INSTALL_PORTAL=true PROXY_COUNT=2 PRODUCTION_MODE=false bash deploy/embervault_sync_and_deploy.sh

# Switch to production mode (after setting admin credentials)
DEPLOY_ROLE=1 INSTALL_PORTAL=true PROXY_COUNT=2 PRODUCTION_MODE=true bash deploy/embervault_sync_and_deploy.sh
```

---

### Option B: Manual Deployment with Docker Compose (Production)

For container hardening with `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, resource limits, and Docker Secrets:

```bash
# 1. Clone the repository
git clone https://github.com/firef0z/embervault.git && cd embervault

# 2. Generate production cryptographic secrets (deploy/secrets/*.txt)
python3 deploy/scripts/generate_secrets.py

# 3. Start the production stack
docker compose -f deploy/compose/docker-compose.yml -f deploy/compose/docker-compose.prod.yml up -d --build
# Or: make up-prod
```

Endpoints:
- **Web Admin Console (`app`)**: `http://<server-ip>:8080`
- **Public Share Portal (`portal`)**: `http://<server-ip>:8083`

---

### Option C: Remote Node Deployment (Proxy & Public Portal)

#### Standalone Remote Proxy
```bash
PROXY_TOKEN="insert_a_secret_token_with_at_least_32_characters" \
EMBERVAULT_PROXY_PORT=8443 \
docker compose -p embervault-proxy -f deploy/compose/docker-compose.proxy.yml up -d --build
```

#### Standalone Public Portal (DMZ)
1. On Primary Host, expose Orchestrator port `8081` using `deploy/compose/docker-compose.expose-orchestrator.yml`.
2. On DMZ host, run:
```bash
EMBERVAULT_ORCHESTRATOR_URL="http://<primary-host-ip>:8081" \
PORTAL_SECRET_KEY="session_secret_key_minimum_32_characters" \
PORTAL_PORT=8083 \
docker compose -p embervault-portal -f deploy/compose/docker-compose.portal.yml up -d --build
```

---

### Option D: Local Development Environment (Dev)

Prerequisites: **Python 3.12+**, **[uv](https://astral.sh/uv)**, and **Docker**.

```bash
uv sync
make up
make ps
make logs
```

Endpoints:
- **Web Console**: [http://localhost:8080](http://localhost:8080)
- **Public Portal**: [http://localhost:8083](http://localhost:8083)
- **PostgreSQL**: `localhost:5432`

---

## 2. Post-Installation Configuration

### Switching from Setup Mode to Production

> [!WARNING]
> Set a strong password for `admin` under **More → Users & Roles** (`/users`) **before** enabling production mode to avoid lockout.

After configuring the administrator password, switch to production:
```bash
sudo bash /opt/embervault/app/deploy/embervault_sync_and_deploy.sh
# Select Role 1, then answer 'y' to enable production mode
```

### Proxy Registration and TOFU Verification

Proxies communicate exclusively over HTTPS (port `8443`) with self-signed TLS certificates and Bearer authentication:
1. In the Web Console, go to **Proxies** and click **Register New Proxy**.
2. Enter **Identifier Name**, **Host / IP**, **HTTPS Port** (`8443`), and **Auth Token**, then click **Probe Proxy**.
3. Verify the certificate SHA-256 fingerprint out-of-band:
   ```bash
   docker logs embervault-proxy 2>&1 | grep -i fingerprint
   ```
4. Click **Confirm Fingerprint & Register** to establish Trust On First Use (TOFU).

### Proxy SSL Certificate Renewal

Proxies issue certificates valid for 90 days:
- **Proactive Alerts**: Warning badges and notifications fire when less than 15 days remain.
- **Rotation**: At 90 days, the proxy rotates certificates and transitions to `Untrusted` (`PROXY_CERT_MISMATCH`). Click **Restore Trust** → **Accept New Fingerprint & Restore Trust** to approve the new fingerprint.
- **Manual Early Renewal**: Click the **Renew TLS Certificate** icon on the proxy row.

### Reverse Proxy & Disaster Recovery

- **Reverse Proxy**: Place `app:8080` and `portal:8083` behind NGINX, Caddy, or Traefik with TLS termination. **Buffering must be disabled on SSE streams** (`/api/ui/events` and `/api/ui/runs/.*/events`). See detailed examples in [Reverse Proxy Documentation](https://docs.embervault.eu/reverse_proxy/).
- **Disaster Recovery**: Automated `.evb` encrypted backups can be configured in **More → Backup & Restore** or via CLI:
  ```bash
  python3 deploy/scripts/backup_restore.py backup --output embervault-backup.tar.gz
  python3 deploy/scripts/backup_restore.py verify --file embervault-backup.tar.gz
  python3 deploy/scripts/backup_restore.py restore --file embervault-backup.tar.gz --confirm
  ```
  *Always keep a secure off-site copy of `master_key.txt`.*

---

## 3. System Architecture

EmberVault adopts a decoupled microservices architecture with segregated Docker networks:

```
             [ Admin Browser ]                     [ External Users ]
                     │                                     │
                     ▼ (Port 8080)                         ▼ (Port 8083)
┌────────────────────────────────── Edge Net ──────────────────────────────────┐
│        ┌──────────────────────┐              ┌──────────────────────┐        │
│        │       Web App        │              │    Public Portal     │        │
│        │   (Flask Admin UI)   │              │    (File Sharing)    │        │
│        └───────────┬──────────┘              └───────────┬──────────┘        │
└────────────────────┼─────────────────────────────────────┼───────────────────┘
                     │                                     │
┌────────────────────┴─────────────────────────────────────┴───────────────────┐
│ Backend Net (Internal — no direct external access)                           │
│                                                                              │
│        ┌──────────────────────┐              ┌──────────────────────┐        │
│        │    PostgreSQL 16     │◄─────────────┤     Orchestrator     │        │
│        │     (Port 5432)      │              │     (Port 8081)      │        │
│        └──────────────────────┘              └─────┬──────────┬─────┘        │
└────────────────────────────────────────────────────┼──────────┼──────────────┘
                                                     │          │
        ┌─────────────────── Proxy Net ──────────────┘          └─── Hooks Net ┐
        │                                                                      │
        ▼                                                                      ▼
┌──────────────────────┐                                      ┌──────────────────────┐
│   Proxy 1..N (TLS)   │                                      │     Hook Runner      │
│     (Port 8443)      │                                      │     (Port 8082)      │
└───────────┬──────────┘                                      └──────────────────────┘
            ▼
  [ Storage Remotes / S3 / SMB / SFTP / NFS / Hypervisors ]
```

- **`app`**: Administrative web console (Flask 3, SSE, multitenancy, RBAC).
- **`orchestrator`**: Central scheduler and supervisor (cron scheduling, heartbeat monitoring, task queues with `SKIP LOCKED`, Apprise notifications).
- **`proxy`**: Stateless execution agent running Rclone, completely isolated from PostgreSQL.
- **`portal`**: DMZ-safe self-service public file browsing and streaming downloads (`/share/<token>`).
- **`hook-runner`**: Sandboxed environment on `hooks_net` for pre/post-run Bash scripts.
- **`postgres`**: PostgreSQL 16 database with automatic Alembic migrations via `migrate`.

---

## 4. Repository Structure

```text
.
├── packages/
│   ├── embervault-common/    # Configuration, AES-256-GCM crypto, log redaction, metrics
│   └── embervault-db/        # SQLAlchemy models, Alembic migrations, repository pattern
├── services/
│   ├── app/                  # Flask Web Admin Console, UI/API blueprints, authentication
│   ├── orchestrator/         # Scheduler, heartbeat loops, state machine, dispatching
│   ├── proxy/                # TLS/Bearer worker execution agent, Rclone wrapper
│   └── portal/               # Public Share Portal for end-users
├── deploy/
│   ├── embervault_sync_and_deploy.sh         # Multi-role automated installer and updater
│   ├── embervault_sync_and_deploy_proxy.sh   # Remote Proxy deploy shortcut
│   ├── embervault_sync_and_deploy_portal.sh  # Remote Public Portal deploy shortcut
│   ├── compose/              # Docker Compose manifests (base, dev, prod, proxy, portal, expose-orchestrator)
│   ├── docker/               # Multi-stage Dockerfiles
│   ├── prometheus/           # Prometheus scraping configuration
│   ├── scripts/              # Secret generator, healthcheck, backup/restore, smoke test
│   └── secrets/              # Local directory for production secret files (*_FILE)
├── docs/
│   └── properdocs/           # ProperDocs technical documentation source and assets
├── tests/                    # Test suite (unit, integration, contract, e2e)
├── Makefile                  # Developer and operations workflow commands
└── pyproject.toml            # uv workspace configuration, ruff, mypy, pytest
```

---

## 5. Configuration & Environment Variables

EmberVault resolves settings across a 4-tier hierarchy: **Code Defaults → Environment Variables & `*_FILE` Secrets → GUI Settings (Database) → Per-Job Overrides**.

| Variable | Default | Description |
|---|---|---|
| `EMBERVAULT_ENV` | `dev` | Execution environment (`dev` or `prod`). |
| `POSTGRES_PASSWORD` / `*_FILE` | - | PostgreSQL database password. |
| `EMBERVAULT_MASTER_KEY` / `*_FILE` | - | AES-256 master key (64 hex characters) for envelope encryption. |
| `EMBERVAULT_SECRET_KEY` / `*_FILE` | - | Flask session cookie signing key. |
| `EMBERVAULT_INTERNAL_API_TOKEN` / `*_FILE` | - | Internal token between `app`, `orchestrator`, and `hook-runner`. |
| `PORTAL_SECRET_KEY` | - | Secret key for Public Portal sessions. |
| `TOKEN` / `TOKEN_FILE` | - | Bearer token for `proxy` nodes (minimum 32 characters). |
| `EMBERVAULT_PUBLIC_URL` | `http://localhost:8080` | Publicly reachable URL of the Web Console. |
| `EMBERVAULT_SESSION_COOKIE_SECURE` | `false` | Enforce `Secure` attribute on cookies (requires HTTPS). |
| `EMBERVAULT_TRUSTED_PROXIES` | - | Comma-separated trusted reverse proxy IPs/subnets for `X-Forwarded-For`. |

*For the full list of all 50+ settings, consult the [Advanced Configuration Guide](https://docs.embervault.eu/configuration/).*

---

## 6. Monitoring & Prometheus Metrics

- **Web App**: `GET http://app:8080/metrics`
- **Orchestrator**: `GET http://orchestrator:8081/metrics`
- **Proxy**: `GET https://proxy:8443/metrics` (`Authorization: Bearer <TOKEN>`)

Scrape configuration template: [`deploy/prometheus/prometheus.yml`](deploy/prometheus/prometheus.yml).

---

## 7. Make Commands & Quality Assurance

| Command | Description |
|---|---|
| `make up` / `make down` | Start / stop development Docker Compose stack |
| `make up-prod` / `make down-prod` | Start / stop hardened production Docker Compose stack |
| `make ps` / `make logs` | View container status / follow real-time logs |
| `make sync` | Sync Python virtualenv with `uv` |
| `make lint` / `make format` | Run lint checks / format code with `ruff` |
| `make typecheck` | Run static type analysis with `mypy` |
| `make arch-check` | Enforce package isolation contracts with `import-linter` |
| `make test` | Run unit and integration test suite with `pytest` |
| `make test-e2e` | Validate Docker Compose security and isolation specifications |
| `make smoke` | Execute end-to-end smoke tests on config, crypto, redaction, and DB |
| `make check` | Run the full verification pipeline (`lint`, `format-check`, `typecheck`, `arch-check`, `test`, `smoke`) |

---

## 8. Security

- **Envelope Encryption (AES-256-GCM)**: Remote credentials are encrypted at rest with contextual Authenticated Additional Data (AAD) preventing cross-record swapping attacks.
- **Zero Database Exposure**: Proxies and Public Portal operate in complete network isolation without database access.
- **Automatic Log Redaction**: Structured logging pipeline scrubs secrets and tokens before writing logs.
- **Container Hardening**: Unprivileged user (`UID 10001`), read-only filesystems, and `cap_drop: [ALL]`.

---

## 9. Documentation

Comprehensive documentation is hosted online and maintained in `docs/properdocs/`:

- 🌐 **Online Documentation**: **[https://docs.embervault.eu/](https://docs.embervault.eu/)**
- 🎮 **Live Demo**: **[https://demo.embervault.eu/](https://demo.embervault.eu/)**
- 🚀 **[Deployment Guide](https://docs.embervault.eu/deployment/)**: Topology options, automated installation, and post-install hardening.
- 🗄️ **[Storage Remotes](https://docs.embervault.eu/remotes/)**: Configuration for 40+ storage providers (S3, SFTP, SMB, WebDAV, local pools).
- ⏱️ **[Backup Jobs](https://docs.embervault.eu/jobs/)**: Copy vs Sync modes, cron scheduling, subfolder sharding, and Bash hooks.
- 🖥️ **[Execution Proxies](https://docs.embervault.eu/proxies/)**: TOFU certificate pinning, edge node management, and reachability.
- 🛡️ **[Authentication & RBAC](https://docs.embervault.eu/authentication/)**: Active Directory (LDAPS), OIDC (PocketID SSO), TOTP 2FA, and roles matrix.
- 🤖 **[AI-Driven Diagnostics](https://docs.embervault.eu/ai/)**: LLM error evaluation, retry backoffs, and executive reporting.
- 🌐 **[Public Share Portal](https://docs.embervault.eu/portal/)**: DMZ file sharing, directory browsing, and on-the-fly streaming.
- 🔒 **[Security Architecture](https://docs.embervault.eu/security/)**: OWASP Top 10 pentest checklist and threat models.
- 🌐 **[Reverse Proxy Setup](https://docs.embervault.eu/reverse_proxy/)**: Nginx, Caddy, and Traefik configs with unbuffered SSE streaming.
- ⚙️ **[Advanced Configuration](https://docs.embervault.eu/configuration/)**: Complete canonical registry of all configuration parameters.

