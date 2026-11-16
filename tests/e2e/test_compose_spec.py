"""Specification and isolation tests for EmberVault Docker Compose files."""

from pathlib import Path
from typing import Any

import yaml


def load_compose_file(relative_path: str) -> dict[str, Any]:
    """Load and parse YAML content of a Docker Compose file."""
    compose_path = Path(relative_path)
    assert compose_path.is_file(), f"File {relative_path} does not exist"
    content = compose_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)
    return parsed


def test_compose_networks_and_service_isolation() -> None:
    """Verify that network isolation conforms strictly to Section 8 of the implementation plan."""
    compose = load_compose_file("deploy/compose/docker-compose.yml")

    networks = compose.get("networks", {})
    assert "edge" in networks, "Missing 'edge' network"
    assert "backend" in networks, "Missing 'backend' network"
    assert "proxy_net" in networks, "Missing 'proxy_net' network"
    assert "hooks_net" in networks, "Missing 'hooks_net' network"

    # Backend and hooks_net networks must be marked internal to prevent external/direct ingress
    assert networks["backend"].get("internal") is True, "Backend network must be internal: true"
    assert networks["hooks_net"].get("internal") is True, "Hooks_net network must be internal: true"

    services = compose.get("services", {})
    expected_services = {
        "postgres",
        "migrate",
        "app",
        "orchestrator",
        "proxy-1",
        "proxy-2",
        "hook-runner",
    }
    assert expected_services.issubset(set(services.keys())), (
        f"Missing services in compose: {expected_services - set(services.keys())}"
    )

    # 1. Postgres must ONLY be on backend network
    assert services["postgres"].get("networks") == ["backend"], (
        "postgres must only be attached to backend network"
    )

    # 2. Migrate must ONLY be on backend network
    assert services["migrate"].get("networks") == ["backend"], (
        "migrate must only be attached to backend network"
    )

    # 3. App must be on edge and backend, and NEVER on proxy_net or hooks_net
    app_networks = set(services["app"].get("networks", []))
    assert app_networks == {"edge", "backend"}
    assert "proxy_net" not in app_networks, "app must NEVER be on proxy_net"
    assert "hooks_net" not in app_networks, "app must NEVER be on hooks_net"

    # 4. Orchestrator must be on backend, proxy_net, and hooks_net, and NEVER on edge
    orch_networks = set(services["orchestrator"].get("networks", []))
    assert orch_networks == {"backend", "proxy_net", "hooks_net"}
    assert "edge" not in orch_networks, "orchestrator must NOT be on edge"

    # 5. Proxies must ONLY be on proxy_net
    for proxy_name in ("proxy-1", "proxy-2"):
        p_networks = set(services[proxy_name].get("networks", []))
        assert p_networks == {"proxy_net"}, f"{proxy_name} must ONLY be attached to proxy_net"

    # 6. Hook runner must ONLY be on hooks_net (strictly no backend, no edge, no proxy_net)
    hook_runner_networks = set(services["hook-runner"].get("networks", []))
    assert hook_runner_networks == {"hooks_net"}, "hook-runner must ONLY be attached to hooks_net"


def test_compose_dependencies_and_healthchecks() -> None:
    """Verify the startup dependency ordering and healthcheck declarations."""
    compose = load_compose_file("deploy/compose/docker-compose.yml")
    services = compose.get("services", {})

    # 1. Postgres has healthcheck
    assert "healthcheck" in services["postgres"], "postgres must declare healthcheck"

    # 2. Migrate depends on postgres healthy, and runs once
    migrate = services["migrate"]
    assert migrate.get("restart") == "no", "migrate service must not restart automatically"
    migrate_deps = migrate.get("depends_on", {})
    assert "postgres" in migrate_deps
    assert migrate_deps["postgres"].get("condition") == "service_healthy"

    # 3. App depends on postgres healthy and migrate completed successfully
    app_deps = services["app"].get("depends_on", {})
    assert app_deps["postgres"].get("condition") == "service_healthy"
    assert app_deps["migrate"].get("condition") == "service_completed_successfully"
    assert "healthcheck" in services["app"], "app must declare healthcheck"

    # 4. Orchestrator depends on postgres healthy and migrate completed successfully
    orch_deps = services["orchestrator"].get("depends_on", {})
    assert orch_deps["postgres"].get("condition") == "service_healthy"
    assert orch_deps["migrate"].get("condition") == "service_completed_successfully"
    assert "healthcheck" in services["orchestrator"], "orchestrator must declare healthcheck"

    # 5. Proxies have healthcheck
    for proxy_name in ("proxy-1", "proxy-2"):
        assert "healthcheck" in services[proxy_name], f"{proxy_name} must declare healthcheck"


def test_compose_dev_overrides() -> None:
    """Verify development compose overrides for volume mounting and live-reload."""
    dev_compose = load_compose_file("deploy/compose/docker-compose.dev.yml")
    dev_services = dev_compose.get("services", {})

    assert "app" in dev_services
    assert "orchestrator" in dev_services
    assert "proxy-1" in dev_services
    assert "proxy-2" in dev_services

    # App and orchestrator should mount code volumes
    assert "volumes" in dev_services["app"]
    assert "volumes" in dev_services["orchestrator"]

    # Gunicorn reload flag should be configured in command
    app_cmd = " ".join(dev_services["app"].get("command", []))
    assert "--reload" in app_cmd


def test_compose_prod_hardening() -> None:
    """Verify production compose overrides for read_only, capabilities, resource limits, and secrets."""
    prod_path = "deploy/compose/docker-compose.prod.yml"
    prod_compose = load_compose_file(prod_path)
    prod_services = prod_compose.get("services", {})

    for svc_name in ("app", "orchestrator", "hook-runner", "proxy-1", "proxy-2"):
        assert svc_name in prod_services, f"Missing {svc_name} in {prod_path}"
        svc = prod_services[svc_name]

        assert svc.get("read_only") is True, f"{svc_name} in {prod_path} must be read_only: true"
        assert svc.get("cap_drop") == ["ALL"], (
            f"{svc_name} in {prod_path} must have cap_drop: [ALL]"
        )
        assert "no-new-privileges:true" in svc.get("security_opt", []), (
            f"{svc_name} in {prod_path} must have no-new-privileges:true"
        )

        # Check tmpfs mounts
        assert "tmpfs" in svc, f"{svc_name} in {prod_path} must declare tmpfs mounts"

        # Check resource limits
        limits = svc.get("deploy", {}).get("resources", {}).get("limits", {})
        assert "cpus" in limits, f"{svc_name} in {prod_path} missing CPU limit"
        assert "memory" in limits, f"{svc_name} in {prod_path} missing memory limit"

        # Check log rotation
        logging_cfg = svc.get("logging", {})
        assert logging_cfg.get("driver") == "json-file"
        assert logging_cfg.get("options", {}).get("max-size") == "10m"
        assert logging_cfg.get("options", {}).get("max-file") == "3"

    # Check secrets declaration
    secrets = prod_compose.get("secrets", {})
    required_secrets = {
        "postgres_password",
        "master_key",
        "secret_key",
        "internal_api_token",
        "proxy_1_token",
        "proxy_2_token",
    }
    assert required_secrets.issubset(set(secrets.keys())), (
        f"Missing secrets in {prod_path}: {required_secrets - set(secrets.keys())}"
    )


def test_compose_standalone_proxy() -> None:
    """Verify standalone remote proxy Docker Compose specification."""
    proxy_compose = load_compose_file("deploy/compose/docker-compose.proxy.yml")
    services = proxy_compose.get("services", {})

    assert "proxy" in services, (
        "deploy/compose/docker-compose.proxy.yml must define 'proxy' service"
    )
    svc = services["proxy"]

    # Security flags
    assert svc.get("read_only") is True
    assert svc.get("cap_drop") == ["ALL"]
    assert "no-new-privileges:true" in svc.get("security_opt", [])

    # Exposed port
    assert "8443" in str(svc.get("ports", []))

    # Persistence volume
    assert "volumes" in svc
    volumes = proxy_compose.get("volumes", {})
    assert "proxy_state" in volumes, "proxy_state volume must be defined"

    # Healthcheck
    assert "healthcheck" in svc
    test_cmd = " ".join(svc["healthcheck"].get("test", []))
    assert "healthcheck.py" in test_cmd


def test_prometheus_scrape_config() -> None:
    """Verify Prometheus scrape targets configuration."""
    scrape_path = Path("deploy/prometheus/prometheus.yml")
    assert scrape_path.is_file(), "deploy/prometheus/prometheus.yml does not exist"
    content = scrape_path.read_text(encoding="utf-8")
    parsed = yaml.safe_load(content)
    assert isinstance(parsed, dict)

    scrape_configs = parsed.get("scrape_configs", [])
    job_names = {cfg["job_name"] for cfg in scrape_configs}
    assert "embervault-app" in job_names
    assert "embervault-orchestrator" in job_names
    assert "embervault-proxies" in job_names

    # Check proxy job config has TLS and auth
    proxy_job = next(cfg for cfg in scrape_configs if cfg["job_name"] == "embervault-proxies")
    assert proxy_job.get("scheme") == "https"
    assert proxy_job.get("tls_config", {}).get("insecure_skip_verify") is True
    assert proxy_job.get("authorization", {}).get("type") == "Bearer"


def test_compose_standalone_portal() -> None:
    """Verify standalone remote portal Docker Compose specification."""
    portal_compose = load_compose_file("deploy/compose/docker-compose.portal.yml")
    services = portal_compose.get("services", {})

    assert "portal" in services, (
        "deploy/compose/docker-compose.portal.yml must define 'portal' service"
    )
    svc = services["portal"]
    assert "8083" in str(svc.get("ports", []))
    assert "healthcheck" in svc
    test_cmd = " ".join(svc["healthcheck"].get("test", []))
    assert "healthcheck.py" in test_cmd


def test_compose_expose_orchestrator_overlay() -> None:
    """Verify expose-orchestrator overlay exposes port 8081."""
    expose_compose = load_compose_file("deploy/compose/docker-compose.expose-orchestrator.yml")
    services = expose_compose.get("services", {})

    assert "orchestrator" in services, "Missing 'orchestrator' service in overlay"
    svc = services["orchestrator"]
    ports = svc.get("ports", [])
    assert any("8081" in p for p in ports)
