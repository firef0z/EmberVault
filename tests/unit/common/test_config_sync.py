"""Test synchronization between CONFIG_REGISTRY, docs/configuration.md, and .env.example."""

from pathlib import Path

from embervault_common.config import (
    CONFIG_REGISTRY,
    generate_configuration_docs,
    generate_env_example,
)


def test_registry_uniqueness_and_completeness() -> None:
    """Verify that all registry keys have unique names, env vars, and valid fields."""
    names = set()
    env_vars = set()

    for item in CONFIG_REGISTRY:
        assert item.name not in names, f"Duplicate config name in registry: {item.name}"
        names.add(item.name)

        assert item.env_var not in env_vars, f"Duplicate env_var in registry: {item.env_var}"
        env_vars.add(item.env_var)

        assert item.description, f"Missing description for {item.name}"
        assert item.service in (
            "common",
            "db",
            "security",
            "app",
            "orchestrator",
            "proxy",
        ), f"Invalid service '{item.service}' for {item.name}"


def test_env_example_in_sync_with_registry() -> None:
    """Verify that .env.example matches exactly the generated output of generate_env_example()."""
    env_example_path = Path(".env.example")
    assert env_example_path.is_file(), ".env.example file must exist in workspace root"

    expected_content = generate_env_example()
    actual_content = env_example_path.read_text(encoding="utf-8")

    assert actual_content.strip() == expected_content.strip(), (
        ".env.example is out of sync with CONFIG_REGISTRY. Run generate_env_example() to update."
    )


def test_configuration_docs_in_sync_with_registry() -> None:
    """Verify that docs/configuration.md matches exactly the output of generate_configuration_docs()."""
    docs_path = Path("docs/configuration.md")
    assert docs_path.is_file(), "docs/configuration.md file must exist"

    expected_content = generate_configuration_docs()
    actual_content = docs_path.read_text(encoding="utf-8")

    assert actual_content.strip() == expected_content.strip(), (
        "docs/configuration.md is out of sync with CONFIG_REGISTRY. Run generate_configuration_docs() to update."
    )
