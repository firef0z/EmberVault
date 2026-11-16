"""Architecture and import-linter tests."""

from pathlib import Path

from importlinter.cli import lint_imports


def test_import_linter_passes() -> None:
    """Verify that current codebase adheres to all import-linter contracts."""
    exit_code = lint_imports(no_cache=True)
    assert exit_code == 0, "Expected import-linter to pass on clean codebase"


def test_import_linter_fails_on_boundary_violation() -> None:
    """Verify that import-linter fails if proxy illegally imports from embervault_db."""
    proxy_init = Path("services/proxy/src/embervault_proxy/__init__.py")
    original_content = proxy_init.read_text(encoding="utf-8")

    try:
        # Inject an illegal import violating the proxy-isolation contract
        violation_content = original_content + "\nimport embervault_db  # type: ignore\n"
        proxy_init.write_text(violation_content, encoding="utf-8")

        exit_code = lint_imports(no_cache=True)
        assert exit_code != 0, "Expected import-linter to fail when proxy imports embervault_db"
    finally:
        # Restore clean state
        proxy_init.write_text(original_content, encoding="utf-8")
