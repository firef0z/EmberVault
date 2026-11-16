"""Smoke tests verifying that packages and services are importable."""

import sys


def test_import_common() -> None:
    import embervault_common

    assert hasattr(embervault_common, "__version__")
    assert embervault_common.__version__ == "1.0.0"


def test_import_db() -> None:
    import embervault_db

    assert hasattr(embervault_db, "__version__")
    assert embervault_db.__version__ == "1.0.0"


def test_import_app() -> None:
    import embervault_app

    assert hasattr(embervault_app, "__version__")
    assert embervault_app.__version__ == "1.0.0"


def test_import_orchestrator() -> None:
    import embervault_orchestrator

    assert hasattr(embervault_orchestrator, "__version__")
    assert embervault_orchestrator.__version__ == "1.0.0"


def test_import_proxy() -> None:
    import embervault_proxy

    assert hasattr(embervault_proxy, "__version__")
    assert embervault_proxy.__version__ == "1.0.0"


def test_import_portal() -> None:
    import embervault_portal

    assert hasattr(embervault_portal, "__version__")
    assert embervault_portal.__version__ == "1.0.0"


def test_proxy_has_no_db_dependency() -> None:
    """Ensure proxy package does not load SQLAlchemy or DB package."""
    # Ensure fresh check
    to_delete = [
        k
        for k in sys.modules
        if k.startswith("embervault_proxy")
        or k.startswith("embervault_db")
        or k.startswith("sqlalchemy")
    ]
    for k in to_delete:
        del sys.modules[k]

    import embervault_proxy  # noqa: F401

    assert "embervault_db" not in sys.modules, "embervault_proxy must not import embervault_db"
    assert "sqlalchemy" not in sys.modules, "embervault_proxy must not import sqlalchemy"


def test_proxy_imports_without_requests(monkeypatch) -> None:
    """Ensure embervault_proxy and embervault_common.security can be imported even when requests is not installed."""
    to_delete = [
        k
        for k in sys.modules
        if k.startswith("embervault_proxy")
        or k.startswith("embervault_common.security")
        or k == "requests"
    ]
    for k in to_delete:
        del sys.modules[k]

    # Simulates 'requests' not installed
    monkeypatch.setitem(sys.modules, "requests", None)

    import embervault_common.security  # noqa: F401
    import embervault_common.security.oidc  # noqa: F401
    import embervault_proxy  # noqa: F401
    from embervault_proxy.factory import create_proxy_app  # noqa: F401
