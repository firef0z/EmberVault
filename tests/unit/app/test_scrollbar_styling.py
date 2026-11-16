"""Unit tests verifying scrollbar styling across all application themes and modes."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask.testing import FlaskClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from embervault_app.factory import create_app
from embervault_common.config import AppSettings
from embervault_common.security.crypto import KeyRing, set_default_key_ring
from embervault_db.models import Base
from embervault_db.seed import seed_initial_data


def test_app_css_contains_all_themes_scrollbar_definitions() -> None:
    """Verify that app.css defines scrollbar variables and rules for all 5 themes in both light and dark modes."""
    css_path = Path(__file__).resolve().parents[3] / "services" / "app" / "src" / "embervault_app" / "static" / "css" / "app.css"
    assert css_path.exists(), f"app.css not found at {css_path}"
    content = css_path.read_text(encoding="utf-8")

    # 1. Default EmberVault theme (Dark & Light)
    assert "--scrollbar-track: rgba(13, 17, 23, 0.7);" in content
    assert "--scrollbar-thumb: #30363d;" in content
    assert "--scrollbar-thumb-hover: #ff7a00;" in content
    assert "--scrollbar-thumb: #cbd5e1;" in content

    # 2. Theeame (Light & Dark)
    assert "/* Scrollbar Theme Variables (Theeame Light) */" in content
    assert "/* Scrollbar Theme Variables (Theeame Dark) */" in content
    assert "--scrollbar-thumb-hover: #00b336;" in content

    # 3. AcroVault (Light & Dark)
    assert "/* Scrollbar Theme Variables (AcroVault Light) */" in content
    assert "/* Scrollbar Theme Variables (AcroVault Dark) */" in content
    assert "--scrollbar-track: #e8eff7;" in content
    assert "--scrollbar-thumb: #a9bcd4;" in content
    assert "--scrollbar-track: #07111e;" in content
    assert "--scrollbar-thumb: #1b375b;" in content

    # 4. EmberXP (Light & Dark)
    assert "/* Scrollbar Theme Variables (EmberXP Luna Light) */" in content
    assert "/* Scrollbar Theme Variables (EmberXP Dark) */" in content
    assert 'html[data-color-theme="emberxp"] ::-webkit-scrollbar-thumb:horizontal' in content
    assert 'html[data-color-theme="emberxp"]:not([data-theme="light"]) ::-webkit-scrollbar-thumb:horizontal' in content

    # 5. iEmberVault (Light & Dark)
    assert "/* Scrollbar Theme Variables (iEmberVault Aqua Light) */" in content
    assert "/* Scrollbar Theme Variables (iEmberVault Graphite Dark) */" in content
    assert 'html[data-color-theme="iembervault"] ::-webkit-scrollbar-thumb:horizontal' in content
    assert 'html[data-color-theme="iembervault"]:not([data-theme="light"]) ::-webkit-scrollbar-thumb:horizontal' in content

    # 6. Universal and Horizontal Component Rules
    assert "scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);" in content
    assert ".job-tabs-nav" in content
    assert ".proxy-tabs-nav" in content
    assert ".table-responsive" in content


def test_job_edit_template_scrollbar_styling() -> None:
    """Verify that job_edit.html defines custom horizontal scrollbar styles for tabs navigation."""
    tmpl_path = Path(__file__).resolve().parents[3] / "services" / "app" / "src" / "embervault_app" / "templates" / "job_edit.html"
    assert tmpl_path.exists()
    tmpl_content = tmpl_path.read_text(encoding="utf-8")

    assert ".job-tabs-nav" in tmpl_content
    assert "overflow-x: auto;" in tmpl_content
    assert "scrollbar-width: thin;" in tmpl_content
    assert "scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);" in tmpl_content
    assert ".job-tabs-nav::-webkit-scrollbar" in tmpl_content
    assert ".job-tabs-nav::-webkit-scrollbar-thumb" in tmpl_content
    assert '[data-theme="light"] .job-tabs-nav' in tmpl_content


def test_job_new_ui_renders_scrollbar_styles() -> None:
    """Verify that rendering /jobs/new outputs the styled tab navigation."""
    set_default_key_ring(KeyRing(keys={"v1": "test_app_key_32_chars_minimum__"}))
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)

    with session_factory() as session:
        seed_initial_data(session)

    settings = AppSettings(app_port=8080, dev_noauth=True)
    app = create_app(settings=settings, session_factory=session_factory)
    app.config["TESTING"] = True

    client = app.test_client()
    res = client.get("/jobs/new")
    assert res.status_code == 200
    html = res.get_data(as_text=True)

    assert "job-tabs-nav" in html
    assert "scrollbar-color: var(--scrollbar-thumb) var(--scrollbar-track);" in html
    assert "tab-name-coords" in html
