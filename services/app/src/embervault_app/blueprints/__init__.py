"""Blueprints package for EmberVault Web Application."""

from embervault_app.blueprints.api import api_bp
from embervault_app.blueprints.ui import ui_bp

__all__ = ["api_bp", "ui_bp"]
