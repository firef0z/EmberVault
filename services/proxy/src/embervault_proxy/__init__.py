"""EmberVault Proxy worker service."""

from embervault_proxy.factory import create_proxy_app

__version__ = "1.0.0"
__all__ = ["create_proxy_app"]
