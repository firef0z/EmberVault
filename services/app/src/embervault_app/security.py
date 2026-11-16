"""Security middleware, Content-Security-Policy with cryptographic nonce, and CSRF protection."""

from __future__ import annotations

import secrets
from typing import Any

from flask import Flask, Response, g
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()


def init_security(app: Flask) -> None:
    """Initialize security middleware, headers, CSP nonces, and CSRF protection."""
    # Initialize CSRF protection
    csrf.init_app(app)

    @app.before_request
    def resolve_trusted_proxy_client_ip() -> None:
        """Resolve client IP from X-Forwarded-For if request came from a trusted reverse proxy."""
        import ipaddress

        from flask import current_app, request

        store = current_app.config.get("SETTINGS_STORE")
        trusted_proxies_str = ""
        if store:
            try:
                trusted_proxies_str = str(store.get_setting("trusted_proxies") or "").strip()
            except Exception:
                trusted_proxies_str = ""

        if not trusted_proxies_str:
            # Also check app settings fallback if not in store
            app_settings = current_app.config.get("SETTINGS")
            trusted_proxies_str = getattr(app_settings, "trusted_proxies", "") or ""

        if not trusted_proxies_str:
            return

        # Parse trusted proxy networks
        trusted_networks = []
        for raw_net in trusted_proxies_str.split(","):
            net_str = raw_net.strip()
            if not net_str:
                continue
            try:
                trusted_networks.append(ipaddress.ip_network(net_str, strict=False))
            except ValueError:
                continue

        if not trusted_networks:
            return

        def is_trusted(ip_str: str) -> bool:
            try:
                addr = ipaddress.ip_address(ip_str.strip())
                return any(addr in net for net in trusted_networks)
            except ValueError:
                return False

        # Verify immediate peer (REMOTE_ADDR)
        remote_ip = (request.environ.get("REMOTE_ADDR") or request.remote_addr or "").strip()
        if not remote_ip or not is_trusted(remote_ip):
            return

        # Inspect X-Forwarded-For header
        xff = request.headers.get("X-Forwarded-For", "").strip()
        if not xff:
            return

        # Walk backwards through proxies: rightmost is closest to us
        hops = [h.strip() for h in xff.split(",") if h.strip()]
        client_ip = remote_ip
        for hop in reversed(hops):
            if is_trusted(hop):
                continue
            client_ip = hop
            break
        else:
            if hops:
                client_ip = hops[0]

        # Override remote_addr in environ and flask request instance
        request.environ["REMOTE_ADDR"] = client_ip
        try:
            request.remote_addr = client_ip
        except Exception:
            pass

    @app.before_request
    def generate_csp_nonce() -> None:
        """Generate a cryptographically secure nonce for this request's CSP header."""
        g.csp_nonce = secrets.token_hex(16)

    @app.after_request
    def set_security_headers(response: Response) -> Response:
        """Apply strict security and Content-Security-Policy headers to every response."""
        nonce = getattr(g, "csp_nonce", "")

        # Strict Content-Security-Policy with nonce
        csp_directives = [
            "default-src 'self'",
            f"script-src 'self' 'nonce-{nonce}'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-ancestors 'none'",
            "base-uri 'self'",
            "form-action 'self'",
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        return response

    @app.context_processor
    def inject_security_context() -> dict[str, Any]:
        """Inject CSP nonce and CSRF helper into Jinja templates."""
        return {
            "csp_nonce": getattr(g, "csp_nonce", ""),
        }
