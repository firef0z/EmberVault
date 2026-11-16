#!/usr/bin/env python3
"""Standard Docker container healthcheck script for EmberVault services.

Uses Python standard library (no extra dependencies required).
Returns exit code 0 if healthy, 1 on failure.
"""

from __future__ import annotations

import argparse
import ssl
import sys
import urllib.error
import urllib.request

DEFAULT_PORTS = {
    "app": 8080,
    "orchestrator": 8081,
    "proxy": 8443,
    "hook-runner": 8082,
    "portal": 8083,
}


def check_health(
    url: str,
    timeout: float = 5.0,
    insecure: bool = False,
) -> bool:
    """Perform HTTP/HTTPS GET request to check endpoint health."""
    context = None
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "EmberVault-Healthcheck/1.0"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            status = response.getcode()
            if status == 200:
                return True
            sys.stderr.write(f"Healthcheck failed: received HTTP {status}\n")
            return False
    except urllib.error.HTTPError as e:
        sys.stderr.write(f"Healthcheck failed with HTTP error: {e.code} {e.reason}\n")
        return False
    except urllib.error.URLError as e:
        sys.stderr.write(f"Healthcheck failed to connect: {e.reason}\n")
        return False
    except Exception as e:
        sys.stderr.write(f"Healthcheck unexpected error: {e}\n")
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description="EmberVault Docker healthcheck utility")
    parser.add_argument(
        "--url",
        type=str,
        default=None,
        help="Full URL to query (e.g. http://127.0.0.1:8080/healthz)",
    )
    parser.add_argument(
        "--service",
        choices=["app", "orchestrator", "proxy", "hook-runner", "portal"],
        default="app",
        help="Target service name",
    )
    parser.add_argument(
        "--type",
        choices=["healthz", "readyz"],
        default="healthz",
        help="Endpoint check type",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Override service port",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable SSL/TLS certificate verification (used for self-signed proxy certificates)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds",
    )

    args = parser.parse_args()

    if args.url:
        target_url = args.url
    else:
        port = args.port or DEFAULT_PORTS.get(args.service, 8080)
        protocol = "https" if args.service == "proxy" else "http"
        target_url = f"{protocol}://127.0.0.1:{port}/{args.type}"

    # Auto-enable insecure for proxy https checks if not specified
    insecure = args.insecure or (args.service == "proxy")

    healthy = check_health(
        url=target_url,
        timeout=args.timeout,
        insecure=insecure,
    )
    return 0 if healthy else 1


if __name__ == "__main__":
    sys.exit(main())
