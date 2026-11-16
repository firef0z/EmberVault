"""Unit tests for deploy/scripts/healthcheck.py."""

import sys
from unittest.mock import MagicMock, patch

from deploy.scripts.healthcheck import check_health, main


def test_check_health_success() -> None:
    """Test check_health returning True on HTTP 200 response."""
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        assert check_health("http://127.0.0.1:8080/healthz") is True


def test_check_health_failure_status_code() -> None:
    """Test check_health returning False on non-200 HTTP response."""
    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 503
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        assert check_health("http://127.0.0.1:8080/healthz") is False


def test_main_cli_execution(monkeypatch: MagicMock) -> None:
    """Test main() CLI execution with argument parsing."""
    monkeypatch.setattr(sys, "argv", ["healthcheck.py", "--service", "app", "--type", "readyz"])
    with patch("deploy.scripts.healthcheck.check_health", return_value=True):
        exit_code = main()
        assert exit_code == 0

    with patch("deploy.scripts.healthcheck.check_health", return_value=False):
        exit_code = main()
        assert exit_code == 1
