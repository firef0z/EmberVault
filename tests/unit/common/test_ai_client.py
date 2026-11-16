"""Unit tests for AIClient in embervault_common.ai.client."""

import json
from unittest.mock import MagicMock, patch

from embervault_common.ai.client import AIClient, AIConnectionError, AIResponseError


def test_openai_compatible_chat_completion_success() -> None:
    client = AIClient(
        endpoint_url="http://localhost:11434",
        model="llama3.2",
        provider_type="openai_compatible",
        api_key="test-key",
    )

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_payload = {
        "model": "llama3.2",
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": '{"decision": "retry", "reason": "transient network glitch"}',
                }
            }
        ],
        "usage": {"prompt_tokens": 50, "completion_tokens": 15},
    }
    mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        resp = client.chat_completion(
            system_prompt="You are an error analyzer",
            user_prompt="Analyze error: timeout",
        )

        assert '{"decision": "retry"' in resp.raw_content
        assert resp.prompt_tokens == 50
        assert resp.completion_tokens == 15
        assert resp.model == "llama3.2"

        # Check request sent
        req_arg = mock_urlopen.call_args[0][0]
        assert req_arg.full_url == "http://localhost:11434/v1/chat/completions"
        assert req_arg.headers.get("Authorization") == "Bearer test-key"


def test_ollama_chat_completion_success() -> None:
    client = AIClient(
        endpoint_url="http://ollama-host:11434",
        model="mistral",
        provider_type="ollama",
    )

    mock_resp = MagicMock()
    mock_resp.getcode.return_value = 200
    mock_payload = {
        "model": "mistral",
        "message": {
            "role": "assistant",
            "content": '{"decision": "fail", "reason": "file corrupt"}',
        },
        "prompt_eval_count": 42,
        "eval_count": 12,
    }
    mock_resp.read.return_value = json.dumps(mock_payload).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        resp = client.chat_completion(
            system_prompt="System prompt",
            user_prompt="User prompt",
        )

        assert '{"decision": "fail"' in resp.raw_content
        assert resp.prompt_tokens == 42
        assert resp.completion_tokens == 12

        req_arg = mock_urlopen.call_args[0][0]
        assert req_arg.full_url == "http://ollama-host:11434/api/chat"


def test_test_connection_success_and_failure() -> None:
    client = AIClient(endpoint_url="http://localhost:11434", model="llama3.2")

    # Success case
    with patch.object(
        client,
        "chat_completion",
        return_value=MagicMock(raw_content="OK", latency_ms=120.0),
    ):
        ok, msg = client.test_connection()
        assert ok is True
        assert "Connessione riuscita" in msg

    # Failure case
    with patch.object(
        client,
        "chat_completion",
        side_effect=AIConnectionError("Connection refused"),
    ):
        ok, msg = client.test_connection()
        assert ok is False
        assert "Test di connessione fallito" in msg
