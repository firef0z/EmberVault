"""AI Client supporting OpenAI-compatible and Ollama endpoints."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from pydantic import SecretStr

from embervault_common.observability import get_logger

logger = get_logger("embervault_common.ai.client")


class AIClientError(Exception):
    """Base exception for AI Client failures."""


class AIConnectionError(AIClientError):
    """Raised when connection to AI endpoint fails."""


class AIResponseError(AIClientError):
    """Raised when AI response is invalid or returns HTTP error status."""


@dataclass
class AIResponse:
    """Standardized response from AI chat completion."""

    raw_content: str
    model: str
    latency_ms: float
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    raw_response: dict[str, Any] | None = None


class AIClient:
    """Client for querying OpenAI-compatible and Ollama chat completion endpoints."""

    def __init__(
        self,
        endpoint_url: str,
        model: str,
        provider_type: str = "openai_compatible",
        api_key: str | SecretStr | None = None,
        timeout_seconds: int = 15,
    ) -> None:
        self.endpoint_url = endpoint_url.rstrip("/")
        self.model = model
        self.provider_type = provider_type.lower().strip()
        if isinstance(api_key, SecretStr):
            self.api_key = api_key.get_secret_value()
        else:
            self.api_key = api_key or ""
        self.timeout_seconds = max(1, timeout_seconds)

    def _get_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "EmberVault-AI/1.0",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _build_request_payload(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Return (target_url, payload_dict) based on provider_type."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        if self.provider_type == "ollama":
            url = f"{self.endpoint_url}/api/chat"
            options: dict[str, Any] = {"temperature": temperature}
            if max_tokens is not None:
                options["num_predict"] = max_tokens
            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": options,
            }
            return url, payload

        # Default: openai_compatible
        if self.endpoint_url.endswith("/v1"):
            url = f"{self.endpoint_url}/chat/completions"
        else:
            url = f"{self.endpoint_url}/v1/chat/completions"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        return url, payload

    def chat_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int | None = None,
    ) -> AIResponse:
        """Send chat completion request to the configured AI endpoint."""
        url, payload = self._build_request_payload(
            system_prompt, user_prompt, temperature, max_tokens=max_tokens
        )
        headers = self._get_headers()
        body_bytes = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
        start_time = time.perf_counter()

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                status_code = resp.getcode()
                response_body = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            err_body = ""
            try:
                err_body = exc.read().decode("utf-8")
            except Exception:
                pass

            # If Ollama native /api/chat returned 404, try openai-compatible endpoint
            if exc.code == 404 and self.provider_type == "ollama":
                try:
                    return self._fallback_openai_completion(
                        system_prompt, user_prompt, temperature, max_tokens=max_tokens
                    )
                except Exception as fb_exc:
                    raise AIResponseError(
                        f"AI endpoint error {exc.code}: {err_body or exc.reason} (fallback also failed: {fb_exc})"
                    ) from exc

            raise AIResponseError(
                f"AI endpoint HTTP error {exc.code}: {err_body or exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise AIConnectionError(
                f"Errore connessione endpoint IA ({url}): {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise AIConnectionError(
                f"Timeout ({self.timeout_seconds}s) durante la richiesta a {url}"
            ) from exc
        except Exception as exc:
            raise AIClientError(f"Errore imprevisto chiamata IA: {exc}") from exc

        latency_ms = (time.perf_counter() - start_time) * 1000.0

        try:
            data = json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise AIResponseError(
                f"Risposta non valida dall'endpoint IA (JSON non valido): {response_body[:200]}"
            ) from exc

        # Extract content based on format
        content = ""
        prompt_tokens = None
        completion_tokens = None

        if self.provider_type == "ollama" and "message" in data:
            content = data.get("message", {}).get("content", "")
            prompt_tokens = data.get("prompt_eval_count")
            completion_tokens = data.get("eval_count")
        elif "choices" in data and len(data["choices"]) > 0:
            content = data["choices"][0].get("message", {}).get("content", "")
            usage = data.get("usage", {})
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")
        else:
            # Fallback extraction
            content = data.get("content") or data.get("response") or str(data)

        return AIResponse(
            raw_content=content,
            model=data.get("model", self.model),
            latency_ms=round(latency_ms, 2),
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            raw_response=data,
        )

    def _fallback_openai_completion(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float,
        max_tokens: int | None = None,
    ) -> AIResponse:
        """Fallback to OpenAI-compatible endpoint when Ollama native path is not found."""
        url = f"{self.endpoint_url}/v1/chat/completions"
        headers = self._get_headers()
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens
        body_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=body_bytes, headers=headers, method="POST")
        start_time = time.perf_counter()

        with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
            response_body = resp.read().decode("utf-8")

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        data = json.loads(response_body)
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        usage = data.get("usage", {})
        return AIResponse(
            raw_content=content,
            model=data.get("model", self.model),
            latency_ms=round(latency_ms, 2),
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            raw_response=data,
        )

    def test_connection(self) -> tuple[bool, str]:
        """Test connection to the AI model and endpoint with a quick prompt.

        Returns:
            (success: bool, message: str)
        """
        try:
            resp = self.chat_completion(
                system_prompt="You are a ping test assistant. Reply strictly with: OK",
                user_prompt="Ping",
                temperature=0.0,
            )
            preview = resp.raw_content.strip().replace("\n", " ")[:80]
            return (
                True,
                f"Connessione riuscita al modello '{self.model}' ({resp.latency_ms:.0f}ms). Risposta: '{preview}'",
            )
        except Exception as exc:
            return False, f"Test di connessione fallito: {exc}"
