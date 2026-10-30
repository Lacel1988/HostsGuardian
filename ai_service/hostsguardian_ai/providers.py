import asyncio
from typing import Literal, Protocol

import httpx
from pydantic import Field, ValidationError

from .config import Settings
from .schemas import Contract, Outcome


class ModelRequest(Contract):
    prompt: str = Field(min_length=1, max_length=8192)
    max_tokens: int = Field(default=512, ge=32, le=512)
    structured: bool = False
    output_schema: dict | None = None


class ModelResponse(Contract):
    provider: str
    outcome: Outcome
    text: str | None = Field(default=None, max_length=32768)
    finish_reason: Literal["stop", "length"] | None = None


class ModelProvider(Protocol):
    identifier: str
    async def availability(self) -> Outcome: ...
    async def generate(self, request: ModelRequest) -> ModelResponse: ...


class MockProvider:
    identifier = "mock"

    async def availability(self) -> Outcome:
        return Outcome.SUCCESS

    async def generate(self, request: ModelRequest) -> ModelResponse:
        return ModelResponse(provider=self.identifier, outcome=Outcome.SUCCESS, text="Fixture response")


class OllamaProvider:
    identifier = "ollama"

    def __init__(self, settings: Settings, transport=None):
        self.settings = settings
        self.transport = transport

    async def _request(self, method: str, path: str, payload=None, timeout=None):
        # Absolute deadline covers total transfer, not just individual socket operations.
        deadline = timeout or self.settings.request_timeout
        async with asyncio.timeout(deadline):
            async with httpx.AsyncClient(timeout=deadline,
                                        trust_env=False, follow_redirects=False,
                                        transport=self.transport) as client:
                async with client.stream(method, self.settings.ollama_endpoint + path, json=payload) as response:
                    response.raise_for_status()
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 262144:
                            raise ValueError("Response too large")
                    import json
                    return json.loads(body)

    async def availability(self) -> Outcome:
        try:
            data = await self._request("GET", "/api/tags")
            models = data["models"]
            if not isinstance(models, list) or any(not isinstance(m, dict) or not isinstance(m.get("name"), str) for m in models):
                return Outcome.INVALID
            return Outcome.SUCCESS if any(m["name"] == self.settings.model and not m.get("remote_host")
                                          and not m.get("remote_model") for m in models) else Outcome.UNAVAILABLE
        except (TimeoutError, httpx.TimeoutException):
            return Outcome.TIMEOUT
        except httpx.HTTPError:
            return Outcome.UNAVAILABLE
        except (ValueError, KeyError, TypeError):
            return Outcome.INVALID

    async def generate(self, request: ModelRequest) -> ModelResponse:
        try:
            payload = {
                "model": self.settings.model, "prompt": request.prompt, "stream": False,
                "options": {"num_predict": request.max_tokens, "num_ctx": 4096, "temperature": 0, "seed": 0,
                            "num_gpu": 0, "num_thread": 4},
            }
            if request.structured:
                payload["format"] = request.output_schema or "json"
                payload["think"] = False
            data = await self._request("POST", "/api/generate", payload, timeout=self.settings.generation_timeout)
            if not isinstance(data.get("response"), str) or data.get("done") is not True:
                raise ValueError("Invalid model response")
            finish_reason = data.get("done_reason") if data.get("done_reason") in ("stop", "length") else None
            return ModelResponse(provider=self.identifier, outcome=Outcome.INVALID if request.structured and finish_reason == "length" else Outcome.SUCCESS,
                                 text=data["response"], finish_reason=finish_reason)
        except (TimeoutError, httpx.TimeoutException):
            outcome = Outcome.TIMEOUT
        except httpx.HTTPError:
            outcome = Outcome.UNAVAILABLE
        except (ValueError, KeyError, TypeError, AttributeError, ValidationError):
            outcome = Outcome.INVALID
        return ModelResponse(provider=self.identifier, outcome=outcome)
