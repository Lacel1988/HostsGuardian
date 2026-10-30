from ipaddress import ip_address
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HG_AI_", extra="forbid", hide_input_in_errors=True)
    host: str = "127.0.0.1"
    port: int = Field(default=8001, ge=1024, le=65535)
    provider: Literal["ollama", "mock"] = "ollama"
    ollama_endpoint: str = "http://127.0.0.1:11434"
    model: str = Field(default="llama3.2:3b", min_length=1, max_length=128)
    request_timeout: float = Field(default=10, gt=0, le=120)
    max_concurrent_investigations: int = Field(default=2, ge=1, le=16)
    max_tool_calls: int = Field(default=4, ge=1, le=4)
    max_retry_rounds: int = Field(default=0, ge=0, le=2)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    retrieval_index: Path | None = None
    embedding_model_path: Path | None = None
    retrieval_corpus_version: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    retrieval_rrf_constant: int = Field(default=60, ge=1, le=1000)
    retrieval_min_similarity: float = Field(default=0.35, ge=-1, le=1)
    workflow_timeout: float = Field(default=90, gt=0, le=180)
    generation_timeout: float = Field(default=60, gt=0, le=120)
    workflow_step_limit: int = Field(default=16, ge=8, le=24)
    workflow_tool_limit: int = Field(default=6, ge=1, le=6)
    workflow_retry_limit: int = Field(default=1, ge=0, le=2)
    workflow_retrieval_k: int = Field(default=3, ge=1, le=5)
    generation_context_chars: int = Field(default=6000, ge=512, le=6000)
    generation_tokens: int = Field(default=256, ge=32, le=512)
    dns_log_retention_hours: int = Field(default=168, ge=1, le=8760)
    identity_log_retention_hours: int = Field(default=168, ge=1, le=8760)
    diagnostic_log_retention_hours: int = Field(default=168, ge=1, le=8760)
    ai_error_retention_hours: int = Field(default=48, ge=1, le=8760)
    retention_cleanup_seconds: float = Field(default=60, gt=0, le=3600)
    retention_max_file_bytes: int = Field(default=1048576, ge=4096, le=16777216)
    retention_max_total_bytes: int = Field(default=4194304, ge=16384, le=67108864)
    retention_max_events: int = Field(default=2000, ge=1, le=100000)
    engine_live_enabled: bool = False
    engine_origin: str | None = None
    engine_certificate_file: Path | None = None
    engine_certificate_sha256: str | None = Field(default=None,pattern=r"^[a-fA-F0-9]{64}$")
    engine_token_file: Path | None = None
    engine_token_format: Literal["hex", "dpapi-current-user"] = "hex"
    ai_client_token_file: Path | None = None
    engine_timeout: float = Field(default=3,gt=0,le=10)
    engine_max_age_seconds: int = Field(default=60,ge=1,le=300)

    @model_validator(mode="after")
    def live_boundary(self):
        if self.engine_live_enabled:
            if not all((self.engine_origin,self.engine_certificate_file,self.engine_certificate_sha256,self.engine_token_file,self.ai_client_token_file)):
                raise ValueError("Live integration requires explicit origin, enrolled certificate and separate credentials")
            from .engine import EngineConfig
            EngineConfig(origin=self.engine_origin,certificate_file=self.engine_certificate_file,
                certificate_sha256=self.engine_certificate_sha256,token_file=self.engine_token_file,token_format=self.engine_token_format,
                timeout=self.engine_timeout,max_age_seconds=self.engine_max_age_seconds)
        return self

    @field_validator("model")
    @classmethod
    def local_model_identifier(cls, value):
        if "://" in value or "cloud" in value.casefold() or not value.strip():
            raise ValueError("Only local model identifiers are permitted")
        return value

    @field_validator("host")
    @classmethod
    def local_host(cls, value: str) -> str:
        if not ip_address(value).is_loopback:
            raise ValueError("Only literal loopback bind addresses are permitted")
        return value

    @field_validator("ollama_endpoint")
    @classmethod
    def local_endpoint(cls, value: str) -> str:
        url = urlsplit(value)
        if (url.scheme != "http" or not url.hostname or
                not ip_address(url.hostname).is_loopback or url.username or
                url.password or url.query or url.fragment or url.path not in ("", "/")):
            raise ValueError("Ollama requires a credential-free literal loopback HTTP origin")
        if url.port is not None and not 1 <= url.port <= 65535:
            raise ValueError("Invalid Ollama port")
        return value.rstrip("/")
