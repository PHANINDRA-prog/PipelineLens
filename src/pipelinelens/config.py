"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(_PROJECT_ROOT / ".env", override=False)


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True, slots=True)
class Settings:
    environment: str
    database_url: str
    redis_url: str
    max_log_bytes: int
    max_context_chars: int
    llm_mode: str
    llm_base_url: str
    llm_model: str
    llm_api_key: str | None = field(repr=False)
    allow_private_context: bool
    configured_gitlab_token: str | None = field(default=None, repr=False)
    configured_gitlab_base_url: str = "https://gitlab.com"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        environment=os.getenv("PIPELINELENS_ENV", "development"),
        database_url=os.getenv("PIPELINELENS_DATABASE_URL", "sqlite:///./data/pipelinelens.db"),
        redis_url=os.getenv("PIPELINELENS_REDIS_URL", "redis://localhost:6379/0"),
        max_log_bytes=int(os.getenv("PIPELINELENS_MAX_LOG_BYTES", "500000")),
        max_context_chars=int(os.getenv("PIPELINELENS_MAX_CONTEXT_CHARS", "18000")),
        llm_mode=os.getenv("PIPELINELENS_LLM_MODE", "disabled").strip().lower(),
        llm_base_url=os.getenv("PIPELINELENS_LLM_BASE_URL", "https://api.openai.com/v1").rstrip(
            "/"
        ),
        llm_model=os.getenv("PIPELINELENS_LLM_MODEL", "gpt-4.1-mini"),
        llm_api_key=os.getenv("PIPELINELENS_LLM_API_KEY") or None,
        allow_private_context=_as_bool(os.getenv("PIPELINELENS_ALLOW_PRIVATE_CONTEXT")),
        configured_gitlab_token=os.getenv("PIPELINELENS_GITLAB_TOKEN") or None,
        configured_gitlab_base_url=os.getenv(
            "PIPELINELENS_GITLAB_BASE_URL", "https://gitlab.com"
        ).rstrip("/"),
    )
