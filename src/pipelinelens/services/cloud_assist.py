"""Optional, strictly opt-in cloud fallback used only when the local cause is unknown.

This module is provider-pluggable: the API and dashboard never call Gemini directly.
They call only :func:`resolve_cloud_assist_provider`, which returns whichever registered
:class:`CloudAssistProvider` matches ``PIPELINELENS_LLM_MODE`` and is configured. Gemini is
shipped as the default provider; a future backend (Amazon Q, Glean, a fine-tuned in-house RAG
model, ...) can be added later with :func:`register_cloud_assist_provider` and zero changes to
the API or dashboard.

A call happens only when ALL of the following hold:
  - the caller (the local API) explicitly requests it for this one analysis
    (``ask_cloud_ai=True`` on the request), and
  - a provider is registered for ``PIPELINELENS_LLM_MODE`` and reports itself configured
    (for the built-in Gemini provider: an API key is set).

Only the already-redacted title/category/evidence text of ONE finding is ever sent to any
provider -- never raw logs, never source code, never credentials, never the full inspection
result, never the repository/project identity. The response is treated purely as an unverified
opinion: it is never merged into the deterministic finding, never changes a confidence score,
and never becomes a source-patch proposal.

Every provider must fail closed: a network error, bad status, malformed body, or timeout must
return ``None``, never raise. A broken or misconfigured cloud assist must never break the
primary, fully local diagnosis.
"""

from __future__ import annotations

import re
from typing import Protocol, runtime_checkable

import httpx
from pydantic import BaseModel, ConfigDict, field_validator

from pipelinelens.config import Settings
from pipelinelens.services.findings import Finding
from pipelinelens.services.redaction import redact_text

GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-2.0-flash"
MAX_EVIDENCE_ITEMS = 3
MAX_EVIDENCE_CHARS = 800
MAX_PROMPT_CHARS = 6_000
MAX_SUMMARY_CHARS = 1_200
TIMEOUT_SECONDS = 20.0
CLOUD_ASSIST_NOTICE = (
    "Unverified cloud opinion, generated from redacted evidence only. This is separate "
    "from the local deterministic diagnosis; review independently before acting on it."
)
_PROVIDER_NAME = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")

__all__ = (
    "CloudAssistProvider",
    "CloudAssistResult",
    "GEMINI_PROVIDER",
    "GeminiCloudAssistProvider",
    "cloud_assist_configured",
    "list_cloud_assist_providers",
    "register_cloud_assist_provider",
    "request_gemini_explanation",
    "resolve_cloud_assist_provider",
)


class CloudAssistResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: str
    model: str
    summary: str
    notice: str = CLOUD_ASSIST_NOTICE

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, value: str) -> str:
        if not isinstance(value, str) or not _PROVIDER_NAME.fullmatch(value):
            raise ValueError(
                "provider must be 1-40 lowercase letters, digits or hyphens, starting "
                "with a letter."
            )
        return value


@runtime_checkable
class CloudAssistProvider(Protocol):
    """Contract any future cloud/RAG backend must satisfy to plug into cloud assist.

    Implement this for Amazon Q, Glean, or an in-house fine-tuned model, then register
    it with :func:`register_cloud_assist_provider`. The API and dashboard never import a
    concrete provider; they call only through this interface and ``resolve_cloud_assist_provider``.
    """

    name: str

    def configured(self, settings: Settings) -> bool:
        """True only when this provider has everything it needs. No I/O, no key logged."""
        ...

    async def ask(
        self, settings: Settings, finding: Finding, *, client: httpx.AsyncClient | None = None,
    ) -> CloudAssistResult | None:
        """Best-effort, fail-closed: return ``None`` on any error; never raise."""
        ...


def _prompt(finding: Finding) -> str:
    evidence = "\n".join(
        redact_text(item.text)[:MAX_EVIDENCE_CHARS]
        for item in finding.evidence[:MAX_EVIDENCE_ITEMS]
    )
    text = (
        "You are assisting with a CI/CD pipeline failure whose automated cause is "
        "unknown. Suggest the most likely category of problem and one or two concrete, "
        "safe checks a developer could run next. Do not invent file names, line "
        "numbers, or commands that are not supported by the evidence below. Keep the "
        "answer under 120 words and never include or ask for secrets.\n\n"
        f"Rule: {finding.rule_id}\nTitle: {redact_text(finding.title)}\n"
        f"Category: {finding.category}\nEvidence (already redacted):\n{evidence}"
    )
    return text[:MAX_PROMPT_CHARS]


class GeminiCloudAssistProvider:
    """Google Gemini implementation of :class:`CloudAssistProvider`; the shipped default."""

    name = "gemini"

    def configured(self, settings: Settings) -> bool:
        """True only when Gemini mode is selected locally and a key is configured.

        Reading this does not make a network call and never logs or returns the key.
        """
        return settings.llm_mode.strip().lower() == self.name and bool(settings.llm_api_key)

    async def ask(
        self, settings: Settings, finding: Finding, *, client: httpx.AsyncClient | None = None,
    ) -> CloudAssistResult | None:
        """Ask Gemini to expand on one unresolved finding. Best-effort; never raises.

        Returns ``None`` for every failure mode (not configured, network error, bad
        status, malformed body) so a broken cloud assist never breaks the local result.
        ``client`` is a trusted test-only injection point; production always builds its
        own short-lived client with redirects disabled and a bounded timeout.
        """
        if not self.configured(settings):
            return None
        model = (settings.llm_model or DEFAULT_MODEL).strip() or DEFAULT_MODEL
        url = f"{GEMINI_API_BASE}/models/{model}:generateContent"
        payload = {
            "contents": [{"parts": [{"text": _prompt(finding)}]}],
            "generationConfig": {"temperature": 0.2, "maxOutputTokens": 300},
        }
        headers = {
            "x-goog-api-key": settings.llm_api_key or "", "Content-Type": "application/json",
        }
        try:
            if client is not None:
                response = await client.post(url, headers=headers, json=payload)
            else:
                async with httpx.AsyncClient(
                    timeout=TIMEOUT_SECONDS, trust_env=False, follow_redirects=False,
                ) as owned_client:
                    response = await owned_client.post(url, headers=headers, json=payload)
            if response.status_code != 200:
                return None
            body = response.json()
            candidates = body.get("candidates")
            if not isinstance(candidates, list) or not candidates:
                return None
            content = candidates[0].get("content") if isinstance(candidates[0], dict) else None
            parts = content.get("parts") if isinstance(content, dict) else None
            if not isinstance(parts, list) or not parts or not isinstance(parts[0], dict):
                return None
            text = parts[0].get("text")
            if not isinstance(text, str) or not text.strip():
                return None
            return CloudAssistResult(
                provider=self.name, model=model,
                summary=redact_text(text.strip())[:MAX_SUMMARY_CHARS],
            )
        except (httpx.HTTPError, ValueError, KeyError, TypeError, AttributeError):
            return None


GEMINI_PROVIDER = GeminiCloudAssistProvider()
_PROVIDERS: dict[str, CloudAssistProvider] = {GEMINI_PROVIDER.name: GEMINI_PROVIDER}


def register_cloud_assist_provider(name: str, provider: CloudAssistProvider) -> None:
    """Plug in a future cloud/RAG backend (Amazon Q, Glean, ...) with no API/UI changes.

    ``name`` must match the value you will set in ``PIPELINELENS_LLM_MODE``. This only adds
    a local, in-process registry entry; it makes no network call and stores no credentials.
    """
    if not isinstance(name, str) or not _PROVIDER_NAME.fullmatch(name):
        raise ValueError(
            "Provider name must be 1-40 lowercase letters, digits or hyphens, starting "
            "with a letter (e.g. 'amazon-q', 'glean')."
        )
    if not isinstance(provider, CloudAssistProvider):
        raise TypeError("Provider must implement name/configured()/async ask().")
    _PROVIDERS[name] = provider


def list_cloud_assist_providers() -> tuple[str, ...]:
    """Names of every registered provider, configured or not. No secrets, no I/O."""
    return tuple(sorted(_PROVIDERS))


def resolve_cloud_assist_provider(settings: Settings) -> CloudAssistProvider | None:
    """The one registered provider matching ``PIPELINELENS_LLM_MODE``, only if configured.

    Returns ``None`` for ``disabled``, an unrecognized mode, or a recognized-but-unconfigured
    provider. The API and dashboard call only this resolver, so a future provider registered
    with :func:`register_cloud_assist_provider` needs no other code change to become usable.
    """
    provider = _PROVIDERS.get(settings.llm_mode.strip().lower())
    return provider if provider is not None and provider.configured(settings) else None


def cloud_assist_configured(settings: Settings) -> bool:
    """Back-compat convenience: True only when the built-in Gemini provider is configured."""
    return GEMINI_PROVIDER.configured(settings)


async def request_gemini_explanation(
    settings: Settings,
    finding: Finding,
    *,
    client: httpx.AsyncClient | None = None,
) -> CloudAssistResult | None:
    """Back-compat convenience: ask the built-in Gemini provider specifically. Never raises."""
    return await GEMINI_PROVIDER.ask(settings, finding, client=client)