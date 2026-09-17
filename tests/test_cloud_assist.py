"""Offline regression coverage for the pluggable cloud-assist architecture.

No real network access. httpx.MockTransport intercepts every request; a stray
request to any other host fails the test instead of reaching a network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import pytest
from pydantic import ValidationError

from pipelinelens.config import Settings
from pipelinelens.services import cloud_assist
from pipelinelens.services.cloud_assist import (
    GEMINI_PROVIDER,
    CloudAssistProvider,
    CloudAssistResult,
    GeminiCloudAssistProvider,
    cloud_assist_configured,
    list_cloud_assist_providers,
    register_cloud_assist_provider,
    request_gemini_explanation,
    resolve_cloud_assist_provider,
)
from pipelinelens.services.findings import Finding, FindingEvidence

SECRET = "fixture-gemini-key-not-a-real-credential"


def _settings(**changes: object) -> Settings:
    base = dict(
        environment="test", database_url="sqlite://", redis_url="",
        max_log_bytes=1000, max_context_chars=0, llm_mode="disabled",
        llm_base_url="", llm_model="gemini-2.0-flash", llm_api_key=None,
        allow_private_context=False,
    )
    base.update(changes)
    return Settings(**base)


def _finding(**changes: object) -> Finding:
    base = dict(
        rule_id="job.insufficient_evidence", severity="warning", category="unknown",
        title="Cause not established", explanation="No specific diagnostic was found.",
        fix=["Inspect the complete trace."],
        evidence=[FindingEvidence(text="generic non-zero exit, token=" + SECRET)],
        confidence="unknown",
    )
    base.update(changes)
    return Finding(**base)


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def test_cloud_assist_configured_requires_gemini_mode_and_a_key() -> None:
    assert cloud_assist_configured(_settings(llm_mode="gemini", llm_api_key=SECRET)) is True
    assert cloud_assist_configured(_settings(llm_mode="gemini", llm_api_key=None)) is False
    assert cloud_assist_configured(_settings(llm_mode="disabled", llm_api_key=SECRET)) is False
    assert cloud_assist_configured(
        _settings(llm_mode="openai-compatible", llm_api_key=SECRET)
    ) is False


async def test_disabled_mode_never_makes_a_request() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("disabled mode must not make a request")

    result = await request_gemini_explanation(
        _settings(llm_mode="disabled"), _finding(), client=_client(handler),
    )
    assert result is None


async def test_successful_response_is_redacted_bounded_and_labelled() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-goog-api-key"] == SECRET
        assert request.url.path.endswith(":generateContent")
        assert "key=" not in str(request.url)
        body = request.content.decode()
        assert SECRET not in body  # The finding's own evidence secret must stay out.
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [
                {"text": f"Likely a flaky dependency. token={SECRET}"},
            ]}}],
        })

    settings = _settings(llm_mode="gemini", llm_api_key=SECRET)
    result = await request_gemini_explanation(settings, _finding(), client=_client(handler))

    assert isinstance(result, CloudAssistResult)
    assert result.provider == "gemini"
    assert result.model == "gemini-2.0-flash"
    assert SECRET not in result.summary
    assert "[REDACTED]" in result.summary
    assert "unverified" in result.notice.lower()


@pytest.mark.parametrize("status_code", [400, 401, 403, 429, 500, 503])
async def test_non_200_status_fails_closed_to_none(status_code: int) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json={"error": SECRET})

    result = await request_gemini_explanation(
        _settings(llm_mode="gemini", llm_api_key=SECRET), _finding(),
        client=_client(handler),
    )
    assert result is None


@pytest.mark.parametrize("body", [
    {},
    {"candidates": []},
    {"candidates": [{}]},
    {"candidates": [{"content": {}}]},
    {"candidates": [{"content": {"parts": []}}]},
    {"candidates": [{"content": {"parts": [{"text": ""}]}}]},
    {"candidates": [{"content": {"parts": [{"text": "   "}]}}]},
    {"candidates": [{"content": {"parts": [{"no_text": "oops"}]}}]},
    "not-a-json-object",
])
async def test_malformed_or_empty_response_fails_closed_to_none(body: object) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=body)

    result = await request_gemini_explanation(
        _settings(llm_mode="gemini", llm_api_key=SECRET), _finding(),
        client=_client(handler),
    )
    assert result is None


async def test_network_error_fails_closed_to_none() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("synthetic failure", request=request)

    result = await request_gemini_explanation(
        _settings(llm_mode="gemini", llm_api_key=SECRET), _finding(),
        client=_client(handler),
    )
    assert result is None


async def test_prompt_never_includes_the_evidence_secret_verbatim() -> None:
    captured: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode()
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": "ok"}]}}],
        })

    await request_gemini_explanation(
        _settings(llm_mode="gemini", llm_api_key=SECRET), _finding(),
        client=_client(handler),
    )
    assert SECRET not in captured["body"]
    assert "[REDACTED]" in captured["body"]


async def test_result_model_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        CloudAssistResult(provider="gemini", model="x", summary="y", extra_field="nope")


@pytest.mark.parametrize("name", ["amazon-q", "glean", "gemini", "x", "a" * 40])
def test_result_model_accepts_any_well_formed_provider_name(name: str) -> None:
    result = CloudAssistResult(provider=name, model="m", summary="s")
    assert result.provider == name


@pytest.mark.parametrize("name", [
    "", "Gemini", "AMAZON-Q", "1gemini", "a" * 41, "has space", "has_underscore",
])
def test_result_model_rejects_malformed_provider_names(name: str) -> None:
    with pytest.raises(ValidationError):
        CloudAssistResult(provider=name, model="m", summary="s")


def test_gemini_provider_satisfies_the_pluggable_protocol() -> None:
    assert isinstance(GEMINI_PROVIDER, CloudAssistProvider)
    assert isinstance(GeminiCloudAssistProvider(), CloudAssistProvider)
    assert GEMINI_PROVIDER.name == "gemini"


def test_gemini_is_registered_by_default() -> None:
    assert "gemini" in list_cloud_assist_providers()


def test_resolve_returns_gemini_only_when_configured() -> None:
    configured = _settings(llm_mode="gemini", llm_api_key=SECRET)
    assert resolve_cloud_assist_provider(configured) is GEMINI_PROVIDER
    assert resolve_cloud_assist_provider(_settings(llm_mode="gemini", llm_api_key=None)) is None
    assert resolve_cloud_assist_provider(_settings(llm_mode="disabled")) is None


def test_resolve_returns_none_for_an_unregistered_mode() -> None:
    assert resolve_cloud_assist_provider(_settings(llm_mode="amazon-q")) is None
    assert resolve_cloud_assist_provider(_settings(llm_mode="totally-unknown")) is None


@dataclass
class _FutureRagProvider:
    """Stands in for a future backend (Amazon Q, Glean, an in-house fine-tuned RAG model)."""

    name: str = "future-rag"
    is_configured: bool = True
    canned: CloudAssistResult | None = None
    calls: list = field(default_factory=list)

    def configured(self, settings: Settings) -> bool:
        return self.is_configured

    async def ask(
        self, settings: Settings, finding: Finding, *, client=None,
    ) -> CloudAssistResult | None:
        self.calls.append((settings, finding))
        return self.canned


@pytest.fixture
def isolated_registry():
    """Snapshot and restore the module-level provider registry around one test."""
    before = dict(cloud_assist._PROVIDERS)
    try:
        yield
    finally:
        cloud_assist._PROVIDERS.clear()
        cloud_assist._PROVIDERS.update(before)


def test_register_rejects_a_malformed_name(isolated_registry) -> None:
    with pytest.raises(ValueError):
        register_cloud_assist_provider("Bad Name!", _FutureRagProvider())
    assert "bad name!" not in list_cloud_assist_providers()


def test_register_rejects_an_object_missing_the_protocol_shape(isolated_registry) -> None:
    class _NotAProvider:
        pass

    with pytest.raises(TypeError):
        register_cloud_assist_provider("broken", _NotAProvider())
    assert "broken" not in list_cloud_assist_providers()


async def test_a_future_provider_plugs_in_with_zero_api_changes(isolated_registry) -> None:
    canned = CloudAssistResult(provider="future-rag", model="in-house-v1", summary="Looks flaky.")
    provider = _FutureRagProvider(canned=canned)
    register_cloud_assist_provider("future-rag", provider)

    assert "future-rag" in list_cloud_assist_providers()
    settings = _settings(llm_mode="future-rag")
    resolved = resolve_cloud_assist_provider(settings)
    assert resolved is provider

    result = await resolved.ask(settings, _finding())
    assert result == canned
    assert len(provider.calls) == 1


def test_registering_a_new_provider_never_disturbs_gemini(isolated_registry) -> None:
    register_cloud_assist_provider("future-rag", _FutureRagProvider())
    configured = _settings(llm_mode="gemini", llm_api_key=SECRET)
    assert resolve_cloud_assist_provider(configured) is GEMINI_PROVIDER
    assert cloud_assist_configured(configured) is True
