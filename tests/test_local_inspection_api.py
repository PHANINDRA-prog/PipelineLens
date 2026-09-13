"""Offline router integration; all credentials and storage are synthetic/temporary.

Mount the router directly, not main.create_app. Safe exception/validation handlers
below are test-app boundaries, not assertions about main's pending error wiring.
"""

from __future__ import annotations

import hmac
import socket
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

# Config normally loads the project's dotenv file at import. This isolated suite
# must not read it, and uses explicit Settings rather than ambient credentials.
with patch("dotenv.load_dotenv", return_value=False):
    from pipelinelens.api import inspection as inspection_api
    from pipelinelens.config import Settings
    from pipelinelens.domain import (
        CiConfigAccessEntry,
        CiConfigAccessReport,
        PipelineJob,
        PipelineRun,
        ProviderName,
        RepositoryRef,
    )
    from pipelinelens.providers.base import ProviderError
    from pipelinelens.services.credentials import CredentialVault, CredentialVaultError
    from pipelinelens.services.findings import Finding, FindingEvidence
    from pipelinelens.services.inspection import InspectionResult
    from pipelinelens.services.local_knowledge import KnowledgeCacheError, LocalKnowledgeCache
    from pipelinelens.services.pipeline_url import GitLabReference, PipelineUrlError


_PREFIX = "/api/v1/local"
_LOCAL = {"X-PipelineLens-Local": "1"}
_HOST = "https://gitlab.example.test"
_PROJECT = "group/project"
_OLD_PROJECT = "group/previous"
_PROJECT_KEY = f"{_HOST}/{_PROJECT}"
_RUN_ID = "101"
_JOB_ID = "501"
_PIPELINE_URL = f"{_PROJECT_KEY}/-/pipelines/{_RUN_ID}"
_SHA = "a" * 40
_RULE = "pipeline.status"
_REQUEST = "opaque-request-only-test-104729"
_OTHER_REQUEST = "opaque-other-request-only-test-130363"
_SAVED = "opaque-saved-only-test-155921"
_CONFIGURED = "opaque-configured-only-test-181081"
_LLM = "opaque-disabled-model-only-test-206369"
_SECRETS = (_REQUEST, _OTHER_REQUEST, _SAVED, _CONFIGURED, _LLM)


def _settings(**changes) -> Settings:
    return replace(Settings(
        environment="test", database_url="sqlite:///:memory:", redis_url="redis://unused",
        max_log_bytes=500_000, max_context_chars=18_000, llm_mode="disabled",
        llm_base_url="https://must-not-be-called.invalid", llm_model="unused",
        llm_api_key=_LLM, allow_private_context=False,
        configured_gitlab_token=_CONFIGURED, configured_gitlab_base_url=_HOST,
    ), **changes)


def _assert_no_secrets(text: str, extra: tuple[str, ...] = ()) -> None:
    if any(value and value in text for value in (*_SECRETS, *extra)):
        pytest.fail("Synthetic credential material was exposed.", pytrace=False)


@dataclass
class _FakeProtector:
    """Authenticated XOR for portable tests only, never a production cipher."""

    fail_protect: bool = False
    fail_unprotect: bool = False

    def protect(self, data: bytes) -> bytes:
        if self.fail_protect:
            raise ValueError(_REQUEST + " unsafe synthetic protection diagnostic")
        body = bytes(value ^ 0xA5 for value in data)
        return b"LOCAL-TEST\0" + hmac.digest(b"test-integrity-only", body, "sha256") + body

    def unprotect(self, data: bytes) -> bytes:
        if self.fail_unprotect:
            raise ValueError(_SAVED + " unsafe synthetic unprotection diagnostic")
        prefix = b"LOCAL-TEST\0"
        tag, body = data[len(prefix):len(prefix) + 32], data[len(prefix) + 32:]
        if not data.startswith(prefix) or not hmac.compare_digest(
            tag, hmac.digest(b"test-integrity-only", body, "sha256"),
        ):
            raise ValueError("Invalid test ciphertext")
        return bytes(value ^ 0xA5 for value in body)


@dataclass
class _Call:
    method: str
    host: str
    project: str
    token: str = field(repr=False)
    resource: str = ""
    max_jobs: int | None = None
    known_projects: tuple[str, ...] = ()


def _assert_only_token(calls: list[_Call], token: str) -> None:
    assert calls
    if any(call.token != token for call in calls):
        pytest.fail("An unexpected credential was forwarded.", pytrace=False)


class _GitLabState:
    def __init__(self, vault: CredentialVault) -> None:
        self.vault = vault
        self.calls: list[_Call] = []
        self.references: list[GitLabReference] = []
        self.opened: list[str] = []
        self.closed: list[str] = []
        self.failures: dict[tuple[str, str], int] = {}
        self.head = _SHA
        self.latest_available = True
        self.run = PipelineRun(
            external_id=_RUN_ID, name="Synthetic pipeline", status="success",
            ref_name="main", commit_sha=_SHA,
        )
        self.jobs = [PipelineJob(
            external_id=_JOB_ID, name="build", status="success",
            raw={"pipeline": {"id": int(_RUN_ID), "project_id": 42}},
        )]
        self.evidence_text = "The pipeline status was inspected."

    def record(
        self, method: str, host: str, token: str, project: str,
        resource: str = "", max_jobs: int | None = None,
    ) -> None:
        projects = tuple(project for item in self.vault.metadata() for project in item["projects"])
        self.calls.append(_Call(method, host, project, token, resource, max_jobs, projects))
        if status := self.failures.get((method, token)):
            raise ProviderError("GitLab", status, token + " unsafe synthetic upstream diagnostic")

    def calls_for(self, method: str) -> list[_Call]:
        return [call for call in self.calls if call.method == method]

    async def inspect(
        self, provider, token: str, repository: RepositoryRef,
        reference: GitLabReference, settings: Settings, *, max_jobs: int = 5,
    ) -> InspectionResult:
        self.record("inspect_gitlab", provider.web_base_url, token,
                    repository.display_name, max_jobs=max_jobs)
        self.references.append(reference)
        assert settings.llm_mode == "disabled"
        project_key = f"{provider.web_base_url}/{repository.display_name}"
        pipeline = (
            None if reference.kind in {"branch", "repository"} and not self.latest_available
            else self.run.model_copy(deep=True)
        )
        ref = pipeline.commit_sha if pipeline else self.head
        resolved_url = project_key
        if pipeline:
            pipeline.web_url = f"{project_key}/-/pipelines/{pipeline.external_id}"
            resolved_url = pipeline.web_url
        selected = self.jobs[0].model_copy(deep=True) if reference.kind == "job" else None
        if selected:
            resolved_url = f"{project_key}/-/jobs/{selected.external_id}"
        return InspectionResult(
            repository=repository, pipeline=pipeline, selected_job=selected,
            resolved_url=resolved_url, reference_kind=reference.kind, project_key=project_key,
            jobs=[job.model_copy(deep=True) for job in self.jobs] if pipeline else [],
            findings=[Finding(
                rule_id=_RULE, severity="info", category="pipeline_status",
                title="Pipeline metadata inspected", explanation=self.evidence_text,
                fix=["Review the observed pipeline before making a change."],
                evidence=[FindingEvidence(text=self.evidence_text, line=1)],
            )],
            ci_config_access=CiConfigAccessReport(complete=True, entries=[CiConfigAccessEntry(
                path=".gitlab-ci.yml", ref=ref, state="readable", relationship="root",
                detail=self.evidence_text,
                source_url=f"{project_key}/-/blob/{ref}/.gitlab-ci.yml",
            )]),
            status=("configuration_only" if pipeline is None else
                    "failed" if pipeline.status == "failed" else "passed"),
        )


class _FakeGitLabProvider:
    def __init__(self, base_url: str, state: _GitLabState) -> None:
        self.web_base_url = base_url
        self.state = state

    async def __aenter__(self):
        self.state.opened.append(self.web_base_url)
        return self

    async def __aexit__(self, *_args) -> None:
        self.state.closed.append(self.web_base_url)

    def record(self, method, token, repository, resource="", max_jobs=None) -> None:
        self.state.record(method, self.web_base_url, token, repository.display_name,
                          resource, max_jobs)

    async def get_repository_by_path(self, token: str, project_path: str) -> RepositoryRef:
        self.state.record("get_repository_by_path", self.web_base_url, token, project_path)
        owner, _, name = project_path.rpartition("/")
        return RepositoryRef(
            provider=ProviderName.GITLAB, external_id="42", owner=owner, name=name,
            web_url=f"{self.web_base_url}/{project_path}", default_branch="main",
        )

    async def get_run(self, token, repository, run_id) -> PipelineRun:
        self.record("get_run", token, repository, run_id)
        assert run_id == self.state.run.external_id
        return self.state.run.model_copy(deep=True)

    async def list_pipeline_jobs(self, token, repository, run_id, *, max_jobs=300):
        self.record("list_pipeline_jobs", token, repository, run_id, max_jobs)
        assert run_id == self.state.run.external_id
        return [job.model_copy(deep=True) for job in self.state.jobs]

    async def get_job(self, token, repository, run_id, job_id) -> PipelineJob:
        self.record("get_job", token, repository, job_id)
        assert run_id == ""  # Parent identity must come from the freshly fetched job.
        return self.state.jobs[0].model_copy(deep=True)

    async def resolve_reference(self, token, repository, reference) -> GitLabReference:
        self.record("resolve_reference", token, repository, reference.ref)
        return reference

    async def resolve_commit(self, token, repository, ref) -> str:
        self.record("resolve_commit", token, repository, ref)
        return self.state.head

    async def latest_run_for_ref(self, token, repository, ref) -> PipelineRun | None:
        self.record("latest_run_for_ref", token, repository, ref)
        return self.state.run.model_copy(deep=True) if self.state.latest_available else None


@dataclass
class _Clock:
    seconds: float = 0

    def monotonic(self) -> float:
        return self.seconds

    def now(self, tz) -> datetime:
        return datetime(2026, 9, 13, tzinfo=UTC).astimezone(tz) + timedelta(seconds=self.seconds)


def _app(settings: Settings, vault: CredentialVault, knowledge: LocalKnowledgeCache) -> FastAPI:
    app = FastAPI()
    app.include_router(inspection_api.create_inspection_router(settings, vault, knowledge))

    async def storage_error(_request: Request, _error: Exception) -> JSONResponse:
        return JSONResponse(status_code=503, content={"detail": "Local storage is unavailable."})

    app.add_exception_handler(CredentialVaultError, storage_error)
    app.add_exception_handler(KnowledgeCacheError, storage_error)

    @app.exception_handler(ProviderError)
    async def provider_error(_request: Request, error: ProviderError) -> JSONResponse:
        return JSONResponse(status_code=error.status_code,
                            content={"detail": "GitLab resource access could not be verified."})

    @app.exception_handler(PipelineUrlError)
    async def url_error(_request: Request, _error: PipelineUrlError) -> JSONResponse:
        return JSONResponse(status_code=422, content={"detail": "Invalid GitLab URL."})

    @app.exception_handler(RequestValidationError)
    async def validation_error(_request: Request, error: RequestValidationError) -> JSONResponse:
        # Main owns this boundary. Only test the router's validation and safe shape
        # here; never serialize input or ctx (which can contain supplied secrets).
        return JSONResponse(status_code=422, content={"detail": [
            {key: item[key] for key in ("loc", "type", "msg")} for item in error.errors()
        ]})

    return app


@dataclass
class _LocalApi:
    client: TestClient
    settings: Settings
    vault: CredentialVault
    protector: _FakeProtector
    knowledge: LocalKnowledgeCache
    gitlab: _GitLabState
    clock: _Clock

    def inspect(self, **changes) -> httpx.Response:
        return self.client.post(_PREFIX + "/inspect", headers=_LOCAL,
                                json={"url": _PIPELINE_URL, "token": _REQUEST, **changes})


@pytest.fixture(autouse=True)
def offline_and_isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "unused-user-profile"))

    def forbidden(*_args, **_kwargs):
        pytest.fail("Outbound network access is forbidden in local API tests.", pytrace=False)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)


@pytest.fixture
def local_api(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[_LocalApi]:
    protector = _FakeProtector()
    vault = CredentialVault(tmp_path / "vault", protector=protector)
    knowledge = LocalKnowledgeCache(tmp_path / "knowledge")
    settings, clock = _settings(), _Clock()
    gitlab = _GitLabState(vault)
    monkeypatch.setattr(inspection_api, "GitLabProvider",
                        lambda base_url: _FakeGitLabProvider(base_url, gitlab))
    monkeypatch.setattr(inspection_api, "inspect_gitlab", gitlab.inspect)
    monkeypatch.setattr(inspection_api, "monotonic", clock.monotonic)
    monkeypatch.setattr(inspection_api, "datetime", clock)
    with TestClient(_app(settings, vault, knowledge)) as client:
        yield _LocalApi(client, settings, vault, protector, knowledge, gitlab, clock)


def test_all_local_endpoints_require_the_exact_local_header(local_api, tmp_path) -> None:
    endpoints = [
        ("GET", "/status", None),
        ("POST", "/inspect", {"url": _PIPELINE_URL, "token": _REQUEST}),
        ("POST", "/connections/forget", {"credential_id": str(uuid4())}),
        ("GET", "/knowledge/export", None),
        ("POST", "/knowledge/confirm", {
            "project_key": _PROJECT_KEY, "rule_id": _RULE,
            "resolution": "Human-reviewed correction", "confirmed": True,
        }),
    ]
    for method, path, body in endpoints:
        for headers in ({}, {"X-PipelineLens-Local": "0"}):
            response = local_api.client.request(method, _PREFIX + path, json=body, headers=headers)
            assert response.status_code == 403
            _assert_no_secrets(response.text)
    assert local_api.gitlab.calls == []
    assert local_api.vault.metadata() == []
    assert not local_api.knowledge.path.exists()
    assert not (tmp_path / "vault").exists()


def test_status_accepts_loopback_and_test_hosts_without_exposing_credentials(local_api) -> None:
    saved_id = local_api.vault.save(_HOST, _OLD_PROJECT, _SAVED)
    for host in ("testserver", "localhost:8000", "127.0.0.1:8000", "[::1]:8000"):
        response = local_api.client.get(_PREFIX + "/status", headers={
            **_LOCAL, "Host": host, "Origin": f"http://{host}",
        })
        assert response.status_code == 200
        payload = response.json()
        assert payload["mode"] == "local_rules"
        assert payload["external_model_calls"] is False
        assert payload["configured_connection"] is True
        assert payload["configured_host"] == _HOST
        assert payload["vault_available"] is True
        assert payload["saved_connections"] == [
            {"id": saved_id, "host": _HOST, "projects": [_OLD_PROJECT]},
        ]
        _assert_no_secrets(response.text)
    assert local_api.gitlab.calls == []


def test_untrusted_hosts_origins_and_cross_site_requests_are_forbidden(local_api) -> None:
    for untrusted in (
        {"Host": "attacker.invalid"}, {"Host": "localhost.attacker.invalid"},
        {"Origin": "https://attacker.invalid"}, {"Origin": "null"},
        {"Host": "[::1"}, {"Sec-Fetch-Site": "cross-site"},
    ):
        response = local_api.client.post(_PREFIX + "/inspect", headers={**_LOCAL, **untrusted},
                                         json={"url": _PIPELINE_URL, "token": _REQUEST})
        assert response.status_code == 403
    assert local_api.gitlab.calls == []
    assert not local_api.knowledge.path.exists()


def test_remote_clients_and_cloud_settings_cannot_use_local_endpoints(local_api) -> None:
    def app(environment):
        return _app(replace(local_api.settings, environment=environment),
                    local_api.vault, local_api.knowledge)

    with TestClient(app("test"), client=("203.0.113.10", 4000)) as remote:
        assert remote.get(_PREFIX + "/status", headers=_LOCAL).status_code == 403
    with TestClient(app("development"), base_url="http://localhost",
                    client=("127.0.0.1", 4000)) as local:
        assert local.get(_PREFIX + "/status", headers=_LOCAL).status_code == 200
        assert local.get(_PREFIX + "/status", headers={
            **_LOCAL, "Host": "testserver",
        }).status_code == 403
    for environment in ("production", "cloud"):
        with TestClient(app(environment), base_url="http://localhost",
                        client=("127.0.0.1", 4000)) as cloud:
            assert cloud.get(_PREFIX + "/status", headers=_LOCAL).status_code == 403
    assert local_api.gitlab.calls == []


def test_provided_token_overrides_saved_and_configured_without_implicit_save(local_api) -> None:
    local_api.vault.save(_HOST, _OLD_PROJECT, _SAVED)
    before = local_api.vault.metadata()
    response = local_api.inspect(token=f" {_REQUEST} ", connection="configured")
    assert response.status_code == 200
    assert response.json()["connection_used"] == "Provided token"
    assert response.json()["credential_saved"] is False
    assert local_api.vault.metadata() == before
    _assert_only_token(local_api.gitlab.calls, _REQUEST)
    assert local_api.gitlab.opened == local_api.gitlab.closed == [_HOST]
    _assert_no_secrets(response.text)


def test_request_and_configured_modes_and_verified_auto_fallback(local_api) -> None:
    local_api.vault.save(_HOST, _OLD_PROJECT, _SAVED)
    before = local_api.vault.metadata()
    assert local_api.inspect(token=None, connection="request").status_code == 422
    assert local_api.gitlab.calls == []
    configured = local_api.inspect(token=None, connection="configured")
    assert configured.status_code == 200
    assert configured.json()["connection_used"] == "Local connection"
    _assert_only_token(local_api.gitlab.calls, _CONFIGURED)
    local_api.gitlab.calls.clear()
    local_api.gitlab.failures[("get_repository_by_path", _SAVED)] = 401
    fallback = local_api.inspect(token=None)
    assert fallback.status_code == 200
    assert fallback.json()["connection_used"] == "Local connection"
    project_calls = local_api.gitlab.calls_for("get_repository_by_path")
    assert len(project_calls) == 2
    _assert_only_token(project_calls[:1], _SAVED)
    _assert_only_token(local_api.gitlab.calls[1:], _CONFIGURED)
    assert local_api.vault.metadata() == before
    _assert_no_secrets(fallback.text)


def test_auto_reuse_adds_project_only_after_fresh_resource_verification(local_api) -> None:
    saved_id = local_api.vault.save(_HOST, _OLD_PROJECT, _SAVED)
    response = local_api.inspect(token=None)
    assert response.status_code == 200
    assert response.json()["connection_used"] == "Saved Windows connection"
    assert response.json()["credential_saved"] is True
    _assert_only_token(local_api.gitlab.calls, _SAVED)
    assert {call.method for call in local_api.gitlab.calls} == {
        "get_repository_by_path", "get_run", "list_pipeline_jobs", "inspect_gitlab",
    }
    assert all(call.known_projects == (_OLD_PROJECT,) for call in local_api.gitlab.calls)
    assert local_api.vault.metadata() == [
        {"id": saved_id, "host": _HOST, "projects": [_OLD_PROJECT, _PROJECT]},
    ]
    reused = local_api.inspect(token=None)
    assert reused.status_code == 200 and reused.json()["cached"] is True
    assert len(local_api.gitlab.calls_for("get_repository_by_path")) == 2
    assert len(local_api.gitlab.calls_for("get_run")) == 2
    assert len(local_api.gitlab.calls_for("list_pipeline_jobs")) == 2
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 1


def test_saved_and_configured_tokens_never_cross_origins(local_api) -> None:
    local_api.vault.save(_HOST, _PROJECT, _SAVED)
    before = local_api.vault.metadata()
    other_host = "https://other-gitlab.example.test"
    for host in (other_host, _HOST + ":8443"):
        response = local_api.inspect(url=f"{host}/{_PROJECT}/-/pipelines/{_RUN_ID}", token=None)
        assert response.status_code == 422
        _assert_no_secrets(response.text)
    assert local_api.gitlab.opened == local_api.gitlab.calls == []
    explicit = local_api.inspect(url=f"{other_host}/{_PROJECT}/-/pipelines/{_RUN_ID}")
    assert explicit.status_code == 200
    assert {call.host for call in local_api.gitlab.calls} == {other_host}
    _assert_only_token(local_api.gitlab.calls, _REQUEST)
    assert local_api.vault.metadata() == before


def test_invalid_tokens_have_only_safe_validation_shape_and_never_reach_provider(local_api) -> None:
    for invalid in (
        _REQUEST + " extra", _REQUEST + "\nextra", _REQUEST + "é", _REQUEST + "x" * 8192,
    ):
        response = local_api.inspect(token=invalid)
        assert response.status_code == 422
        errors = response.json()["detail"]
        assert errors and all(error["loc"] == ["body", "token"] for error in errors)
        assert all(set(error) == {"loc", "type", "msg"} for error in errors)
        _assert_no_secrets(response.text, (invalid,))
    assert local_api.gitlab.calls == []
    assert local_api.vault.metadata() == []


def test_failed_supplied_auth_never_falls_back_saves_or_associates(local_api, caplog) -> None:
    local_api.vault.save(_HOST, _OLD_PROJECT, _SAVED)
    before = local_api.vault.metadata()
    local_api.gitlab.failures[("get_run", _REQUEST)] = 403
    response = local_api.inspect(remember_token=True)
    assert response.status_code == 403
    assert "No new project association was saved" in response.json()["detail"]
    assert local_api.vault.metadata() == before
    assert local_api.gitlab.calls_for("get_repository_by_path")
    assert local_api.gitlab.calls_for("inspect_gitlab") == []
    _assert_only_token(local_api.gitlab.calls, _REQUEST)
    assert not local_api.knowledge.path.exists()
    _assert_no_secrets(response.text + caplog.text)


def test_failed_saved_resource_access_cannot_associate_or_return_cached_evidence(local_api) -> None:
    local_api.vault.save(_HOST, _OLD_PROJECT, _SAVED)
    before = local_api.vault.metadata()
    for token in (_SAVED, _CONFIGURED):
        local_api.gitlab.failures[("list_pipeline_jobs", token)] = 404
    denied = local_api.inspect(token=None)
    assert denied.status_code == 404
    assert local_api.vault.metadata() == before
    assert local_api.gitlab.calls_for("inspect_gitlab") == []
    local_api.gitlab.failures.clear()
    assert local_api.inspect(token=None).status_code == 200
    verified = local_api.vault.metadata()
    for token in (_SAVED, _CONFIGURED):
        local_api.gitlab.failures[("get_run", token)] = 403
    revoked = local_api.inspect(token=None)
    assert revoked.status_code == 403
    assert "findings" not in revoked.json()
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 1
    assert local_api.vault.metadata() == verified
    assert local_api.knowledge.summary()["observations"] == 1
    _assert_no_secrets(denied.text + revoked.text)


def test_forgetting_connection_clears_the_vault_entry_and_response_cache(local_api) -> None:
    remembered = local_api.inspect(remember_token=True)
    assert remembered.status_code == 200 and remembered.json()["credential_saved"] is True
    assert all(call.known_projects == () for call in local_api.gitlab.calls)
    saved_id = local_api.vault.metadata()[0]["id"]
    assert local_api.inspect(token=None).json()["cached"] is True
    forgotten = local_api.client.post(_PREFIX + "/connections/forget", headers=_LOCAL,
                                      json={"credential_id": saved_id})
    assert forgotten.status_code == 200 and forgotten.json() == {"removed": True}
    assert local_api.vault.metadata() == []
    fresh = local_api.inspect()
    assert fresh.status_code == 200 and fresh.json()["cached"] is False
    assert fresh.json()["credential_saved"] is False
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 2
    assert local_api.client.post(_PREFIX + "/connections/forget", headers=_LOCAL,
                                 json={"credential_id": saved_id}).json() == {"removed": False}


def test_cache_hits_reverify_resource_and_label_original_source_time_and_age(local_api) -> None:
    first = local_api.inspect()
    assert first.status_code == 200
    original = first.json()
    local_api.clock.seconds = 9.75
    local_api.gitlab.evidence_text = "New source contents require an explicit refresh."
    cached = local_api.inspect()
    assert cached.status_code == 200
    payload = cached.json()
    assert original["cached"] is False and original["cache_age_seconds"] == 0
    assert payload["cached"] is True and payload["cache_age_seconds"] == 9
    assert payload["inspected_at"] == original["inspected_at"]
    assert datetime.fromisoformat(payload["inspected_at"]).tzinfo == UTC
    assert payload["ci_config_access"] == original["ci_config_access"]
    assert payload["findings"] == original["findings"]
    assert payload["mode"] == "local_rules" and payload["elapsed_ms"] >= 0
    for method in ("get_repository_by_path", "get_run", "list_pipeline_jobs"):
        assert len(local_api.gitlab.calls_for(method)) == 2
    job_calls = local_api.gitlab.calls_for("list_pipeline_jobs")
    assert [call.max_jobs for call in job_calls] == [300, 300]
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 1


def test_response_cache_is_isolated_by_token_and_max_jobs(local_api) -> None:
    cached_flags = []
    for token, max_jobs in (
        (_REQUEST, 2), (_REQUEST, 2), (_OTHER_REQUEST, 2), (_REQUEST, 3), (_OTHER_REQUEST, 2),
    ):
        response = local_api.inspect(token=token, max_jobs=max_jobs)
        assert response.status_code == 200
        cached_flags.append(response.json()["cached"])
        _assert_no_secrets(response.text)
    assert cached_flags == [False, True, False, False, True]
    calls = local_api.gitlab.calls_for("inspect_gitlab")
    assert [call.max_jobs for call in calls] == [2, 2, 3]
    _assert_only_token(calls[:1] + calls[2:], _REQUEST)
    _assert_only_token(calls[1:2], _OTHER_REQUEST)
    assert local_api.inspect(max_jobs=9).status_code == 422
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 3


def test_refresh_and_expiry_bypass_response_cache(local_api) -> None:
    original = local_api.inspect().json()
    local_api.clock.seconds = 5
    refreshed = local_api.inspect(refresh=True).json()
    assert refreshed["cached"] is False
    assert refreshed["inspected_at"] != original["inspected_at"]
    assert refreshed["cache_age_seconds"] == 0
    assert local_api.inspect().json()["cached"] is True
    local_api.clock.seconds += 120
    expired = local_api.inspect().json()
    assert expired["cached"] is False
    assert expired["inspected_at"] != refreshed["inspected_at"]
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 3


def test_fresh_pipeline_status_and_job_failure_metadata_invalidate_cache(local_api) -> None:
    assert local_api.inspect().json()["status"] == "passed"
    local_api.gitlab.run.status = "failed"
    failed = local_api.inspect().json()
    assert failed["status"] == "failed" and failed["cached"] is False
    for name, value in (
        ("status", "failed"), ("allow_failure", True), ("failure_reason", "runner_system_failure"),
    ):
        setattr(local_api.gitlab.jobs[0], name, value)
        response = local_api.inspect()
        assert response.status_code == 200
        assert response.json()["cached"] is False
        assert response.json()["jobs"][0][name] == value
    assert local_api.inspect().json()["cached"] is True
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 5


def test_job_url_requires_fresh_selected_job_and_matching_parent_project(local_api) -> None:
    url = f"{_PROJECT_KEY}/-/jobs/{_JOB_ID}"
    response = local_api.inspect(url=url)
    assert response.status_code == 200
    payload = response.json()
    assert payload["reference_kind"] == "job" and payload["resolved_url"] == url
    assert payload["selected_job"]["external_id"] == _JOB_ID
    assert payload["pipeline"]["external_id"] == _RUN_ID
    assert local_api.gitlab.references == [GitLabReference(_HOST, _PROJECT, "job", job_id=_JOB_ID)]
    assert local_api.gitlab.calls_for("get_job")[0].resource == _JOB_ID
    assert local_api.gitlab.calls_for("get_run")[0].resource == _RUN_ID
    local_api.gitlab.jobs[0].raw["pipeline"]["project_id"] = 999
    invalid = local_api.inspect(url=url, remember_token=True)
    assert invalid.status_code == 502
    assert len(local_api.gitlab.calls_for("get_job")) == 2
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 1
    assert local_api.vault.metadata() == []
    _assert_no_secrets(invalid.text)


def test_branch_input_resolves_refs_and_latest_changes_or_errors_never_return_stale(local_api):
    url = f"{_PROJECT_KEY}/-/blob/feature%2Fchecks/.gitlab-ci.yml?ref_type=heads"
    first = local_api.inspect(url=url)
    assert first.status_code == 200 and first.json()["reference_kind"] == "branch"
    assert local_api.gitlab.references == [GitLabReference(
        _HOST, _PROJECT, "branch", ref="feature/checks", file_path=".gitlab-ci.yml",
    )]
    for method in ("resolve_reference", "resolve_commit", "latest_run_for_ref"):
        assert local_api.gitlab.calls_for(method)[0].resource == "feature/checks"
    assert local_api.inspect(url=url).json()["cached"] is True
    local_api.gitlab.run = local_api.gitlab.run.model_copy(update={
        "external_id": "102", "status": "failed", "commit_sha": "b" * 40,
    })
    latest = local_api.inspect(url=url).json()
    assert latest["cached"] is False and latest["status"] == "failed"
    assert latest["pipeline"]["external_id"] == "102"
    local_api.gitlab.failures[("latest_run_for_ref", _REQUEST)] = 503
    unavailable = local_api.inspect(url=url)
    assert unavailable.status_code == 503 and "findings" not in unavailable.json()
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 2
    assert len(local_api.gitlab.calls_for("latest_run_for_ref")) == 4
    assert local_api.gitlab.opened == local_api.gitlab.closed
    _assert_no_secrets(unavailable.text)


def test_repository_default_branch_cache_tracks_head_and_absent_then_present_pipeline(local_api):
    local_api.gitlab.latest_available = False
    first = local_api.inspect(url=_PROJECT_KEY).json()
    assert first["reference_kind"] == "repository"
    assert first["status"] == "configuration_only" and first["pipeline"] is None
    assert local_api.inspect(url=_PROJECT_KEY).json()["cached"] is True
    local_api.gitlab.head = "c" * 40
    changed = local_api.inspect(url=_PROJECT_KEY).json()
    assert changed["cached"] is False
    assert changed["ci_config_access"]["entries"][0]["ref"] == "c" * 40
    for method in ("resolve_commit", "latest_run_for_ref"):
        assert {call.resource for call in local_api.gitlab.calls_for(method)} == {"main"}
    assert local_api.gitlab.calls_for("get_run") == []
    assert local_api.gitlab.calls_for("list_pipeline_jobs") == []
    local_api.gitlab.latest_available = True
    new_pipeline = local_api.inspect(url=_PROJECT_KEY).json()
    assert new_pipeline["cached"] is False and new_pipeline["status"] == "passed"
    assert new_pipeline["pipeline"]["external_id"] == _RUN_ID
    assert len(local_api.gitlab.calls_for("inspect_gitlab")) == 3


def test_remember_redacts_knowledge_and_does_not_auto_confirm_suggested_fixes(local_api) -> None:
    # Deliberately stress the knowledge boundary. The real inspection service's
    # response redaction is outside this router test and is replaced by the fake.
    local_api.gitlab.evidence_text = f"Observed {_REQUEST} {_CONFIGURED} {_LLM}; review required."
    response = local_api.inspect()
    assert response.status_code == 200
    assert response.json()["knowledge_saved"] is True
    assert response.json()["confirmed_resolutions"] == []
    exported = local_api.client.get(_PREFIX + "/knowledge/export", headers=_LOCAL)
    assert exported.status_code == 200
    data = exported.json()
    observation = data["observations"][0]
    assert observation["human_confirmed"] is False
    assert observation["fix_status"] == "unreviewed_suggestion"
    assert data["resolutions"] == [] and local_api.knowledge.lookup(_PROJECT_KEY, _RULE) == []
    assert "unencrypted" in data["notice"] and "Review" in data["notice"]
    assert "REDACTED" in exported.text
    _assert_no_secrets(exported.text + local_api.knowledge.path.read_text(encoding="utf-8"))
    assert local_api.knowledge.summary() == {
        "observations": 1, "projects": 1, "confirmed_resolutions": 0,
    }


def test_feedback_requires_explicit_boolean_true_not_missing_false_string_or_integer(local_api):
    body = {"project_key": _PROJECT_KEY, "rule_id": _RULE, "resolution": "Human-reviewed fix"}
    statuses = {}
    for label, extra in (
        ("missing", {}), ("false", {"confirmed": False}),
        ("string", {"confirmed": "true"}), ("integer", {"confirmed": 1}),
    ):
        response = local_api.client.post(_PREFIX + "/knowledge/confirm", headers=_LOCAL,
                                         json={**body, **extra})
        statuses[label] = response.status_code
    assert statuses == {"missing": 422, "false": 422, "string": 422, "integer": 422}, (
        "Only an explicit JSON boolean true may assert human confirmation."
    )
    assert local_api.knowledge.lookup(_PROJECT_KEY, _RULE) == []


def test_confirmed_feedback_redacts_credentials_and_matches_only_exact_project_and_rule(local_api):
    local_api.vault.save(_HOST, _PROJECT, _SAVED)
    local_api.knowledge.record_resolution(f"{_HOST}/other/project", _RULE, "Other project fix")
    local_api.knowledge.record_resolution(_PROJECT_KEY, "another.rule", "Other rule fix")
    response = local_api.client.post(_PREFIX + "/knowledge/confirm", headers=_LOCAL, json={
        "project_key": _PROJECT_KEY, "rule_id": _RULE, "confirmed": True,
        "resolution": f"Human reviewed correction after rotating {_SAVED} {_CONFIGURED} {_LLM}.",
    })
    assert response.status_code == 200
    assert response.json() == {"saved": True, "human_confirmed": True}
    inspected = local_api.inspect()
    assert inspected.status_code == 200
    confirmed = inspected.json()["confirmed_resolutions"]
    assert len(confirmed) == 1
    assert confirmed[0]["project_key"] == _PROJECT_KEY and confirmed[0]["rule_id"] == _RULE
    assert confirmed[0]["human_confirmed"] is True
    assert "Human reviewed correction" in confirmed[0]["resolution"]
    exported = local_api.client.get(_PREFIX + "/knowledge/export", headers=_LOCAL)
    assert exported.status_code == 200
    _assert_no_secrets(inspected.text + exported.text)
    _assert_no_secrets(local_api.knowledge.path.read_text(encoding="utf-8"))


def test_feedback_rejects_resource_urls_instead_of_project_identity(local_api) -> None:
    for project_key in (_PIPELINE_URL, f"{_PROJECT_KEY}/-/tree/main"):
        response = local_api.client.post(_PREFIX + "/knowledge/confirm", headers=_LOCAL, json={
            "project_key": project_key, "rule_id": _RULE,
            "resolution": "Human-reviewed fix", "confirmed": True,
        })
        assert response.status_code == 422
    assert local_api.knowledge.summary()["confirmed_resolutions"] == 0
    assert not local_api.knowledge.path.exists()
    assert local_api.gitlab.calls == []


def test_protection_failure_is_safe_and_preserves_usable_inspection(local_api, caplog, tmp_path):
    local_api.protector.fail_protect = True
    response = local_api.inspect(remember_token=True)
    assert response.status_code == 200
    payload = response.json()
    assert payload["credential_saved"] is False and payload["knowledge_saved"] is True
    assert payload["status"] == "passed"
    assert any("could not be saved" in note for note in payload["notes"])
    assert local_api.vault.metadata() == []
    assert not (tmp_path / "vault").exists()
    _assert_no_secrets(response.text + caplog.text)


def test_corrupt_vault_errors_use_safe_test_app_boundaries_without_overwriting(local_api, tmp_path):
    saved_id = local_api.vault.save(_HOST, _PROJECT, _SAVED)
    path = tmp_path / "vault" / "vault.dpapi"
    original = path.read_bytes()
    local_api.protector.fail_unprotect = True
    status = local_api.client.get(_PREFIX + "/status", headers=_LOCAL)
    assert status.status_code == 200
    assert status.json()["saved_connections"] == [] and status.json()["notes"]
    inspected = local_api.inspect(token=None)
    forgotten = local_api.client.post(_PREFIX + "/connections/forget", headers=_LOCAL,
                                      json={"credential_id": saved_id})
    assert inspected.status_code == forgotten.status_code == 503
    assert local_api.gitlab.calls == []
    assert path.read_bytes() == original
    _assert_no_secrets(status.text + inspected.text + forgotten.text)