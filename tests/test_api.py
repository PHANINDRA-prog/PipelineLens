import asyncio
from dataclasses import replace

from fastapi.testclient import TestClient

from pipelinelens.api.main import create_app
from pipelinelens.config import Settings
from pipelinelens.demo import get_demo_incident
from pipelinelens.domain import (
    CiConfigAccessEntry,
    CiConfigAccessReport,
    ProviderIdentity,
    ProviderName,
    RepositoryRef,
    RepositoryTreeEntry,
)
from pipelinelens.storage import IncidentStore


def _settings(database_url: str) -> Settings:
    return Settings(
        environment="test",
        database_url=database_url,
        redis_url="redis://localhost:6379/0",
        max_log_bytes=500000,
        max_context_chars=18000,
        llm_mode="disabled",
        llm_base_url="http://localhost:11434",
        llm_model="test-model",
        llm_api_key=None,
        allow_private_context=False,
    )


def test_demo_analysis_and_feedback_api(tmp_path) -> None:
    store = IncidentStore(f"sqlite:///{tmp_path / 'api.db'}")
    client = TestClient(create_app(_settings(f"sqlite:///{tmp_path / 'api.db'}"), store))

    fixtures = client.get("/api/v1/demo/incidents")
    analysis = client.post("/api/v1/demo/incidents/gitlab-auth-expired/analyze")

    assert fixtures.status_code == 200
    assert len(fixtures.json()) == 4
    assert analysis.status_code == 200
    payload = analysis.json()
    assert payload["snapshot"]["fingerprint"]["category"] == "authentication_failure"
    assert "glpat-" not in payload["snapshot"]["redacted_log"]

    feedback = client.post(
        f"/api/v1/incidents/{payload['incident_id']}/feedback",
        json={"outcome": "resolved", "confirmed_resolution": "Rotate the protected credential."},
    )
    clusters = client.get("/api/v1/incidents/clusters")

    assert feedback.status_code == 204
    assert clusters.status_code == 200
    assert clusters.json()[0]["category"] == "authentication_failure"


def test_health_endpoints_are_ready() -> None:
    client = TestClient(create_app(_settings("sqlite:///:memory:")))

    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {"status": "ready"}
    system_status = client.get("/api/v1/system/status")
    assert system_status.status_code == 200
    assert system_status.json()["llm"]["mode"] == "disabled"


def test_local_configured_gitlab_token_stays_on_configured_host(monkeypatch, tmp_path) -> None:
    class ConfiguredTokenProvider:
        async def validate_token(self, token: str) -> ProviderIdentity:
            assert token == "server-held-development-token"
            return ProviderIdentity(provider=ProviderName.GITLAB, login="local-developer")

        async def list_repositories(self, token: str) -> list[RepositoryRef]:
            assert token == "server-held-development-token"
            return []

    configured_settings = replace(
        _settings(f"sqlite:///{tmp_path / 'configured-token.db'}"),
        environment="development",
        configured_gitlab_token="server-held-development-token",
        configured_gitlab_base_url="https://gitlab.internal",
    )
    captured: dict[str, object] = {}

    def get_configured_provider(provider: ProviderName, base_url: str | None):
        captured["provider"] = provider
        captured["base_url"] = base_url
        return ConfiguredTokenProvider()

    monkeypatch.setattr("pipelinelens.api.main.get_provider", get_configured_provider)
    client = TestClient(create_app(configured_settings))
    response = client.post(
        "/api/v1/connect",
        json={
            "provider": "gitlab",
            "use_configured_token": True,
            "base_url": "https://untrusted.example",
        },
    )

    assert response.status_code == 200
    assert response.json()["identity"]["login"] == "local-developer"
    assert captured == {"provider": ProviderName.GITLAB, "base_url": "https://gitlab.internal"}


def test_local_configured_token_is_rejected_outside_development(tmp_path) -> None:
    production_settings = replace(
        _settings(f"sqlite:///{tmp_path / 'production-token.db'}"),
        environment="production",
        configured_gitlab_token="server-held-development-token",
    )
    client = TestClient(create_app(production_settings))

    response = client.post(
        "/api/v1/connect",
        json={"provider": "gitlab", "use_configured_token": True},
    )

    assert response.status_code == 403


def test_pasted_gitlab_pipeline_url_verifies_access_and_analyzes_failed_job(
    monkeypatch,
    tmp_path,
) -> None:
    fixture = get_demo_incident("gitlab-auth-expired")

    class UrlProvider:
        async def get_repository_by_path(self, token: str, project_path: str) -> RepositoryRef:
            assert token == "server-held-development-token"
            assert project_path == "group/sample"
            return fixture.repository

        async def get_run(self, token, repository, run_id):
            assert run_id == "101"
            return fixture.run

        async def list_jobs(self, token, repository, run_id):
            assert run_id == "101"
            return [fixture.job]

        async def list_repository_tree(self, token, repository, ref, max_depth, max_entries):
            assert ref == fixture.run.commit_sha
            assert max_depth == 3
            assert max_entries == 200
            return []

        async def inspect_ci_config_access(self, token, repository, run):
            assert run.external_id == "101"
            return CiConfigAccessReport(
                entries=[
                    CiConfigAccessEntry(
                        path=".gitlab-ci.yml",
                        ref=run.commit_sha,
                        state="readable",
                        relationship="root",
                        detail="Read at the failed pipeline commit.",
                    )
                ],
                complete=True,
            )

        async def fetch_file_at_ref(self, token, repository, path, ref):
            assert path == ".gitlab-ci.yml"
            assert ref == fixture.run.commit_sha
            return fixture.configs[0]

        async def fetch_ci_config_bundle(self, token, repository, run, target_job_name=None):
            assert target_job_name == fixture.job.name
            return fixture.configs

        async def fetch_job_log(self, token, repository, run_id, job_id):
            return fixture.log

    configured_settings = replace(
        _settings(f"sqlite:///{tmp_path / 'pipeline-url.db'}"),
        environment="development",
        configured_gitlab_token="server-held-development-token",
        configured_gitlab_base_url="https://gitlab.test",
    )
    monkeypatch.setattr("pipelinelens.api.main.GitLabProvider", lambda base_url: UrlProvider())
    client = TestClient(create_app(configured_settings))

    response = client.post(
        "/api/v1/gitlab/pipeline-url/analyze",
        json={"pipeline_url": "https://gitlab.test/group/sample/-/pipelines/101"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["access_verified"] is True
    assert payload["failed_job_count"] == 1
    assert payload["project_structure"] == []
    assert payload["ci_config_access"]["complete"] is True
    assert payload["ci_config_access"]["entries"][0]["path"] == ".gitlab-ci.yml"
    assert payload["analyses"][0]["snapshot"]["fingerprint"]["category"] == "authentication_failure"
    assert payload["analyses"][0]["snapshot"]["job_source"]["path"] == "ci/deploy.yml"
    assert "glpat-" not in payload["analyses"][0]["snapshot"]["redacted_log"]


def test_pasted_pipeline_analysis_runs_before_slow_project_outline(monkeypatch, tmp_path) -> None:
    fixture = get_demo_incident("gitlab-auth-expired")
    analysis_started = False

    class AsyncProvider:
        async def get_repository_by_path(self, token: str, project_path: str) -> RepositoryRef:
            return fixture.repository

        async def get_run(self, token, repository, run_id):
            return fixture.run

        async def list_jobs(self, token, repository, run_id):
            return [fixture.job]

        async def list_repository_tree(self, token, repository, ref, max_depth, max_entries):
            assert ref == fixture.run.commit_sha
            assert max_depth == 3
            assert max_entries == 200
            for _ in range(5):
                await asyncio.sleep(0)
                assert analysis_started
            return []

        async def fetch_file_at_ref(self, token, repository, path, ref):
            nonlocal analysis_started
            analysis_started = True
            return fixture.configs[0]

        async def fetch_ci_config_bundle(self, token, repository, run, target_job_name=None):
            nonlocal analysis_started
            analysis_started = True
            return fixture.configs

        async def fetch_job_log(self, token, repository, run_id, job_id):
            return fixture.log

    configured_settings = replace(
        _settings(f"sqlite:///{tmp_path / 'overlap.db'}"),
        environment="development",
        configured_gitlab_token="server-held-development-token",
        configured_gitlab_base_url="https://gitlab.test",
    )
    monkeypatch.setattr("pipelinelens.api.main.GitLabProvider", lambda base_url: AsyncProvider())
    client = TestClient(create_app(configured_settings))

    response = client.post(
        "/api/v1/gitlab/pipeline-url/analyze",
        json={"pipeline_url": "https://gitlab.test/group/sample/-/pipelines/101"},
    )

    assert response.status_code == 200
    assert analysis_started is True


def test_pasted_gitlab_pipeline_url_rejects_a_different_host(tmp_path) -> None:
    configured_settings = replace(
        _settings(f"sqlite:///{tmp_path / 'pipeline-url-host.db'}"),
        environment="development",
        configured_gitlab_token="server-held-development-token",
        configured_gitlab_base_url="https://gitlab.test",
    )
    client = TestClient(create_app(configured_settings))

    response = client.post(
        "/api/v1/gitlab/pipeline-url/analyze",
        json={"pipeline_url": "https://gitlab.com/group/sample/-/pipelines/101"},
    )

    assert response.status_code == 422
    assert "different GitLab server" in response.json()["detail"]


def test_pasted_gitlab_pipeline_url_request_token_overrides_local_token(
    monkeypatch,
    tmp_path,
) -> None:
    fixture = get_demo_incident("gitlab-auth-expired")
    captured: dict[str, str] = {}

    class ManualTokenProvider:
        async def get_repository_by_path(self, token: str, project_path: str) -> RepositoryRef:
            captured["token"] = token
            captured["project_path"] = project_path
            return fixture.repository

        async def get_run(self, token, repository, run_id):
            return fixture.run

        async def list_jobs(self, token, repository, run_id):
            return [fixture.job]

        async def list_repository_tree(self, token, repository, ref, max_depth, max_entries):
            assert ref == fixture.run.commit_sha
            assert max_depth == 3
            assert max_entries == 200
            return []

        async def fetch_ci_config_bundle(self, token, repository, run, target_job_name=None):
            return fixture.configs

        async def fetch_job_log(self, token, repository, run_id, job_id):
            return fixture.log

    monkeypatch.setattr(
        "pipelinelens.api.main.GitLabProvider",
        lambda base_url: captured.update(base_url=base_url) or ManualTokenProvider(),
    )
    configured_settings = replace(
        _settings(f"sqlite:///{tmp_path / 'manual-token.db'}"),
        environment="development",
        configured_gitlab_token="server-held-development-token",
        configured_gitlab_base_url="https://configured.gitlab.test",
    )
    client = TestClient(create_app(configured_settings))

    response = client.post(
        "/api/v1/gitlab/pipeline-url/analyze",
        json={
            "pipeline_url": "https://gitlab.other/group/sample/-/pipelines/101",
            "token": "request-scoped-read-only-token",
        },
    )

    assert response.status_code == 200
    assert captured == {
        "base_url": "https://gitlab.other",
        "project_path": "group/sample",
        "token": "request-scoped-read-only-token",
    }
    assert "request-scoped-read-only-token" not in response.text


def test_pasted_gitlab_pipeline_url_requires_a_token_when_local_access_is_unavailable(
    tmp_path,
) -> None:
    client = TestClient(create_app(_settings(f"sqlite:///{tmp_path / 'token-required.db'}")))

    response = client.post(
        "/api/v1/gitlab/pipeline-url/analyze",
        json={"pipeline_url": "https://gitlab.test/group/sample/-/pipelines/101"},
    )

    assert response.status_code == 422
    assert "read-only GitLab personal access token" in response.json()["detail"]


def test_repository_structure_api_delegates_to_the_selected_provider(monkeypatch, tmp_path) -> None:
    class StructureProvider:
        async def list_repository_tree(self, token, repository, ref, max_depth, max_entries):
            assert token == "read-only-token"
            assert repository.display_name == "sample-org/sample"
            assert ref == "main"
            assert max_depth == 3
            assert max_entries == 200
            return [
                RepositoryTreeEntry(path=".github", entry_type="directory"),
                RepositoryTreeEntry(path=".github/workflows", entry_type="directory"),
            ]

    monkeypatch.setattr(
        "pipelinelens.api.main.get_provider",
        lambda provider, base_url: StructureProvider(),
    )
    database_url = f"sqlite:///{tmp_path / 'structure.db'}"
    client = TestClient(create_app(_settings(database_url)))
    response = client.post(
        "/api/v1/repository-structure",
        json={
            "provider": "github",
            "token": "read-only-token",
            "ref": "main",
            "repository": {
                "provider": "github",
                "external_id": "99",
                "owner": "sample-org",
                "name": "sample",
                "web_url": "https://github.com/sample-org/sample",
                "default_branch": "main",
            },
        },
    )

    assert response.status_code == 200
    assert response.json() == [
        {"path": ".github", "entry_type": "directory"},
        {"path": ".github/workflows", "entry_type": "directory"},
    ]
