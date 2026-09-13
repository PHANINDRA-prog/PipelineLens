import asyncio
import base64

import httpx
import pytest

from pipelinelens.domain import CiConfigFile, PipelineRun, ProviderName, RepositoryRef
from pipelinelens.providers.github import GitHubProvider
from pipelinelens.providers.gitlab import GitLabProvider
from pipelinelens.services.gitlab_includes import project_include_key


def _json_response(payload, status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code=status_code, json=payload)


@pytest.mark.asyncio
async def test_github_adapter_lists_a_failed_run_and_downloads_config() -> None:
    workflow = "name: CI\non: [push]\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer token"
        if request.url.path == "/user":
            return _json_response({"login": "dev", "name": "Developer"})
        if request.url.path == "/user/repos":
            return _json_response(
                [
                    {
                        "id": 9,
                        "name": "sample",
                        "owner": {"login": "octo"},
                        "html_url": "https://github.com/octo/sample",
                        "default_branch": "main",
                    }
                ]
            )
        if request.url.path == "/repos/octo/sample/actions/runs":
            return _json_response(
                {
                    "workflow_runs": [
                        {
                            "id": 21,
                            "name": "CI",
                            "status": "completed",
                            "conclusion": "failure",
                            "head_branch": "main",
                            "head_sha": "abc123",
                            "workflow_id": 77,
                        }
                    ]
                }
            )
        if request.url.path == "/repos/octo/sample/actions/workflows/77":
            return _json_response({"path": ".github/workflows/ci.yml"})
        if request.url.path == "/repos/octo/sample/contents":
            assert request.url.params["ref"] == "main"
            return _json_response(
                [
                    {"path": ".github", "type": "dir"},
                    {"path": "src", "type": "dir"},
                    {"path": "README.md", "type": "file"},
                ]
            )
        if request.url.path == "/repos/octo/sample/git/trees/main":
            return _json_response(
                {
                    "tree": [
                        {"path": "src", "type": "tree"},
                        {"path": "src/api.py", "type": "blob"},
                        {"path": "src/internal/worker.py", "type": "blob"},
                        {"path": "src/internal/deep/task.py", "type": "blob"},
                    ]
                }
            )
        if request.url.path == "/repos/octo/sample/contents/.github/workflows/ci.yml":
            assert request.url.params["ref"] == "abc123"
            return _json_response(
                {"content": base64.b64encode(workflow.encode()).decode(), "sha": "file-sha"}
            )
        raise AssertionError(f"Unexpected request: {request.url}")

    provider = GitHubProvider("https://api.github.test", transport=httpx.MockTransport(handler))
    identity = await provider.validate_token("token")
    repositories = await provider.list_repositories("token")
    runs = await provider.list_failed_runs("token", repositories[0])
    bundle = await provider.fetch_ci_config_bundle("token", repositories[0], runs[0])
    tree = await provider.list_repository_tree("token", repositories[0])
    top_level_tree = await provider.list_repository_tree("token", repositories[0], max_depth=1)

    assert identity.login == "dev"
    assert repositories[0].display_name == "octo/sample"
    assert runs[0].commit_sha == "abc123"
    assert bundle[0].path == ".github/workflows/ci.yml"
    assert "pytest" in bundle[0].content
    assert [entry.path for entry in tree] == ["src", "src/api.py", "src/internal/worker.py"]
    assert [entry.path for entry in top_level_tree] == [".github", "src", "README.md"]


@pytest.mark.asyncio
async def test_gitlab_adapter_resolves_a_local_include_and_downloads_trace() -> None:
    GitLabProvider._config_bundle_cache.clear()
    root_yaml = "spec:\n  inputs: {}\n---\ninclude:\n  - local: ci/deploy.yml\nstages: [test, deploy]\ntest:\n  stage: test\n  script: pytest\n"
    deploy_yaml = "deploy:\n  stage: deploy\n  needs: [test]\n  script: ./deploy.sh\n"

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["PRIVATE-TOKEN"] == "token"
        if request.url.path == "/api/v4/user":
            return _json_response({"username": "dev", "name": "Developer"})
        if request.url.path == "/api/v4/projects":
            return _json_response(
                [
                    {
                        "id": 42,
                        "path": "sample",
                        "path_with_namespace": "group/sample",
                        "namespace": {"full_path": "group"},
                        "web_url": "https://gitlab.test/group/sample",
                        "default_branch": "main",
                    }
                ]
            )
        if request.url.path in {
            "/api/v4/projects/group%2Fsample",
            "/api/v4/projects/group/sample",
        }:
            return _json_response(
                {
                    "id": 42,
                    "path": "sample",
                    "path_with_namespace": "group/sample",
                    "namespace": {"full_path": "group"},
                    "web_url": "https://gitlab.test/group/sample",
                    "default_branch": "main",
                }
            )
        if request.url.path == "/api/v4/projects/42/pipelines":
            return _json_response([{"id": 12, "status": "failed", "ref": "main", "sha": "abc123"}])
        if request.url.path == "/api/v4/projects/42/repository/tree":
            if request.url.params.get("recursive") is None:
                return _json_response(
                    [
                        {"path": ".gitlab-ci.yml", "type": "blob"},
                        {"path": "ci", "type": "tree"},
                        {"path": "src", "type": "tree"},
                        {"path": "src/main.py", "type": "blob"},
                    ]
                )
            if request.url.params.get("page") == "1":
                return httpx.Response(
                    200,
                    json=[
                        {"path": "ci", "type": "tree"},
                    ],
                    headers={"x-next-page": "2"},
                )
            return _json_response(
                [
                    {"path": "ci/deploy.yml", "type": "blob"},
                    {"path": "ci/templates/job.yml", "type": "blob"},
                ]
            )
        if request.url.path == "/api/v4/projects/42/jobs/55/trace":
            return httpx.Response(
                200, text="$ pytest\nFAILED tests/test_api.py::test_login\nexit code 1"
            )
        if request.url.path == "/api/v4/projects/42/repository/files/.gitlab-ci.yml/raw":
            return httpx.Response(200, text=root_yaml)
        if request.url.path in {
            "/api/v4/projects/42/repository/files/ci/deploy.yml/raw",
            "/api/v4/projects/42/repository/files/ci%2Fdeploy.yml/raw",
        }:
            return httpx.Response(200, text=deploy_yaml)
        raise AssertionError(f"Unexpected request: {request.url}")

    provider = GitLabProvider("https://gitlab.test", transport=httpx.MockTransport(handler))
    identity = await provider.validate_token("token")
    repositories = await provider.list_repositories("token")
    resolved_repository = await provider.get_repository_by_path("token", "group/sample")
    runs = await provider.list_failed_runs("token", repositories[0])
    trace = await provider.fetch_job_log("token", repositories[0], "12", "55")
    bundle = await provider.fetch_ci_config_bundle("token", repositories[0], runs[0])
    tree = await provider.list_repository_tree("token", repositories[0])
    top_level_tree = await provider.list_repository_tree("token", repositories[0], max_depth=1)

    assert identity.provider == ProviderName.GITLAB
    assert repositories[0].external_id == "42"
    assert resolved_repository.display_name == "group/sample"
    assert "FAILED" in trace
    assert [item.path for item in bundle] == [".gitlab-ci.yml", "ci/deploy.yml"]
    assert [entry.path for entry in tree] == [
        ".gitlab-ci.yml",
        "ci",
        "ci/deploy.yml",
        "ci/templates/job.yml",
    ]
    assert [entry.path for entry in top_level_tree] == [".gitlab-ci.yml", "ci", "src"]


@pytest.mark.asyncio
async def test_gitlab_adapter_fetches_an_accessible_project_include() -> None:
    GitLabProvider._config_bundle_cache.clear()
    root_repository = RepositoryRef(
        provider=ProviderName.GITLAB,
        external_id="42",
        owner="group",
        name="sample",
        web_url="https://gitlab.test/group/sample",
        default_branch="main",
    )
    root_yaml = """include:
  - project: platform/shared-ci
    file: HandleAll.yml
    ref: release/1.0
"""
    external_yaml = """build-job:
  stage: build
  script: dotnet test
"""

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["PRIVATE-TOKEN"] == "token"
        if request.url.path == "/api/v4/projects/42/repository/files/.gitlab-ci.yml/raw":
            return httpx.Response(200, text=root_yaml)
        if request.url.path in {
            "/api/v4/projects/platform%2Fshared-ci",
            "/api/v4/projects/platform/shared-ci",
        }:
            return _json_response(
                {
                    "id": 88,
                    "path": "shared-ci",
                    "path_with_namespace": "platform/shared-ci",
                    "namespace": {"full_path": "platform"},
                    "web_url": "https://gitlab.test/platform/shared-ci",
                    "default_branch": "main",
                }
            )
        if request.url.path == "/api/v4/projects/88/repository/files/HandleAll.yml/raw":
            assert request.url.params["ref"] == "release/1.0"
            return httpx.Response(200, text=external_yaml)
        raise AssertionError(f"Unexpected request: {request.url}")

    provider = GitLabProvider("https://gitlab.test", transport=httpx.MockTransport(handler))
    bundle = await provider.fetch_ci_config_bundle(
        "token",
        root_repository,
        PipelineRun(external_id="12", name="Pipeline #12", status="failed", commit_sha="abc123"),
    )

    assert [config.path for config in bundle] == [
        ".gitlab-ci.yml",
        project_include_key("platform/shared-ci", "HandleAll.yml", "release/1.0"),
    ]
    assert bundle[1].source_url is not None
    assert bundle[1].source_url.endswith("HandleAll.yml")


@pytest.mark.asyncio
async def test_gitlab_access_audit_reports_readable_unreadable_and_unresolved_sources() -> None:
    repository = RepositoryRef(
        provider=ProviderName.GITLAB,
        external_id="91",
        owner="group",
        name="audited",
        web_url="https://gitlab.test/group/audited",
        default_branch="main",
    )
    root_yaml = """include:
  - local: ci/readable.yml
  - local: ci/restricted.yml
  - remote: https://example.invalid/shared.yml
"""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v4/projects/91/repository/files/.gitlab-ci.yml/raw":
            return httpx.Response(200, text=root_yaml)
        if request.url.path in {
            "/api/v4/projects/91/repository/files/ci%2Freadable.yml/raw",
            "/api/v4/projects/91/repository/files/ci/readable.yml/raw",
        }:
            return httpx.Response(200, text="test:\n  script: pytest\n")
        if request.url.path in {
            "/api/v4/projects/91/repository/files/ci%2Frestricted.yml/raw",
            "/api/v4/projects/91/repository/files/ci/restricted.yml/raw",
        }:
            return _json_response({"message": "forbidden"}, status_code=403)
        raise AssertionError(f"Unexpected request: {request.url}")

    provider = GitLabProvider("https://gitlab.test", transport=httpx.MockTransport(handler))
    report = await provider.inspect_ci_config_access(
        "token",
        repository,
        PipelineRun(external_id="17", name="Pipeline #17", status="failed", commit_sha="abc123"),
    )
    entries = {entry.path: entry for entry in report.entries}

    assert report.complete is False
    assert entries[".gitlab-ci.yml"].state == "readable"
    assert entries["ci/readable.yml"].state == "readable"
    assert entries["ci/restricted.yml"].state == "unreadable"
    assert entries["ci/restricted.yml"].detail == (
        "The token can access the pipeline but cannot read this CI configuration source."
    )
    assert entries[".gitlab-ci.yml (unresolved include)"].state == "unresolved"


@pytest.mark.asyncio
async def test_gitlab_adapter_reuses_the_resolved_config_bundle_for_the_same_commit() -> None:
    GitLabProvider._config_bundle_cache.clear()
    repository = RepositoryRef(
        provider=ProviderName.GITLAB,
        external_id="52",
        owner="group",
        name="cached",
        web_url="https://gitlab.test/group/cached",
        default_branch="main",
    )
    request_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_count
        request_count += 1
        assert request.url.path == "/api/v4/projects/52/repository/files/.gitlab-ci.yml/raw"
        return httpx.Response(200, text="test:\n  script: pytest\n")

    provider = GitLabProvider("https://gitlab.test", transport=httpx.MockTransport(handler))
    run = PipelineRun(external_id="14", name="Pipeline #14", status="failed", commit_sha="abc123")

    first = await provider.fetch_ci_config_bundle("token", repository, run)
    second = await provider.fetch_ci_config_bundle("token", repository, run)

    assert first == second
    assert request_count == 1


@pytest.mark.asyncio
async def test_gitlab_adapter_stops_after_finding_the_selected_job_definition() -> None:
    GitLabProvider._config_bundle_cache.clear()
    repository = RepositoryRef(
        provider=ProviderName.GITLAB,
        external_id="53",
        owner="group",
        name="targeted",
        web_url="https://gitlab.test/group/targeted",
        default_branch="main",
    )
    root_yaml = """include:
  - local: ci/target.yml
"""
    target_yaml = """target-job:
  stage: test
  script: pytest
include:
  - local: ci/not-needed.yml
"""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v4/projects/53/repository/files/.gitlab-ci.yml/raw":
            return httpx.Response(200, text=root_yaml)
        if request.url.path in {
            "/api/v4/projects/53/repository/files/ci%2Ftarget.yml/raw",
            "/api/v4/projects/53/repository/files/ci/target.yml/raw",
        }:
            return httpx.Response(200, text=target_yaml)
        raise AssertionError("The target-aware fetch should not request downstream unrelated includes.")

    provider = GitLabProvider("https://gitlab.test", transport=httpx.MockTransport(handler))
    bundle = await provider.fetch_ci_config_bundle(
        "token",
        repository,
        PipelineRun(external_id="15", name="Pipeline #15", status="failed", commit_sha="abc123"),
        target_job_name="target-job",
    )

    assert [item.path for item in bundle] == [".gitlab-ci.yml", "ci/target.yml"]


@pytest.mark.asyncio
async def test_gitlab_adapter_cancels_unrelated_include_reads_after_target_found(
    monkeypatch,
) -> None:
    GitLabProvider._config_bundle_cache.clear()
    repository = RepositoryRef(
        provider=ProviderName.GITLAB,
        external_id="54",
        owner="group",
        name="targeted-cancel",
        web_url="https://gitlab.test/group/targeted-cancel",
        default_branch="main",
    )
    slow_read_started = asyncio.Event()
    slow_read_cancelled = False
    never_complete = asyncio.Event()

    async def fetch_file_at_ref(token, requested_repository, path, ref):
        nonlocal slow_read_cancelled
        del token, requested_repository
        if path == ".gitlab-ci.yml":
            return CiConfigFile(
                path=path,
                ref=ref,
                content="include:\n  - local: ci/target.yml\n  - local: ci/slow.yml\n",
            )
        if path == "ci/target.yml":
            await slow_read_started.wait()
            return CiConfigFile(path=path, ref=ref, content="target-job:\n  script: pytest\n")
        if path == "ci/slow.yml":
            slow_read_started.set()
            try:
                await never_complete.wait()
            except asyncio.CancelledError:
                slow_read_cancelled = True
                raise
        raise AssertionError(f"Unexpected path: {path}")

    provider = GitLabProvider("https://gitlab.test")
    monkeypatch.setattr(provider, "fetch_file_at_ref", fetch_file_at_ref)
    bundle = await provider.fetch_ci_config_bundle(
        "token",
        repository,
        PipelineRun(external_id="16", name="Pipeline #16", status="failed", commit_sha="abc123"),
        target_job_name="target-job",
    )

    assert [item.path for item in bundle] == [".gitlab-ci.yml", "ci/target.yml"]
    assert slow_read_cancelled is True


@pytest.mark.asyncio
async def test_gitlab_adapter_request_scope_reuses_and_closes_its_http_client() -> None:
    provider = GitLabProvider("https://gitlab.test")

    async with provider:
        first_client = provider._shared_client
        assert first_client is not None
        assert provider._shared_client is first_client

    assert provider._shared_client is None
