"""Isolated, read-only GitLab inspection regressions; never uses real credentials or I/O."""

import asyncio
from collections import Counter
from dataclasses import is_dataclass

import httpx
import pytest

from pipelinelens.domain import PipelineRun, ProviderName, RepositoryRef
from pipelinelens.providers.base import ProviderError
from pipelinelens.providers.gitlab import ConfigInspection, GitLabProvider
from pipelinelens.services.gitlab_includes import project_include_key
from pipelinelens.services.pipeline_url import PipelineUrlError, parse_gitlab_url
from pipelinelens.services.yaml_graph import analyze_gitlab_yaml

ORIGIN = "https://gitlab.test"
ROOT_SHA = "a" * 40
EXTERNAL_SHA = "b" * 40


def repository(project_id="42", path="group/sample", **kwargs):
    owner, _, name = path.rpartition("/")
    return RepositoryRef(
        provider=ProviderName.GITLAB, external_id=project_id, owner=owner, name=name,
        web_url=f"{ORIGIN}/{path}", default_branch="main", **kwargs,
    )


def project_payload(project_id, path, **kwargs):
    owner, _, name = path.rpartition("/")
    return {
        "id": int(project_id), "path": name, "namespace": {"full_path": owner},
        "path_with_namespace": path, "web_url": f"{ORIGIN}/{path}", **kwargs,
    }


def run(**kwargs):
    return PipelineRun(
        external_id="60178941", name="pipeline", status="success", commit_sha=ROOT_SHA, **kwargs
    )


def provider_for(handler):
    async def guarded(request):
        assert request.method == "GET"
        assert request.url.host == "gitlab.test"
        assert request.headers["PRIVATE-TOKEN"] in {"test-token", "other-token"}
        result = handler(request)
        if asyncio.iscoroutine(result):
            result = await result
        return result

    return GitLabProvider(ORIGIN, transport=httpx.MockTransport(guarded))


def test_repository_and_job_populate_new_domain_fields() -> None:
    empty_config = GitLabProvider._repository(
        project_payload(407446, "group/rlp", ci_config_path="")
    )
    assert empty_config.ci_config_path is None
    assert GitLabProvider._repository(
        project_payload(33268, "q2c-nextgen/q2c_code_sfdx", ci_config_path="ci/main.yml")
    ).ci_config_path == "ci/main.yml"
    job = GitLabProvider._job({
        "id": 181725104, "name": "sonarqube-check", "status": "failed",
        "allow_failure": True, "failure_reason": "runner_system_failure",
    })
    assert job.allow_failure is True
    assert job.failure_reason == "runner_system_failure"
    assert GitLabProvider._job({"id": 1}).allow_failure is False


@pytest.mark.asyncio
async def test_all_status_jobs_are_paginated_and_allowed_failure_is_preserved() -> None:
    calls = []

    def handler(request):
        assert request.url.path == "/api/v4/projects/42/pipelines/59848076/jobs"
        assert "scope[]" not in request.url.params
        assert request.url.params["include_retried"] == "false"
        page = int(request.url.params["page"])
        calls.append(page)
        if page == 1:
            return httpx.Response(200, json=[
                {"id": 181725104, "name": "sonarqube-check", "status": "failed",
                 "allow_failure": True, "failure_reason": "runner_system_failure"},
                {"id": 2, "status": "success"},
            ], headers={"x-next-page": "2"})
        return httpx.Response(200, json=[
            {"id": 3, "status": "manual"}, {"id": 4, "status": "skipped"},
            {"id": 5, "status": "running"}, {"id": 6, "status": "canceled"},
        ])

    jobs = await provider_for(handler).list_pipeline_jobs("test-token", repository(), "59848076")
    assert calls == [1, 2]
    assert {job.status for job in jobs} == {
        "failed", "success", "manual", "skipped", "running", "canceled",
    }
    assert jobs[0].allow_failure is True
    assert jobs[0].failure_reason == "runner_system_failure"


@pytest.mark.asyncio
async def test_jobs_bound_pages_results_and_repeated_next_page_headers() -> None:
    calls = []

    def handler(request):
        calls.append(int(request.url.params["page"]))
        return httpx.Response(
            200, json=[{"id": index, "status": "pending"} for index in range(100)],
            headers={"x-next-page": "1"},
        )

    provider = provider_for(handler)
    assert len(await provider.list_pipeline_jobs("test-token", repository(), "12", 3)) == 3
    assert len(await provider.list_pipeline_jobs("test-token", repository(), "12", 300)) == 100
    assert await provider.list_pipeline_jobs("test-token", repository(), "12", 0) == []
    assert calls == [1, 1]


@pytest.mark.asyncio
async def test_bridges_are_paginated_bounded_and_only_public_allowlisted_fields_escape() -> None:
    def handler(request):
        assert request.url.path.endswith("/pipelines/12/bridges")
        assert "scope[]" not in request.url.params
        page = int(request.url.params["page"])
        return httpx.Response(200, json=[{
            "id": page, "name": "child", "status": "success", "allow_failure": True,
            "user": {"email": "private@example.test"}, "token": "not-for-output",
            "variables": [{"key": "SECRET", "value": "not-for-output"}],
            "downstream_pipeline": {
                "id": 17, "iid": 2, "project_id": 99, "ref": "main", "sha": ROOT_SHA,
                "web_url": f"{ORIGIN}/group/child/-/pipelines/17", "status": "success",
                "variables": {"TOKEN": "not-for-output"}, "user": {"email": "private"},
            },
        }], headers={"x-next-page": "2" if page == 1 else ""})

    bridges = await provider_for(handler).list_pipeline_bridges("test-token", repository(), "12")
    assert len(bridges) == 2
    assert set(bridges[0]) == {"id", "name", "status", "allow_failure", "downstream_pipeline"}
    assert set(bridges[0]["downstream_pipeline"]) == {
        "id", "iid", "project_id", "ref", "sha", "web_url", "status",
    }
    assert "not-for-output" not in str(bridges)
    assert "email" not in str(bridges)


@pytest.mark.asyncio
async def test_job_url_retains_parent_pipeline_and_success_run_can_have_allowed_failure() -> None:
    def handler(request):
        if request.url.path.endswith("/jobs/182928815"):
            return httpx.Response(200, json={
                "id": 182928815, "name": "successful-job", "status": "success",
                "pipeline": {"id": 60178941, "project_id": 33268},
            })
        if request.url.path.endswith("/pipelines/59848076"):
            return httpx.Response(200, json={"id": 59848076, "status": "success", "sha": ROOT_SHA})
        raise AssertionError("Unexpected mocked endpoint")

    provider = provider_for(handler)
    parsed = parse_gitlab_url(f"{ORIGIN}/q2c-nextgen/q2c_code_sfdx/-/jobs/182928815")
    job = await provider.get_job("test-token", repository("33268"), "", parsed.job_id)
    assert job.raw["pipeline"]["id"] == 60178941
    assert job.status == "success"
    assert (await provider.get_run("test-token", repository(), "59848076")).status == "success"


@pytest.mark.asyncio
async def test_latest_run_and_exact_slash_ref_commit_resolution() -> None:
    def handler(request):
        if request.url.path.endswith("/pipelines"):
            assert "status" not in request.url.params
            assert request.url.params["per_page"] == "1"
            assert request.url.params["order_by"] == "id"
            if request.url.params["ref"] == "empty":
                return httpx.Response(200, json=[])
            assert request.url.params["ref"] == "validation_release_godzilla"
            return httpx.Response(200, json=[{
                "id": 17, "status": "success", "ref": "validation_release_godzilla",
                "sha": ROOT_SHA,
            }])
        assert request.url.path.endswith("/repository/commits/release/4.2")
        assert b"release%2F4.2" in request.url.raw_path
        return httpx.Response(200, json={"id": EXTERNAL_SHA})

    provider = provider_for(handler)
    result = await provider.latest_run_for_ref(
        "test-token", repository(), "validation_release_godzilla"
    )
    assert result.status == "success"
    assert await provider.latest_run_for_ref("test-token", repository(), "empty") is None
    assert await provider.resolve_commit("test-token", repository(), "release/4.2") == EXTERNAL_SHA


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["blob", "tree"])
async def test_longest_existing_ref_disambiguates_directories_from_slash_branches(kind) -> None:
    calls = []

    def handler(request):
        ref = request.url.path.split("/repository/commits/", 1)[1]
        calls.append(ref)
        if ref == "release/4.2":
            return httpx.Response(200, json={"id": EXTERNAL_SHA})
        return httpx.Response(404)

    provider = provider_for(handler)
    suffix = "ci/nested.yml" if kind == "blob" else "ci"
    parsed = parse_gitlab_url(f"{ORIGIN}/group/sample/-/{kind}/release/4.2/{suffix}")
    resolved = await provider.resolve_reference("test-token", repository(), parsed)
    assert resolved.ref == "release/4.2"
    assert resolved.file_path == suffix
    assert calls == ["release/4.2/ci", "release/4.2"]


@pytest.mark.asyncio
async def test_full_inspection_reads_entire_chain_once_despite_root_job_match() -> None:
    counts = Counter()
    sources = {
        ".gitlab-ci.yml": """spec:
  inputs: {}
---
include:
  - local: ci/first.yml
target:
  script: !reference [.hidden, script]
""",
        "ci/first.yml": "include: /.gitlab/deeper.yml\nfirst:\n  script: echo first\n",
        ".gitlab/deeper.yml": ".hidden:\n  script: pytest\nlast:\n  script: echo last\n",
    }

    def handler(request):
        path = request.url.path.split("/repository/files/", 1)[1].removesuffix("/raw")
        counts[path] += 1
        assert request.url.params["ref"] == ROOT_SHA
        return httpx.Response(200, text=sources[path])

    provider = provider_for(handler)
    first, second = await asyncio.gather(
        provider.load_ci_sources("test-token", repository(), run()),
        provider.load_ci_sources("test-token", repository(), run()),
    )
    assert is_dataclass(first) and isinstance(first, ConfigInspection)
    assert [config.path for config in first.configs] == list(sources)
    assert first.access.complete is True
    assert first.access.notes == []
    assert first == second
    first.configs[0].content = "changed by caller"
    third = await provider.load_ci_sources("test-token", repository(), run())
    assert third.configs[0].content == sources[".gitlab-ci.yml"]
    assert counts == {path: 1 for path in sources}
    graph = analyze_gitlab_yaml(
        third.configs[0], {item.path: item.content for item in third.configs}.get
    )
    assert {node.key for node in graph.nodes} == {"target", "first", "last"}


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", [None, "", "ci/custom.yml", ".gitlab/main.yml"])
async def test_ci_config_setting_selects_root_and_never_substitutes_an_include(configured) -> None:
    expected = configured or ".gitlab-ci.yml"

    def handler(request):
        assert request.url.path.endswith(f"/repository/files/{expected}/raw")
        return httpx.Response(200, text="root-job:\n  script: echo root\n")

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository("407446", ci_config_path=configured), run()
    )
    assert result.configs[0].path == expected
    assert result.access.entries[0].relationship == "root"


@pytest.mark.asyncio
async def test_live_sfdx_include_array_rules_and_mutable_head_keep_logical_keys() -> None:
    external = "q2c-nextgen/q2c_code_sfdx-ci"
    files = [
        "SalesforceDelta.gitlab-ci.yml", "Salesforce.gitlab-ci.yml", "dataloader.gitlab-ci.yml",
    ]
    counts = Counter()

    def handler(request):
        counts[request.url.path] += 1
        if request.url.path == "/api/v4/projects/33268/repository/files/.gitlab-ci.yml/raw":
            return httpx.Response(200, text=f"""include:
  - project: {external}
    file: {files[0]}
    rules:
      - if: $SALESFORCE_DELTA
  - project: {external}
    file: [{files[1]}, {files[2]}]
""")
        if request.url.path == f"/api/v4/projects/{external}":
            return httpx.Response(200, json=project_payload(88, external))
        if request.url.path == "/api/v4/projects/88/repository/commits/HEAD":
            return httpx.Response(200, json={"id": EXTERNAL_SHA})
        path = request.url.path.split("/repository/files/", 1)[1].removesuffix("/raw")
        assert request.url.params["ref"] == EXTERNAL_SHA
        assert path in files
        return httpx.Response(200, text=f"job-{files.index(path)}:\n  script: echo fixture\n")

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository("33268", "q2c-nextgen/q2c_code_sfdx"),
        run(ref_name="validation_release_godzilla"),
    )
    assert [config.path for config in result.configs] == [
        ".gitlab-ci.yml", *[project_include_key(external, path, "HEAD") for path in files],
    ]
    assert counts[f"/api/v4/projects/{external}"] == 1
    assert counts["/api/v4/projects/88/repository/commits/HEAD"] == 1
    assert any("potential" in note for note in result.access.notes)
    assert any("historical" in note for note in result.access.notes)
    assert not result.access.complete
    graph = analyze_gitlab_yaml(
        result.configs[0], {item.path: item.content for item in result.configs}.get
    )
    assert len(graph.nodes) == 3
    assert not any("unavailable" in note for note in graph.unresolved_includes)


@pytest.mark.asyncio
async def test_handleall_slash_ref_and_nested_external_local_use_physical_root_paths() -> None:
    external = "sfdc-dxdevops/Q2C/asfgitlabtools"
    counts = Counter()

    def handler(request):
        counts[request.url.path] += 1
        if request.url.path == "/api/v4/projects/521276/repository/files/.gitlab-ci.yml/raw":
            return httpx.Response(200, text=f"""include:
  project: {external}
  file: HandleAll.yml
  ref: release/4.2
""")
        if request.url.path == f"/api/v4/projects/{external}":
            return httpx.Response(200, json=project_payload(99, external))
        if request.url.path == "/api/v4/projects/99/repository/commits/release/4.2":
            return httpx.Response(200, json={"id": EXTERNAL_SHA})
        assert request.url.path.startswith("/api/v4/projects/99/repository/files/")
        assert request.url.params["ref"] == EXTERNAL_SHA
        path = request.url.path.split("/repository/files/", 1)[1].removesuffix("/raw")
        sources = {
            "HandleAll.yml": "include: ci/deep.yml\n",
            "ci/deep.yml": "include: /.gitlab/jobs.yml\n",
            ".gitlab/jobs.yml": "build-job:\n  script: dotnet test\n",
        }
        return httpx.Response(200, text=sources[path])

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository("521276", "sfdc-dxdevops/q2c/q2c"), run(ref_name="develop")
    )
    expected = project_include_key(external, ".gitlab/jobs.yml", "release/4.2")
    assert result.configs[-1].path == expected
    assert result.configs[-1].ref == EXTERNAL_SHA
    assert counts["/api/v4/projects/99/repository/commits/release/4.2"] == 1
    graph = analyze_gitlab_yaml(
        result.configs[0], {item.path: item.content for item in result.configs}.get
    )
    assert graph.nodes[0].source.path == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["raw", "blob"])
async def test_same_host_remote_gitlab_include_uses_api_and_keeps_nested_loader_keys(kind) -> None:
    remote = f"{ORIGIN}/group/shared/-/{kind}/release/4.2/ci/entry.yml?ref_type=heads"
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if request.url.path == "/api/v4/projects/42/repository/files/.gitlab-ci.yml/raw":
            return httpx.Response(200, text=f"include:\n  remote: {remote}\n")
        if request.url.path == "/api/v4/projects/group/shared":
            return httpx.Response(200, json=project_payload(99, "group/shared"))
        if "/repository/commits/" in request.url.path:
            return (httpx.Response(200, json={"id": EXTERNAL_SHA})
                    if request.url.path.endswith("/release/4.2") else httpx.Response(404))
        assert request.url.params["ref"] == EXTERNAL_SHA
        if request.url.path.endswith("/repository/files/ci/entry.yml/raw"):
            return httpx.Response(200, text="include: .gitlab/jobs.yml\n")
        assert request.url.path.endswith("/repository/files/.gitlab/jobs.yml/raw")
        return httpx.Response(200, text="test:\n  script: pytest\n")

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert result.configs[1].path == remote
    assert result.configs[1].ref == EXTERNAL_SHA
    assert all(path.startswith("/api/v4/projects/") for path in calls)
    graph = analyze_gitlab_yaml(
        result.configs[0], {item.path: item.content for item in result.configs}.get
    )
    assert [node.key for node in graph.nodes] == ["test"]
    assert not any("unavailable" in note for note in graph.unresolved_includes)


@pytest.mark.asyncio
async def test_external_or_secret_remote_urls_are_never_requested_or_echoed() -> None:
    urls = [
        "https://evil.test/group/ci/-/raw/main/.gitlab-ci.yml",
        "https://gitlab.test.evil.test/group/ci/-/raw/main/.gitlab-ci.yml",
        "https://user:private-value@gitlab.test/group/ci/-/raw/main/.gitlab-ci.yml",
        "https://gitlab.test/group/ci/-/raw/main/.gitlab-ci.yml?private_token=private-value",
    ]
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        assert request.url.path == "/api/v4/projects/42/repository/files/.gitlab-ci.yml/raw"
        return httpx.Response(
            200, text="include:\n" + "".join(f"  - remote: {url}\n" for url in urls)
        )

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert calls == 1
    assert not result.access.complete
    assert "private-value" not in result.access.model_dump_json()
    assert any("external" in note.lower() for note in result.access.notes)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 302, 307, 308])
async def test_redirects_do_not_forward_private_token_even_for_api_requests(status) -> None:
    calls = []

    def handler(request):
        calls.append(request.url.host)
        return httpx.Response(status, headers={"location": "https://evil.test/collect"})

    provider = provider_for(handler)
    result = await provider.load_ci_sources("test-token", repository(), run())
    assert calls == ["gitlab.test"]
    assert result.configs == []
    assert result.access.entries[0].relationship == "root"
    assert result.access.entries[0].state == "unreadable"
    assert "test-token" not in result.access.model_dump_json()


@pytest.mark.asyncio
async def test_denied_project_duplicates_and_cycles_have_bounded_requests_and_notes() -> None:
    counts = Counter()

    def handler(request):
        counts[request.url.path] += 1
        if request.url.path.endswith("/repository/files/.gitlab-ci.yml/raw"):
            return httpx.Response(200, text="""include:
  - local: ci/cycle.yml
  - project: private/denied
    file: [a.yml, b.yml, c.yml, a.yml]
""")
        if request.url.path.endswith("/repository/files/ci/cycle.yml/raw"):
            return httpx.Response(200, text="include: .gitlab-ci.yml\n")
        assert request.url.path == "/api/v4/projects/private/denied"
        return httpx.Response(403, json={"message": "test-token private contents"})

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert sum(counts.values()) == 3
    assert any(entry.state == "unreadable" for entry in result.access.entries)
    assert any("cycle" in note.lower() for note in result.access.notes)
    assert "test-token" not in result.access.model_dump_json()


@pytest.mark.asyncio
async def test_huge_fanout_and_denied_projects_are_bounded_before_resolution() -> None:
    calls = Counter()

    def handler(request):
        calls[request.url.path] += 1
        if request.url.path.endswith("/repository/files/.gitlab-ci.yml/raw"):
            return httpx.Response(200, text="include:\n" + "".join(
                f"  - project: group/project{index}\n    file: ci.yml\n" for index in range(500)
            ))
        return httpx.Response(403)

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository(), run(), max_files=3
    )
    assert sum(calls.values()) <= 13
    assert len(result.configs) <= 3
    assert any("truncated" in note for note in result.access.notes)


@pytest.mark.asyncio
async def test_file_limit_stops_reads_even_when_every_include_is_a_distinct_local_file() -> None:
    calls = 0

    def handler(_request):
        nonlocal calls
        calls += 1
        content = (
            "include: [a.yml, b.yml, c.yml, d.yml, e.yml]\n" if calls == 1
            else "job:\n  script: true\n"
        )
        return httpx.Response(200, text=content)

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository(), run(), max_files=3
    )
    assert calls == 3
    assert len(result.configs) == 3
    assert any("truncated" in note for note in result.access.notes)


@pytest.mark.asyncio
async def test_inspection_parallelism_is_bounded_and_results_preserve_declaration_order() -> None:
    active = 0
    peak = 0
    batch_ready = asyncio.Event()

    async def handler(request):
        nonlocal active, peak
        if request.url.path.endswith("/repository/files/.gitlab-ci.yml/raw"):
            return httpx.Response(200, text="include: [a.yml, b.yml, c.yml, d.yml]\n")
        active += 1
        peak = max(peak, active)
        if active == 4:
            batch_ready.set()
        await asyncio.wait_for(batch_ready.wait(), 2)
        active -= 1
        return httpx.Response(200, text="job:\n  script: pytest\n")

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert peak == 4
    assert [config.path for config in result.configs] == [
        ".gitlab-ci.yml", "a.yml", "b.yml", "c.yml", "d.yml",
    ]


@pytest.mark.asyncio
async def test_instance_and_token_caches_are_isolated_and_close_clears_them() -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if request.headers["PRIVATE-TOKEN"] == "other-token":
            return httpx.Response(403)
        return httpx.Response(200, text="private-job:\n  script: pytest\n")

    provider = provider_for(handler)
    first = await provider.load_ci_sources("test-token", repository(), run())
    second = await provider.load_ci_sources("other-token", repository(), run())
    third = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert first.configs and third.configs
    assert not second.configs
    assert calls == 3
    assert GitLabProvider._config_bundle_cache == {}
    await provider.aclose()
    assert provider._request_cache == {}
    await provider.load_ci_sources("test-token", repository(), run())
    assert calls == 4


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "content", ["job: [invalid", "- scalar-list", "job:\n  script: !reference [.hidden, script]\n"]
)
async def test_invalid_yaml_is_partial_and_reference_tags_do_not_block_discovery(content) -> None:
    result = await provider_for(lambda _: httpx.Response(200, text=content)).load_ci_sources(
        "test-token", repository(), run()
    )
    assert len(result.configs) == 1
    if "!reference" in content:
        assert not any("parse" in note for note in result.access.notes)
    else:
        assert result.access.notes
        assert result.access.complete is False


@pytest.mark.asyncio
async def test_ref_resolution_failure_falls_back_with_historical_warning() -> None:
    def handler(request):
        if request.url.path.endswith("/projects/42/repository/files/.gitlab-ci.yml/raw"):
            return httpx.Response(
                200, text="include: {project: group/shared, file: job.yml, ref: v1}\n"
            )
        if request.url.path == "/api/v4/projects/group/shared":
            return httpx.Response(200, json=project_payload(88, "group/shared"))
        if "/repository/commits/" in request.url.path:
            return httpx.Response(403)
        assert request.url.params["ref"] == "v1"
        return httpx.Response(200, text="job:\n  script: pytest\n")

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert len(result.configs) == 2
    assert any("could not be pinned" in note for note in result.access.notes)
    assert any("historical" in note for note in result.access.notes)


@pytest.mark.asyncio
async def test_inspection_read_budget_counts_commit_disambiguation_calls() -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if request.url.path.endswith("/repository/files/.gitlab-ci.yml/raw"):
            tail = "/".join(["part"] * 30)
            return httpx.Response(200, text="include:\n" + "".join(
                f"  - remote: {ORIGIN}/group/p{i}/-/raw/{tail}/file.yml\n" for i in range(12)
            ))
        if "/repository/commits/" in request.url.path:
            return httpx.Response(404)
        return httpx.Response(
            200, json=project_payload(99, request.url.path.split("/projects/")[1])
        )

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository(), run(), max_files=2
    )
    assert calls <= 18
    assert any("truncated" in note for note in result.access.notes)


@pytest.mark.parametrize(
    "base", ["http://gitlab.test", "https://user:secret@gitlab.test", "https://gitlab.test:99999"]
)
def test_provider_rejects_unsafe_configured_origins(base) -> None:
    with pytest.raises(PipelineUrlError):
        GitLabProvider(base)


@pytest.mark.asyncio
async def test_read_only_provider_rejects_non_get_and_absolute_request_paths() -> None:
    provider = provider_for(lambda _: pytest.fail("Unsafe API call should be rejected before I/O"))
    for method, path in [
        ("POST", "/projects/42"), ("GET", "https://evil.test/"), ("GET", "//evil.test/"),
    ]:
        with pytest.raises(ProviderError):
            await provider._request("test-token", method, path)


@pytest.mark.asyncio
async def test_job_pagination_keeps_page_size_stable_for_non_multiple_limits() -> None:
    pages = []

    def handler(request):
        page, size = int(request.url.params["page"]), int(request.url.params["per_page"])
        pages.append((page, size))
        start = (page - 1) * size
        return httpx.Response(200, json=[
            {"id": index, "status": "success"} for index in range(start, start + size)
        ], headers={"x-next-page": str(page + 1)})

    jobs = await provider_for(handler).list_pipeline_jobs("test-token", repository(), "12", 125)
    assert [job.external_id for job in jobs] == [str(index) for index in range(125)]
    assert pages == [(1, 100), (2, 100)]


@pytest.mark.asyncio
async def test_bridge_listing_has_a_hard_result_limit() -> None:
    count = 0

    def handler(request):
        nonlocal count
        count += 1
        page = int(request.url.params["page"])
        return httpx.Response(200, json=[
            {"id": (page - 1) * 100 + index, "status": "success"} for index in range(100)
        ], headers={"x-next-page": str(page + 1)})

    bridges = await provider_for(handler).list_pipeline_bridges("test-token", repository(), "12")
    assert len(bridges) == 300
    assert count == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", [".gitlab-ci.yml", "ci/custom.yml"])
async def test_tree_always_preserves_the_actual_ci_root_within_its_result_limit(configured) -> None:
    def handler(request):
        if request.url.path.endswith("/repository/tree"):
            return httpx.Response(200, json=[
                {"path": "src", "type": "tree"}, {"path": configured, "type": "blob"},
            ])
        assert request.url.path.endswith(f"/repository/files/{configured}/raw")
        return httpx.Response(200, text="job:\n  script: pytest\n")

    entries = await provider_for(handler).list_repository_tree(
        "test-token", repository(ci_config_path=configured), ROOT_SHA, max_entries=1
    )
    assert [entry.path for entry in entries] == [configured]


@pytest.mark.asyncio
async def test_custom_project_ci_entry_is_first_and_uses_the_external_commit() -> None:
    def handler(request):
        if request.url.path == "/api/v4/projects/group/shared":
            return httpx.Response(200, json=project_payload(88, "group/shared"))
        if request.url.path.endswith("/repository/commits/release/4.2"):
            return httpx.Response(200, json={"id": EXTERNAL_SHA})
        assert request.url.path == "/api/v4/projects/88/repository/files/ci/main.yml/raw"
        assert request.url.params["ref"] == EXTERNAL_SHA
        return httpx.Response(200, text="external-root:\n  script: pytest\n")

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository(ci_config_path="ci/main.yml@group/shared:release/4.2"), run()
    )
    expected = project_include_key("group/shared", "ci/main.yml", "release/4.2")
    assert result.configs[0].path == expected
    assert result.access.entries[0].relationship == "root"
    assert result.configs[0].ref == EXTERNAL_SHA


@pytest.mark.asyncio
async def test_custom_remote_ci_entry_is_loaded_via_the_same_host_api() -> None:
    remote = f"{ORIGIN}/group/shared/-/raw/main/.gitlab-ci.yml"

    def handler(request):
        if request.url.path == "/api/v4/projects/group/shared":
            return httpx.Response(200, json=project_payload(88, "group/shared"))
        if request.url.path.endswith("/repository/commits/main"):
            return httpx.Response(200, json={"id": EXTERNAL_SHA})
        assert request.url.path == "/api/v4/projects/88/repository/files/.gitlab-ci.yml/raw"
        return httpx.Response(200, text="external-root:\n  script: pytest\n")

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository(ci_config_path=remote), run()
    )
    assert result.configs[0].path == remote
    assert result.access.entries[0].relationship == "root"


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", ["../private.yml", "https://user:secret@evil.test/ci.yml"])
async def test_unsafe_ci_entry_point_is_partial_without_fallback_or_network(configured) -> None:
    provider = provider_for(lambda _: pytest.fail("Unsafe root entry must not contact GitLab"))
    result = await provider.load_ci_sources(
        "test-token", repository(ci_config_path=configured), run()
    )
    assert result.configs == []
    assert not result.access.complete
    assert "user:secret" not in result.access.model_dump_json()


@pytest.mark.asyncio
async def test_pinned_external_include_is_read_once_with_both_declared_loader_aliases() -> None:
    calls = Counter()

    def handler(request):
        calls[request.url.path] += 1
        if request.url.path.endswith("/projects/42/repository/files/.gitlab-ci.yml/raw"):
            return httpx.Response(200, text=f"""include:
  - project: group/shared
    file: job.yml
    ref: main
  - project: group/shared
    file: job.yml
    ref: {EXTERNAL_SHA}
""")
        if request.url.path == "/api/v4/projects/group/shared":
            return httpx.Response(200, json=project_payload(88, "group/shared"))
        if "/repository/commits/" in request.url.path:
            assert request.url.path.endswith("/main")
            return httpx.Response(200, json={"id": EXTERNAL_SHA})
        assert request.url.params["ref"] == EXTERNAL_SHA
        return httpx.Response(200, text="test:\n  script: pytest\n")

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert calls["/api/v4/projects/88/repository/files/job.yml/raw"] == 1
    assert {config.path for config in result.configs[1:]} == {
        project_include_key("group/shared", "job.yml", "main"),
        project_include_key("group/shared", "job.yml", EXTERNAL_SHA),
    }


@pytest.mark.asyncio
async def test_direct_commit_project_include_does_not_make_mutable_ref_claims() -> None:
    def handler(request):
        if request.url.path.endswith("/projects/42/repository/files/.gitlab-ci.yml/raw"):
            return httpx.Response(200, text=(
                f"include: {{project: group/shared, file: job.yml, ref: '{EXTERNAL_SHA}'}}\n"
            ))
        if request.url.path == "/api/v4/projects/group/shared":
            return httpx.Response(200, json=project_payload(88, "group/shared"))
        assert "/repository/commits/" not in request.url.path
        return httpx.Response(200, text="test:\n  script: pytest\n")

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert result.access.complete
    assert not result.access.notes


@pytest.mark.asyncio
async def test_empty_root_is_a_real_root_file_not_a_substitute_include() -> None:
    result = await provider_for(lambda _: httpx.Response(200, text="")).load_ci_sources(
        "test-token", repository("407446", ci_config_path=""), run()
    )
    assert result.configs[0].path == ".gitlab-ci.yml"
    assert result.configs[0].content == ""
    assert result.access.entries[0].state == "readable"


@pytest.mark.asyncio
async def test_missing_pipeline_sha_reports_root_mutability() -> None:
    pipeline = PipelineRun(external_id="1", name="run", status="success", ref_name="main")
    provider = provider_for(lambda _: httpx.Response(200, text="job:\n  script: pytest\n"))
    result = await provider.load_ci_sources("test-token", repository(), pipeline)
    assert result.configs[0].ref == "main"
    assert any("Root CI ref is mutable" in note for note in result.access.notes)
    assert not result.access.complete


@pytest.mark.asyncio
async def test_include_depth_is_bounded_and_not_silently_complete() -> None:
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, text=f"include: ci/level{calls}.yml\n")

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run(), 100)
    assert calls == 21
    assert any("depth" in note for note in result.access.notes)
    assert not result.access.complete


@pytest.mark.asyncio
async def test_invalid_project_response_yields_partial_report_without_exposing_payload() -> None:
    def handler(request):
        if request.url.path.endswith("/repository/files/.gitlab-ci.yml/raw"):
            return httpx.Response(200, text="include: {project: group/broken, file: job.yml}\n")
        return httpx.Response(200, json={"private": "do-not-echo"})

    result = await provider_for(handler).load_ci_sources("test-token", repository(), run())
    assert not result.access.complete
    assert "do-not-echo" not in result.access.model_dump_json()
    assert any("invalid source metadata" in note for note in result.access.notes)


@pytest.mark.asyncio
async def test_denied_custom_root_project_remains_the_root_in_the_access_report() -> None:
    def handler(request):
        assert request.url.path == "/api/v4/projects/group/private"
        return httpx.Response(403)

    result = await provider_for(handler).load_ci_sources(
        "test-token", repository(ci_config_path="ci.yml@group/private"), run()
    )
    assert result.configs == []
    assert result.access.entries[0].relationship == "root"
    assert result.access.entries[0].state == "unreadable"