"""Synthetic-only tests for the opt-in public GitHub Actions failure corpus."""

from __future__ import annotations

import asyncio
import base64
import json
import socket
import sqlite3
from hashlib import sha256
from unittest.mock import patch

import httpx
import pytest

# The normal analyzer still imports configuration. Block dotenv for its first import
# as well as runtime calls; no test may inspect a real environment or corpus file.
with (
    patch("dotenv.load_dotenv", return_value=False),
    patch("dotenv.main.DotEnv.dict", return_value={}),
):
    from pipelinelens.services import analysis, findings, public_corpus
    from pipelinelens.services.findings import Finding
    from pipelinelens.services.public_corpus import (
        MAX_CONFIG_BYTES,
        MAX_LOG_BYTES,
        PUBLIC_CORPUS_NOTICE,
        PublicCorpus,
        PublicCorpusError,
        PublicCorpusLimitError,
        PublicGitHubClient,
        PublicRateLimitError,
        _ConfigCapture,
        _JobCapture,
        _JobDraft,
        _LogCapture,
        _RunDraft,
        harvest_public_repositories,
        preview_public_harvest,
        reevaluate_public_corpus,
    )


REPOSITORY = "actions/checkout"
REPOSITORIES = (REPOSITORY, "pallets/flask", "psf/requests")
SHA = "a" * 40
WORKFLOW_PATH = ".github/workflows/build.yml"
TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz123456"
LOG = (
    "Program.cs(12,3): error CS0161: 'Demo.Run()': not all code paths return a value\n"
    f"token={TOKEN}\n"
)
CONFIG = (
    "name: Build\non:\n  push:\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
    f"    env:\n      token: {TOKEN}\n"
)


@pytest.fixture(autouse=True)
def no_real_network_or_wait(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Public corpus tests must not make real network requests or sleep")

    # Windows asyncio uses a loopback socketpair internally. Allow only that local
    # primitive, not arbitrary connect calls or any real HTTP transport.
    original_connect = socket.socket.connect
    original_socketpair = socket.socketpair

    def local_socketpair(*args, **kwargs):
        with patch.object(socket.socket, "connect", original_connect):
            return original_socketpair(*args, **kwargs)

    monkeypatch.setattr(socket, "socketpair", local_socketpair)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    monkeypatch.setattr(asyncio, "sleep", forbidden)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: False)
    monkeypatch.setattr("dotenv.main.DotEnv.dict", lambda *args, **kwargs: {})


class GitHubScript:
    """Mocked public API server that rejects discovery, artifacts, and foreign destinations."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.metadata: dict[str, object] = {
            "private": False,
            "visibility": "public",
            "fork": True,
            "archived": True,
            "full_name": REPOSITORY,
            "owner": {"login": "must-not-store-user"},
        }
        self.repository_response: httpx.Response | None = None
        self.list_status = 200
        self.list_headers: dict[str, str] = {}
        self.run_pages: dict[int, list[dict[str, object]]] | None = None
        self.job_pages: dict[int, list[dict[str, object]]] | None = None
        self.job_total_count: object = None
        self.jobs_by_run: dict[int, list[dict[str, object]]] = {}
        self.job_responses: dict[int, httpx.Response] = {}
        self.jobs_response: httpx.Response | None = None
        self.log_response: httpx.Response | None = None
        self.workflow_response: httpx.Response | None = None
        self.contents_response: httpx.Response | None = None
        self.runs = [
            {
                "id": 101,
                "status": "completed",
                "conclusion": "failure",
                "head_sha": SHA,
                "workflow_id": 7,
                "path": WORKFLOW_PATH,
                "actor": {"login": "must-not-store-user"},
                "html_url": f"https://github.com/{REPOSITORY}/actions/runs/101",
            }
        ]
        self.jobs = [
            {"id": 501, "name": f"build {TOKEN}", "status": "completed", "conclusion": "failure"},
        ]

    def client(self) -> PublicGitHubClient:
        return PublicGitHubClient(transport=httpx.MockTransport(self.handle))

    async def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.scheme == "https"
        assert request.url.host == "api.github.com"
        assert request.headers["user-agent"] == "PipelineLens-PublicCorpus/1.0"
        assert request.headers["accept-encoding"] == "identity"
        assert "authorization" not in request.headers
        assert "cookie" not in request.headers
        self.requests.append(request)
        path = request.url.path
        if path == f"/repos/{REPOSITORY}":
            assert not request.url.params
            return self.repository_response or httpx.Response(200, json=self.metadata)
        if path == f"/repos/{REPOSITORY}/actions/runs":
            params = dict(request.url.params)
            assert set(params) == {"status", "per_page", "page"}
            assert params["status"] == "failure"
            assert 1 <= int(params["per_page"]) <= 10
            assert int(params["page"]) in {1, 2}
            runs = (
                self.run_pages.get(int(params["page"]), [])
                if self.run_pages is not None else self.runs
            )
            return httpx.Response(
                self.list_status,
                json={"workflow_runs": runs},
                headers=self.list_headers,
            )
        if path.startswith(f"/repos/{REPOSITORY}/actions/runs/") and path.endswith("/jobs"):
            params = dict(request.url.params)
            assert set(params) == {"per_page", "page"}
            assert params["per_page"] == "100"
            assert int(params["page"]) in {1, 2}
            run_id = int(path.split("/")[-2])
            jobs = (
                self.job_pages.get(int(params["page"]), [])
                if self.job_pages is not None else self.jobs_by_run.get(run_id, self.jobs)
            )
            payload: dict[str, object] = {"jobs": jobs}
            if self.job_total_count is not None:
                payload["total_count"] = self.job_total_count
            return (
                self.job_responses.get(run_id) or self.jobs_response
                or httpx.Response(200, json=payload)
            )
        if path.startswith(f"/repos/{REPOSITORY}/actions/jobs/") and path.endswith("/logs"):
            assert not request.url.params
            return self.log_response or httpx.Response(200, text=LOG)
        if path == f"/repos/{REPOSITORY}/actions/workflows/7":
            return self.workflow_response or httpx.Response(
                200, json={"path": WORKFLOW_PATH}
            )
        if path == f"/repos/{REPOSITORY}/contents/{WORKFLOW_PATH}":
            assert dict(request.url.params) == {"ref": SHA}
            return self.contents_response or httpx.Response(
                200,
                json={
                    "type": "file",
                    "encoding": "base64",
                    "content": base64.b64encode(CONFIG.encode()).decode(),
                    "html_url": "https://outside.example/signed?token=must-not-store",
                },
            )
        pytest.fail(f"Unexpected public corpus endpoint: {path}")


async def harvest(script: GitHubScript, corpus: PublicCorpus, *, per_repo: int = 1):
    async with script.client() as client:
        return await harvest_public_repositories(
            [REPOSITORY],
            runs_per_repository=per_repo,
            corpus=corpus,
            client=client,
        )


def test_preview_is_inert_and_does_not_create_storage(tmp_path):
    directory = tmp_path / "not-created"
    corpus = PublicCorpus(directory)

    plan = preview_public_harvest(["Actions/Checkout"])

    assert plan.repositories == (REPOSITORY,)
    assert plan.runs_per_repository == 4
    assert plan.notice == PUBLIC_CORPUS_NOTICE
    assert corpus.summary().run_count == 0
    assert corpus.match("compiler.cs0161") == 0
    assert not directory.exists()


@pytest.mark.asyncio
async def test_execute_collects_only_redacted_public_fixture_data(tmp_path):
    script = GitHubScript()
    corpus = PublicCorpus(tmp_path)

    report = await harvest(script, corpus)

    assert report.state == "complete"
    assert report.repositories[0].state == "collected"
    assert (
        report.summary.repository_count == report.summary.run_count == report.summary.job_count == 1
    )
    assert report.summary.classified_job_count == 1
    assert report.summary.unknown_job_count == 0
    assert report.summary.no_job_run_count == report.summary.limited_job_run_count == 0
    assert report.summary.captured_log_job_count == report.summary.captured_config_run_count == 1
    assert report.selected_run_count == report.new_run_count == 1
    assert report.already_retained_run_count == 0
    assert corpus.match("compiler.cs0161") == 1
    paths = [request.url.path for request in script.requests]
    assert paths == [
        f"/repos/{REPOSITORY}",
        f"/repos/{REPOSITORY}/actions/runs",
        f"/repos/{REPOSITORY}/actions/runs/101/jobs",
        f"/repos/{REPOSITORY}/actions/jobs/501/logs",
        f"/repos/{REPOSITORY}/contents/{WORKFLOW_PATH}",
    ]
    assert not any("artifact" in path for path in paths)
    stored = corpus.path.read_text(encoding="utf-8", errors="replace")
    assert TOKEN not in stored
    assert "must-not-store-user" not in stored
    assert "[REDACTED]" in stored
    serialized = report.model_dump_json()
    assert (
        TOKEN not in serialized
        and CONFIG not in serialized
        and f"github.com/{REPOSITORY}" not in serialized
    )
    with sqlite3.connect(corpus.path) as database:
        row = database.execute(
            "SELECT config_content, config_content_hash, config_source_url, "
            "config_source_modified FROM runs"
        ).fetchone()
    assert row is not None
    assert TOKEN not in row[0]
    assert len(row[1]) == 64
    assert row[2] == f"https://github.com/{REPOSITORY}/blob/{SHA}/{WORKFLOW_PATH}"
    assert row[3] == 1


@pytest.mark.asyncio
async def test_private_repository_is_rejected_before_any_run_or_source_read(tmp_path):
    script = GitHubScript()
    script.metadata["private"] = True

    report = await harvest(script, PublicCorpus(tmp_path))

    assert report.state == "partial"
    assert report.repositories[0].state == "rejected"
    assert report.summary.run_count == report.summary.job_count == 0
    assert [request.url.path for request in script.requests] == [f"/repos/{REPOSITORY}"]


@pytest.mark.asyncio
async def test_redirected_logs_are_not_followed_or_retained(tmp_path):
    script = GitHubScript()
    script.log_response = httpx.Response(
        302, headers={"Location": "https://storage.example/signed?token=must-not-store"}
    )
    corpus = PublicCorpus(tmp_path)

    report = await harvest(script, corpus)

    assert report.state == "partial"
    assert report.summary.redirect_log_job_count == report.summary.no_log_job_count == 1
    assert report.summary.captured_log_job_count == report.summary.classified_job_count == 0
    assert len([request for request in script.requests if request.url.path.endswith("/logs")]) == 1
    assert not any(request.url.host != "api.github.com" for request in script.requests)
    assert "storage.example" not in corpus.path.read_text(encoding="utf-8", errors="replace")


@pytest.mark.asyncio
async def test_oversized_log_is_discarded_without_partial_storage(tmp_path):
    script = GitHubScript()
    script.log_response = httpx.Response(
        200,
        content=(TOKEN + "x" * MAX_LOG_BYTES).encode(),
        headers={"Content-Length": str(MAX_LOG_BYTES + len(TOKEN))},
    )
    corpus = PublicCorpus(tmp_path)

    report = await harvest(script, corpus)

    assert report.summary.oversized_log_job_count == report.summary.no_log_job_count == 1
    with sqlite3.connect(corpus.path) as database:
        assert database.execute("SELECT log_content FROM jobs").fetchone()[0] == ""
    assert TOKEN not in corpus.path.read_text(encoding="utf-8", errors="replace")


@pytest.mark.asyncio
async def test_offline_reevaluation_never_uses_the_public_api(tmp_path, monkeypatch):
    script = GitHubScript()
    script.log_response = httpx.Response(200, text="ERROR: uncommon deterministic failure\n")
    corpus = PublicCorpus(tmp_path)
    first = await harvest(script, corpus)
    assert first.summary.unknown_job_count == 1
    requests_before = list(script.requests)

    def rediagnosed(snapshot):
        assert snapshot.repository.provider.value == "github"
        assert snapshot.config_bundle[0].content
        return Finding(
            rule_id="public.fixture.rule",
            severity="error",
            category="build_failure",
            title="Fixture diagnosis",
            explanation="Local deterministic fixture result.",
            fix=[],
            evidence=[],
            confidence="observed",
        )

    monkeypatch.setattr(findings, "diagnose_job", rediagnosed)
    report = reevaluate_public_corpus(corpus)

    assert script.requests == requests_before
    assert report.reevaluated_job_count == report.classified_job_count == 1
    assert report.unknown_job_count == report.analysis_error_job_count == 0
    assert corpus.match("public.fixture.rule") == 1


def test_corrupt_database_fails_closed_without_replacement(tmp_path):
    path = tmp_path / "public-actions.sqlite3"
    original = b"not a sqlite database"
    path.write_bytes(original)

    with pytest.raises(PublicCorpusError):
        PublicCorpus(tmp_path).summary()

    assert path.read_bytes() == original


@pytest.mark.parametrize("key,value", [
    ("visibility", "private"), ("visibility", "internal"), ("visibility", None),
    ("visibility", "Public"), ("visibility", True), ("private", 0), ("private", "false"),
    ("private", None), ("full_name", "actions/checkout-other"),
    ("full_name", "other/checkout"), ("full_name", REPOSITORY + "/"), ("full_name", None),
])
@pytest.mark.asyncio
async def test_public_access_requires_all_explicit_repository_checks(tmp_path, key, value):
    script = GitHubScript()
    script.metadata[key] = value

    report = await harvest(script, PublicCorpus(tmp_path))

    assert report.repositories[0].state == "rejected"
    assert report.summary.run_count == report.selected_run_count == report.new_run_count == 0
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_missing_visibility_is_not_inferred_from_private_false(tmp_path):
    script = GitHubScript()
    del script.metadata["visibility"]
    report = await harvest(script, PublicCorpus(tmp_path))
    assert report.repositories[0].state == "rejected"
    assert len(script.requests) == 1


def succeeded_jobs(count=100):
    return [
        {"id": index + 1000, "name": "passed", "status": "completed", "conclusion": "success"}
        for index in range(count)
    ]


@pytest.mark.asyncio
async def test_failed_job_on_second_page_is_captured_once(tmp_path):
    script = GitHubScript()
    script.job_pages = {1: succeeded_jobs(), 2: [*script.jobs, {**script.jobs[0], "id": 502}]}
    report = await harvest(script, PublicCorpus(tmp_path))
    job_requests = [request for request in script.requests if request.url.path.endswith("/jobs")]
    assert [request.url.params["page"] for request in job_requests] == ["1", "2"]
    assert report.summary.job_count == report.summary.captured_log_job_count == 1
    assert len([request for request in script.requests if request.url.path.endswith("/logs")]) == 1


@pytest.mark.parametrize("total,state", [(None, "limited"), (201, "limited"), (200, "none")])
@pytest.mark.asyncio
async def test_full_job_page_bound_is_not_mistaken_for_exhaustion(tmp_path, total, state):
    script = GitHubScript()
    script.job_pages = {1: succeeded_jobs(), 2: succeeded_jobs()}
    script.job_total_count = total
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.summary.no_job_run_count == 1
    assert report.summary.limited_job_run_count == int(state == "limited")
    assert report.summary.job_count == report.summary.captured_log_job_count == 0
    assert len([request for request in script.requests if request.url.path.endswith("/jobs")]) == 2
    assert not any(request.url.path.endswith("/logs") for request in script.requests)
    with sqlite3.connect(corpus.path) as database:
        assert database.execute("SELECT job_state FROM runs").fetchone()[0] == state


@pytest.mark.parametrize("content", [
    "", "name: no jobs\n", "jobs: [broken", "jobs: []\n", "- not-a-workflow\n",
    "jobs:\n  build:\n    steps: 7\n", "jobs: {}\n---\njobs: {}\n",
])
@pytest.mark.asyncio
async def test_malformed_config_uses_log_only_diagnostics_without_synthetic_evidence(
    tmp_path, monkeypatch, content,
):
    script = GitHubScript()
    script.contents_response = httpx.Response(200, json={
        "type": "file", "encoding": "base64",
        "content": base64.b64encode(content.encode()).decode(),
    })
    real_diagnose = findings.diagnose_job
    calls = []

    def log_only(snapshot):
        assert not snapshot.config_bundle
        assert snapshot.config.content == snapshot.config.path == snapshot.config.ref == ""
        assert snapshot.config.source_url is None
        assert snapshot.config.source_modified
        assert snapshot.job_source is None
        assert snapshot.graph.config_files == snapshot.graph.nodes == []
        assert snapshot.progress.ci_configuration.value == "failed"
        finding = real_diagnose(snapshot)
        assert all(item.path != ".github/workflows/unavailable.yml" for item in finding.evidence)
        calls.append(finding)
        return finding

    monkeypatch.setattr(findings, "diagnose_job", log_only)
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.summary.classified_job_count == 1
    assert report.summary.analysis_error_job_count == 0
    reevaluated = reevaluate_public_corpus(corpus)
    assert reevaluated.classified_job_count == 1
    assert len(calls) == 2
    with sqlite3.connect(corpus.path) as database:
        assert database.execute("SELECT config_content FROM runs").fetchone()[0] == content


@pytest.mark.parametrize("mode", ["missing", "unavailable", "invalid", "truncated"])
@pytest.mark.asyncio
async def test_incomplete_config_still_allows_captured_logs_to_classify(tmp_path, mode):
    script = GitHubScript()
    if mode == "missing":
        script.runs[0]["head_sha"] = None
    elif mode == "unavailable":
        script.contents_response = httpx.Response(404)
    elif mode == "invalid":
        script.contents_response = httpx.Response(200, json={"type": "symlink"})
    else:
        script.contents_response = httpx.Response(200, json={
            "type": "file", "encoding": "base64",
            "content": base64.b64encode((CONFIG + "#" * MAX_CONFIG_BYTES).encode()).decode(),
        })
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.summary.classified_job_count == report.summary.captured_log_job_count == 1
    assert report.summary.analysis_error_job_count == report.summary.captured_config_run_count == 0
    assert report.summary.truncated_config_run_count == int(mode == "truncated")
    assert reevaluate_public_corpus(corpus).classified_job_count == 1
    with sqlite3.connect(corpus.path) as database:
        content = database.execute("SELECT config_content FROM runs").fetchone()[0]
    assert content != "jobs: {}\n"
    assert ".github/workflows/unavailable.yml" not in corpus.path.read_text(
        encoding="utf-8", errors="replace",
    )


@pytest.mark.asyncio
async def test_duplicate_counts_are_per_collection_not_lifetime(tmp_path):
    script = GitHubScript()
    original = script.runs[0]
    script.runs = [original, {**original, "id": 102}]
    script.jobs_by_run[102] = [{**script.jobs[0], "id": 502}]
    corpus = PublicCorpus(tmp_path)
    first = await harvest(script, corpus, per_repo=2)
    assert first.selected_run_count == first.new_run_count == first.summary.run_count == 2
    assert first.already_retained_run_count == 0
    script.requests.clear()
    script.runs = [original]
    second = await harvest(script, corpus)
    assert second.selected_run_count == second.already_retained_run_count == 1
    assert second.new_run_count == second.repositories[0].new_run_count == 0
    assert second.summary.run_count == second.repositories[0].retained_run_count == 2
    assert second.repositories[0].selected_run_count == 1
    assert len(script.requests) == 2  # Reverify access and list only; never recapture duplicates.


@pytest.mark.parametrize("repository", REPOSITORIES)
def test_explicit_repository_plans_never_discover_or_write(repository, tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Preview must not construct clients or access storage")

    monkeypatch.setattr(httpx, "AsyncClient", forbidden)
    monkeypatch.setattr(sqlite3, "connect", forbidden)
    monkeypatch.setattr(PublicCorpus, "initialize", forbidden)
    plan = preview_public_harvest([repository.upper(), repository])
    assert plan.repositories == (repository,)
    assert plan.target_run_count == 4
    assert plan.max_job_listing_pages == plan.max_listing_pages == 2
    assert plan.max_jobs_per_run == 1
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("repository", [
    "", "actions", "actions/checkout/extra", "https://github.com/actions/checkout",
    "//github.com/actions/checkout", "actions/checkout?token=synthetic", "actions/checkout#main",
    "actions/checkout%2fother", "../checkout", "actions/..", "actions/checkout\n",
    " actions/checkout", "actions\\checkout", "actions/" + TOKEN,
])
def test_unsafe_repository_identifiers_are_rejected(repository):
    with pytest.raises(PublicCorpusError):
        preview_public_harvest([repository])


@pytest.mark.parametrize("limit", [0, 11, -1, True, "4", None])
def test_plan_run_limits_are_strict(limit):
    with pytest.raises(PublicCorpusError):
        preview_public_harvest([REPOSITORY], runs_per_repository=limit)


def test_plan_repository_and_total_caps():
    with pytest.raises(PublicCorpusError):
        preview_public_harvest([])
    with pytest.raises(PublicCorpusError):
        preview_public_harvest([f"fixture/repo-{index}" for index in range(101)])
    with pytest.raises(PublicCorpusLimitError):
        preview_public_harvest(
            [f"fixture/repo-{index}" for index in range(51)], runs_per_repository=10,
        )
    assert preview_public_harvest(
        [f"fixture/repo-{index}" for index in range(50)], runs_per_repository=10,
    ).target_run_count == 500


RUNS_PATH = f"/repos/{REPOSITORY}/actions/runs"
JOBS_PATH = RUNS_PATH + "/101/jobs"
LOG_PATH = f"/repos/{REPOSITORY}/actions/jobs/501/logs"
CONTENTS_PATH = f"/repos/{REPOSITORY}/contents/{WORKFLOW_PATH}"


@pytest.mark.parametrize("path,params", [
    (f"/repos/{REPOSITORY}", {}),
    (RUNS_PATH, {"status": "failure", "per_page": 1, "page": 1}),
    (RUNS_PATH, {"status": "failure", "per_page": 10, "page": 2}),
    (JOBS_PATH, {"per_page": 100, "page": 1}),
    (JOBS_PATH, {"per_page": 100, "page": 2}),
    (LOG_PATH, {}),
    (f"/repos/{REPOSITORY}/actions/workflows/7", {}),
    (CONTENTS_PATH, {"ref": SHA}),
    (CONTENTS_PATH, {"ref": "B" * 64}),
])
def test_exact_bounded_request_whitelist(path, params):
    assert public_corpus._request_is_allowed(path, params)


@pytest.mark.parametrize("path,params", [
    ("https://api.github.com" + RUNS_PATH, {}),
    ("https://other.example" + RUNS_PATH, {}),
    ("//api.github.com" + RUNS_PATH, {}),
    ("https://[bad/", {}),
    ("/user", {}), ("/search/repositories", {"q": "failure"}), ("/repositories", {}),
    (RUNS_PATH + "/101/artifacts", {}), (RUNS_PATH + "/101/logs", {}),
    (f"/repos/{REPOSITORY}/actions/artifacts", {}),
    (f"/repos/{REPOSITORY}/tarball", {}),
    (f"/repos/{REPOSITORY}/contents/.env", {"ref": SHA}),
    (f"/repos/{REPOSITORY}/contents/../hidden", {"ref": SHA}),
    (CONTENTS_PATH + "%3ftoken=synthetic", {"ref": SHA}),
    (CONTENTS_PATH.replace("/", "\\"), {"ref": SHA}),
    (LOG_PATH + "?token=synthetic", {}), (LOG_PATH + "#fragment", {}),
    (LOG_PATH, {"access_token": "synthetic"}),
    (LOG_PATH.replace("501", "0"), {}), (LOG_PATH.replace("501", "-1"), {}),
    (LOG_PATH.replace("501", str(2**63)), {}),
    (f"/repos/{REPOSITORY}", {"page": 1}),
    (RUNS_PATH, {"status": "completed", "conclusion": "failure", "per_page": 1, "page": 1}),
    (RUNS_PATH, {"status": "failure", "conclusion": "failure", "per_page": 1, "page": 1}),
    (RUNS_PATH, {"status": "completed", "per_page": 1, "page": 1}),
    (RUNS_PATH, {"status": "success", "per_page": 1, "page": 1}),
    (RUNS_PATH, {"status": "failure", "per_page": 100, "page": 1}),
    (RUNS_PATH, {"status": "failure", "per_page": True, "page": 1}),
    (RUNS_PATH, {"status": "failure", "per_page": "1", "page": 1}),
    (RUNS_PATH, {"status": "failure", "per_page": 1, "page": 3}),
    (RUNS_PATH, {"status": "failure", "per_page": 1, "page": True}),
    (JOBS_PATH, {"per_page": 100}),
    (JOBS_PATH, {"per_page": 100, "page": 0}),
    (JOBS_PATH, {"per_page": 100, "page": 3}),
    (JOBS_PATH, {"per_page": "100", "page": 1}),
    (JOBS_PATH, {"per_page": 100, "page": "1"}),
    (JOBS_PATH, {"per_page": 100, "page": True}),
    (JOBS_PATH, {"per_page": 100, "page": 1, "filter": "all"}),
    (CONTENTS_PATH, {"ref": "HEAD"}),
    (CONTENTS_PATH, {"ref": "a" * 41}),
    (CONTENTS_PATH, {"ref": SHA, "token": "synthetic"}),
])
@pytest.mark.asyncio
async def test_disallowed_requests_never_reach_transport(path, params):
    def forbidden(request):
        pytest.fail("A rejected route/query reached HTTP transport")

    async with PublicGitHubClient(transport=httpx.MockTransport(forbidden)) as client:
        with pytest.raises(PublicCorpusError):
            await client._request(path, params=params)


@pytest.mark.parametrize("max_bytes", [0, -1, True, "100", MAX_LOG_BYTES + 1])
@pytest.mark.asyncio
async def test_request_byte_limit_is_strict(max_bytes):
    script = GitHubScript()
    async with script.client() as client:
        with pytest.raises(PublicCorpusError):
            await client._request(LOG_PATH, max_bytes=max_bytes)
    assert not script.requests


@pytest.mark.parametrize("change", [
    {"status": "queued"}, {"status": "in_progress"}, {"status": "Completed"},
    {"conclusion": "success"}, {"conclusion": "cancelled"}, {"conclusion": "timed_out"},
    {"conclusion": None}, {"id": None}, {"id": True}, {"id": 0}, {"id": -1},
    {"id": "001"}, {"id": 2**63},
])
@pytest.mark.asyncio
async def test_run_response_filters_remain_required_even_with_status_failure(change):
    script = GitHubScript()
    script.runs[0].update(change)
    async with script.client() as client:
        assert await client.list_failed_runs(REPOSITORY, 2) == []
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_run_list_is_deduplicated_and_capped_at_two_pages():
    script = GitHubScript()
    run = script.runs[0]
    script.run_pages = {
        1: [run, run, {**run, "conclusion": "success"}],
        2: [run, {**run, "id": 102}, {**run, "id": 103, "status": "in_progress"}],
        3: [{**run, "id": 104}],
    }
    async with script.client() as client:
        runs = await client.list_failed_runs(REPOSITORY, 3)
    assert [run.run_id for run in runs] == [101, 102]
    assert [request.url.params["page"] for request in script.requests] == ["1", "2"]


@pytest.mark.asyncio
async def test_run_selection_stops_when_requested_count_is_met():
    script = GitHubScript()
    script.runs.append({**script.runs[0], "id": 102})
    async with script.client() as client:
        assert len(await client.list_failed_runs(REPOSITORY, 2)) == 2
    assert len(script.requests) == 1


@pytest.mark.parametrize("change", [
    {"status": "in_progress"}, {"status": "queued"}, {"conclusion": "success"},
    {"conclusion": "cancelled"}, {"conclusion": "timed_out"}, {"id": None},
    {"id": True}, {"id": 0}, {"id": 2**63}, {"name": None}, {"name": 17},
])
@pytest.mark.asyncio
async def test_job_response_filters_choose_only_one_valid_completed_failure(change):
    script = GitHubScript()
    valid = script.jobs[0]
    script.jobs = [{**valid, **change}, valid, {**valid, "id": 502}]
    async with script.client() as client:
        capture = await client.failed_job(REPOSITORY, 101)
    assert capture.state == "captured"
    assert capture.job.job_id == 501
    assert len(script.requests) == 1


@pytest.mark.parametrize("payload", [
    {}, {"jobs": None}, {"jobs": {}}, {"jobs": succeeded_jobs(101)},
    {"jobs": [], "total_count": True}, {"jobs": [], "total_count": -1},
    {"jobs": [], "total_count": "100"},
])
@pytest.mark.asyncio
async def test_malformed_job_lists_are_not_reported_as_no_failed_job(payload):
    script = GitHubScript()
    script.jobs_response = httpx.Response(200, json=payload)
    async with script.client() as client:
        result = await client.failed_job(REPOSITORY, 101)
    assert result.state == "invalid"
    assert result.job is None
    assert len(script.requests) == 1


@pytest.mark.parametrize("total", [None, 0, 99])
@pytest.mark.asyncio
async def test_short_exhausted_job_list_stops_without_second_page(total):
    script = GitHubScript()
    script.jobs = succeeded_jobs(99) if total else []
    script.job_total_count = total
    async with script.client() as client:
        result = await client.failed_job(REPOSITORY, 101)
    assert result.state == "none"
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_short_page_with_reported_remaining_jobs_is_not_none():
    script = GitHubScript()
    script.jobs = []
    script.job_total_count = 201
    async with script.client() as client:
        result = await client.failed_job(REPOSITORY, 101)
    assert result.state == "limited"
    assert len(script.requests) == 2


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("endpoint", ["repository", "runs", "jobs", "logs", "workflow", "contents"])
@pytest.mark.asyncio
async def test_all_endpoint_redirects_are_rejected_without_following_or_leaking(
    tmp_path, status, endpoint,
):
    script = GitHubScript()
    location = "https://storage.example/signed?token=" + TOKEN
    response = httpx.Response(status, headers={"Location": location}, text=TOKEN)
    if endpoint == "repository":
        script.repository_response = response
    elif endpoint == "runs":
        script.list_status = status
        script.list_headers = {"Location": location}
    elif endpoint == "jobs":
        script.jobs_response = response
    elif endpoint == "logs":
        script.log_response = response
    elif endpoint == "workflow":
        script.runs[0].pop("path")
        script.workflow_response = response
    else:
        script.contents_response = response
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.state == "partial"
    assert all(request.url.host == "api.github.com" for request in script.requests)
    serialized = report.model_dump_json()
    stored = corpus.path.read_text(encoding="utf-8", errors="replace")
    assert "storage.example" not in serialized + stored
    assert TOKEN not in serialized + stored
    if endpoint in {"repository", "runs"}:
        assert report.summary.run_count == 0
        assert len(script.requests) == (1 if endpoint == "repository" else 2)
    if endpoint == "logs":
        assert report.summary.captured_log_job_count == 0
        assert report.summary.redirect_log_job_count == 1


@pytest.mark.parametrize("status,headers", [
    (429, {}), (403, {"X-RateLimit-Remaining": "0"}), (403, {"Retry-After": "10"}),
])
@pytest.mark.asyncio
async def test_rate_limit_opens_circuit_without_retry_or_wait(status, headers):
    script = GitHubScript()
    script.list_status, script.list_headers = status, headers
    async with script.client() as client:
        with pytest.raises(PublicRateLimitError):
            await client.list_failed_runs(REPOSITORY, 1)
        with pytest.raises(PublicRateLimitError):
            await client.verify_public_repository(REPOSITORY)
    assert len(script.requests) == 1


@pytest.mark.asyncio
async def test_rate_limit_report_preserves_current_invocation_progress_and_stops_repositories(
    tmp_path,
):
    script = GitHubScript()
    script.runs.append({**script.runs[0], "id": 102})
    script.job_responses[102] = httpx.Response(429)
    corpus = PublicCorpus(tmp_path)
    async with script.client() as client:
        report = await harvest_public_repositories(
            REPOSITORIES, runs_per_repository=2, corpus=corpus, client=client,
        )
    assert report.state == "rate_limited"
    assert report.selected_run_count == report.repositories[0].selected_run_count == 2
    assert report.new_run_count == report.summary.run_count == 1
    assert report.already_retained_run_count == 0
    assert len(report.repositories) == 1
    assert script.requests[-1].url.path == RUNS_PATH + "/102/jobs"


@pytest.mark.asyncio
async def test_ambient_credentials_proxies_and_response_cookies_are_never_forwarded(
    tmp_path, monkeypatch,
):
    for key in (
        "GH_TOKEN", "GITHUB_TOKEN", "GITLAB_TOKEN", "PIPELINELENS_GITHUB_TOKEN",
        "PIPELINELENS_LLM_API_KEY",
    ):
        monkeypatch.setenv(key, TOKEN)
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(key, "http://synthetic:password@proxy.invalid:9999")
    monkeypatch.setenv("NETRC", str(tmp_path / "must-not-read-netrc"))
    script = GitHubScript()
    script.repository_response = httpx.Response(
        200, json=script.metadata, headers={"Set-Cookie": "session=synthetic; Path=/"},
    )
    captured_settings = []
    original_analyze = analysis.PipelineAnalyzer.analyze_input

    def offline_only(self, analysis_input, *args, **kwargs):
        assert self.settings.llm_mode == "disabled"
        assert self.settings.llm_api_key is None
        assert not self.settings.allow_private_context
        assert not hasattr(self.settings, "github_token")
        captured_settings.append(self.settings)
        return original_analyze(self, analysis_input, *args, **kwargs)

    monkeypatch.setattr(analysis.PipelineAnalyzer, "analyze_input", offline_only)
    report = await harvest(script, PublicCorpus(tmp_path))
    assert report.summary.classified_job_count == 1
    assert len(captured_settings) == 1
    for request in script.requests:
        assert "authorization" not in request.headers
        assert "proxy-authorization" not in request.headers
        assert "cookie" not in request.headers
        assert TOKEN not in str(request.url) + str(request.headers)


@pytest.mark.parametrize("status,headers,body,expected", [
    pytest.param(403, {}, LOG.encode(), "forbidden", id="forbidden"),
    pytest.param(401, {}, LOG.encode(), "unavailable", id="auth-required"),
    pytest.param(404, {}, LOG.encode(), "unavailable", id="missing"),
    pytest.param(500, {}, LOG.encode(), "unavailable", id="server-error"),
    pytest.param(206, {}, LOG.encode(), "unavailable", id="partial-status"),
    pytest.param(200, {"Content-Range": "bytes 0-9/100"}, LOG.encode(), "invalid", id="range"),
    pytest.param(200, {"Content-Encoding": "br"}, b"", "invalid", id="encoded"),
    pytest.param(200, {"Content-Length": "999"}, b"error", "invalid", id="short-body"),
    pytest.param(200, {"Content-Length": "1"}, b"error", "invalid", id="long-body"),
    pytest.param(200, {"Content-Length": "nope"}, b"error", "invalid", id="bad-length"),
    pytest.param(200, {}, b"\xff\xfe", "invalid", id="bad-utf8"),
    pytest.param(200, {}, b"", "empty", id="empty"),
    pytest.param(200, {}, b" \n\t", "empty", id="whitespace"),
])
@pytest.mark.asyncio
async def test_unusable_logs_never_count_as_captured_or_classified(
    tmp_path, monkeypatch, status, headers, body, expected,
):
    script = GitHubScript()
    script.log_response = httpx.Response(status, headers=headers, content=body)

    def forbidden(*args, **kwargs):
        pytest.fail("Unavailable/partial logs must not reach deterministic classification")

    monkeypatch.setattr(analysis.PipelineAnalyzer, "analyze_input", forbidden)
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.state == "partial"
    assert report.summary.job_count == report.summary.no_log_job_count == 1
    assert report.summary.captured_log_job_count == report.summary.classified_job_count == 0
    assert report.summary.unknown_job_count == report.summary.analysis_error_job_count == 0
    assert reevaluate_public_corpus(corpus).reevaluated_job_count == 0
    with sqlite3.connect(corpus.path) as database:
        assert database.execute(
            "SELECT log_state, log_content, classification_state FROM jobs"
        ).fetchone() == (expected, "", "no_log")


class SyntheticByteStream(httpx.AsyncByteStream):
    def __init__(self, chunks, *, fail=False):
        self.chunks = chunks
        self.fail = fail
        self.yielded = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.yielded += 1
            yield chunk
        if self.fail:
            raise httpx.ReadError("synthetic partial body " + TOKEN)


@pytest.mark.parametrize("failure", ["oversized", "interrupted"])
@pytest.mark.asyncio
async def test_streaming_log_bound_and_disconnect_discard_all_partial_content(tmp_path, failure):
    script = GitHubScript()
    chunks = [b"x" * 65536] * 18 if failure == "oversized" else [LOG.encode()]
    stream = SyntheticByteStream(chunks, fail=failure == "interrupted")
    script.log_response = httpx.Response(200, stream=stream)
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.summary.captured_log_job_count == report.summary.classified_job_count == 0
    assert report.summary.no_log_job_count == 1
    assert stream.yielded == (17 if failure == "oversized" else 1)
    with sqlite3.connect(corpus.path) as database:
        assert database.execute("SELECT log_content FROM jobs").fetchone()[0] == ""
    assert TOKEN not in report.model_dump_json()


@pytest.mark.asyncio
async def test_run_path_is_used_even_if_workflow_metadata_is_deleted(tmp_path):
    script = GitHubScript()
    script.runs[0]["workflow_id"] = None
    script.workflow_response = httpx.Response(404)
    report = await harvest(script, PublicCorpus(tmp_path))
    assert report.summary.captured_config_run_count == 1
    assert not any("/actions/workflows/" in request.url.path for request in script.requests)


@pytest.mark.asyncio
async def test_missing_run_path_falls_back_to_validated_metadata_at_run_sha(tmp_path):
    script = GitHubScript()
    script.runs[0].pop("path")
    report = await harvest(script, PublicCorpus(tmp_path))
    assert report.summary.captured_config_run_count == 1
    assert script.requests[-2].url.path.endswith("/actions/workflows/7")
    assert script.requests[-1].url.path == CONTENTS_PATH
    assert dict(script.requests[-1].url.params) == {"ref": SHA}


@pytest.mark.parametrize("ref", [
    "main", "refs/heads/feature/example", "refs/pull/17/merge", "b" * 40,
])
@pytest.mark.asyncio
async def test_qualified_run_path_discards_mutable_ref_and_preserves_sha_binding(tmp_path, ref):
    script = GitHubScript()
    script.runs[0]["path"] = WORKFLOW_PATH + "@" + ref
    script.runs[0]["workflow_id"] = None
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.summary.captured_config_run_count == 1
    assert not any("/actions/workflows/" in request.url.path for request in script.requests)
    assert script.requests[-1].url.path == CONTENTS_PATH
    assert dict(script.requests[-1].url.params) == {"ref": SHA}
    assert next(corpus._observations()).config_path == WORKFLOW_PATH


@pytest.mark.parametrize("path", [
    ".env", "../.github/workflows/build.yml", ".github/workflows/../build.yml",
    ".github/workflows/build.yml?token=synthetic", ".github/workflows/build.yml@",
    "https://outside.example/workflow.yml", ".github/workflows/" + TOKEN + ".yml",
])
@pytest.mark.asyncio
async def test_invalid_run_and_metadata_paths_never_reach_contents(tmp_path, path):
    script = GitHubScript()
    script.runs[0]["path"] = path
    script.workflow_response = httpx.Response(200, json={"path": path})
    report = await harvest(script, PublicCorpus(tmp_path))
    assert report.summary.captured_config_run_count == 0
    assert report.summary.classified_job_count == 1
    assert not any("/contents/" in request.url.path for request in script.requests)
    assert TOKEN not in report.model_dump_json()


@pytest.mark.parametrize("redacted", [False, True])
@pytest.mark.asyncio
async def test_source_modified_survives_retention_and_offline_reclassification(
    tmp_path, monkeypatch, redacted,
):
    script = GitHubScript()
    content = CONFIG if redacted else "jobs: {}\n"
    script.contents_response = httpx.Response(200, json={
        "type": "file", "encoding": "base64",
        "content": base64.b64encode(content.encode()).decode(),
    })
    original = findings.diagnose_job
    seen = []

    def observe(snapshot):
        source = snapshot.config_bundle[0]
        assert source.source_modified is redacted
        assert source.source_url == f"https://github.com/{REPOSITORY}/blob/{SHA}/{WORKFLOW_PATH}"
        seen.append(source)
        return original(snapshot)

    monkeypatch.setattr(findings, "diagnose_job", observe)
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.summary.modified_config_run_count == int(redacted)
    assert reevaluate_public_corpus(corpus).classified_job_count == 1
    assert len(seen) == 2
    assert next(corpus._observations()).config_source_modified is redacted


def test_storage_defense_redacts_sources_and_preserves_modified_provenance(tmp_path):
    corpus = PublicCorpus(tmp_path)
    corpus.record_run(
        REPOSITORY, _RunDraft(101, SHA, 7, WORKFLOW_PATH),
        job_capture=_JobCapture(_JobDraft(501, "build"), "captured"),
        log_capture=_LogCapture("captured", LOG),
        config_capture=_ConfigCapture(
            "captured", path=WORKFLOW_PATH, content=CONFIG,
            source_url="https://untrusted.example/?token=" + TOKEN,
        ),
        classification=("classified", "compiler.cs0161", "build_failure"),
    )
    observation = next(corpus._observations())
    assert observation.config_source_modified
    assert TOKEN not in observation.config_content + observation.log_content
    assert "untrusted.example" not in corpus.path.read_text(encoding="utf-8", errors="replace")
    with sqlite3.connect(corpus.path) as database:
        content, digest = database.execute(
            "SELECT config_content, config_content_hash FROM runs"
        ).fetchone()
    assert digest == sha256(content.encode()).hexdigest()


@pytest.mark.asyncio
async def test_synthetic_legacy_store_is_read_only_until_explicit_migration(tmp_path, monkeypatch):
    script = GitHubScript()
    corpus = PublicCorpus(tmp_path)
    await harvest(script, corpus)
    # Construct a legacy fixture from this test's own database, never an existing corpus.
    with sqlite3.connect(corpus.path) as database:
        database.execute("ALTER TABLE runs DROP COLUMN config_source_modified")
        database.execute("PRAGMA user_version = 1")
    before = corpus.path.read_bytes()
    assert corpus.summary().modified_config_run_count == 1
    assert next(corpus._observations()).config_source_modified
    assert corpus.path.read_bytes() == before
    original = findings.diagnose_job

    def conservative_provenance(snapshot):
        assert snapshot.config.source_modified
        return original(snapshot)

    monkeypatch.setattr(findings, "diagnose_job", conservative_provenance)
    assert reevaluate_public_corpus(corpus).classified_job_count == 1
    with sqlite3.connect(corpus.path) as database:
        assert database.execute("PRAGMA user_version").fetchone()[0] == 2
        assert database.execute("SELECT config_source_modified FROM runs").fetchone()[0] == 1


@pytest.mark.asyncio
async def test_config_provenance_schema_corruption_fails_closed(tmp_path):
    corpus = PublicCorpus(tmp_path)
    await harvest(GitHubScript(), corpus)
    with sqlite3.connect(corpus.path) as database:
        database.execute("ALTER TABLE runs DROP COLUMN config_source_modified")
    before = corpus.path.read_bytes()
    with pytest.raises(PublicCorpusError):
        corpus.summary()
    assert corpus.path.read_bytes() == before


@pytest.mark.asyncio
async def test_retention_capacity_preserves_existing_synthetic_rows(tmp_path, monkeypatch):
    monkeypatch.setattr(public_corpus, "MAX_RETAINED_RUNS", 1)
    script = GitHubScript()
    corpus = PublicCorpus(tmp_path)
    await harvest(script, corpus)
    script.runs[0]["id"] = 102
    with pytest.raises(PublicCorpusLimitError):
        await harvest(script, corpus)
    assert corpus.summary().run_count == corpus.summary().job_count == 1
    assert corpus.has_run(REPOSITORY, 101)
    assert not corpus.has_run(REPOSITORY, 102)


@pytest.mark.asyncio
async def test_analyzer_failure_is_not_confused_with_invalid_config_fallback(tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("synthetic analysis error " + TOKEN)

    monkeypatch.setattr(analysis.PipelineAnalyzer, "analyze_input", broken)
    corpus = PublicCorpus(tmp_path)
    report = await harvest(GitHubScript(), corpus)
    assert report.state == "partial"
    assert report.summary.analysis_error_job_count == 1
    assert report.summary.classified_job_count == report.summary.unknown_job_count == 0
    assert report.summary.captured_log_job_count == 1
    assert TOKEN not in json.dumps(report.model_dump(mode="json"))


@pytest.mark.parametrize("config_available", [False, True])
@pytest.mark.asyncio
async def test_log_only_fallback_does_not_promote_unknown_logs_to_observed_diagnoses(
    tmp_path, config_available,
):
    script = GitHubScript()
    script.log_response = httpx.Response(200, text="Process completed with exit code 1.\n")
    script.contents_response = (
        httpx.Response(200, json={
            "type": "file", "encoding": "base64",
            "content": base64.b64encode(b"jobs: [invalid").decode(),
        }) if config_available else httpx.Response(404)
    )
    corpus = PublicCorpus(tmp_path)
    report = await harvest(script, corpus)
    assert report.summary.captured_log_job_count == report.summary.unknown_job_count == 1
    assert report.summary.classified_job_count == report.summary.analysis_error_job_count == 0
    assert reevaluate_public_corpus(corpus).unknown_job_count == 1
