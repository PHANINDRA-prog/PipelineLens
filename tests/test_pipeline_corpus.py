"""Synthetic-only corpus/CLI tests: no .env, real credentials, traces or network."""

import asyncio
import base64
import json
import re
import socket
import sqlite3
from collections import Counter
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch
from urllib.parse import quote, quote_plus

import httpx
import pytest

# config imports load_dotenv at module scope. Disable it BEFORE importing the app
# so even test discovery never opens the user's credential configuration.
with patch("dotenv.load_dotenv", return_value=False):
    from pipelinelens import harvest as cli
    from pipelinelens.config import Settings
    from pipelinelens.providers.base import ProviderError
    from pipelinelens.providers.gitlab import GitLabProvider
    from pipelinelens.services import pipeline_corpus as module
    from pipelinelens.services.findings import Finding
    from pipelinelens.services.pipeline_corpus import (
        MAX_TRACE_BYTES,
        CorpusError,
        CorpusGitLabProvider,
        CorpusMatch,
        PipelineCorpus,
        harvest_pipelines,
        preview_harvest,
        reevaluate_corpus,
    )

ORIGIN = "https://gitlab.test"
TOKEN = "synthetic-opaque-token-84219"
KNOWN = "Program.cs(12,3): error CS0161: 'Example.Run()': not all code paths return a value\n"
UNKNOWN = "unsupported component diagnostic alpha\nERROR: custom deployment result 753\n"


@pytest.fixture
def settings():
    return Settings(
        environment="test", database_url="sqlite://", redis_url="", max_log_bytes=10,
        max_context_chars=100, llm_mode="openai", llm_base_url="https://must-not-call.test",
        llm_model="must-not-load", llm_api_key="synthetic-other-key-67129",
        allow_private_context=False, configured_gitlab_token=TOKEN,
        configured_gitlab_base_url=ORIGIN,
    )


@pytest.fixture(autouse=True)
def forbid_network_and_implicit_configuration(monkeypatch, settings):
    def forbidden(*args, **kwargs):
        pytest.fail("Corpus tests must not use network, delays or real configuration")

    socketpair, connect = socket.socketpair, socket.socket.connect

    def local_socketpair(*args, **kwargs):
        # Windows asyncio uses a loopback-only socket pair for its internal wakeup.
        with patch.object(socket.socket, "connect", connect):
            return socketpair(*args, **kwargs)

    monkeypatch.setattr(socket, "socketpair", local_socketpair)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(asyncio, "sleep", forbidden)
    monkeypatch.setattr(module, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)


class GitLabScript:
    """HTTP mock exercising real provider parsing and job pagination."""

    def __init__(self, pipelines=None, *, origin=ORIGIN, token=TOKEN):
        self.origin, self.token = origin, token
        self.projects = {"group/a": 1, "group/b": 2, "group/c": 3}
        self.pipelines = pipelines if pipelines is not None else {1: [101]}
        self.jobs = {}
        self.traces = {}
        self.page_overrides = {}
        self.repository_overrides = {}
        self.requests = []
        self.trace_calls = Counter()
        self.active = 0
        self.max_active = 0
        self.barrier_size = 0
        self.barrier = asyncio.Event()
        self.pause_job = None
        self.paused = asyncio.Event()
        self.release = asyncio.Event()

    def provider(self):
        return CorpusGitLabProvider(self.origin, transport=httpx.MockTransport(self.handle))

    async def handle(self, request):
        assert request.method == "GET"
        assert str(request.url).startswith(self.origin + "/api/v4/projects/")
        assert request.headers["PRIVATE-TOKEN"] == self.token
        assert request.headers["Accept-Encoding"] == "identity"
        path = request.url.path.removeprefix("/api/v4")
        self.requests.append((path, dict(request.url.params)))
        if match := re.fullmatch(r"/projects/(\d+)/pipelines", path):
            project_id = int(match[1])
            params = request.url.params
            assert params["status"] == "failed"
            assert params["order_by"] == "id" and params["sort"] == "desc"
            page, size = int(params["page"]), int(params["per_page"])
            assert 1 <= size <= 100
            if (project_id, page) in self.page_overrides:
                return self.page_overrides[project_id, page]
            identifiers = sorted(self.pipelines.get(project_id, []), reverse=True)
            selected = identifiers[(page - 1) * size:page * size]
            return httpx.Response(200, json=[{
                "id": identifier, "status": "failed", "created_at": "2026-09-13T10:00:00Z",
                "ref": "raw-ref-marker", "variables": {"token": "raw-variable-marker"},
                "user": {"email": "raw-private-user-marker"},
            } for identifier in selected], headers={
                "x-next-page": str(page + 1) if len(identifiers) > page * size else "",
            })
        if match := re.fullmatch(r"/projects/(\d+)/pipelines/(\d+)/jobs", path):
            project_id, pipeline_id = int(match[1]), int(match[2])
            assert request.url.params["include_retried"] == "false"
            value = self.jobs.get((project_id, pipeline_id), [{
                "id": pipeline_id * 10, "name": "build", "status": "failed",
                "raw_field": "raw-job-marker", "web_url": "https://other.test/private",
            }])
            if isinstance(value, httpx.Response):
                return value
            page, size = int(request.url.params["page"]), int(request.url.params["per_page"])
            selected = value[(page - 1) * size:page * size]
            return httpx.Response(200, json=selected, headers={
                "x-next-page": str(page + 1) if len(value) > page * size else "",
            })
        if match := re.fullmatch(r"/projects/(\d+)/jobs/(\d+)/trace", path):
            project_id, job_id = int(match[1]), int(match[2])
            self.trace_calls[project_id, job_id] += 1
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            try:
                if self.barrier_size:
                    if self.active >= self.barrier_size:
                        self.barrier.set()
                    await self.barrier.wait()
                if job_id == self.pause_job:
                    self.paused.set()
                    await self.release.wait()
                value = self.traces.get((project_id, job_id), KNOWN)
                return value if isinstance(value, httpx.Response) else httpx.Response(
                    200, text=value,
                )
            finally:
                self.active -= 1
        project_path = path.removeprefix("/projects/")
        assert project_path in self.projects, "Unexpected expensive or unapproved endpoint"
        if project_path in self.repository_overrides:
            return self.repository_overrides[project_path]
        owner, _, name = project_path.rpartition("/")
        return httpx.Response(200, json={
            "id": self.projects[project_path], "path": name, "namespace": {"full_path": owner},
            "path_with_namespace": project_path, "web_url": f"{self.origin}/{project_path}",
        })


async def collect(script, settings, corpus, projects=("group/a",), *, per_project=1, concurrency=2):
    async with script.provider() as provider:
        return await harvest_pipelines(
            settings, projects, corpus=corpus, per_project=per_project,
            concurrency=concurrency, provider=provider,
        )


def test_preview_and_empty_readers_are_lazy(tmp_path, settings):
    directory = tmp_path / "not-created"
    store = PipelineCorpus(directory, settings=settings)
    plan = preview_harvest(settings, ["group/a", "group/b", "group/c"])
    assert plan.target_distinct_pipelines == 225
    assert plan.per_project == 75 and plan.concurrency == 2
    assert plan.token_configured
    assert not directory.exists()
    assert store.summary().retained_pipeline_count == 0
    assert store.match(f"{ORIGIN}/group/a", "compiler.cs0161") == CorpusMatch()
    assert store.checkpoint() is None
    assert list(store.iter_jobs()) == []
    assert not directory.exists()
    default = PipelineCorpus(settings=settings)
    assert default.directory == Path(module.__file__).resolve().parents[3] / "data/corpus"


@pytest.mark.parametrize("projects", [
    ["https://outside.test/group/a"], ["../escape"], ["group/a?token=credential"],
    ["group/a/-/pipelines/1"], ["//outside.test/group/a"], ["group\\a"],
    ["https://user:password@gitlab.test/group/a"], ["group/a#secret"],
    ["group/%2e%2e"], ["group/" + TOKEN], [],
])
def test_preview_rejects_unsafe_projects_without_echo(settings, projects):
    with pytest.raises(CorpusError) as error:
        preview_harvest(settings, projects)
    assert TOKEN not in str(error.value)
    assert "password" not in str(error.value)


@pytest.mark.parametrize("kwargs", [
    {"per_project": 0}, {"per_project": 501}, {"concurrency": 4}, {"concurrency": 1},
    {"per_project": True},
])
def test_plan_bounds_are_explicit(settings, kwargs):
    with pytest.raises(CorpusError):
        preview_harvest(settings, ["group/a"], **kwargs)


def test_plan_deduplicates_host_path_and_case(settings):
    plan = preview_harvest(settings, ["group/a", ORIGIN + "/group/a", "GROUP/A"])
    assert plan.projects == ("group/a",)
    assert plan.target_distinct_pipelines == 75


@pytest.mark.asyncio
async def test_collects_225_distinct_failed_pipelines_not_225_jobs(tmp_path, settings, monkeypatch):
    script = GitLabScript({1: list(range(1, 91)), 2: list(range(1, 91)), 3: list(range(1, 91))})
    store = PipelineCorpus(tmp_path, settings=settings)
    analyze = module.PipelineAnalyzer.analyze_input
    calls = []

    def observed(analyzer, analysis_input, *args, **kwargs):
        assert analyzer.settings.llm_mode == "disabled"
        assert analyzer.settings.llm_base_url == ""
        assert analysis_input.configs == []
        assert analysis_input.run.raw == analysis_input.job.raw == {}
        calls.append(analysis_input.run.external_id)
        return analyze(analyzer, analysis_input, *args, **kwargs)

    monkeypatch.setattr(module.PipelineAnalyzer, "analyze_input", observed)
    report = await collect(
        script, settings, store, ("group/a", "group/b", "group/c"), per_project=75,
    )
    assert report.target_met and report.state == "complete"
    assert report.over_200_distinct_failed_pipelines
    assert report.selected_distinct_pipeline_count == 225
    assert report.completed_distinct_pipeline_count == 225
    assert report.summary.retained_pipeline_count == report.summary.retained_job_count == 225
    assert len(calls) == 225
    for project in report.projects:
        assert project.retained_pipeline_count == project.analyzed_pipeline_count == 75
        assert project.newest_pipeline_id == 90 and project.oldest_pipeline_id == 16
        assert project.rule_distribution[0].rule_id == "compiler.cs0161"
    assert store.match(ORIGIN + "/group/a", "compiler.cs0161").model_dump() == {
        "seen_failed_pipelines": 75, "failed_jobs": 75,
    }
    serialized = report.model_dump_json() + store.path.read_bytes().decode(errors="replace")
    assert "raw-private-user-marker" not in serialized
    assert "raw-variable-marker" not in serialized
    assert "raw-ref-marker" not in serialized and "raw-job-marker" not in serialized
    assert all(job.configuration == "omitted" and not job.source_verified
               for job in store.iter_jobs())
    assert report.summary.rule_checksums == (module.rule_checksum(),)


@pytest.mark.asyncio
async def test_numeric_order_and_stable_pagination_over_100(tmp_path, settings):
    script = GitLabScript({1: list(range(1, 131))})
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store, per_project=125)
    listings = [params for path, params in script.requests if path.endswith("/pipelines")]
    assert [(p["page"], p["per_page"]) for p in listings] == [("1", "100"), ("2", "100")]
    assert report.target_met
    assert report.projects[0].newest_pipeline_id == 130
    assert report.projects[0].oldest_pipeline_id == 6
    trace_ids = [int(re.search(r"/jobs/(\d+)/trace", path)[1]) for path, _ in script.requests
                 if path.endswith("/trace")]
    assert trace_ids == sorted(trace_ids, reverse=True)


@pytest.mark.asyncio
async def test_blocking_failed_jobs_first_two_and_actual_failed_only(tmp_path, settings):
    script = GitLabScript()
    script.jobs[1, 101] = [
        {"id": 50, "name": "optional", "status": "failed", "allow_failure": True},
        {"id": 99, "name": "passed", "status": "success"},
        {"id": 7, "name": "blocking first", "status": "failed"},
        {"id": 8, "name": "blocking latest", "status": "failed"},
        {"id": 8, "name": "duplicate", "status": "failed"},
    ]
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store)
    assert list(script.trace_calls) == [(1, 8), (1, 7)]
    assert report.summary.retained_job_count == 2
    assert store.match(ORIGIN + "/group/a", "compiler.cs0161").model_dump() == {
        "seen_failed_pipelines": 1, "failed_jobs": 2,
    }
    assert not report.over_200_distinct_failed_pipelines


@pytest.mark.asyncio
async def test_allowed_failure_is_sampled_when_no_blocking_failure(tmp_path, settings):
    script = GitLabScript()
    script.jobs[1, 101] = [{"id": 5, "status": "failed", "allow_failure": True}]
    store = PipelineCorpus(tmp_path, settings=settings)
    await collect(script, settings, store)
    assert next(store.iter_jobs()).allow_failure


@pytest.mark.asyncio
async def test_repeated_execution_deduplicates_and_reuses_jobs(tmp_path, settings):
    script = GitLabScript({1: [9, 10, 100]})
    store = PipelineCorpus(tmp_path, settings=settings)
    first = await collect(script, settings, store, per_project=2)
    assert first.summary.retained_pipeline_count == 2
    counts = script.trace_calls.copy()
    second = await collect(
        script, settings, PipelineCorpus(tmp_path, settings=settings), per_project=2,
    )
    assert second.target_met and second.summary.retained_pipeline_count == 2
    assert script.trace_calls == counts
    script.pipelines[1].append(101)
    third = await collect(script, settings, store, per_project=2)
    assert third.selected_distinct_pipeline_count == 2
    assert third.summary.retained_pipeline_count == 3
    assert script.trace_calls[1, 1010] == 1


@pytest.mark.asyncio
async def test_no_logs_unreadable_empty_unknown_are_distinct(tmp_path, settings):
    script = GitLabScript({1: [1, 2, 3, 4, 5, 6]})
    script.jobs[1, 1] = []
    script.jobs[1, 2] = httpx.Response(403, text=TOKEN)
    script.traces[1, 30] = "  \n\t"
    script.traces[1, 40] = httpx.Response(404, text=TOKEN)
    script.traces[1, 50] = UNKNOWN
    script.traces[1, 60] = "x" * (MAX_TRACE_BYTES + 1)
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store, per_project=6)
    project = report.projects[0]
    assert report.target_met  # Target counts distinct pipeline observations, not readable traces.
    assert project.analyzed_pipeline_count == project.unknown_pipeline_count == 1
    assert project.analyzed_job_count == project.unknown_job_count == 1
    assert project.no_logs_pipeline_count == 5
    assert project.unreadable_pipeline_count == 3
    assert project.unreadable_job_count == 2 and project.oversized_job_count == 1
    assert project.empty_job_count == 1
    assert len(project.unknown_excerpts) == 1
    assert "753" in project.unknown_excerpts[0].text
    assert TOKEN not in report.model_dump_json()
    unknown = next(job for job in store.iter_jobs() if job.state == "unknown")
    assert unknown.log == UNKNOWN
    assert not any("confirmed" in key or "probability" in key for key in
                   store.match(ORIGIN + "/group/a", unknown.rule_id).model_dump())


@pytest.mark.asyncio
async def test_unknown_excerpts_are_bounded_and_full_logs_retained(tmp_path, settings):
    script = GitLabScript({1: list(range(1, 9))})
    log = "diagnostic context\n" * 80 + "ERROR: " + "α" * 1500
    for pipeline_id in range(1, 9):
        script.traces[1, pipeline_id * 10] = log
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store, per_project=8)
    assert len(report.projects[0].unknown_excerpts) == 5
    assert all(len(excerpt.text.encode()) <= 800 for excerpt in report.projects[0].unknown_excerpts)
    assert all(job.log == log for job in store.iter_jobs())


@pytest.mark.asyncio
async def test_redacts_known_exact_encoded_keys_and_metadata_before_any_cut(tmp_path, settings):
    secret = 'synthetic opaque /+&?"\\-value-12349'
    settings = replace(settings, configured_gitlab_token=secret)
    script = GitLabScript(token=secret)
    encoded = [
        secret, quote(secret, safe=""), quote_plus(secret, safe=""),
        quote(quote(secret, safe=""), safe=""), json.dumps(secret, ensure_ascii=True)[1:-1],
        base64.b64encode(secret.encode()).decode(),
        base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
        "".join(f"%{byte:02x}" for byte in secret.encode()), settings.llm_api_key,
    ]
    script.jobs[1, 101] = [{
        "id": 10, "status": "failed", "name": "x" * 245 + secret,
        "failure_reason": secret, "raw": {"secret": secret},
    }]
    script.traces[1, 10] = "\n".join(encoded) + "\n" + KNOWN
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store)
    stored = store.path.read_bytes().decode(errors="replace")
    job = next(store.iter_jobs())
    for value in encoded:
        assert value not in stored and value not in report.model_dump_json()
        assert value not in job.log
    assert "synthetic opaque" not in job.name
    assert "[REDACTED]" in job.log
    # A cut inside a credential may not retain its prefix: sanitize first.
    sanitized = store.scrub.text("x" * (MAX_TRACE_BYTES - 10) + secret)
    bounded, truncated = module._bounded(sanitized, MAX_TRACE_BYTES, log=True)
    assert "synthetic" not in bounded
    assert len(bounded.encode()) <= MAX_TRACE_BYTES
    assert isinstance(truncated, bool)


@pytest.mark.asyncio
async def test_new_configured_secret_rescrubs_existing_traces_without_network(tmp_path, settings):
    script = GitLabScript()
    secret = "previously-unknown-opaque-value-836497"
    script.traces[1, 1010] = secret + "\n" + KNOWN
    store = PipelineCorpus(tmp_path, settings=settings)
    await collect(script, settings, store)
    assert secret in store.path.read_bytes().decode(errors="replace")
    fresh = PipelineCorpus(tmp_path, settings=replace(settings, llm_api_key=secret))
    assert secret not in next(fresh.iter_jobs()).log
    reevaluate_corpus(fresh)
    assert secret not in fresh.path.read_bytes().decode(errors="replace")


@pytest.mark.asyncio
async def test_429_job_checkpoint_resumes_without_refetching_completed_trace(tmp_path, settings):
    script = GitLabScript()
    script.jobs[1, 101] = [{"id": job, "status": "failed"} for job in (20, 10)]
    script.traces[1, 10] = httpx.Response(429, text=TOKEN, headers={"Retry-After": "3600"})
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store)
    assert report.state == "rate_limited" and not report.target_met
    assert report.summary.retained_pipeline_count == 1
    assert report.summary.retained_job_count == 2
    assert report.projects[0].pending_job_count == 1
    assert report.projects[0].unreadable_job_count == 0
    assert store.checkpoint().state == "rate_limited"
    assert script.trace_calls == {(1, 20): 1, (1, 10): 1}
    script.traces[1, 10] = KNOWN
    resumed = await collect(script, settings, PipelineCorpus(tmp_path, settings=settings))
    assert resumed.target_met
    assert script.trace_calls == {(1, 20): 1, (1, 10): 2}
    assert resumed.projects[0].pending_pipeline_count == 0


@pytest.mark.asyncio
async def test_429_listing_checkpoints_metadata_and_stops_all_remote_work(tmp_path, settings):
    script = GitLabScript({1: list(range(1, 126)), 2: [1000]})
    script.page_overrides[1, 2] = httpx.Response(429, text=TOKEN)
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store, ("group/a", "group/b"), per_project=125)
    assert report.state == "rate_limited"
    assert report.selected_distinct_pipeline_count == 100
    assert report.completed_distinct_pipeline_count == 0
    assert len(script.requests) == 3 and not script.trace_calls
    assert report.progress[1].listing_state == "pending"


@pytest.mark.asyncio
async def test_cancellation_preserves_completed_job_and_pending_sample(tmp_path, settings):
    script = GitLabScript()
    script.jobs[1, 101] = [{"id": job, "status": "failed"} for job in (20, 10)]
    script.pause_job = 10
    store = PipelineCorpus(tmp_path, settings=settings)
    task = asyncio.create_task(collect(script, settings, store))
    await script.paused.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert store.checkpoint().state == "interrupted"
    assert {job.state for job in store.iter_jobs()} == {"analyzed", "pending"}
    script.pause_job = None
    resumed = await collect(script, settings, PipelineCorpus(tmp_path, settings=settings))
    assert resumed.target_met and script.trace_calls[1, 20] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("concurrency", [2, 3])
async def test_pipeline_concurrency_is_bounded_without_delays(tmp_path, settings, concurrency):
    script = GitLabScript({1: list(range(1, 9))})
    script.barrier_size = concurrency
    async with script.provider() as provider:
        assert provider._max_parallel_requests == 4
        report = await harvest_pipelines(
            settings, ["group/a"], corpus=PipelineCorpus(tmp_path, settings=settings),
            provider=provider, per_project=8, concurrency=concurrency,
        )
    assert report.target_met
    assert script.max_active == concurrency


@pytest.mark.asyncio
@pytest.mark.parametrize("header", ["1", "900", "broken", None])
async def test_duplicate_or_bad_pagination_never_inflates_count(tmp_path, settings, header):
    script = GitLabScript()
    payload = [{"id": 101, "status": "failed"}] * 3
    script.page_overrides[1, 1] = httpx.Response(
        200, json=payload, headers={} if header is None else {"x-next-page": header},
    )
    script.page_overrides[1, 2] = httpx.Response(200, json=payload, headers={"x-next-page": "3"})
    report = await collect(
        script, settings, PipelineCorpus(tmp_path, settings=settings), per_project=3,
    )
    assert not report.target_met and report.state == "shortfall"
    assert report.selected_distinct_pipeline_count == 1
    assert report.projects[0].retained_pipeline_count == 1
    assert len([path for path, _ in script.requests if path.endswith("/pipelines")]) <= 2


@pytest.mark.asyncio
async def test_insufficient_projects_report_shortfall_not_a_fake_225(tmp_path, settings):
    script = GitLabScript({1: [1], 2: [1], 3: []})
    report = await collect(
        script, settings, PipelineCorpus(tmp_path, settings=settings),
        ("group/a", "group/b", "group/c"), per_project=75,
    )
    assert report.state == "shortfall" and not report.target_met
    assert report.selected_distinct_pipeline_count == 2
    assert not report.over_200_distinct_failed_pipelines
    assert all(progress.listing_state == "exhausted" for progress in report.progress)


@pytest.mark.asyncio
async def test_offline_reevaluation_updates_rules(tmp_path, settings, monkeypatch):
    script = GitLabScript()
    script.traces[1, 1010] = UNKNOWN
    store = PipelineCorpus(tmp_path, settings=settings)
    first = await collect(script, settings, store)
    assert first.projects[0].unknown_job_count == 1
    before_calls = list(script.requests)

    def updated(snapshot):
        assert snapshot.config_bundle == []
        assert snapshot.redacted_log == UNKNOWN
        return Finding(
            rule_id="custom.new_pattern", severity="error", category="deployment_failure",
            title="New local diagnostic", explanation="Log-only observation.",
            fix=[], evidence=[], confidence="observed",
        )

    monkeypatch.setattr(module, "diagnose_job", updated)
    monkeypatch.setattr(module, "rule_checksum", lambda: "d" * 64)
    offline_settings = replace(settings, configured_gitlab_token=None)
    report = reevaluate_corpus(PipelineCorpus(tmp_path, settings=offline_settings))
    assert script.requests == before_calls
    assert report.reevaluated_job_count == 1 and report.unknown_job_count == 0
    assert report.rule_checksum == "d" * 64
    assert store.match(ORIGIN + "/group/a", "custom.new_pattern").failed_jobs == 1
    assert store.match(ORIGIN + "/group/b", "custom.new_pattern").failed_jobs == 0
    assert store.match("https://other.test/group/a", "custom.new_pattern").failed_jobs == 0
    assert next(store.iter_jobs()).log == UNKNOWN


@pytest.mark.asyncio
async def test_analysis_error_keeps_log_for_offline_recovery(tmp_path, settings, monkeypatch):
    script = GitLabScript()
    store = PipelineCorpus(tmp_path, settings=settings)
    original = module.diagnose_job

    def broken(snapshot):
        raise ValueError(TOKEN + snapshot.redacted_log)

    monkeypatch.setattr(module, "diagnose_job", broken)
    report = await collect(script, settings, store)
    assert report.projects[0].analysis_error_job_count == 1
    assert report.projects[0].unreadable_job_count == 0
    assert next(store.iter_jobs()).log == KNOWN
    assert TOKEN not in report.model_dump_json()
    monkeypatch.setattr(module, "diagnose_job", original)
    updated = reevaluate_corpus(store)
    assert updated.reevaluated_job_count == 1 and updated.analysis_error_job_count == 0


@pytest.mark.asyncio
async def test_distinct_ids_are_scoped_by_host_project_pipeline_and_job(tmp_path, settings):
    store = PipelineCorpus(tmp_path, settings=settings)
    await collect(GitLabScript({1: [1], 2: [1]}), settings, store, ("group/a", "group/b"))
    other = replace(settings, configured_gitlab_base_url="https://second.test")
    await collect(GitLabScript({1: [1]}, origin=other.configured_gitlab_base_url), other, store)
    assert store.summary().retained_pipeline_count == store.summary().retained_job_count == 3
    for project in (ORIGIN + "/group/a", ORIGIN + "/group/b", "https://second.test/group/a"):
        assert store.match(project, "compiler.cs0161").failed_jobs == 1


@pytest.mark.parametrize("content", [b"", b"not a sqlite store", b'{"schema_version": 1}'])
def test_corrupt_store_fails_closed_and_is_never_replaced(tmp_path, settings, content):
    path = tmp_path / "pipelines.sqlite3"
    path.write_bytes(content)
    for operation in ("summary", "initialize"):
        with pytest.raises(CorpusError):
            getattr(PipelineCorpus(tmp_path, settings=settings), operation)()
        assert path.read_bytes() == content


@pytest.mark.asyncio
async def test_corrupt_record_is_a_controlled_error(tmp_path, settings):
    store = PipelineCorpus(tmp_path, settings=settings)
    await collect(GitLabScript(), settings, store)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE jobs SET record = ?", ('{"raw": "untrusted-corrupt-marker"}',))
    before = store.path.read_bytes()
    with pytest.raises(CorpusError):
        PipelineCorpus(tmp_path, settings=settings).initialize()
    assert store.path.read_bytes() == before


@pytest.mark.asyncio
async def test_pipeline_capacity_stops_without_eviction(tmp_path, settings):
    store = PipelineCorpus(tmp_path, settings=settings, max_pipelines=2)
    report = await collect(GitLabScript({1: [1, 2, 3]}), settings, store, per_project=3)
    assert report.state == "capacity" and not report.target_met
    assert report.summary.retained_pipeline_count == 2
    assert report.projects[0].oldest_pipeline_id == 2


@pytest.mark.asyncio
async def test_database_byte_capacity_stops_without_oversized_store(tmp_path, settings):
    script = GitLabScript()
    script.traces[1, 1010] = "ordinary retained diagnostic\n" * 4000
    store = PipelineCorpus(tmp_path, settings=settings, max_store_bytes=65536)
    report = await collect(script, settings, store)
    assert report.state == "capacity"
    assert store.path.stat().st_size <= 65536
    assert report.summary.retained_pipeline_count == 1
    assert next(store.iter_jobs()).state == "pending"


@pytest.mark.asyncio
async def test_locked_store_has_no_busy_retry_or_overwrite(tmp_path, settings):
    store = PipelineCorpus(tmp_path, settings=settings)
    store.initialize()
    with sqlite3.connect(store.path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        with pytest.raises(CorpusError):
            await collect(GitLabScript(), settings, store)
    assert store.summary().retained_pipeline_count == 0


@pytest.mark.asyncio
async def test_provider_rejects_redirect_and_stops_at_429_without_retry(settings):
    calls = []

    def handle(request):
        calls.append(request)
        return httpx.Response(429, text=TOKEN, headers={"Retry-After": "60"})

    async with CorpusGitLabProvider(ORIGIN, transport=httpx.MockTransport(handle)) as provider:
        for _ in range(3):
            with pytest.raises(ProviderError) as error:
                await provider._request(TOKEN, "GET", "/projects/1/pipelines")
            assert error.value.status_code == 429
            assert TOKEN not in str(error.value)
    assert len(calls) == 1
    calls.clear()

    def redirect(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": "https://outside.test/collect"})

    async with CorpusGitLabProvider(ORIGIN, transport=httpx.MockTransport(redirect)) as provider:
        with pytest.raises(ProviderError):
            await provider._request(TOKEN, "GET", "/projects/1")
    assert len(calls) == 1


@pytest.mark.asyncio
async def test_transport_error_is_one_shot_and_does_not_echo_request():
    calls = []

    def handle(request):
        calls.append(request)
        raise httpx.ConnectError(TOKEN, request=request)

    async with CorpusGitLabProvider(ORIGIN, transport=httpx.MockTransport(handle)) as provider:
        with pytest.raises(ProviderError) as error:
            await provider._request(TOKEN, "GET", "/projects/1")
    assert len(calls) == 1 and TOKEN not in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize("method,path", [
    ("POST", "/projects/1"), ("GET", "https://outside.test/projects/1"),
    ("GET", "//outside.test/projects/1"), ("GET", "/projects/1/repository/tree"),
    ("GET", "/projects/1/merge_requests"), ("GET", "/projects/.."),
    ("GET", "/projects/%2e%2e"), ("GET", "/projects/1?token=abc"),
])
async def test_provider_only_allows_harvest_get_paths(method, path):
    def forbidden(request):
        pytest.fail("Disallowed endpoint reached HTTP transport")

    provider = CorpusGitLabProvider(ORIGIN, transport=httpx.MockTransport(forbidden))
    with pytest.raises(ProviderError):
        await provider._request(TOKEN, method, path)


@pytest.mark.asyncio
async def test_streamed_oversize_is_discarded_not_partially_redacted(tmp_path, settings):
    closed = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"x" * (MAX_TRACE_BYTES - 10)
            yield TOKEN.encode()

        async def aclose(self):
            closed.append(True)

    script = GitLabScript()
    script.traces[1, 1010] = httpx.Response(200, stream=Stream())
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store)
    assert closed
    assert report.projects[0].oversized_job_count == 1
    assert next(store.iter_jobs()).log == ""
    assert "synthetic-opaque" not in store.path.read_bytes().decode(errors="replace")


@pytest.mark.asyncio
async def test_missing_token_or_wrong_provider_host_never_writes(tmp_path, settings):
    no_token = replace(settings, configured_gitlab_token=None)
    directory = tmp_path / "absent"
    store = PipelineCorpus(directory, settings=no_token)
    assert not preview_harvest(no_token, ["group/a"]).token_configured
    with pytest.raises(CorpusError):
        await harvest_pipelines(no_token, ["group/a"], corpus=store)
    with pytest.raises(CorpusError):
        await harvest_pipelines(settings, ["group/a"], corpus=store,
                                provider=CorpusGitLabProvider("https://outside.test"))
    with pytest.raises(CorpusError):
        await harvest_pipelines(
            settings, ["group/a"], corpus=store, provider=GitLabProvider(ORIGIN),
        )
    assert not directory.exists()


def test_cli_defaults_to_offline_preview_and_summary(tmp_path, capsys):
    directory = tmp_path / "absent"
    assert cli.main(["--project", "group/a", "--directory", str(directory)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "harvest_preview"
    assert output["writes"] is output["remote_requests"] is False
    assert not directory.exists()
    assert cli.main(["--summary", "--directory", str(directory)]) == 0
    assert json.loads(capsys.readouterr().out)["retained_pipeline_count"] == 0
    assert not directory.exists()
    assert cli.main(["--reevaluate", "--directory", str(directory)]) == 0
    assert json.loads(capsys.readouterr().out)["mode"] == "reevaluation_preview"
    assert not directory.exists()


def test_cli_execute_and_reevaluate_are_explicit(tmp_path, monkeypatch, capsys, settings):
    script = GitLabScript()
    real_harvest = module.harvest_pipelines

    async def mocked_harvest(configuration, projects, **kwargs):
        assert configuration.configured_gitlab_token == TOKEN
        async with script.provider() as provider:
            return await real_harvest(configuration, projects, provider=provider, **kwargs)

    monkeypatch.setattr(cli, "harvest_pipelines", mocked_harvest)
    assert cli.main([
        "--project", "group/a", "--per-project", "1", "--execute", "--directory", str(tmp_path),
    ]) == 0
    assert json.loads(capsys.readouterr().out)["target_met"]
    calls = list(script.requests)
    monkeypatch.setattr(cli, "get_settings", lambda: replace(
        settings, configured_gitlab_token=None,
    ))
    assert cli.main(["--reevaluate", "--execute", "--directory", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["reevaluated_job_count"] == 1
    assert script.requests == calls


def test_cli_rejects_token_arguments_without_echoing_them(capsys):
    with pytest.raises(SystemExit) as error:
        cli.main(["--project", "group/a", "--token", TOKEN])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert TOKEN not in output.out + output.err


def test_cli_errors_hide_configuration_and_upstream_details(tmp_path, monkeypatch, capsys):
    def broken():
        raise ValueError(TOKEN)

    monkeypatch.setattr(cli, "get_settings", broken)
    assert cli.main(["--summary", "--directory", str(tmp_path)]) == 2
    assert TOKEN not in capsys.readouterr().out


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_job", [
    {"id": "../invalid", "status": "failed"},
    {"id": 50, "status": "failed", "failure_reason": {"token": TOKEN}},
    {"status": "failed", "name": TOKEN},
])
async def test_bad_job_metadata_is_unreadable_without_stopping_other_pipelines(
    tmp_path, settings, bad_job,
):
    script = GitLabScript({1: [1, 2]})
    if "id" in bad_job:
        script.jobs[1, 2] = [bad_job]
    else:
        # The provider deliberately filters a missing-ID dict; a malformed list
        # itself must still be recorded as unreadable rather than empty success.
        script.jobs[1, 2] = httpx.Response(200, json={"raw": bad_job})
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store, per_project=2)
    assert report.target_met
    assert report.projects[0].unreadable_pipeline_count == 1
    assert report.projects[0].analyzed_pipeline_count == 1
    assert TOKEN not in report.model_dump_json()


@pytest.mark.asyncio
async def test_writer_lease_rejects_overlapping_runs_and_is_reusable(tmp_path, settings):
    store = PipelineCorpus(tmp_path, settings=settings)
    script = GitLabScript()
    with store._writer():
        with pytest.raises(CorpusError, match="writer"):
            await collect(script, settings, PipelineCorpus(tmp_path, settings=settings))
        assert not script.requests
        with pytest.raises(CorpusError, match="writer"):
            reevaluate_corpus(PipelineCorpus(tmp_path, settings=settings))
    report = await collect(script, settings, store)
    assert report.target_met
    assert (tmp_path / ".writer.lock").stat().st_size == 1


@pytest.mark.asyncio
async def test_existing_reader_revalidates_external_schema_change(tmp_path, settings):
    store = PipelineCorpus(tmp_path, settings=settings)
    await collect(GitLabScript(), settings, store)
    assert store.summary().retained_job_count == 1
    with sqlite3.connect(store.path) as connection:
        connection.execute("PRAGMA user_version = 999")
    before = store.path.read_bytes()
    with pytest.raises(CorpusError):
        store.summary()
    with pytest.raises(CorpusError):
        store.initialize()
    assert before == store.path.read_bytes()


@pytest.mark.asyncio
async def test_summary_and_lazy_job_reads_preserve_log_byte_count(tmp_path, settings):
    store = PipelineCorpus(tmp_path, settings=settings)
    await collect(GitLabScript(), settings, store)
    job = next(store.iter_jobs())
    pipeline = store._pipelines()[0]
    assert store._jobs(pipeline, with_log=False)[0].log_bytes == len(job.log.encode())
    assert PipelineCorpus(tmp_path, settings=settings).summary().retained_job_count == 1


@pytest.mark.asyncio
async def test_bounded_job_enumeration_reports_incomplete_coverage(tmp_path, settings):
    script = GitLabScript()
    script.jobs[1, 101] = [{"id": index, "status": "success"} for index in range(1, 351)]
    store = PipelineCorpus(tmp_path, settings=settings)
    report = await collect(script, settings, store)
    assert report.projects[0].job_enumeration_capped_pipeline_count == 1
    assert report.projects[0].no_logs_pipeline_count == 1
    assert report.summary.retained_job_count == 0
    assert len([path for path, _ in script.requests if path.endswith("/jobs")]) == 3


@pytest.mark.asyncio
async def test_explicit_zero_projects_are_present_in_report(tmp_path, settings):
    script = GitLabScript({1: []})
    report = await collect(script, settings, PipelineCorpus(tmp_path, settings=settings))
    assert report.projects[0].project_key == ORIGIN + "/group/a"
    assert report.projects[0].retained_pipeline_count == 0
    assert not report.target_met