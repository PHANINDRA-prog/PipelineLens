"""Service regressions against the actual GitLab provider, with no production I/O."""

from __future__ import annotations

import asyncio
import inspect
from collections import Counter
from dataclasses import replace
from urllib.parse import quote

import httpx
import pytest
from pydantic import ValidationError

from pipelinelens.config import Settings
from pipelinelens.domain import CiConfigAccessReport, DownloadState
from pipelinelens.providers.base import ProviderError
from pipelinelens.providers.gitlab import GitLabProvider
from pipelinelens.services import inspection
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.gitlab_includes import project_include_key
from pipelinelens.services.inspection import InspectionResult, inspect_gitlab
from pipelinelens.services.pipeline_url import PipelineUrlError, parse_gitlab_url

ORIGIN = "https://gitlab.test"
SHA = "a" * 40
HEAD = "b" * 40
TOKEN = "request-opaque-secret"
PROJECT = "group/sample"
RUN_ID = "59848076"
CS0161 = (
    "src/Controller.cs(47,30): error CS0161: Controller.GetItems(string, bool): "
    "not all code paths return a value"
)
SSH_FAILURE = (
    "ERROR: Preparation failed: creating docker connection: creating docker tunnel: "
    "preparing environment: dial ssh: after retrying 167 times during 10m0s timeout: "
    "dial tcp executor.invalid:22: i/o timeout"
)
ROOT_YAML = (
    "stages: [build, deploy]\nbuild:\n  stage: build\n  script: dotnet build\n"
    "deploy:\n  stage: deploy\n  script: ./deploy.sh\n"
    "sonarqube-check:\n  script: sonar-scanner\n"
)


def settings() -> Settings:
    return Settings(
        environment="test", database_url="sqlite://", redis_url="redis://unused",
        max_log_bytes=500_000, max_context_chars=18_000, llm_mode="disabled",
        llm_base_url="https://must-not-be-called.invalid", llm_model="unused",
        llm_api_key="configured-llm-secret", allow_private_context=False,
        configured_gitlab_token="configured-gitlab-secret", configured_gitlab_base_url=ORIGIN,
    )


class GitLabStub:
    """GET-only endpoint fixtures; unexpected calls fail instead of reaching a network."""

    def __init__(self) -> None:
        self.responses: dict = {}
        self.calls: list[httpx.Request] = []
        self.yield_requests = False
        self.active = 0
        self.peak = 0
        self.overlaps: list[set[str]] = []
        self.inflight: set[str] = set()
        self.provider = GitLabProvider(ORIGIN, transport=httpx.MockTransport(self.handle))
        self.add_project("42", PROJECT)
        self.add_pipeline(RUN_ID, "success")
        self.responses["/projects/42/repository/commits/main"] = {"id": HEAD}
        self.responses["/projects/42/pipelines"] = [self.pipeline]

    @property
    def repository(self):
        return self.provider._repository(self.responses[f"/projects/{PROJECT}"])

    @property
    def pipeline(self):
        return self.responses[f"/projects/42/pipelines/{RUN_ID}"]

    def add_project(self, project_id: str, path: str) -> None:
        owner, _, name = path.rpartition("/")
        payload = {
            "id": int(project_id), "path": name, "path_with_namespace": path,
            "namespace": {"full_path": owner}, "default_branch": "main",
            "web_url": f"{ORIGIN}/{path}", "ci_config_path": None,
        }
        self.responses[f"/projects/{project_id}"] = payload
        self.responses[f"/projects/{path}"] = payload
        self.responses[f"/projects/{project_id}/repository/files/.gitlab-ci.yml/raw"] = ROOT_YAML
        self.responses[f"/projects/{project_id}/repository/tree"] = [
            {"path": ".gitlab-ci.yml", "type": "blob"},
            {"path": "src/Controller.cs", "type": "blob"},
            {"path": "MigrationManagerPackage/Intended", "type": "tree"},
        ]

    def add_pipeline(
        self, run_id: str, status: str, project_id: str = "42", sha: str = SHA,
    ) -> None:
        self.responses[f"/projects/{project_id}/pipelines/{run_id}"] = {
            "id": int(run_id), "project_id": int(project_id), "status": status,
            "ref": "main", "sha": sha, "name": "Pipeline fixture",
            "web_url": f"{ORIGIN}/unused/path/-/pipelines/{run_id}",
            "variables": [{"key": "PRIVATE", "value": "RAW-MUST-NOT-ESCAPE"}],
        }
        for resource in ("jobs", "bridges", "merge_requests"):
            self.responses[f"/projects/{project_id}/pipelines/{run_id}/{resource}"] = []
        self.responses[f"/projects/{project_id}/repository/commits/{sha}/diff"] = []

    def set_jobs(self, jobs: list[dict], run_id: str = RUN_ID, project_id: str = "42") -> None:
        self.responses[f"/projects/{project_id}/pipelines/{run_id}/jobs"] = jobs
        for job in jobs:
            job.setdefault("pipeline", {"id": int(run_id), "project_id": int(project_id)})
            job.setdefault("allow_failure", False)
            self.responses[f"/projects/{project_id}/jobs/{job['id']}"] = job
            self.responses[f"/projects/{project_id}/jobs/{job['id']}/trace"] = (
                CS0161 if job.get("status") == "failed" else "Job succeeded"
            )

    async def handle(self, request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.host == "gitlab.test"
        assert request.headers["PRIVATE-TOKEN"] == TOKEN
        assert not any(part in request.url.path for part in (
            "/variables", "/secrets", "/trigger", "/retry", "/play",
        ))
        self.calls.append(request)
        self.active += 1
        self.peak = max(self.peak, self.active)
        self.inflight.add(request.url.path)
        self.overlaps.append(self.inflight.copy())
        try:
            if self.yield_requests:
                await asyncio.sleep(0)  # Scheduling yield, not a real delay/network operation.
            path = request.url.path.removeprefix("/api/v4")
            if path not in self.responses:
                if "/repository/commits/" in path and not path.endswith("/diff"):
                    return httpx.Response(404)
                raise AssertionError(f"Unexpected mocked GET: {path}")
            payload = self.responses[path]
            if callable(payload):
                payload = payload(request)
                if inspect.isawaitable(payload):
                    payload = await payload
            if isinstance(payload, Exception):
                raise payload
            if isinstance(payload, httpx.Response):
                return payload
            if type(payload) is int:
                return httpx.Response(payload, json={"message": TOKEN + " private upstream body"})
            return (httpx.Response(200, text=payload) if isinstance(payload, str)
                    else httpx.Response(200, json=payload))
        finally:
            self.active -= 1
            self.inflight.discard(request.url.path)

    async def inspect(self, suffix: str | None = None, **kwargs) -> InspectionResult:
        reference = parse_gitlab_url(
            f"{ORIGIN}/{PROJECT}{suffix if suffix is not None else '/-/pipelines/' + RUN_ID}"
        )
        return await inspect_gitlab(
            self.provider, TOKEN, self.repository, reference, kwargs.pop("settings", settings()),
            **kwargs,
        )

    def count(self, path: str) -> int:
        return sum(request.url.path == "/api/v4" + path for request in self.calls)

    def trace_ids(self) -> list[str]:
        return [request.url.path.split("/")[-2] for request in self.calls
                if request.url.path.endswith("/trace")]


@pytest.fixture
async def gitlab():
    stub = GitLabStub()
    try:
        yield stub
    finally:
        await stub.provider.aclose()


def job(job_id: int, name: str = "build", status: str = "failed", **kwargs) -> dict:
    return {"id": job_id, "name": name, "status": status, **kwargs}


def linked_mr(stub: GitLabStub, iid: int = 7, head: str = SHA, rows: list | None = None) -> None:
    item = {
        "iid": iid, "project_id": 42, "title": "Change the CI input", "state": "opened",
        "source_branch": "feature", "target_branch": "main",
        "web_url": f"{ORIGIN}/{PROJECT}/-/merge_requests/{iid}",
        "author": {"email": "PRIVATE-EMAIL"}, "description": "PRIVATE-DESCRIPTION",
        "variables": {"secret": "PRIVATE-MR-VARIABLE"},
    }
    stub.responses[f"/projects/42/pipelines/{RUN_ID}/merge_requests"].append(item)
    stub.responses[f"/projects/42/merge_requests/{iid}"] = {
        **item, "diff_refs": {"head_sha": head, "base_sha": "c" * 40},
    }
    stub.responses[f"/projects/42/merge_requests/{iid}/diffs"] = rows or []


def bridge(project_id: int = 99, run_id: int = 17, **kwargs) -> dict:
    return {
        "id": project_id, "name": "trigger-child", "status": "failed",
        "allow_failure": False, "variables": {"PRIVATE": "PRIVATE-BRIDGE-VARIABLE"},
        "downstream_pipeline": {
            "id": run_id, "project_id": project_id, "status": "failed", "sha": SHA,
            "web_url": "https://evil.invalid/steal", "token": "PRIVATE-CHILD-TOKEN",
        }, **kwargs,
    }


def test_contract_signature_defaults_and_no_parent_owned_submitted_url() -> None:
    signature = inspect.signature(inspect_gitlab)
    assert list(signature.parameters) == [
        "provider", "token", "repository", "reference", "settings", "max_jobs",
    ]
    assert signature.parameters["max_jobs"].default == 5
    assert signature.return_annotation == "InspectionResult"
    assert set(InspectionResult.model_fields) == {
        "repository", "pipeline", "selected_job", "resolved_url", "reference_kind", "project_key",
        "findings", "jobs", "analyses", "ci_config_access", "config_bundle", "project_structure",
        "merge_requests", "changes", "downstream", "notes", "analyzed_job_count",
        "skipped_job_count", "status",
    }
    repo = GitLabProvider._repository({
        "id": 42, "path": "sample", "namespace": {"full_path": "group"},
        "web_url": f"{ORIGIN}/{PROJECT}",
    })
    data = dict(repository=repo, resolved_url=repo.web_url, reference_kind="repository",
                project_key=repo.web_url, ci_config_access=CiConfigAccessReport(complete=False),
                status="configuration_only")
    first, second = InspectionResult(**data), InspectionResult(**data)
    first.notes.append("one")
    assert second.notes == []
    assert first.pipeline is None and first.selected_job is None
    with pytest.raises(ValidationError):
        InspectionResult(**{**data, "status": "healthy"})


async def test_success_59848076_allowed_sonar_ssh_failure_is_warning_not_quality_gate(gitlab):
    gitlab.set_jobs([
        job(181725104, "sonarqube-check", allow_failure=True,
            failure_reason="runner_system_failure"),
        job(2, "deploy", "success"),
    ])
    gitlab.responses["/projects/42/jobs/181725104/trace"] = "Preparing runner\n" + SSH_FAILURE
    result = await gitlab.inspect()

    assert result.pipeline.external_id == RUN_ID
    assert result.pipeline.status == "success"
    assert result.status == "warning"
    finding = next(item for item in result.findings if item.job_id == "181725104")
    assert finding.rule_id == "runner.ssh_executor_unavailable"
    assert finding.category == "runner_infrastructure_failure"
    assert finding.severity == "warning" and finding.confidence == "observed"
    assert "allow_failure=true" in finding.explanation
    assert "overall pipeline successful" in finding.explanation
    assert finding.evidence[0].line == 2
    assert not any(item.category == "quality_gate_failure" for item in result.findings)
    assert not any(item.severity == "error" for item in result.findings)
    assert result.project_key == f"{ORIGIN}/{PROJECT}"
    assert result.analyses[0].job_source.source_url.startswith(f"{ORIGIN}/{PROJECT}/-/blob/{SHA}")
    assert result.analyzed_job_count == 2 and result.skipped_job_count == 0
    assert gitlab.count("/projects/42/repository/files/.gitlab-ci.yml/raw") == 1
    assert "RAW-MUST-NOT-ESCAPE" not in result.model_dump_json()
    assert all(snapshot.run.raw == snapshot.job.raw == {} for snapshot in result.analyses)


async def test_selected_success_182928815_fresh_parent60178941_and_failed_priority(gitlab):
    gitlab.add_pipeline("60178941", "success")
    gitlab.set_jobs([
        job(3, "deploy", "success"), job(4, "build", allow_failure=True),
        job(182928815, "validate", "success"),
    ], "60178941")
    result = await gitlab.inspect("/-/jobs/182928815", max_jobs=2)
    assert result.selected_job.external_id == "182928815"
    assert result.pipeline.external_id == "60178941"
    assert result.resolved_url.endswith("/-/jobs/182928815")
    assert result.reference_kind == "job"
    assert [snapshot.job.external_id for snapshot in result.analyses] == ["182928815", "4"]
    assert gitlab.trace_ids() == ["182928815", "4"]
    assert result.skipped_job_count == 1
    assert gitlab.count("/projects/42/jobs/182928815") == 1
    assert gitlab.count("/projects/42/pipelines/60178941") == 1


async def test_selected_job_outside_listing_is_still_included_even_at_budget_one(gitlab):
    gitlab.set_jobs([job(8), job(9, "deploy", "success")])
    gitlab.responses["/projects/42/jobs/10"] = job(
        10, "validate", "success", pipeline={"id": int(RUN_ID), "project_id": 42},
    )
    gitlab.responses["/projects/42/jobs/10/trace"] = "Job succeeded"
    result = await gitlab.inspect("/-/jobs/10", max_jobs=1)
    assert gitlab.trace_ids() == ["10"]
    assert {item.external_id for item in result.jobs} == {"8", "9", "10"}
    assert result.skipped_job_count == 2
    assert any(item.rule_id == "jobs.unanalyzed_failures" for item in result.findings)


async def test_failed60202316_compiler_cs0161_not_auth_and_authoritative_file_url(gitlab):
    gitlab.add_pipeline("60202316", "failed")
    gitlab.set_jobs([job(11)], "60202316")
    gitlab.responses["/projects/42/jobs/11/trace"] = (
        "Permission is hereby granted; 403 license clauses; 401 tests passed\n" + CS0161
    )
    result = await gitlab.inspect("/-/pipelines/60202316")
    assert result.status == "failed"
    assert result.findings[0].rule_id == "compiler.cs0161"
    assert result.findings[0].severity == "error"
    evidence = next(item for item in result.findings[0].evidence if item.path)
    assert evidence.path == "src/Controller.cs" and evidence.line == 47
    assert evidence.source_url == f"{ORIGIN}/{PROJECT}/-/blob/{SHA}/src/Controller.cs#L47"
    assert not any(item.category == "authentication_failure" for item in result.findings)
    assert any(item.rule_id == "pipeline.failed" for item in result.findings)


@pytest.mark.parametrize(("pipeline_status", "expected"), [
    ("success", "passed"), ("failed", "failed"), ("running", "in_progress"),
    ("pending", "in_progress"), ("created", "in_progress"),
    ("waiting_for_resource", "in_progress"), ("manual", "warning"),
    ("canceled", "warning"), ("skipped", "warning"), ("unknown", "warning"),
])
async def test_status_mapping_preserves_actual_outcome_without_rejecting_success(
    gitlab, pipeline_status, expected,
):
    gitlab.pipeline["status"] = pipeline_status
    result = await gitlab.inspect()
    assert result.status == expected
    assert result.pipeline.status == pipeline_status


async def test_success_scan_is_only_three_interesting_jobs_and_explicitly_not_complete(gitlab):
    gitlab.set_jobs([
        job(index, name, "success") for index, name in enumerate(
            ["misc", "build", "sonar-check", "package", "validate", "deploy"], 1,
        )
    ])
    result = await gitlab.inspect(max_jobs=8)
    assert [snapshot.job.name for snapshot in result.analyses] == ["deploy", "package", "validate"]
    assert result.analyzed_job_count == 3 and result.skipped_job_count == 3
    assert "not a complete pipeline audit" in " ".join(result.notes)
    assert all(item.severity == "info" for item in result.findings)


@pytest.mark.parametrize(("budget", "count"), [(-3, 1), (0, 1), (1, 1), (5, 5), (999, 8)])
async def test_trace_budget_clamps_one_to_eight_and_reports_skipped_failures(gitlab, budget, count):
    gitlab.pipeline["status"] = "failed"
    gitlab.set_jobs([job(index) for index in range(1, 13)])
    result = await gitlab.inspect(max_jobs=budget)
    assert len(gitlab.trace_ids()) == result.analyzed_job_count == count
    assert result.skipped_job_count == 12 - count
    assert any(item.rule_id == "jobs.unanalyzed_failures" for item in result.findings)


@pytest.mark.parametrize("status", [401, 403, 404])
async def test_unavailable_trace_does_not_abort_other_evidence(gitlab, status):
    gitlab.pipeline["status"] = "failed"
    gitlab.set_jobs([job(1), job(2)])
    gitlab.responses["/projects/42/jobs/1/trace"] = status
    result = await gitlab.inspect()
    assert result.analyzed_job_count == 2
    assert result.analyses[0].progress.job_log == DownloadState.FAILED
    assert result.analyses[0].redacted_log == ""
    assert any(item.rule_id == "compiler.cs0161" and item.job_id == "2" for item in result.findings)
    assert any(f"HTTP {status}" in note and "partial" in note for note in result.notes)
    assert TOKEN not in result.model_dump_json()
    assert "private upstream body" not in result.model_dump_json()


async def test_empty_success_trace_has_no_error_or_deployment_claim(gitlab):
    gitlab.set_jobs([job(1, "deploy", "success")])
    gitlab.responses["/projects/42/jobs/1/trace"] = ""
    result = await gitlab.inspect()
    finding = next(item for item in result.findings if item.job_id == "1")
    assert finding.rule_id == "job.no_failure_observed"
    assert finding.severity == "info" and finding.confidence == "unknown"
    assert "does not prove" in finding.explanation
    assert result.analyses[0].diagnosis.summary == finding.title
    assert not any(item.severity == "error" for item in result.findings)


@pytest.mark.parametrize("yaml", ["build: [invalid", "- this is not a mapping"])
async def test_malformed_config_falls_back_to_log_only_and_retains_redacted_config(gitlab, yaml):
    gitlab.pipeline["status"] = "failed"
    gitlab.set_jobs([job(1)])
    gitlab.responses["/projects/42/repository/files/.gitlab-ci.yml/raw"] = yaml
    result = await gitlab.inspect()
    snapshot = result.analyses[0]
    assert snapshot.config_bundle == [] and snapshot.job_source is None
    assert snapshot.progress.ci_configuration == DownloadState.FAILED
    assert result.config_bundle[0].content == yaml
    assert not result.ci_config_access.complete
    assert any("parse failure" in note for note in result.notes)
    assert any(item.rule_id == "compiler.cs0161" for item in result.findings)


async def test_invalid_include_does_not_leave_a_partially_guessed_job_graph(gitlab):
    gitlab.set_jobs([job(1)])
    gitlab.responses["/projects/42/repository/files/.gitlab-ci.yml/raw"] = (
        "include: ci/invalid.yml\n" + ROOT_YAML
    )
    gitlab.responses["/projects/42/repository/files/ci/invalid.yml/raw"] = "broken: ["
    result = await gitlab.inspect()
    assert not result.analyses[0].graph.nodes
    assert any(item.rule_id == "ci.configuration_unparseable" for item in result.findings)


@pytest.mark.parametrize("suffix", [
    "/-/blob/release/4.2/ci/config.yml", "/-/tree/release/4.2/ci", "",
])
async def test_branch_blob_and_repository_use_pipeline_sha_not_new_head(gitlab, suffix):
    gitlab.responses["/projects/42/repository/commits/release/4.2"] = {"id": HEAD}
    result = await gitlab.inspect(suffix)
    assert result.pipeline.external_id == RUN_ID
    assert result.reference_kind == ("repository" if not suffix else "branch")
    assert result.config_bundle[0].ref == SHA
    assert any(HEAD in note and SHA in note and "not current HEAD" in note for note in result.notes)
    for request in gitlab.calls:
        if (
            "/repository/files/" in request.url.path
            or request.url.path.endswith("/repository/tree")
        ):
            assert request.url.params["ref"] == SHA
    if suffix:
        assert gitlab.count("/projects/42/repository/commits/release/4.2/ci") == 1
        assert gitlab.count("/projects/42/repository/commits/release/4.2") >= 1
        latest = next(request for request in gitlab.calls
                  if request.url.path.endswith("/pipelines"))
        assert latest.url.params["ref"] == "release/4.2"
    assert result.resolved_url.endswith("/-/pipelines/" + RUN_ID)


@pytest.mark.parametrize("suffix", ["", "/-/tree/main", "/-/blob/main/.gitlab-ci.yml"])
async def test_no_pipeline_is_configuration_only_at_current_full_sha(gitlab, suffix):
    gitlab.responses["/projects/42/pipelines"] = []
    result = await gitlab.inspect(suffix)
    assert result.pipeline is None and result.status == "configuration_only"
    assert result.jobs == result.analyses == []
    assert result.config_bundle[0].ref == HEAD
    assert HEAD in result.resolved_url
    assert any("No pipeline exists" in note for note in result.notes)
    assert not any("/pipelines/" in request.url.path for request in gitlab.calls)


async def test_unreadable_latest_pipeline_does_not_claim_no_pipeline_exists(gitlab):
    gitlab.responses["/projects/42/pipelines"] = 403
    result = await gitlab.inspect("")
    assert result.status == "warning" and result.pipeline is None
    assert not any("No pipeline exists" in note for note in result.notes)
    assert result.config_bundle == []


async def test_mutable_metadata_is_refreshed_each_call_but_sources_load_once(gitlab):
    gitlab.set_jobs([job(1, "build", "success")])
    first = await gitlab.inspect()
    gitlab.pipeline["status"] = "failed"
    gitlab.set_jobs([job(1), job(2)])
    second = await gitlab.inspect()
    assert first.pipeline.status == "success" and second.pipeline.status == "failed"
    assert len(first.jobs) == 1 and len(second.jobs) == 2
    assert gitlab.count(f"/projects/{PROJECT}") == 2
    assert gitlab.count(f"/projects/42/pipelines/{RUN_ID}") == 2
    assert gitlab.count(f"/projects/42/pipelines/{RUN_ID}/jobs") == 2
    assert gitlab.count("/projects/42/repository/files/.gitlab-ci.yml/raw") == 1


async def test_preanalyzer_and_public_strings_are_scrubbed(gitlab, monkeypatch):
    configured = settings()
    values = [TOKEN, configured.configured_gitlab_token, configured.llm_api_key]
    gitlab.pipeline["name"] = " ".join(values)
    gitlab.set_jobs([job(1, " ".join(values), "success")])
    gitlab.responses["/projects/42/jobs/1/trace"] = (
        "\n".join(values) + "\npassword=unrelated-credential\nJob succeeded"
    )
    gitlab.responses["/projects/42/repository/files/.gitlab-ci.yml/raw"] = ROOT_YAML + (
        "# " + " ".join(values) + "\n"
    )
    gitlab.responses["/projects/42/repository/tree"].append({
        "path": "src/" + TOKEN + ".txt", "type": "blob",
    })
    linked_mr(gitlab)
    gitlab.responses["/projects/42/merge_requests/7"]["title"] = " ".join(values)
    gitlab.responses["/projects/42/merge_requests/7"]["web_url"] = (
        f"{ORIGIN}/{PROJECT}/-/merge_requests/7?token=" + quote(TOKEN)
    )
    calls = []
    original = PipelineAnalyzer.analyze_input

    def checked(self, analysis_input: AnalysisInput):
        public = " ".join([
            analysis_input.repository.model_dump_json(), analysis_input.run.model_dump_json(),
            analysis_input.job.model_dump_json(), analysis_input.raw_log,
            *[config.model_dump_json() for config in analysis_input.configs],
        ])
        assert all(value not in public for value in values)
        assert "unrelated-credential" not in public
        assert analysis_input.run.raw == analysis_input.job.raw == {}
        calls.append(analysis_input)
        return original(self, analysis_input)

    monkeypatch.setattr(PipelineAnalyzer, "analyze_input", checked)
    result = await gitlab.inspect(settings=configured)
    payload = result.model_dump_json()
    assert calls
    assert all(value not in payload for value in values)
    assert "unrelated-credential" not in payload
    assert "RAW-MUST-NOT-ESCAPE" not in payload
    assert "PRIVATE-DESCRIPTION" not in payload
    assert result.merge_requests[0]["web_url"] == f"{ORIGIN}/{PROJECT}/-/merge_requests/7"
    assert gitlab.pipeline["name"] == " ".join(values)  # Provider inputs remain untouched.


async def test_redaction_keeps_private_key_and_omitted_log_line_semantics(gitlab):
    gitlab.set_jobs([job(1)])
    trace = (
        "-----BEGIN RSA PRIVATE KEY-----\nprivate\nkey\n-----END RSA PRIVATE KEY-----\n"
        + CS0161
    )
    gitlab.responses["/projects/42/jobs/1/trace"] = trace
    first = await gitlab.inspect()
    finding = next(item for item in first.findings if item.rule_id == "compiler.cs0161")
    assert finding.evidence[0].line == 5
    gitlab.responses["/projects/42/jobs/1/trace"] = "head\n[PIPELINELENS_LOG_TRUNCATED]\n" + CS0161
    second = await gitlab.inspect()
    finding = next(item for item in second.findings if item.rule_id == "compiler.cs0161")
    assert finding.evidence[0].line is None
    assert "#L" not in finding.evidence[0].source_url
    assert next(item for item in finding.evidence if item.path).line == 47


async def test_matching_mr_head_uses_diffs_and_exposes_only_allowlisted_metadata(gitlab):
    linked_mr(gitlab, rows=[{
        "old_path": "src/Controller.cs", "new_path": "src/Controller.cs",
        "new_file": False, "renamed_file": False, "deleted_file": False,
        "diff": "@@ -1 +1 @@\n-old\n+new", "private": "PRIVATE-DIFF-METADATA",
    }])
    result = await gitlab.inspect()
    assert gitlab.count("/projects/42/merge_requests/7/diffs") == 1
    assert gitlab.count(f"/projects/42/repository/commits/{SHA}/diff") == 0
    assert set(result.merge_requests[0]) == {
        "iid", "title", "status", "source", "target", "web_url", "head_sha", "source_type",
    }
    assert result.merge_requests[0]["source_type"] == "merge_request"
    assert all(set(item) == {
        "old_path", "new_path", "new_file", "renamed_file", "deleted_file",
        "collapsed", "too_large",
    } for item in result.changes)
    assert "@@" not in result.model_dump_json()
    assert "PRIVATE-" not in result.model_dump_json()


@pytest.mark.parametrize("mixed_heads", [False, True])
async def test_changed_mr_head_uses_commit_diff_never_current_mr_diff(gitlab, mixed_heads):
    if mixed_heads:
        linked_mr(gitlab, iid=6)
    linked_mr(gitlab, head=HEAD)
    gitlab.responses[f"/projects/42/repository/commits/{SHA}/diff"] = [{
        "old_path": "ci/change.yml", "new_path": "ci/change.yml", "new_file": True,
        "diff": "@@ -0,0 +1,2 @@\n+include:\n+  - local: migrationmanagerpackage/Intended/ci.yml",
    }]
    gitlab.responses["/projects/42/repository/files/ci/change.yml/raw"] = (
        "include:\n  - local: migrationmanagerpackage/Intended/ci.yml\n"
    )
    result = await gitlab.inspect()
    assert not any(request.url.path.endswith("/diffs") for request in gitlab.calls)
    assert gitlab.count(f"/projects/42/repository/commits/{SHA}/diff") == 1
    assert all(item["source_type"] == "pipeline_commit" for item in result.merge_requests)
    assert any("current MR head changed" in note and "pipeline commit diff" in note
               for note in result.notes)
    risk = next(item for item in result.findings if item.rule_id == "change.ci_path_case_mismatch")
    assert risk.severity == "warning"
    assert risk.evidence[0].source_url == f"{ORIGIN}/{PROJECT}/-/blob/{SHA}/ci/change.yml#L2"


@pytest.mark.parametrize("status", [401, 403, 404])
async def test_missing_mr_access_is_unknown_context_not_a_job_failure(gitlab, status):
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/merge_requests"] = status
    result = await gitlab.inspect()
    assert result.merge_requests == []
    assert not any(item.severity == "error" for item in result.findings)
    assert gitlab.count(f"/projects/42/repository/commits/{SHA}/diff") == 1
    assert any("not a failure" in note for note in result.notes)


async def test_mr_changes_and_additional_yaml_are_bounded_and_root_not_reloaded(gitlab):
    for iid in (7, 8, 9):
        linked_mr(gitlab, iid=iid, head=HEAD)
    rows = [{
        "old_path": path, "new_path": path, "new_file": True,
        "diff": "@@ -0,0 +1 @@\n+include: missing.yml",
    } for path in [".gitlab-ci.yml", *[f"ci/change{index:03}.yml" for index in range(104)]]]
    gitlab.responses[f"/projects/42/repository/commits/{SHA}/diff"] = rows
    for index in range(3):
        gitlab.responses[f"/projects/42/repository/files/ci/change{index:03}.yml/raw"] = (
            "include: missing.yml"
        )
    result = await gitlab.inspect()
    assert len(result.merge_requests) == 2 and len(result.changes) == 100
    assert gitlab.count("/projects/42/merge_requests/9") == 0
    file_calls = [request for request in gitlab.calls if "/repository/files/" in request.url.path]
    assert len(file_calls) == 4
    assert all(request.url.params["ref"] == SHA for request in file_calls)
    assert all(item.severity != "error" for item in result.findings)
    assert any("three additional" in note for note in result.notes)
    assert any("bounded to 100" in note for note in result.notes)
    assert any(item.rule_id == "change.ci_path_unverified" for item in result.findings)


async def test_bounded_tree_absence_is_warning_not_proof_of_missing_package(gitlab):
    gitlab.responses[f"/projects/42/repository/commits/{SHA}/diff"] = [{
        "old_path": "ci/deploy.yml", "new_path": "ci/deploy.yml", "new_file": True,
        "diff": "@@ -0,0 +1,2 @@\n+variables:\n+  PACKAGE_PATH: generated/package",
    }]
    gitlab.responses["/projects/42/repository/files/ci/deploy.yml/raw"] = (
        "variables:\n  PACKAGE_PATH: generated/package\n"
    )
    result = await gitlab.inspect()
    risk = next(item for item in result.findings if item.rule_id == "change.ci_path_unverified")
    assert risk.severity == "warning" and risk.confidence == "unknown"
    assert "absence alone does not prove" in risk.explanation


async def test_downstream_uses_explicit_project_id_fresh_reads_and_separate_child_analysis(gitlab):
    gitlab.pipeline["status"] = "failed"
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge()]
    gitlab.add_project("99", "actual/child-project")
    gitlab.add_pipeline("17", "failed", "99")
    gitlab.set_jobs([job(99)], "17", "99")
    result = await gitlab.inspect()
    assert gitlab.count("/projects/99") == 1
    assert gitlab.count("/projects/99/pipelines/17") == 1
    assert gitlab.count("/projects/99/pipelines/17/jobs") == 1
    assert gitlab.count("/projects/actual/child-project") == 0
    assert gitlab.count("/projects/99/pipelines/17/bridges") == 0
    assert result.downstream[0]["access"] == "readable"
    assert result.downstream[0]["analyzed_job_id"] == "99"
    assert result.analyses[0].repository.display_name == "actual/child-project"
    assert result.analyses[0].run.external_id == "17"
    assert result.jobs == [] and result.analyzed_job_count == 1
    assert any(item.rule_id == "compiler.cs0161" for item in result.findings)
    assert "evil.invalid" not in result.model_dump_json()
    assert "PRIVATE-" not in result.model_dump_json()


@pytest.mark.parametrize("status", [401, 403, 404])
@pytest.mark.parametrize("allowed", [False, True])
async def test_inaccessible_child_preserves_allow_failure_policy(gitlab, status, allowed):
    gitlab.pipeline["status"] = "success" if allowed else "failed"
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge(allow_failure=allowed)]
    gitlab.responses["/projects/99"] = status
    result = await gitlab.inspect()
    finding = next(item for item in result.findings if item.rule_id == "downstream.unavailable")
    assert finding.severity == ("warning" if allowed else "error")
    assert finding.confidence == "unknown"
    assert result.status == ("warning" if allowed else "failed")
    assert result.downstream[0]["access"] == "unavailable"
    assert "evil.invalid" not in result.model_dump_json()


async def test_no_downstream_project_id_never_guesses_repository_from_url_or_folder(gitlab):
    item = bridge()
    item["downstream_pipeline"].pop("project_id")
    item["downstream_pipeline"]["web_url"] = (
        f"{ORIGIN}/MigrationManagerPackage/child/-/pipelines/17"
    )
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [item]
    result = await gitlab.inspect()
    assert any(item.rule_id == "downstream.unavailable" for item in result.findings)
    assert all("MigrationManagerPackage" not in request.url.path for request in gitlab.calls)
    assert not any("/projects/99" in request.url.path for request in gitlab.calls)


async def test_at_most_two_downstream_pipelines_and_one_failed_child_trace_no_recursion(gitlab):
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [
        bridge(project_id, project_id + 100) for project_id in (99, 100, 101)
    ]
    for project_id in (99, 100, 101):
        gitlab.add_project(str(project_id), f"child/project-{project_id}")
        gitlab.add_pipeline(str(project_id + 100), "failed", str(project_id))
        gitlab.set_jobs([job(project_id)], str(project_id + 100), str(project_id))
    result = await gitlab.inspect()
    assert len(result.downstream) == 2
    assert gitlab.trace_ids() == ["99"]
    assert gitlab.count("/projects/101") == 0
    assert result.analyzed_job_count == 1 and result.skipped_job_count == 1
    assert all(item.severity != "error" for item in result.findings)
    assert any("without recursion" in note for note in result.notes)


async def test_downstream_never_exceeds_global_trace_budget_or_displaces_explicit_selection(gitlab):
    gitlab.set_jobs([job(1, "deploy", "success")])
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge()]
    gitlab.add_project("99", "actual/child")
    gitlab.add_pipeline("17", "failed", "99")
    gitlab.set_jobs([job(99)], "17", "99")
    result = await gitlab.inspect("/-/jobs/1", max_jobs=1)
    assert gitlab.trace_ids() == ["1"]
    assert result.analyzed_job_count == 1 and result.skipped_job_count == 1
    assert result.downstream[0]["analyzed_job_id"] is None


async def test_declared_external_include_has_authoritative_source_not_guessed_root_project(gitlab):
    gitlab.add_project("88", "q2c/shared-ci")
    gitlab.responses["/projects/42/repository/files/.gitlab-ci.yml/raw"] = (
        "include:\n  project: q2c/shared-ci\n  file: Salesforce.yml\n  ref: " + HEAD + "\n"
    )
    gitlab.responses["/projects/88/repository/files/Salesforce.yml/raw"] = (
        "deploy:\n  script: sf project deploy start\n"
    )
    gitlab.set_jobs([job(1, "deploy", "success")])
    result = await gitlab.inspect()
    source = result.analyses[0].job_source
    assert source.path == project_include_key("q2c/shared-ci", "Salesforce.yml", HEAD)
    assert source.source_url == f"{ORIGIN}/q2c/shared-ci/-/blob/{HEAD}/Salesforce.yml#L1"
    assert result.analyses[0].graph.nodes[0].source.source_url == source.source_url
    assert gitlab.count("/projects/q2c/shared-ci") == 1


@pytest.mark.parametrize("ambiguous", [False, True])
async def test_guessed_code_locations_marked_and_ambiguous_locations_not_linked(gitlab, ambiguous):
    gitlab.set_jobs([job(1)])
    gitlab.responses["/projects/42/jobs/1/trace"] = CS0161.replace("src/", "/runner/")
    if ambiguous:
        gitlab.responses["/projects/42/repository/tree"].append({
            "path": "other/Controller.cs", "type": "blob",
        })
    result = await gitlab.inspect()
    finding = next(item for item in result.findings if item.rule_id == "compiler.cs0161")
    evidence = next(item for item in finding.evidence if item.path)
    if ambiguous:
        assert evidence.source_url is None and "Unverified" in evidence.text
    else:
        assert evidence.path == "src/Controller.cs" and "Inferred" in evidence.text
        assert evidence.source_url.endswith("/src/Controller.cs#L47")


async def test_sources_tree_mr_and_traces_overlap_with_bounded_concurrency(gitlab):
    gitlab.yield_requests = True
    gitlab.set_jobs([job(index) for index in range(1, 9)])
    await gitlab.inspect(max_jobs=8)
    assert 2 <= gitlab.peak <= 4
    assert any(any(path.endswith("/trace") for path in overlap)
               and any("/repository/" in path for path in overlap) for overlap in gitlab.overlaps)
    assert gitlab.count("/projects/42/repository/files/.gitlab-ci.yml/raw") == 1


async def test_unexpected_provider_programming_exception_is_not_silenced(gitlab):
    gitlab.set_jobs([job(1)])
    gitlab.responses["/projects/42/jobs/1/trace"] = RuntimeError("fixture programming defect")
    with pytest.raises(RuntimeError, match="programming defect"):
        await gitlab.inspect()


async def test_unexpected_analyzer_exception_is_not_mislabeled_as_invalid_yaml(gitlab, monkeypatch):
    gitlab.set_jobs([job(1)])

    def broken(*args, **kwargs):
        raise ValueError("analyzer programming defect")

    monkeypatch.setattr(PipelineAnalyzer, "analyze_input", broken)
    with pytest.raises(ValueError, match="analyzer programming defect"):
        await gitlab.inspect()


async def test_parser_analyzer_exception_can_fall_back_without_refetch(gitlab, monkeypatch):
    gitlab.set_jobs([job(1)])
    original = PipelineAnalyzer.analyze_input

    def fail_config(self, analysis_input):
        if analysis_input.configs:
            raise inspection.CiConfigParseError("fixture parser failure")
        return original(self, analysis_input)

    monkeypatch.setattr(PipelineAnalyzer, "analyze_input", fail_config)
    result = await gitlab.inspect()
    assert not result.analyses[0].config_bundle
    assert any("falling back to log-only" in note for note in result.notes)
    assert gitlab.count("/projects/42/repository/files/.gitlab-ci.yml/raw") == 1


async def test_job_parent_must_be_same_validated_repository(gitlab):
    gitlab.set_jobs([job(1, pipeline={"id": int(RUN_ID), "project_id": 99})])
    with pytest.raises(ProviderError, match="parent project mismatch"):
        await gitlab.inspect("/-/jobs/1")
    assert gitlab.count(f"/projects/42/pipelines/{RUN_ID}") == 0


async def test_reference_host_is_validated_before_read_or_sending_token(gitlab):
    reference = parse_gitlab_url(f"https://evil.invalid/{PROJECT}/-/pipelines/{RUN_ID}")
    with pytest.raises(PipelineUrlError, match="validated repository/server"):
        await inspect_gitlab(gitlab.provider, TOKEN, gitlab.repository, reference, settings())
    assert gitlab.calls == []


async def test_pipeline_without_sha_never_substitutes_current_head(gitlab):
    gitlab.pipeline.pop("sha")
    gitlab.set_jobs([job(1)])
    result = await gitlab.inspect()
    assert result.config_bundle == []
    assert any("No verified snapshot SHA" in note for note in result.notes)
    assert not any("/repository/" in request.url.path for request in gitlab.calls)
    assert result.analyzed_job_count == 1


async def test_findings_sorted_by_severity_then_evidence_confidence(gitlab):
    gitlab.pipeline["status"] = "failed"
    gitlab.set_jobs([job(1), job(2), job(3, "deploy", "success")])
    gitlab.responses["/projects/42/jobs/1/trace"] = ""
    result = await gitlab.inspect()
    ranks = [({"error": 0, "warning": 1, "info": 2}[item.severity],
              {"observed": 0, "likely": 1, "unknown": 2}[item.confidence])
             for item in result.findings]
    assert ranks == sorted(ranks)


async def test_log_budget_omission_does_not_fabricate_original_line_numbers(gitlab):
    gitlab.set_jobs([job(1)])
    gitlab.responses["/projects/42/jobs/1/trace"] = "noise\n" * 2000 + CS0161
    result = await gitlab.inspect(settings=replace(settings(), max_log_bytes=300))
    finding = next(item for item in result.findings if item.rule_id == "compiler.cs0161")
    assert finding.evidence[0].line is None
    assert next(item for item in finding.evidence if item.path).line == 47


async def test_no_unexpected_pagination_secrets_or_mutation_endpoints(gitlab):
    gitlab.set_jobs([job(1, "build", "success")])
    await gitlab.inspect()
    counts = Counter(request.method for request in gitlab.calls)
    assert set(counts) == {"GET"}
    for request in gitlab.calls:
        assert TOKEN not in str(request.url)
        if request.url.path.endswith("/jobs"):
            assert "scope[]" not in request.url.params
            assert request.url.params["include_retried"] == "false"
        if request.url.path.endswith("/merge_requests"):
            assert request.url.params["per_page"] == "2"


@pytest.mark.parametrize("status", [401, 403, 404])
async def test_denied_pipeline_detail_still_refreshes_job_metadata(gitlab, status):
    gitlab.set_jobs([job(1)])
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}"] = status
    result = await gitlab.inspect()
    assert result.pipeline is None and result.status == "warning"
    assert [item.external_id for item in result.jobs] == ["1"]
    assert result.skipped_job_count == 1
    assert result.resolved_url.endswith("/-/pipelines/" + RUN_ID)
    assert gitlab.count(f"/projects/42/pipelines/{RUN_ID}/jobs") == 1
    assert not any("/repository/" in request.url.path for request in gitlab.calls)


async def test_fresh_custom_ci_entry_point_not_assumed_default_filename(gitlab):
    gitlab.responses[f"/projects/{PROJECT}"]["ci_config_path"] = "ci/custom.yml"
    gitlab.responses["/projects/42/repository/files/ci/custom.yml/raw"] = ROOT_YAML
    gitlab.responses["/projects/42/repository/tree"].append({
        "path": "ci/custom.yml", "type": "blob",
    })
    gitlab.set_jobs([job(1, "build", "success")])
    result = await gitlab.inspect()
    assert result.config_bundle[0].path == "ci/custom.yml"
    assert result.analyses[0].job_source.path == "ci/custom.yml"
    assert gitlab.count("/projects/42/repository/files/.gitlab-ci.yml/raw") == 0
    assert gitlab.count("/projects/42/repository/files/ci/custom.yml/raw") == 1


async def test_selected_job_without_parent_id_stays_partial_without_guessing(gitlab):
    gitlab.responses["/projects/42/jobs/1"] = job(1, "build", "success")
    result = await gitlab.inspect("/-/jobs/1")
    assert result.selected_job.external_id == "1"
    assert result.pipeline is None and result.analyses == []
    assert result.status == "warning"
    assert any("no verifiable parent pipeline ID" in note for note in result.notes)
    assert not any("/pipelines" in request.url.path for request in gitlab.calls)


async def test_downstream_denied_jobs_keeps_fresh_failure_and_safe_partial_link(gitlab):
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge()]
    gitlab.add_project("99", "actual/child")
    gitlab.add_pipeline("17", "failed", "99")
    gitlab.responses["/projects/99/pipelines/17/jobs"] = 403
    result = await gitlab.inspect()
    assert result.downstream[0]["access"] == "partial"
    assert result.downstream[0]["downstream_pipeline"]["web_url"] == (
        f"{ORIGIN}/actual/child/-/pipelines/17"
    )
    assert any(item.rule_id == "downstream.failed" for item in result.findings)
    assert result.analyses == []


async def test_parent_success_does_not_invent_allow_failure_for_failed_child(gitlab):
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge()]
    gitlab.add_project("99", "actual/child")
    gitlab.add_pipeline("17", "failed", "99")
    gitlab.set_jobs([job(99)], "17", "99")
    result = await gitlab.inspect()
    finding = next(item for item in result.findings if item.rule_id == "compiler.cs0161")
    assert finding.severity == "warning"
    assert "allow_failure=true" not in finding.explanation
    assert "parent/pipeline successful" in finding.explanation


async def test_failed_parent_and_allowed_bridge_keep_child_diagnostic_as_warning(gitlab):
    gitlab.pipeline["status"] = "failed"
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge(allow_failure=True)]
    gitlab.add_project("99", "actual/child")
    gitlab.add_pipeline("17", "failed", "99")
    gitlab.set_jobs([job(99)], "17", "99")
    result = await gitlab.inspect()
    assert result.status == "failed"
    finding = next(item for item in result.findings if item.rule_id == "compiler.cs0161")
    assert finding.severity == "warning" and "allow_failure=true" in finding.explanation


async def test_successful_child_does_not_erase_failed_trigger_or_invent_child_failure(gitlab):
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge()]
    gitlab.add_project("99", "actual/child")
    gitlab.add_pipeline("17", "success", "99")
    result = await gitlab.inspect()
    assert result.status == "warning"
    assert any(item.rule_id == "downstream.bridge_failed" for item in result.findings)
    assert not any(item.rule_id == "downstream.failed" for item in result.findings)
    assert result.analyses == []


async def test_safe_child_link_retained_on_denied_project_and_never_fetched_as_url(gitlab):
    item = bridge()
    url = f"{ORIGIN}/actual/child/-/pipelines/17"
    item["downstream_pipeline"]["web_url"] = url
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [item]
    gitlab.responses["/projects/99"] = 403
    result = await gitlab.inspect()
    assert result.downstream[0]["downstream_pipeline"]["web_url"] == url
    assert any(evidence.source_url == url for finding in result.findings
               for evidence in finding.evidence)
    assert all("/actual/child/" not in request.url.path for request in gitlab.calls)


async def test_self_referencing_bridge_is_not_followed(gitlab):
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge(42, int(RUN_ID))]
    result = await gitlab.inspect()
    assert result.downstream == []
    assert gitlab.count(f"/projects/42/pipelines/{RUN_ID}") == 1
    assert any("self-referencing" in note for note in result.notes)


async def test_missing_default_branch_does_not_guess_head(gitlab):
    gitlab.responses[f"/projects/{PROJECT}"]["default_branch"] = None
    result = await gitlab.inspect("")
    assert result.pipeline is None and result.status == "warning"
    assert result.config_bundle == []
    assert len(gitlab.calls) == 1


async def test_mr_diff_denial_falls_back_to_pipeline_commit_without_aborting_jobs(gitlab):
    linked_mr(gitlab)
    gitlab.responses["/projects/42/merge_requests/7/diffs"] = 403
    gitlab.set_jobs([job(1)])
    result = await gitlab.inspect()
    assert gitlab.count(f"/projects/42/repository/commits/{SHA}/diff") == 1
    assert result.merge_requests[0]["source_type"] == "pipeline_commit"
    assert any(item.rule_id == "compiler.cs0161" for item in result.findings)


async def test_unreadable_changed_yaml_does_not_discard_diff_names_or_other_analyses(gitlab):
    linked_mr(gitlab, rows=[{
        "old_path": "ci/denied.yml", "new_path": "ci/denied.yml", "diff": "",
    }])
    gitlab.responses["/projects/42/repository/files/ci/denied.yml/raw"] = 403
    gitlab.set_jobs([job(1)])
    result = await gitlab.inspect()
    assert result.changes[0]["new_path"] == "ci/denied.yml"
    assert any(item.rule_id == "compiler.cs0161" for item in result.findings)
    assert any("Changed YAML" in note and "HTTP 403" in note for note in result.notes)


async def test_invalid_mr_json_is_annotated_as_partial_not_an_unexpected_exception(gitlab):
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/merge_requests"] = httpx.Response(
        200, text="not JSON",
    )
    result = await gitlab.inspect()
    assert result.status == "warning"
    assert any("Linked merge requests unavailable (HTTP 502)" in note for note in result.notes)


async def test_opaque_secret_split_by_ansi_is_removed_before_analyzer(gitlab, monkeypatch):
    gitlab.set_jobs([job(1, "build", "success")])
    gitlab.responses["/projects/42/jobs/1/trace"] = (
        TOKEN[:8] + "\x1b[31m" + TOKEN[8:] + "\x1b[0m\nJob succeeded"
    )
    original = PipelineAnalyzer.analyze_input

    def checked(self, analysis_input):
        assert TOKEN not in analysis_input.raw_log
        return original(self, analysis_input)

    monkeypatch.setattr(PipelineAnalyzer, "analyze_input", checked)
    result = await gitlab.inspect()
    assert TOKEN not in result.model_dump_json()


async def test_percent_encoded_configured_secret_removed_from_paths_and_text(gitlab):
    configured = replace(settings(), llm_api_key="opaque/key+value")
    encoded = quote(configured.llm_api_key, safe="")
    gitlab.set_jobs([job(1, "build", "success")])
    gitlab.responses["/projects/42/jobs/1/trace"] = encoded + "\nJob succeeded"
    gitlab.responses["/projects/42/repository/files/.gitlab-ci.yml/raw"] = (
        ROOT_YAML + f"# https://gitlab.test/project/{encoded}\n"
    )
    result = await gitlab.inspect(settings=configured)
    assert encoded not in result.model_dump_json()
    assert configured.llm_api_key not in result.model_dump_json()


async def test_oversized_config_and_diff_are_bounded_without_partial_secret_leakage(gitlab):
    gitlab.set_jobs([job(1)])
    gitlab.responses["/projects/42/repository/files/.gitlab-ci.yml/raw"] = (
        "# " + "x" * 1_000_010 + TOKEN
    )
    gitlab.responses[f"/projects/42/repository/commits/{SHA}/diff"] = [{
        "old_path": "README.md", "new_path": "README.md",
        "diff": "@@ -0,0 +1 @@\n+" + "y" * 100_010 + TOKEN,
    }]
    result = await gitlab.inspect()
    assert len(result.config_bundle[0].content) < 100
    assert "CONFIG_OMITTED" in result.config_bundle[0].content
    assert TOKEN not in result.model_dump_json()
    assert "diff" not in result.changes[0]
    assert any("Oversized diff text omitted" in note for note in result.notes)
    assert any(item.rule_id == "compiler.cs0161" for item in result.findings)


async def test_failed_child_precedes_success_sampling_within_global_trace_budget(gitlab):
    gitlab.set_jobs([job(1, "deploy", "success")])
    gitlab.responses[f"/projects/42/pipelines/{RUN_ID}/bridges"] = [bridge()]
    gitlab.add_project("99", "actual/child")
    gitlab.add_pipeline("17", "failed", "99")
    gitlab.set_jobs([job(99)], "17", "99")
    result = await gitlab.inspect(max_jobs=1)
    assert gitlab.trace_ids() == ["99"]
    assert result.analyzed_job_count == 1 and result.skipped_job_count == 1
    assert any("reserved for a failed child" in note for note in result.notes)


async def test_changed_path_case_check_uses_inventory_not_diff_augmented_baseline(gitlab):
    gitlab.responses[f"/projects/42/repository/commits/{SHA}/diff"] = [{
        "old_path": "src/controller.cs", "new_path": "src/controller.cs",
        "new_file": True, "diff": "@@ -0,0 +1 @@\n+namespace Fixture;",
    }]
    result = await gitlab.inspect()
    finding = next(item for item in result.findings if item.rule_id == "change.path_case_mismatch")
    assert finding.severity == "warning"
    assert finding.evidence[0].path == "src/controller.cs"
    assert "src/Controller.cs" in finding.explanation