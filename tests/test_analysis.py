from pipelinelens.demo import get_demo_incident
from pipelinelens.domain import CiConfigFile, DownloadState, ProviderName, RepositoryRef
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer, _limit_log, _source_url
from pipelinelens.services.diagnosis import build_deterministic_diagnosis
from pipelinelens.services.llm import EvidenceConstrainedDiagnoser
from pipelinelens.services.orchestrator import PipelineLensOrchestrator
from pipelinelens.services.retrieval import HybridRetriever
from pipelinelens.storage import IncidentStore


def test_demo_auth_failure_creates_a_redacted_evidence_snapshot() -> None:
    snapshot = PipelineAnalyzer().analyze_demo("gitlab-auth-expired")

    assert snapshot.progress.job_log == DownloadState.FETCHED
    assert snapshot.progress.sanitization == DownloadState.REDACTED
    assert snapshot.fingerprint.category == "authentication_failure"
    assert "glpat-" not in snapshot.redacted_log
    assert snapshot.job_source is not None
    assert snapshot.job_source.path == "ci/deploy.yml"
    assert snapshot.diagnosis.evidence[0].source_type == "job_log"
    assert snapshot.diagnosis.auto_remediation_allowed is False


def test_gitlab_log_remains_diagnosable_when_ci_configuration_is_unreadable() -> None:
    fixture = get_demo_incident("gitlab-auth-expired")

    snapshot = PipelineAnalyzer().analyze_input(
        AnalysisInput(
            repository=fixture.repository,
            run=fixture.run,
            job=fixture.job,
            configs=[],
            raw_log=fixture.log,
        )
    )

    assert snapshot.progress.ci_configuration == DownloadState.FAILED
    assert snapshot.config_bundle == []
    assert snapshot.job_source is None
    assert snapshot.fingerprint.category == "authentication_failure"


def test_demo_artifact_failure_maps_to_its_upstream_job() -> None:
    snapshot = PipelineAnalyzer().analyze_demo("gitlab-artifact-missing")

    assert snapshot.fingerprint.category == "artifact_missing"
    assert snapshot.job_source is not None
    assert snapshot.job_source.job_key == "publish-release"
    assert snapshot.graph.nodes[1].needs == ["package"]
    assert "artifact" in snapshot.diagnosis.safe_next_steps[0].lower()


def test_deployment_component_dependencies_produce_specific_probable_fixes() -> None:
    fixture = get_demo_incident("gitlab-auth-expired")
    trace = "\n".join(
        [
            "Component Failures [1]",
            (
                "LightningComponentBundle  quoteWidget  The component is referenced by "
                "quoteWidget : Custom Tab Definition - quoteWidget."
            ),
            "Test Results Summary",
        ]
    )
    snapshot = PipelineAnalyzer().analyze_input(
        AnalysisInput(
            repository=fixture.repository,
            run=fixture.run,
            job=fixture.job,
            configs=fixture.configs,
            raw_log=trace,
        )
    )

    assert snapshot.fingerprint.category == "deployment_failure"
    assert snapshot.component_failures[0].component_name == "quoteWidget"
    assert "Custom Tab Definition" in snapshot.diagnosis.likely_root_cause
    assert "same deployment package" in snapshot.diagnosis.safe_next_steps[0]


def test_ambiguous_datasync_target_produces_an_actionable_mapping_diagnosis() -> None:
    fixture = get_demo_incident("gitlab-auth-expired")
    trace = "\n".join(
        [
            "DEPLOYMENT STEP FAILED",
            "Error       : DataSync run failed for 1 target(s).",
            "2026-09-10T05:45:13.994801Z 01O  62 | ApprovalRuleAssignee | FAIL | AMBIGUOUS",
            "ERROR: Job failed: exit code 1",
        ]
    )
    snapshot = PipelineAnalyzer().analyze_input(
        AnalysisInput(
            repository=fixture.repository,
            run=fixture.run,
            job=fixture.job,
            configs=fixture.configs,
            raw_log=trace,
        )
    )

    assert snapshot.fingerprint.category == "deployment_failure"
    assert snapshot.diagnosis.failure_category == "deployment_failure"
    assert "ApprovalRuleAssignee" in snapshot.diagnosis.summary
    assert "multiple matching mappings" in snapshot.diagnosis.likely_root_cause
    assert "explicit mapping identifier" in snapshot.diagnosis.safe_next_steps[1]


def test_source_urls_use_provider_specific_file_and_line_paths() -> None:
    github = RepositoryRef(
        provider=ProviderName.GITHUB,
        external_id="github-id",
        owner="sample-org",
        name="api",
        web_url="https://github.com/sample-org/api",
    )
    gitlab = RepositoryRef(
        provider=ProviderName.GITLAB,
        external_id="gitlab-id",
        owner="sample-org",
        name="api",
        web_url="https://gitlab.com/sample-org/api",
    )

    assert _source_url(github, "abc123", "src/api.py", 42) == (
        "https://github.com/sample-org/api/blob/abc123/src/api.py#L42"
    )
    assert _source_url(gitlab, "abc123", "src/api.py", 42) == (
        "https://gitlab.com/sample-org/api/-/blob/abc123/src/api.py#L42"
    )


def test_csharp_build_fixture_extracts_a_linked_source_location() -> None:
    snapshot = PipelineAnalyzer().analyze_demo("gitlab-csharp-build-failure")

    assert snapshot.fingerprint.category == "build_failure"
    assert len(snapshot.code_references) == 1
    assert snapshot.code_references[0].path == "customcodes/Pricing/QuoteEngine.cs"
    assert snapshot.code_references[0].line == 42
    assert snapshot.code_references[0].source_url.endswith("QuoteEngine.cs#L42")


def test_configuration_and_raw_provider_metadata_are_redacted_before_serialization() -> None:
    fixture = get_demo_incident("gitlab-auth-expired")
    simulated_token = "gl" + "pat-" + "abcdefghijklmnopqrstuvwxyz123456"
    config = CiConfigFile(
        path=".gitlab-ci.yml",
        ref=fixture.run.commit_sha or "main",
        content=(
            "variables:\n"
            f"  DEPLOY_TOKEN: {simulated_token}\n"
            "deploy:\n"
            "  script: ./deploy.sh\n"
        ),
    )
    run = fixture.run.model_copy(update={"raw": {"access_token": simulated_token}})
    job = fixture.job.model_copy(update={"raw": {"token": simulated_token}})

    snapshot = PipelineAnalyzer().analyze_input(
        AnalysisInput(
            repository=fixture.repository,
            run=run,
            job=job,
            configs=[config],
            raw_log=fixture.log,
        )
    )

    serialized = snapshot.model_dump_json()
    assert "glpat-" not in snapshot.config.content
    assert "glpat-" not in serialized
    assert "access_token" not in serialized


def test_mapped_job_includes_the_resolved_configuration_source_url() -> None:
    fixture = get_demo_incident("gitlab-csharp-build-failure")
    config = fixture.configs[0].model_copy(
        update={"source_url": "https://gitlab.example/sample-org/release-service/-/blob/abc/.gitlab-ci.yml"}
    )

    snapshot = PipelineAnalyzer().analyze_input(
        AnalysisInput(
            repository=fixture.repository,
            run=fixture.run,
            job=fixture.job,
            configs=[config],
            raw_log=fixture.log,
        )
    )

    assert snapshot.job_source is not None
    assert snapshot.job_source.source_url == (
        "https://gitlab.example/sample-org/release-service/-/blob/abc/.gitlab-ci.yml#L3"
    )


async def test_completed_analysis_exposes_rag_sources_and_disabled_model_state(tmp_path) -> None:
    store = IncidentStore(f"sqlite:///{tmp_path / 'rag.db'}")
    store.initialize()
    orchestrator = PipelineLensOrchestrator(
        analyzer=PipelineAnalyzer(),
        store=store,
        retriever=HybridRetriever(store),
        diagnoser=EvidenceConstrainedDiagnoser(),
    )

    _, snapshot = await orchestrator.analyze_demo("gitlab-auth-expired")

    assert snapshot.rag is not None
    assert snapshot.rag.retrieval_enabled is True
    assert snapshot.rag.llm_used is False
    assert snapshot.rag.llm_mode == "disabled"
    assert any(source.source_type == "job_log" for source in snapshot.rag.sources)
    assert any(source.source_type == "ci_yaml" for source in snapshot.rag.sources)
    assert any(source.source_type == "skill_pack" for source in snapshot.rag.sources)


async def test_disabled_llm_fallback_preserves_component_dependency_diagnosis(tmp_path) -> None:
    fixture = get_demo_incident("gitlab-auth-expired")
    trace = "\n".join(
        [
            "Component Failures [1]",
            (
                "LightningComponentBundle  quoteWidget  The component is referenced by "
                "quoteWidget : Custom Tab Definition - quoteWidget."
            ),
            "Test Results Summary",
        ]
    )
    store = IncidentStore(f"sqlite:///{tmp_path / 'component-rag.db'}")
    store.initialize()
    orchestrator = PipelineLensOrchestrator(
        analyzer=PipelineAnalyzer(),
        store=store,
        retriever=HybridRetriever(store),
        diagnoser=EvidenceConstrainedDiagnoser(),
    )
    initial_snapshot = PipelineAnalyzer().analyze_input(
        AnalysisInput(
            repository=fixture.repository,
            run=fixture.run,
            job=fixture.job,
            configs=fixture.configs,
            raw_log=trace,
        )
    )

    _, snapshot = await orchestrator._complete_snapshot(initial_snapshot)

    assert snapshot.diagnosis.generation == "deterministic"
    assert "Custom Tab Definition" in snapshot.diagnosis.likely_root_cause
    assert len(snapshot.diagnosis.safe_next_steps) == 3


def test_developer_compiler_diagnosis_is_cause_first_and_preserves_the_repository_prefix() -> None:
    fixture = get_demo_incident("gitlab-csharp-build-failure")
    path = "platform-ext-app/resources/customcodes/API/Controller.cs"
    trace = "\n".join([
        *["restore progress"] * 43,
        f"/builds/example/repo/{path}(47,30): error CS0161: "
        "GetItems(): not all code paths return a value",
        *["Controller.cs(100,20): warning CS8604: null argument"] * 300,
        "Permission is granted under this license. Tests: 403.",
        "ERROR: Job failed: exit code 1",
    ])
    snapshot = PipelineAnalyzer().analyze_input(AnalysisInput(
        repository=fixture.repository, run=fixture.run, job=fixture.job,
        configs=fixture.configs, raw_log=trace,
    ))

    assert snapshot.fingerprint.category == "build_failure"
    assert "CS0161" in snapshot.diagnosis.summary
    assert "every reachable branch" in snapshot.diagnosis.safe_next_steps[0]
    assert "Original log line 44" in snapshot.diagnosis.evidence[0].explanation
    assert snapshot.code_references[0].path == path
    assert snapshot.code_references[0].source_url.endswith(f"/{path}#L47")
    assert len(snapshot.code_references) == 1


def test_legacy_diagnosis_ignores_a_stale_auth_fingerprint_when_logs_only_show_warnings() -> None:
    snapshot = PipelineAnalyzer().analyze_demo("gitlab-auth-expired")
    from pipelinelens.services.logs import analyze_log

    log = analyze_log("Controller.cs(47,30): warning CS0161: example warning\n0 Error(s)")
    diagnosis = build_deterministic_diagnosis(snapshot.fingerprint, log.chunks, None)

    assert diagnosis.failure_category == "unknown"
    assert "Insufficient evidence" in diagnosis.summary
    assert "Rotate" not in " ".join(diagnosis.safe_next_steps)


def test_limited_log_tail_has_no_fabricated_original_line_citation() -> None:
    from pipelinelens.services.logs import analyze_log

    trace = "\n".join([
        *["normal output " * 20] * 100,
        "Controller.cs(47,30): error CS0161: not all code paths return a value",
    ])
    bounded = _limit_log(trace, 2000)
    assert "[PIPELINELENS_LOG_TRUNCATED]" in bounded
    log = analyze_log(bounded)
    diagnosis = build_deterministic_diagnosis(log.fingerprint, log.chunks, None)

    assert diagnosis.failure_category == "build_failure"
    assert "original line number unknown" in diagnosis.evidence[0].explanation
    assert "Original log line" not in diagnosis.evidence[0].explanation
    assert diagnosis.missing_information


def test_success_trace_does_not_become_an_auth_test_or_build_failure() -> None:
    fixture = get_demo_incident("gitlab-auth-expired")
    snapshot = PipelineAnalyzer().analyze_input(AnalysisInput(
        repository=fixture.repository, run=fixture.run,
        job=fixture.job.model_copy(update={"status": "success", "conclusion": "success"}),
        configs=fixture.configs,
        raw_log="\n".join([
            "Controller.cs(47,30): warning CS8604: possible null argument",
            "TestUnauthorized403 PASSED", "0 Error(s)", "Test Failures [0]", "Job succeeded",
        ]),
    ))

    assert snapshot.fingerprint.category == "no_failure_observed"
    assert snapshot.diagnosis.failure_category == "no_failure_observed"
    assert "No failure observed" in snapshot.diagnosis.summary
    assert snapshot.code_references == []
