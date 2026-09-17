"""Read-only proposal enrichment with synthetic source responses, never live GitLab."""

from dataclasses import replace
from unittest.mock import patch

import pytest

from pipelinelens.config import Settings
from pipelinelens.demo import get_demo_incident
from pipelinelens.domain import CiConfigAccessReport, CiConfigFile
from pipelinelens.providers.base import ProviderError
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.findings import diagnose_job
from pipelinelens.services.inspection import InspectionResult
from pipelinelens.services.repair_context import enrich_remediations

SHA = "a" * 40
ORIGIN = "https://gitlab.test"
PROJECT = ORIGIN + "/fixtures/metadata"
PATH = "App/destructiveChangesPre.xml"
NAMESPACE = "http://soap.sforce.com/2006/04/metadata"
MANIFEST = (
    '<Package xmlns="' + NAMESPACE + '">\n'
    '  <types>\n    <members>quoteWidget</members>\n'
    '    <members>unrelatedWidget</members>\n'
    '    <name>LightningComponentBundle</name>\n  </types>\n'
    '  <version>60.0</version>\n</Package>\n'
)
TRACE = (
    'Component Failures [1]\nLightningComponentBundle  quoteWidget  '
    'The component is referenced by quoteWidget : Custom Tab Definition - quoteWidget.\n'
    'Test Results Summary\nERROR: Job failed: exit code 1'
)


def settings():
    return Settings(
        environment="test", database_url="sqlite://", redis_url="", max_log_bytes=500000,
        max_context_chars=0, llm_mode="disabled", llm_base_url="", llm_model="",
        llm_api_key=None, allow_private_context=False,
        configured_gitlab_base_url=ORIGIN, configured_gitlab_token="synthetic-secret",
    )


def result():
    fixture = get_demo_incident("gitlab-auth-expired")
    repository = fixture.repository.model_copy(update={
        "owner": "fixtures", "name": "metadata", "web_url": PROJECT,
    })
    run = fixture.run.model_copy(update={"commit_sha": SHA, "status": "failed"})
    job = fixture.job.model_copy(update={"web_url": PROJECT + "/-/jobs/12", "status": "failed"})
    snapshot = PipelineAnalyzer(settings()).analyze_input(AnalysisInput(
        repository=repository, run=run, job=job, configs=[], raw_log=TRACE,
    ))
    return InspectionResult(
        repository=repository, pipeline=run, jobs=[job], analyses=[snapshot],
        findings=[diagnose_job(snapshot)], resolved_url=PROJECT + "/-/pipelines/10",
        reference_kind="pipeline", project_key=PROJECT,
        ci_config_access=CiConfigAccessReport(complete=False),
        changes=[{"new_path": PATH, "deleted_file": False}], status="failed",
    )


class Sources:
    web_base_url = ORIGIN

    def __init__(self):
        self.calls = []
        self.content = MANIFEST
        self.ref = SHA
        self.code = None

    async def fetch_file_at_ref(self, token, repository, path, ref):
        assert token == "synthetic-secret"
        self.calls.append((repository.external_id, path, ref))
        if self.code:
            raise ProviderError("GitLab", self.code, "Not displayed")
        return CiConfigFile(
            path=path, ref=self.ref, content=self.content,
            source_url=f"{PROJECT}/-/blob/{self.ref}/{path}",
        )


async def test_enrichment_fetches_exact_commit_and_proposes_only_blocked_member():
    provider, inspection = Sources(), result()
    before = inspection.model_dump_json()
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), inspection)
    assert provider.calls == [(inspection.repository.external_id, PATH, SHA)]
    assert len(plans) == 1 and len(plans[0].proposals) == 1
    change = plans[0].proposals[0]
    assert change.ref == SHA and change.path == PATH
    assert "-    <members>quoteWidget</members>" in change.diff
    assert "-    <members>unrelatedWidget</members>" not in change.diff
    assert change.condition == "If this component must remain available"
    assert plans[0].cause_confidence > plans[0].fix_confidence
    assert plans[0].auto_apply_allowed is False
    assert "meta_deploy_deleting_files" in plans[0].documentation[0]
    assert inspection.model_dump_json() == before


@pytest.mark.parametrize("status", [401, 403, 404, 429, 502])
async def test_source_denial_keeps_diagnosis_but_never_fabricates_diff(status):
    provider = Sources()
    provider.code = status
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), result())
    assert not plans[0].proposals
    assert any(f"HTTP {status}" in note for note in plans[0].missing_information)


async def test_newer_source_sha_does_not_create_a_historical_patch():
    provider = Sources()
    provider.ref = "b" * 40
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), result())
    assert not plans[0].proposals
    assert any("identity differs" in note for note in plans[0].missing_information)


async def test_exact_credential_redaction_blocks_patch_and_preserves_safe_snippet():
    provider = Sources()
    provider.content = MANIFEST.replace("<types>", "<!-- synthetic-secret -->\n  <types>")
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), result())
    assert not plans[0].proposals
    assert "synthetic-secret" not in plans[0].model_dump_json()


async def test_markerless_userinfo_redaction_also_blocks_exact_source_patch():
    provider = Sources()
    provider.content = MANIFEST.replace(
        "<types>", "<!-- https://test-user:test-password@host.invalid/docs -->\n  <types>",
    )
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), result())
    assert not plans[0].proposals
    assert plans[0].source_blocks
    assert "test-password" not in plans[0].model_dump_json()
    assert any("changed by sanitization" in note for note in plans[0].confidence_basis)


async def test_previously_sanitized_reused_config_remains_snippet_only():
    provider, inspection = Sources(), result()
    inspection.config_bundle = [CiConfigFile(
        path=PATH, ref=SHA, content=MANIFEST, source_modified=True,
        source_url=f"{PROJECT}/-/blob/{SHA}/{PATH}",
    )]
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), inspection)
    assert not provider.calls and not plans[0].proposals
    assert plans[0].source_blocks


async def test_candidate_reads_are_deduplicated_across_same_job_findings():
    provider, inspection = Sources(), result()
    inspection.findings.append(inspection.findings[0].model_copy())
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), inspection)
    assert len(provider.calls) == 1
    assert len(plans) == 2 and all(plan.proposals for plan in plans)


async def test_secret_path_and_missing_sha_cannot_initiate_reads():
    provider, inspection = Sources(), result()
    inspection.changes = [{"new_path": ".env"}, {"new_path": "../destructiveChanges.xml"}]
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), inspection)
    assert not provider.calls and not plans[0].proposals
    inspection.changes = [{"new_path": PATH}]
    inspection.analyses[0].run.commit_sha = None
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), inspection)
    assert not provider.calls and not plans[0].proposals


async def test_changed_source_size_limit_withholds_patch():
    provider = Sources()
    provider.content = " " * 250001
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), result())
    assert not plans[0].proposals
    assert any("size limit" in note for note in plans[0].missing_information)


async def test_only_eight_sources_are_requested_and_existing_config_is_reused():
    provider, inspection = Sources(), result()
    paths = [f"App/destructiveChanges{i}.xml" for i in range(12)]
    with patch("pipelinelens.services.repair_context.candidate_source_paths", return_value=paths):
        plans = await enrich_remediations(provider, "synthetic-secret", settings(), inspection)
    assert len(provider.calls) == 8
    assert any("eight-source" in note for note in plans[0].missing_information)
    provider.calls.clear()
    inspection.config_bundle = [CiConfigFile(
        path=PATH, ref=SHA, content=MANIFEST, source_url=f"{PROJECT}/-/blob/{SHA}/{PATH}",
    )]
    plans = await enrich_remediations(provider, "synthetic-secret", settings(), inspection)
    assert not provider.calls and plans[0].proposals


async def test_notes_and_runbooks_never_invoke_an_external_model():
    configured = replace(settings(), llm_mode="openai-compatible",
                         llm_base_url="https://must-not-use.invalid", llm_api_key="unused-key")
    plans = await enrich_remediations(Sources(), "synthetic-secret", configured, result())
    assert plans[0].score_label == "Rule-based heuristic; not a calibrated probability"
    assert plans[0].proposals