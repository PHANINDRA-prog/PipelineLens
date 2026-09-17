"""Assemble durable, evidence-first analysis snapshots from CI inputs."""

from __future__ import annotations

import asyncio
import hashlib
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from urllib.parse import quote

from pipelinelens.config import Settings, get_settings
from pipelinelens.demo import DemoIncident, get_demo_incident
from pipelinelens.domain import (
    AnalysisProgress,
    AnalysisSnapshot,
    CiConfigFile,
    DownloadState,
    PipelineJob,
    PipelineRun,
    ProviderName,
    RepositoryRef,
    SimilarIncident,
)
from pipelinelens.providers.base import CiProvider
from pipelinelens.services.diagnosis import build_deterministic_diagnosis
from pipelinelens.services.logs import (
    analyze_log,
    extract_code_references,
    extract_deployment_component_failures,
)
from pipelinelens.services.redaction import SecretRedactor
from pipelinelens.services.yaml_graph import analyze_ci_config, match_job_to_graph


@dataclass(frozen=True, slots=True)
class AnalysisInput:
    repository: RepositoryRef
    run: PipelineRun
    job: PipelineJob
    configs: list[CiConfigFile]
    raw_log: str


def _limit_log(content: str, max_bytes: int) -> str:
    encoded = content.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return content
    head_bytes = int(max_bytes * 0.2)
    tail_bytes = max_bytes - head_bytes
    head = encoded[:head_bytes].decode("utf-8", errors="replace")
    tail = encoded[-tail_bytes:].decode("utf-8", errors="replace")
    return f"{head}\n[PIPELINELENS_LOG_TRUNCATED]\n{tail}"


def _source_url(repository: RepositoryRef, ref: str | None, path: str, line: int) -> str | None:
    if not ref or not path or path.startswith(("/", "http://", "https://")):
        return None
    encoded_path = quote(path, safe="/")
    if repository.provider == ProviderName.GITHUB:
        return f"{repository.web_url}/blob/{ref}/{encoded_path}#L{line}"
    if repository.provider == ProviderName.GITLAB:
        return f"{repository.web_url}/-/blob/{ref}/{encoded_path}#L{line}"
    return None


class PipelineAnalyzer:
    """Orchestrates deterministic analysis before optional retrieval or LLM synthesis."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.redactor = SecretRedactor()

    def _redact_configs(self, configs: list[CiConfigFile]) -> list[CiConfigFile]:
        """Ensure CI YAML is sanitized before parsing, display, retrieval, or serialization."""

        output = []
        for config in configs:
            content = self.redactor.redact(config.content).content
            output.append(config.model_copy(update={
                "content": content,
                "source_modified": config.source_modified or content != config.content,
            }))
        return output

    def analyze_input(
        self, analysis_input: AnalysisInput, similar_incidents: Iterable[SimilarIncident] = ()
    ) -> AnalysisSnapshot:
        redacted_configs = self._redact_configs(analysis_input.configs)
        if redacted_configs:
            root_config = redacted_configs[0]
            config_by_path = {config.path: config.content for config in redacted_configs}
            config_details_by_path = {config.path: config for config in redacted_configs}
            graph = analyze_ci_config(
                analysis_input.repository.provider,
                root_config,
                include_loader=lambda path: config_by_path.get(path),
            )
            job_source = match_job_to_graph(analysis_input.job, graph)
            if job_source:
                source_config = config_details_by_path.get(job_source.path)
                if source_config and source_config.source_url:
                    job_source = job_source.model_copy(
                        update={
                            "source_url": (
                                f"{source_config.source_url}#L{job_source.line_start}"
                            )
                        }
                    )
            config_state = DownloadState.FETCHED
        else:
            if analysis_input.repository.provider != ProviderName.GITLAB:
                raise ValueError("No CI configuration was fetched for the selected run.")
            root_config = CiConfigFile(
                path=".gitlab-ci.yml",
                ref=(
                    analysis_input.run.commit_sha
                    or analysis_input.run.ref_name
                    or analysis_input.repository.default_branch
                    or "HEAD"
                ),
                content="",
            )
            graph = analyze_ci_config(analysis_input.repository.provider, root_config)
            job_source = None
            config_state = DownloadState.FAILED
        log_analysis = analyze_log(_limit_log(analysis_input.raw_log, self.settings.max_log_bytes))
        component_failures = extract_deployment_component_failures(log_analysis.redaction.content)
        code_references = [
            reference.model_copy(
                update={
                    "source_url": _source_url(
                        analysis_input.repository,
                        analysis_input.run.commit_sha,
                        reference.path,
                        reference.line,
                    )
                }
            )
            for reference in extract_code_references(log_analysis.redaction.content)
        ]
        progress = AnalysisProgress(
            ci_configuration=config_state,
            job_log=DownloadState.FETCHED,
            sanitization=DownloadState.REDACTED,
            graph_analysis=DownloadState.ANALYZED,
            retrieval=DownloadState.ANALYZED,
            diagnosis=DownloadState.ANALYZED,
        )
        similar = list(similar_incidents)
        return AnalysisSnapshot(
            analysis_id=str(uuid.uuid4()),
            repository=analysis_input.repository,
            run=analysis_input.run,
            job=analysis_input.job,
            progress=progress,
            config=root_config,
            config_bundle=redacted_configs,
            graph=graph,
            job_source=job_source,
            redacted_log=log_analysis.redaction.content,
            chunks=log_analysis.chunks,
            code_references=code_references,
            component_failures=component_failures,
            fingerprint=log_analysis.fingerprint,
            similar_incidents=similar,
            diagnosis=build_deterministic_diagnosis(
                log_analysis.fingerprint,
                log_analysis.chunks,
                job_source,
                similar,
                component_failures,
            ),
        )

    def analyze_demo(
        self, fixture_id: str, similar_incidents: Iterable[SimilarIncident] = ()
    ) -> AnalysisSnapshot:
        fixture = get_demo_incident(fixture_id)
        return self.analyze_fixture(fixture, similar_incidents)

    def analyze_fixture(
        self, fixture: DemoIncident, similar_incidents: Iterable[SimilarIncident] = ()
    ) -> AnalysisSnapshot:
        return self.analyze_input(
            AnalysisInput(
                repository=fixture.repository,
                run=fixture.run,
                job=fixture.job,
                configs=fixture.configs,
                raw_log=fixture.log,
            ),
            similar_incidents,
        )

    async def analyze_live(
        self,
        provider: CiProvider,
        token: str,
        repository: RepositoryRef,
        run_id: str,
        job_id: str,
        similar_incidents: Iterable[SimilarIncident] = (),
    ) -> AnalysisSnapshot:
        run, job = await asyncio.gather(
            provider.get_run(token, repository, run_id),
            provider.get_job(token, repository, run_id, job_id),
        )
        return await self.analyze_resolved(
            provider,
            token,
            repository,
            run,
            job,
            similar_incidents,
        )

    async def analyze_resolved(
        self,
        provider: CiProvider,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        job: PipelineJob,
        similar_incidents: Iterable[SimilarIncident] = (),
        resolve_job_source: bool = True,
    ) -> AnalysisSnapshot:
        """Analyze provider metadata that was already resolved by a pipeline URL request."""

        if not resolve_job_source and repository.provider == ProviderName.GITLAB:
            ref = run.commit_sha or run.ref_name or repository.default_branch or "HEAD"
            root_config, raw_log = await asyncio.gather(
                provider.fetch_file_at_ref(token, repository, ".gitlab-ci.yml", ref),
                provider.fetch_job_log(token, repository, run.external_id, job.external_id),
            )
            configs = [root_config]
        else:
            configs, raw_log = await asyncio.gather(
                provider.fetch_ci_config_bundle(
                    token,
                    repository,
                    run,
                    target_job_name=job.key or job.name,
                ),
                provider.fetch_job_log(token, repository, run.external_id, job.external_id),
            )
        return self.analyze_input(
            AnalysisInput(
                repository=repository, run=run, job=job, configs=configs, raw_log=raw_log
            ),
            similar_incidents,
        )


def stable_incident_id(repository: RepositoryRef, run: PipelineRun, job: PipelineJob) -> str:
    """Provide a stable idempotency key for persistent incident storage."""

    source = f"{repository.provider}:{repository.external_id}:{run.external_id}:{job.external_id}"
    return hashlib.sha256(source.encode()).hexdigest()[:24]
