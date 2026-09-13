"""FastAPI application for read-only PipelineLens analysis workflows."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, SecretStr

from pipelinelens.api.inspection import create_inspection_router
from pipelinelens.config import Settings, get_settings
from pipelinelens.demo import list_demo_incidents
from pipelinelens.domain import (
    AnalysisSnapshot,
    CiConfigAccessReport,
    LlmRuntimeStatus,
    PipelineJob,
    PipelineRun,
    ProviderIdentity,
    ProviderName,
    RepositoryRef,
    RepositoryTreeEntry,
)
from pipelinelens.providers.base import ProviderError
from pipelinelens.providers.factory import get_provider
from pipelinelens.providers.gitlab import GitLabProvider
from pipelinelens.services.analysis import PipelineAnalyzer
from pipelinelens.services.credentials import CredentialVault, CredentialVaultError
from pipelinelens.services.llm import EvidenceConstrainedDiagnoser, get_llm_runtime_status
from pipelinelens.services.local_knowledge import KnowledgeCacheError, LocalKnowledgeCache
from pipelinelens.services.orchestrator import PipelineLensOrchestrator
from pipelinelens.services.pipeline_url import PipelineUrlError, parse_gitlab_pipeline_url
from pipelinelens.services.retrieval import HybridRetriever
from pipelinelens.storage import IncidentStore


class TokenRequest(BaseModel):
    provider: Literal[ProviderName.GITHUB, ProviderName.GITLAB]
    token: SecretStr | None = None
    base_url: str | None = None
    use_configured_token: bool = False


class RepositoryRequest(TokenRequest):
    repository: RepositoryRef


class RunRequest(RepositoryRequest):
    limit: int = Field(default=25, ge=1, le=100)


class JobRequest(RepositoryRequest):
    run_id: str


class RepositoryStructureRequest(RepositoryRequest):
    ref: str | None = None
    max_depth: int = Field(default=3, ge=1, le=8)
    max_entries: int = Field(default=200, ge=1, le=500)


class LiveAnalysisRequest(RepositoryRequest):
    run_id: str
    job_id: str


class GitLabPipelineUrlRequest(BaseModel):
    pipeline_url: str = Field(min_length=16, max_length=2048)
    token: SecretStr | None = None
    use_configured_token: bool = False
    max_failed_jobs: int = Field(default=3, ge=1, le=5)


class FeedbackRequest(BaseModel):
    outcome: Literal["resolved", "not_useful", "needs_review"]
    confirmed_resolution: str | None = Field(default=None, max_length=4000)


class ConnectionResponse(BaseModel):
    identity: ProviderIdentity
    repositories: list[RepositoryRef]


class AnalysisResponse(BaseModel):
    incident_id: str
    snapshot: AnalysisSnapshot


class GitLabPipelineUrlAnalysisResponse(BaseModel):
    access_verified: bool
    repository: RepositoryRef
    pipeline: PipelineRun
    project_structure: list[RepositoryTreeEntry]
    ci_config_access: CiConfigAccessReport
    failed_job_count: int
    skipped_job_count: int
    analyses: list[AnalysisResponse]


class SystemStatusResponse(BaseModel):
    local_gitlab_ready: bool
    gitlab_base_url: str | None = None
    llm: LlmRuntimeStatus


def _assert_provider_matches(request_provider: ProviderName, repository: RepositoryRef) -> None:
    if repository.provider != request_provider:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Repository provider mismatch."
        )


def _resolve_token(request: TokenRequest, settings: Settings) -> str:
    if request.use_configured_token:
        if settings.environment != "development":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Configured tokens are available only in the local development environment.",
            )
        if request.provider != ProviderName.GITLAB:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Only GitLab supports the local configured token mode.",
            )
        if not settings.configured_gitlab_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No local GitLab token is configured for this development server.",
            )
        return settings.configured_gitlab_token
    if request.token is None or not request.token.get_secret_value().strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Provide a read-only personal access token.",
        )
    return request.token.get_secret_value()


def _resolve_provider_base_url(request: TokenRequest, settings: Settings) -> str | None:
    if request.use_configured_token:
        # Never allow a browser value to redirect a server-held token to another host.
        return settings.configured_gitlab_base_url
    return request.base_url


def _provider_and_token(request: TokenRequest, settings: Settings):
    return (
        get_provider(request.provider, _resolve_provider_base_url(request, settings)),
        _resolve_token(request, settings),
    )


def _has_local_gitlab_token(settings: Settings) -> bool:
    return settings.environment == "development" and bool(settings.configured_gitlab_token)


def _resolve_pipeline_url_token(
    request: GitLabPipelineUrlRequest,
    settings: Settings,
) -> tuple[str, str | None]:
    """Use a request-scoped token when supplied, otherwise allow local development access."""

    if request.use_configured_token:
        if not _has_local_gitlab_token(settings):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No local GitLab token is configured for this development server.",
            )
        return settings.configured_gitlab_token or "", settings.configured_gitlab_base_url
    if request.token is not None and request.token.get_secret_value().strip():
        return request.token.get_secret_value().strip(), None
    if _has_local_gitlab_token(settings):
        return settings.configured_gitlab_token or "", settings.configured_gitlab_base_url
    if request.token is None or not request.token.get_secret_value().strip():
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Enter a read-only GitLab personal access token to analyze this pipeline.",
        )
    return request.token.get_secret_value().strip(), None


@asynccontextmanager
async def _provider_request_scope(provider: Any) -> AsyncIterator[Any]:
    """Reuse a provider HTTP session when available without constraining adapters."""

    if not hasattr(provider, "__aenter__"):
        yield provider
        return
    async with provider:
        yield provider


async def _inspect_gitlab_ci_config_access(
    provider: Any,
    token: str,
    repository: RepositoryRef,
    pipeline: PipelineRun,
) -> CiConfigAccessReport:
    """Allow older test adapters while real GitLab adapters expose the access audit."""

    inspector = getattr(provider, "inspect_ci_config_access", None)
    if not callable(inspector):
        return CiConfigAccessReport(entries=[], complete=False)
    return await inspector(token, repository, pipeline)


def create_app(settings: Settings | None = None, store: IncidentStore | None = None) -> FastAPI:
    settings = settings or get_settings()
    store = store or IncidentStore(settings.database_url)
    store.initialize()
    analyzer = PipelineAnalyzer(settings)
    retriever = HybridRetriever(
        store,
        max_context_chars=settings.max_context_chars,
        include_private_context=settings.allow_private_context,
    )
    orchestrator = PipelineLensOrchestrator(
        analyzer=analyzer,
        store=store,
        retriever=retriever,
        diagnoser=EvidenceConstrainedDiagnoser(settings),
    )
    app = FastAPI(
        title="PipelineLens API",
        version="0.1.0",
        description=(
            "Evidence-first, read-only CI failure analysis for GitHub Actions and GitLab CI/CD."
        ),
    )
    app.state.settings = settings
    app.state.store = store
    app.state.orchestrator = orchestrator
    app.state.credential_vault = CredentialVault()
    app.state.local_knowledge = LocalKnowledgeCache()
    app.include_router(create_inspection_router(
        settings, app.state.credential_vault, app.state.local_knowledge,
    ))

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_, error: RequestValidationError) -> JSONResponse:
        # Pydantic error.input/error.ctx can include password fields or whole bodies.
        # The client needs a helpful description, never the original supplied value.
        del error
        return JSONResponse(status_code=422, content={
            "detail": "Check the GitLab link and connection fields. Tokens must be "
            "plain access tokens, not URLs or values containing whitespace.",
        })

    @app.exception_handler(CredentialVaultError)
    async def credential_error_handler(_, error: CredentialVaultError) -> JSONResponse:
        del error
        return JSONResponse(status_code=409, content={
            "detail": "The Windows credential vault could not be read or updated. "
            "Use a request-only token or repair the local saved connection; "
            "no plaintext credential fallback was used.",
        })

    @app.exception_handler(KnowledgeCacheError)
    async def knowledge_error_handler(_, error: KnowledgeCacheError) -> JSONResponse:
        del error
        return JSONResponse(status_code=409, content={
            "detail": "The local knowledge cache could not be read or updated. "
            "Review the cache before replacing it; credentials are stored separately.",
        })

    @app.exception_handler(ProviderError)
    async def provider_error_handler(_, error: ProviderError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "detail": f"{error.provider} request failed ({error.status_code}): {error.message}"
            },
        )

    @app.exception_handler(PipelineUrlError)
    async def pipeline_url_error_handler(_, error: PipelineUrlError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={"detail": str(error)},
        )

    @app.get("/health/live")
    async def liveness() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/health/ready")
    async def readiness() -> dict[str, str]:
        try:
            store.list_clusters(limit=1)
        except Exception as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Storage is unavailable."
            ) from error
        return {"status": "ready"}

    @app.get("/api/v1/system/status", response_model=SystemStatusResponse)
    async def system_status() -> SystemStatusResponse:
        return SystemStatusResponse(
            local_gitlab_ready=_has_local_gitlab_token(settings),
            gitlab_base_url=(
                settings.configured_gitlab_base_url if settings.configured_gitlab_token else None
            ),
            llm=await get_llm_runtime_status(settings),
        )

    @app.get("/api/v1/demo/incidents")
    async def demo_incidents() -> list[dict[str, str]]:
        return [
            {
                "fixture_id": incident.fixture_id,
                "title": incident.title,
                "description": incident.description,
                "provider": str(incident.repository.provider),
                "repository": incident.repository.display_name,
                "job": incident.job.name,
            }
            for incident in list_demo_incidents()
        ]

    @app.post("/api/v1/demo/incidents/{fixture_id}/analyze", response_model=AnalysisResponse)
    async def analyze_demo(fixture_id: str) -> AnalysisResponse:
        try:
            incident_id, snapshot = await orchestrator.analyze_demo(fixture_id)
        except KeyError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Unknown demo incident."
            ) from error
        return AnalysisResponse(incident_id=incident_id, snapshot=snapshot)

    @app.post("/api/v1/connect", response_model=ConnectionResponse)
    async def connect(request: TokenRequest) -> ConnectionResponse:
        provider, token = _provider_and_token(request, settings)
        identity = await provider.validate_token(token)
        repositories = await provider.list_repositories(token)
        return ConnectionResponse(identity=identity, repositories=repositories)

    @app.post("/api/v1/runs", response_model=list[PipelineRun])
    async def list_runs(request: RunRequest) -> list[PipelineRun]:
        _assert_provider_matches(request.provider, request.repository)
        provider, token = _provider_and_token(request, settings)
        return await provider.list_failed_runs(
            token, request.repository, request.limit
        )

    @app.post("/api/v1/repository-structure", response_model=list[RepositoryTreeEntry])
    async def repository_structure(
        request: RepositoryStructureRequest,
    ) -> list[RepositoryTreeEntry]:
        _assert_provider_matches(request.provider, request.repository)
        provider, token = _provider_and_token(request, settings)
        return await provider.list_repository_tree(
            token,
            request.repository,
            ref=request.ref,
            max_depth=request.max_depth,
            max_entries=request.max_entries,
        )

    @app.post("/api/v1/jobs", response_model=list[PipelineJob])
    async def list_jobs(request: JobRequest) -> list[PipelineJob]:
        _assert_provider_matches(request.provider, request.repository)
        provider, token = _provider_and_token(request, settings)
        return await provider.list_jobs(
            token, request.repository, request.run_id
        )

    @app.post("/api/v1/analyze", response_model=AnalysisResponse)
    async def analyze_live(request: LiveAnalysisRequest) -> AnalysisResponse:
        _assert_provider_matches(request.provider, request.repository)
        provider, token = _provider_and_token(request, settings)
        incident_id, snapshot = await orchestrator.analyze_live(
            provider,
            token,
            request.repository,
            request.run_id,
            request.job_id,
        )
        return AnalysisResponse(incident_id=incident_id, snapshot=snapshot)

    @app.post(
        "/api/v1/gitlab/pipeline-url/analyze",
        response_model=GitLabPipelineUrlAnalysisResponse,
    )
    async def analyze_gitlab_pipeline_url(
        request: GitLabPipelineUrlRequest,
    ) -> GitLabPipelineUrlAnalysisResponse:
        token, expected_base_url = _resolve_pipeline_url_token(request, settings)
        reference = parse_gitlab_pipeline_url(
            request.pipeline_url,
            expected_base_url=expected_base_url,
        )
        async with _provider_request_scope(GitLabProvider(reference.base_url)) as provider:
            repository = await provider.get_repository_by_path(token, reference.project_path)
            pipeline, failed_jobs = await asyncio.gather(
                provider.get_run(token, repository, reference.pipeline_id),
                provider.list_jobs(token, repository, reference.pipeline_id),
            )
            if not failed_jobs:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="Pipeline access was verified, but it has no failed jobs to analyze.",
                )
            selected_jobs = failed_jobs[: request.max_failed_jobs]
            analysis_tasks = [
                asyncio.create_task(
                    orchestrator.analyze_resolved(
                        provider,
                        token,
                        repository,
                        pipeline,
                        job,
                        resolve_job_source=True,
                    )
                )
                for job in selected_jobs
            ]
            selected_ref = pipeline.commit_sha or pipeline.ref_name
            project_structure_task = asyncio.create_task(
                provider.list_repository_tree(
                    token,
                    repository,
                    ref=selected_ref,
                    max_depth=3,
                    max_entries=200,
                )
            )
            ci_config_access_task = asyncio.create_task(
                _inspect_gitlab_ci_config_access(provider, token, repository, pipeline)
            )
            try:
                completed_analyses = await asyncio.gather(*analysis_tasks)
                analyses = [
                    AnalysisResponse(incident_id=incident_id, snapshot=snapshot)
                    for incident_id, snapshot in completed_analyses
                ]
                try:
                    project_structure = await project_structure_task
                except ProviderError:
                    project_structure = []
                ci_config_access = await ci_config_access_task
            finally:
                for task in (project_structure_task, ci_config_access_task):
                    if not task.done():
                        task.cancel()
                await asyncio.gather(
                    project_structure_task,
                    ci_config_access_task,
                    return_exceptions=True,
                )
        return GitLabPipelineUrlAnalysisResponse(
            access_verified=True,
            repository=repository,
            pipeline=pipeline,
            project_structure=project_structure,
            ci_config_access=ci_config_access,
            failed_job_count=len(failed_jobs),
            skipped_job_count=max(0, len(failed_jobs) - len(selected_jobs)),
            analyses=analyses,
        )

    @app.post("/api/v1/incidents/{incident_id}/feedback", status_code=status.HTTP_204_NO_CONTENT)
    async def submit_feedback(incident_id: str, request: FeedbackRequest) -> None:
        try:
            store.record_feedback(incident_id, request.outcome, request.confirmed_resolution)
        except KeyError as error:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Unknown incident."
            ) from error

    @app.get("/api/v1/incidents/clusters")
    async def incident_clusters() -> list[dict[str, object]]:
        return store.list_clusters()

    return app


app = create_app()


def run() -> None:
    uvicorn.run("pipelinelens.api.main:app", host="127.0.0.1", port=8000, reload=True)
