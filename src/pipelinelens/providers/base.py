"""Shared read-only contract for CI providers."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pipelinelens.domain import (
    CiConfigFile,
    PipelineJob,
    PipelineRun,
    ProviderIdentity,
    RepositoryRef,
    RepositoryTreeEntry,
)


class ProviderError(RuntimeError):
    """A provider error that is safe to display without request credentials."""

    def __init__(self, provider: str, status_code: int, message: str) -> None:
        self.provider = provider
        self.status_code = status_code
        self.message = message
        super().__init__(f"{provider} API request failed ({status_code}): {message}")


class CiProvider(ABC):
    """Read-only provider API used by PipelineLens services."""

    @abstractmethod
    async def validate_token(self, token: str) -> ProviderIdentity:
        """Validate a read-only personal access token."""

    @abstractmethod
    async def list_repositories(self, token: str) -> list[RepositoryRef]:
        """List repositories accessible through the token."""

    @abstractmethod
    async def list_repository_tree(
        self,
        token: str,
        repository: RepositoryRef,
        ref: str | None = None,
        max_depth: int = 3,
        max_entries: int = 200,
    ) -> list[RepositoryTreeEntry]:
        """List a bounded, read-only project tree for the selected repository."""

    @abstractmethod
    async def list_ci_config_files(
        self, token: str, repository: RepositoryRef, ref: str | None = None
    ) -> list[CiConfigFile]:
        """List CI configuration files without writing to the repository."""

    @abstractmethod
    async def list_failed_runs(
        self, token: str, repository: RepositoryRef, limit: int = 25
    ) -> list[PipelineRun]:
        """List recent failed workflows or pipelines."""

    @abstractmethod
    async def list_jobs(
        self, token: str, repository: RepositoryRef, run_id: str
    ) -> list[PipelineJob]:
        """List jobs within a workflow run or pipeline."""

    @abstractmethod
    async def get_run(self, token: str, repository: RepositoryRef, run_id: str) -> PipelineRun:
        """Fetch one workflow run or pipeline."""

    @abstractmethod
    async def get_job(
        self, token: str, repository: RepositoryRef, run_id: str, job_id: str
    ) -> PipelineJob:
        """Fetch one workflow job or pipeline job."""

    @abstractmethod
    async def fetch_job_log(
        self, token: str, repository: RepositoryRef, run_id: str, job_id: str
    ) -> str:
        """Download a selected job trace in read-only mode."""

    @abstractmethod
    async def fetch_file_at_ref(
        self, token: str, repository: RepositoryRef, path: str, ref: str
    ) -> CiConfigFile:
        """Fetch a repository file at an immutable commit or selected ref."""

    @abstractmethod
    async def fetch_ci_config_bundle(
        self,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        target_job_name: str | None = None,
    ) -> list[CiConfigFile]:
        """Fetch CI configuration needed to analyze the selected run and optional job."""
