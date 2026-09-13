"""Read-only GitHub Actions adapter."""

from __future__ import annotations

import base64
import io
import zipfile
from typing import Any

import httpx

from pipelinelens.domain import (
    CiConfigFile,
    PipelineJob,
    PipelineRun,
    ProviderIdentity,
    ProviderName,
    RepositoryRef,
    RepositoryTreeEntry,
)
from pipelinelens.providers.base import CiProvider
from pipelinelens.providers.http import ReadOnlyHttpProvider


class GitHubProvider(ReadOnlyHttpProvider, CiProvider):
    provider_name = "GitHub"

    def __init__(
        self,
        base_url: str = "https://api.github.com",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        super().__init__(base_url, transport)

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    @staticmethod
    def _repository(payload: dict[str, Any]) -> RepositoryRef:
        owner = payload.get("owner") or {}
        return RepositoryRef(
            provider=ProviderName.GITHUB,
            external_id=str(payload["id"]),
            owner=str(
                owner.get("login") or payload.get("full_name", "unknown/unknown").split("/")[0]
            ),
            name=str(payload["name"]),
            web_url=str(payload.get("html_url") or payload.get("url")),
            default_branch=payload.get("default_branch"),
        )

    @staticmethod
    def _run(payload: dict[str, Any]) -> PipelineRun:
        return PipelineRun(
            external_id=str(payload["id"]),
            name=str(payload.get("name") or payload.get("display_title") or f"Run {payload['id']}"),
            status=str(payload.get("status") or "unknown"),
            conclusion=payload.get("conclusion"),
            ref_name=payload.get("head_branch"),
            commit_sha=payload.get("head_sha"),
            web_url=payload.get("html_url"),
            started_at=payload.get("run_started_at"),
            finished_at=payload.get("updated_at"),
            raw=payload,
        )

    @staticmethod
    def _job(payload: dict[str, Any]) -> PipelineJob:
        return PipelineJob(
            external_id=str(payload["id"]),
            name=str(payload.get("name") or f"Job {payload['id']}"),
            key=payload.get("name"),
            stage=None,
            status=str(payload.get("status") or "unknown"),
            conclusion=payload.get("conclusion"),
            web_url=payload.get("html_url"),
            started_at=payload.get("started_at"),
            finished_at=payload.get("completed_at"),
            raw=payload,
        )

    async def validate_token(self, token: str) -> ProviderIdentity:
        response = await self._request(token, "GET", "/user")
        payload = response.json()
        return ProviderIdentity(
            provider=ProviderName.GITHUB,
            login=str(payload["login"]),
            display_name=payload.get("name"),
            avatar_url=payload.get("avatar_url"),
        )

    async def list_repositories(self, token: str) -> list[RepositoryRef]:
        response = await self._request(
            token,
            "GET",
            "/user/repos",
            params={"per_page": 100, "sort": "updated", "direction": "desc"},
        )
        return [self._repository(item) for item in response.json()]

    async def list_repository_tree(
        self,
        token: str,
        repository: RepositoryRef,
        ref: str | None = None,
        max_depth: int = 3,
        max_entries: int = 200,
    ) -> list[RepositoryTreeEntry]:
        selected_ref = ref or repository.default_branch or "HEAD"
        if max_depth == 1:
            response = await self._request(
                token,
                "GET",
                f"/repos/{repository.owner}/{repository.name}/contents",
                params={"ref": selected_ref},
            )
            payload = response.json()
            if not isinstance(payload, list):
                return []
            return [
                RepositoryTreeEntry(
                    path=item["path"],
                    entry_type="directory" if item.get("type") == "dir" else "file",
                )
                for item in payload
                if item.get("type") in {"dir", "file"}
            ][:max_entries]
        response = await self._request(
            token,
            "GET",
            f"/repos/{repository.owner}/{repository.name}/git/trees/{selected_ref}",
            params={"recursive": "1"},
        )
        entries = [
            RepositoryTreeEntry(
                path=item["path"],
                entry_type="directory" if item.get("type") == "tree" else "file",
            )
            for item in response.json().get("tree", [])
            if item.get("type") in {"tree", "blob"}
            and len(item.get("path", "").split("/")) <= max_depth
        ]
        return entries[:max_entries]

    async def list_ci_config_files(
        self, token: str, repository: RepositoryRef, ref: str | None = None
    ) -> list[CiConfigFile]:
        selected_ref = ref or repository.default_branch or "HEAD"
        response = await self._request(
            token,
            "GET",
            f"/repos/{repository.owner}/{repository.name}/git/trees/{selected_ref}",
            params={"recursive": "1"},
        )
        entries = response.json().get("tree", [])
        return [
            CiConfigFile(
                path=item["path"], ref=selected_ref, content="", content_sha=item.get("sha")
            )
            for item in entries
            if item.get("type") == "blob"
            and item.get("path", "").startswith(".github/workflows/")
            and item.get("path", "").endswith((".yml", ".yaml"))
        ]

    async def list_failed_runs(
        self, token: str, repository: RepositoryRef, limit: int = 25
    ) -> list[PipelineRun]:
        response = await self._request(
            token,
            "GET",
            f"/repos/{repository.owner}/{repository.name}/actions/runs",
            params={"per_page": limit, "status": "completed", "conclusion": "failure"},
        )
        return [self._run(item) for item in response.json().get("workflow_runs", [])]

    async def list_jobs(
        self, token: str, repository: RepositoryRef, run_id: str
    ) -> list[PipelineJob]:
        response = await self._request(
            token,
            "GET",
            f"/repos/{repository.owner}/{repository.name}/actions/runs/{run_id}/jobs",
            params={"per_page": 100},
        )
        jobs = [self._job(item) for item in response.json().get("jobs", [])]
        return [job for job in jobs if job.conclusion == "failure" or job.status == "failed"]

    async def get_run(self, token: str, repository: RepositoryRef, run_id: str) -> PipelineRun:
        response = await self._request(
            token, "GET", f"/repos/{repository.owner}/{repository.name}/actions/runs/{run_id}"
        )
        return self._run(response.json())

    async def get_job(
        self, token: str, repository: RepositoryRef, run_id: str, job_id: str
    ) -> PipelineJob:
        del run_id
        response = await self._request(
            token, "GET", f"/repos/{repository.owner}/{repository.name}/actions/jobs/{job_id}"
        )
        return self._job(response.json())

    async def fetch_job_log(
        self, token: str, repository: RepositoryRef, run_id: str, job_id: str
    ) -> str:
        del run_id
        response = await self._request(
            token,
            "GET",
            f"/repos/{repository.owner}/{repository.name}/actions/jobs/{job_id}/logs",
            headers={"Accept": "application/vnd.github+json"},
        )
        content = response.content
        if content.startswith(b"PK"):
            with zipfile.ZipFile(io.BytesIO(content)) as archive:
                first_file = next(
                    (name for name in archive.namelist() if not name.endswith("/")), None
                )
                return (
                    archive.read(first_file).decode("utf-8", errors="replace") if first_file else ""
                )
        return content.decode("utf-8", errors="replace")

    async def fetch_file_at_ref(
        self, token: str, repository: RepositoryRef, path: str, ref: str
    ) -> CiConfigFile:
        response = await self._request(
            token,
            "GET",
            f"/repos/{repository.owner}/{repository.name}/contents/{path}",
            params={"ref": ref},
        )
        payload = response.json()
        encoded = str(payload.get("content") or "").replace("\n", "")
        content = base64.b64decode(encoded).decode("utf-8", errors="replace")
        return CiConfigFile(
            path=path,
            ref=ref,
            content=content,
            content_sha=payload.get("sha"),
            source_url=payload.get("html_url"),
        )

    async def fetch_ci_config_bundle(
        self,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        target_job_name: str | None = None,
    ) -> list[CiConfigFile]:
        del target_job_name
        ref = run.commit_sha or run.ref_name or repository.default_branch or "HEAD"
        workflow_id = run.raw.get("workflow_id")
        config_path: str | None = None
        if workflow_id:
            response = await self._request(
                token,
                "GET",
                f"/repos/{repository.owner}/{repository.name}/actions/workflows/{workflow_id}",
            )
            config_path = response.json().get("path")
        if not config_path:
            candidates = await self.list_ci_config_files(token, repository, ref)
            if not candidates:
                return []
            config_path = candidates[0].path
        return [await self.fetch_file_at_ref(token, repository, config_path, ref)]
