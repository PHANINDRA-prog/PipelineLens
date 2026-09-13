"""Read-only GitLab CI/CD adapter for GitLab.com and self-hosted GitLab."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from hashlib import sha256
from time import monotonic
from typing import Any, Literal, TypeVar
from urllib.parse import quote, unquote, urlsplit

import httpx
from ruamel.yaml import YAML, YAMLError

from pipelinelens.domain import (
    CiConfigAccessEntry,
    CiConfigAccessReport,
    CiConfigFile,
    PipelineJob,
    PipelineRun,
    ProviderIdentity,
    ProviderName,
    RepositoryRef,
    RepositoryTreeEntry,
)
from pipelinelens.providers.base import CiProvider, ProviderError
from pipelinelens.providers.http import ReadOnlyHttpProvider
from pipelinelens.services.gitlab_includes import (
    GitLabIncludeReference,
    collect_gitlab_includes,
    is_concrete_ref,
    is_project_path,
    normalize_local_path,
    parse_project_include_key,
    project_include_key,
)
from pipelinelens.services.pipeline_url import (
    GitLabReference,
    PipelineUrlError,
    _origin,
    parse_gitlab_url,
)

_T = TypeVar("_T")
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})")
_Relationship = Literal["root", "local_include", "project_include", "unsupported_include"]


@dataclass(frozen=True, slots=True)
class ConfigInspection:
    """One bounded CI source load, shared by graph analysis and the access report."""

    configs: list[CiConfigFile]
    access: CiConfigAccessReport


@dataclass(frozen=True, slots=True)
class _ConfigRequest:
    repository: RepositoryRef
    physical_path: str
    ref: str
    logical_path: str


@dataclass(frozen=True, slots=True)
class _ConfigAccessRequest:
    repository: RepositoryRef
    physical_path: str
    ref: str
    logical_path: str
    relationship: _Relationship
    ancestors: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class _IncludeRequest:
    parent: _ConfigAccessRequest
    include: GitLabIncludeReference
    root: bool = False


class _InspectionLimit(ValueError):
    pass


class _UnresolvedConfig(ValueError):
    pass


@dataclass(slots=True)
class _RequestBudget:
    remaining: int

    def consume(self) -> None:
        if self.remaining <= 0:
            raise _InspectionLimit("CI source requests truncated at the inspection safety limit.")
        self.remaining -= 1


@dataclass(frozen=True, slots=True)
class _CachedRequest:
    expires_at: float
    task: asyncio.Task[Any]


@dataclass(frozen=True, slots=True)
class _CachedConfigBundle:
    expires_at: float
    bundle: tuple[CiConfigFile, ...]


class GitLabProvider(ReadOnlyHttpProvider, CiProvider):
    provider_name = "GitLab"
    # Compatibility for old callers that clear this attribute. Instances shadow it;
    # no configuration content or credentials are ever stored on the class.
    _config_bundle_cache: dict[tuple[str, str, str, str, str], _CachedConfigBundle] = {}
    _config_bundle_cache_ttl_seconds = 300
    _max_parallel_requests = 4
    _max_cache_entries = 256
    _max_ci_files = 100
    _max_include_depth = 20
    _max_ref_candidates = 12
    _max_yaml_characters = 1_000_000

    def __init__(
        self,
        base_url: str = "https://gitlab.com",
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.web_base_url = _origin(base_url)
        super().__init__(f"{self.web_base_url}/api/v4", transport)
        self._request_semaphore = asyncio.Semaphore(self._max_parallel_requests)
        self._request_cache: dict[tuple[str, ...], _CachedRequest] = {}
        self._config_bundle_cache = {}
        # Round-trip mode understands GitLab !reference tags without executing them.
        self._yaml = YAML(typ="rt")
        self._yaml.version = (1, 2)

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url,
            follow_redirects=False,
            trust_env=False,
            timeout=httpx.Timeout(20.0, connect=8.0),
            transport=self._transport,
        )

    def _safe_error_message(self, response: httpx.Response) -> str:
        del response
        # Upstream errors can echo credentials; never surface arbitrary response bodies.
        return "GitLab rejected the read-only request."

    async def _request(
        self,
        token: str,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        if (
            method != "GET"
            or not path.startswith("/")
            or path.startswith("//")
            or "\\" in unquote(path)
            or any(part in {".", ".."} for part in unquote(path).split("/"))
            or urlsplit(path).netloc
            or urlsplit(path).query
            or urlsplit(path).fragment
        ):
            raise ProviderError(
                self.provider_name, 400, "Only same-server read-only API paths are allowed."
            )
        async with self._request_semaphore:
            try:
                response = await super()._request(
                    token, method, path, params=params, headers=headers
                )
            except httpx.HTTPError:
                raise ProviderError(
                    self.provider_name, 502, "The GitLab read-only request could not be completed."
                ) from None
        if response.is_redirect:
            raise ProviderError(
                self.provider_name, response.status_code,
                "GitLab redirects are not followed; configure the canonical HTTPS server origin.",
            )
        return response

    async def _cached_operation(
        self,
        token: str,
        key: tuple[str, ...],
        operation: Callable[[], Awaitable[_T]],
        budget: _RequestBudget | None = None,
    ) -> _T:
        """Instance-only, token-isolated cache, including in-flight and denied reads."""

        cache_key = (sha256(token.encode()).hexdigest(), *key)
        cached = self._request_cache.get(cache_key)
        if cached is None or (cached.task.done() and cached.expires_at <= monotonic()):
            if budget is not None:
                budget.consume()
            for old_key, old_value in list(self._request_cache.items()):
                if old_value.task.done() and (
                    old_value.expires_at <= monotonic()
                    or len(self._request_cache) >= self._max_cache_entries
                ):
                    del self._request_cache[old_key]
            if len(self._request_cache) >= self._max_cache_entries:
                raise _InspectionLimit("Concurrent cache work truncated at the safety limit.")
            cached = _CachedRequest(
                monotonic() + self._config_bundle_cache_ttl_seconds,
                asyncio.create_task(operation()),
            )
            self._request_cache[cache_key] = cached
        try:
            return await cached.task
        except asyncio.CancelledError:
            self._request_cache.pop(cache_key, None)
            raise

    async def aclose(self) -> None:
        tasks = [entry.task for entry in self._request_cache.values()]
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._request_cache.clear()
        self._config_bundle_cache.clear()
        await super().aclose()

    def _headers(self, token: str) -> dict[str, str]:
        return {"PRIVATE-TOKEN": token, "Accept": "application/json"}

    @staticmethod
    def _repository(payload: dict[str, Any]) -> RepositoryRef:
        namespace = payload.get("namespace") or {}
        owner = str(
            namespace.get("full_path")
            or payload.get("path_with_namespace", "unknown/unknown").rsplit("/", 1)[0]
        )
        return RepositoryRef(
            provider=ProviderName.GITLAB,
            external_id=str(payload["id"]),
            owner=owner,
            name=str(payload["path"]),
            web_url=str(payload.get("web_url") or payload.get("http_url_to_repo", "")),
            default_branch=payload.get("default_branch"),
            ci_config_path=payload.get("ci_config_path") or None,
        )

    @staticmethod
    def _run(payload: dict[str, Any]) -> PipelineRun:
        return PipelineRun(
            external_id=str(payload["id"]),
            name=str(payload.get("name") or f"Pipeline #{payload['id']}"),
            status=str(payload.get("status") or "unknown"),
            conclusion=str(payload.get("status") or "unknown"),
            ref_name=payload.get("ref"),
            commit_sha=payload.get("sha"),
            web_url=payload.get("web_url"),
            started_at=payload.get("started_at") or payload.get("created_at"),
            finished_at=payload.get("finished_at") or payload.get("updated_at"),
            raw=payload,
        )

    @staticmethod
    def _job(payload: dict[str, Any]) -> PipelineJob:
        return PipelineJob(
            external_id=str(payload["id"]),
            name=str(payload.get("name") or f"Job {payload['id']}"),
            key=payload.get("name"),
            stage=payload.get("stage"),
            status=str(payload.get("status") or "unknown"),
            conclusion=str(payload.get("status") or "unknown"),
            allow_failure=payload.get("allow_failure") is True,
            failure_reason=payload.get("failure_reason"),
            web_url=payload.get("web_url"),
            started_at=payload.get("started_at"),
            finished_at=payload.get("finished_at"),
            raw=payload,
        )

    def _project_path(self, repository: RepositoryRef) -> str:
        return quote(repository.external_id, safe="")

    async def get_repository_by_path(self, token: str, project_path: str) -> RepositoryRef:
        """Resolve a GitLab project path from a pasted pipeline URL with read-only API access."""

        if not is_project_path(project_path):
            raise ProviderError(self.provider_name, 400, "Invalid GitLab project path.")
        response = await self._request(token, "GET", f"/projects/{quote(project_path, safe='')}")
        return self._repository(response.json())

    async def validate_token(self, token: str) -> ProviderIdentity:
        response = await self._request(token, "GET", "/user")
        payload = response.json()
        return ProviderIdentity(
            provider=ProviderName.GITLAB,
            login=str(payload["username"]),
            display_name=payload.get("name"),
            avatar_url=payload.get("avatar_url"),
        )

    async def list_repositories(self, token: str) -> list[RepositoryRef]:
        response = await self._request(
            token,
            "GET",
            "/projects",
            params={
                "membership": "true",
                "simple": "true",
                "per_page": 100,
                "order_by": "last_activity_at",
            },
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
        max_entries = max(0, min(max_entries, 1000))
        if max_entries == 0 or max_depth < 1:
            return []
        selected_ref = ref or repository.default_branch or "HEAD"
        entries: list[RepositoryTreeEntry] = []
        if max_depth == 1:
            response = await self._request(
                token,
                "GET",
                f"/projects/{self._project_path(repository)}/repository/tree",
                params={
                    "per_page": min(100, max_entries),
                    "ref": selected_ref,
                },
            )
            entries.extend(
                RepositoryTreeEntry(
                    path=item["path"],
                    entry_type="directory" if item.get("type") == "tree" else "file",
                )
                for item in response.json()
                if item.get("type") in {"tree", "blob"}
                and len(item.get("path", "").split("/")) == 1
            )
        else:
            page = 1
            for _ in range(10):
                if len(entries) >= max_entries:
                    break
                response = await self._request(
                    token,
                    "GET",
                    f"/projects/{self._project_path(repository)}/repository/tree",
                    params={
                        "recursive": "true",
                        "per_page": min(100, max_entries - len(entries)),
                        "page": page,
                        "ref": selected_ref,
                    },
                )
                entries.extend(
                    RepositoryTreeEntry(
                        path=item["path"],
                        entry_type="directory" if item.get("type") == "tree" else "file",
                    )
                    for item in response.json()
                    if item.get("type") in {"tree", "blob"}
                    and len(item.get("path", "").split("/")) <= max_depth
                )
                next_page = response.headers.get("x-next-page")
                if not next_page or not next_page.isdecimal() or int(next_page) <= page:
                    break
                page = int(next_page)

        # GitLab can return directory-heavy pages first. Preserve the root CI entry so
        # the bounded explorer still shows the configuration that controls this project.
        try:
            root_request = self._root_config_request(repository, selected_ref)
        except _UnresolvedConfig:
            root_request = None
        root_path = (
            root_request.physical_path if isinstance(root_request, _ConfigAccessRequest) else None
        )
        if root_path and not any(entry.path == root_path for entry in entries):
            try:
                await self.fetch_file_at_ref(token, repository, root_path, selected_ref)
            except ProviderError as error:
                if error.status_code != 404:
                    raise
            else:
                entries.insert(0, RepositoryTreeEntry(path=root_path, entry_type="file"))
        elif root_path:
            # Keep the root entry even when it falls beyond the explorer's slice.
            entries.sort(key=lambda entry: entry.path != root_path)
        return entries[:max_entries]

    async def list_ci_config_files(
        self, token: str, repository: RepositoryRef, ref: str | None = None
    ) -> list[CiConfigFile]:
        selected_ref = ref or repository.default_branch or "HEAD"
        response = await self._request(
            token,
            "GET",
            f"/projects/{self._project_path(repository)}/repository/tree",
            params={"recursive": "true", "per_page": 100, "ref": selected_ref},
        )
        return [
            CiConfigFile(
                path=item["path"], ref=selected_ref, content="", content_sha=item.get("id")
            )
            for item in response.json()
            if item.get("type") == "blob"
            and (
                item.get("path") == ".gitlab-ci.yml"
                or item.get("path", "").endswith((".gitlab-ci.yml", ".yml", ".yaml"))
            )
        ]

    async def list_failed_runs(
        self, token: str, repository: RepositoryRef, limit: int = 25
    ) -> list[PipelineRun]:
        response = await self._request(
            token,
            "GET",
            f"/projects/{self._project_path(repository)}/pipelines",
            params={
                "status": "failed",
                "per_page": limit,
                "order_by": "updated_at",
                "sort": "desc",
            },
        )
        return [self._run(item) for item in response.json()]

    async def list_jobs(
        self, token: str, repository: RepositoryRef, run_id: str
    ) -> list[PipelineJob]:
        response = await self._request(
            token,
            "GET",
            f"/projects/{self._project_path(repository)}/pipelines/{run_id}/jobs",
            params={"scope[]": "failed", "per_page": 100},
        )
        jobs = [self._job(item) for item in response.json()]
        return [job for job in jobs if job.status == "failed"]

    async def _pipeline_items(
        self,
        token: str,
        repository: RepositoryRef,
        run_id: str,
        resource: str,
        limit: int,
    ) -> list[dict[str, Any]]:
        """Bound pages, results and repeated IDs, even if pagination headers are broken."""

        limit = max(0, min(limit, 1000))
        per_page = min(100, limit)
        items: list[dict[str, Any]] = []
        seen: set[str] = set()
        page = 1
        for _ in range(10):
            if len(items) >= limit:
                break
            # Keep page size stable: changing it on the last page changes GitLab's offset.
            params: dict[str, Any] = {"per_page": per_page, "page": page}
            if resource == "jobs":
                params["include_retried"] = "false"
            response = await self._request(
                token, "GET",
                f"/projects/{self._project_path(repository)}/pipelines/"
                f"{quote(str(run_id), safe='')}/{resource}",
                params=params,
            )
            payload = response.json()
            if not isinstance(payload, list):
                raise ProviderError(self.provider_name, 502, "GitLab returned an invalid page.")
            before = len(items)
            for item in payload[:100]:
                if not isinstance(item, dict) or item.get("id") is None:
                    continue
                item_id = str(item["id"])
                if item_id not in seen:
                    seen.add(item_id)
                    items.append(item)
                if len(items) >= limit:
                    break
            if len(items) == before:
                break
            next_page = response.headers.get("x-next-page")
            if next_page is None and len(payload) == params["per_page"]:
                page += 1
            elif next_page and next_page.isdecimal() and int(next_page) > page:
                page = int(next_page)
            else:
                break
        return items

    async def list_pipeline_jobs(
        self, token: str, repository: RepositoryRef, run_id: str, max_jobs: int = 300
    ) -> list[PipelineJob]:
        """All statuses, paginated, excluding retried attempts; list_jobs stays failed-only."""

        return [
            self._job(item)
            for item in await self._pipeline_items(token, repository, run_id, "jobs", max_jobs)
        ]

    async def list_pipeline_bridges(
        self, token: str, repository: RepositoryRef, run_id: str
    ) -> list[dict[str, Any]]:
        """At most 300 trigger jobs, exposing only explicitly allowed public metadata."""

        bridges = await self._pipeline_items(token, repository, run_id, "bridges", 300)
        output: list[dict[str, Any]] = []
        for bridge in bridges:
            public: dict[str, Any] = {
                key: bridge[key] for key in ("id", "name", "status") if key in bridge
                and isinstance(bridge[key], (str, int))
            }
            public["allow_failure"] = bridge.get("allow_failure") is True
            downstream = bridge.get("downstream_pipeline")
            if isinstance(downstream, dict):
                public["downstream_pipeline"] = {
                    key: downstream[key]
                    for key in ("id", "iid", "project_id", "ref", "sha", "web_url", "status")
                    if key in downstream and isinstance(downstream[key], (str, int))
                }
                if "web_url" in public["downstream_pipeline"]:
                    try:
                        parse_gitlab_url(
                            str(public["downstream_pipeline"]["web_url"]), self.web_base_url
                        )
                    except PipelineUrlError:
                        del public["downstream_pipeline"]["web_url"]
            else:
                public["downstream_pipeline"] = None
            output.append(public)
        return output

    async def latest_run_for_ref(
        self, token: str, repository: RepositoryRef, ref: str
    ) -> PipelineRun | None:
        if not is_concrete_ref(ref):
            raise ProviderError(self.provider_name, 400, "Invalid GitLab ref.")
        response = await self._request(
            token, "GET", f"/projects/{self._project_path(repository)}/pipelines",
            params={"ref": ref, "per_page": 1, "order_by": "id", "sort": "desc"},
        )
        payload = response.json()
        if not isinstance(payload, list):
            raise ProviderError(
                self.provider_name, 502, "GitLab returned an invalid pipeline list."
            )
        return self._run(payload[0]) if payload else None

    async def resolve_commit(self, token: str, repository: RepositoryRef, ref: str) -> str:
        """Resolve one exact ref to its current full SHA; never infer historical ref state."""

        if not is_concrete_ref(ref):
            raise ProviderError(self.provider_name, 400, "Invalid GitLab ref.")
        response = await self._request(
            token, "GET",
            f"/projects/{self._project_path(repository)}/repository/commits/{quote(ref, safe='')}",
        )
        payload = response.json()
        commit = payload.get("id") if isinstance(payload, dict) else None
        if not isinstance(commit, str) or not _SHA.fullmatch(commit):
            raise ProviderError(self.provider_name, 502, "GitLab did not return a full commit SHA.")
        return commit.lower()

    async def _resolve_reference(
        self,
        token: str,
        repository: RepositoryRef,
        reference: GitLabReference,
        budget: _RequestBudget | None = None,
    ) -> GitLabReference:
        if reference.kind != "branch" or not reference.ref:
            return reference
        if (
            reference.base_url != self.web_base_url
            or reference.project_path.lower() != repository.display_name.lower()
            or not is_concrete_ref(reference.ref)
        ):
            raise ProviderError(
                self.provider_name, 400, "The GitLab ref does not match this repository."
            )
        pieces = reference.ref.split("/")
        for count in range(len(pieces), max(0, len(pieces) - self._max_ref_candidates), -1):
            candidate = "/".join(pieces[:count])
            try:
                await self._cached_operation(
                    token, ("commit", repository.external_id, candidate),
                    lambda candidate=candidate: self.resolve_commit(token, repository, candidate),
                    budget,
                )
            except ProviderError as error:
                if error.status_code == 404:
                    continue
                raise
            remainder = pieces[count:] + ([reference.file_path] if reference.file_path else [])
            return replace(reference, ref=candidate, file_path="/".join(remainder) or None)
        raise ProviderError(
            self.provider_name, 404,
            "No existing ref was found within the bounded longest-prefix URL resolution.",
        )

    async def resolve_reference(
        self, token: str, repository: RepositoryRef, reference: GitLabReference
    ) -> GitLabReference:
        """Disambiguate tree/blob slash refs by trying at most 12 longest existing prefixes."""

        return await self._resolve_reference(token, repository, reference)

    async def get_run(self, token: str, repository: RepositoryRef, run_id: str) -> PipelineRun:
        response = await self._request(
            token, "GET",
            f"/projects/{self._project_path(repository)}/pipelines/{quote(str(run_id), safe='')}",
        )
        return self._run(response.json())

    async def get_job(
        self, token: str, repository: RepositoryRef, run_id: str, job_id: str
    ) -> PipelineJob:
        del run_id
        response = await self._request(
            token, "GET",
            f"/projects/{self._project_path(repository)}/jobs/{quote(str(job_id), safe='')}",
        )
        return self._job(response.json())

    async def fetch_job_log(
        self, token: str, repository: RepositoryRef, run_id: str, job_id: str
    ) -> str:
        del run_id
        response = await self._request(
            token,
            "GET",
            f"/projects/{self._project_path(repository)}/jobs/{quote(str(job_id), safe='')}/trace",
            headers={"Accept": "text/plain"},
        )
        return response.text

    async def fetch_file_at_ref(
        self, token: str, repository: RepositoryRef, path: str, ref: str
    ) -> CiConfigFile:
        if normalize_local_path(path) != path or not is_concrete_ref(ref):
            raise ProviderError(
                self.provider_name, 400, "Invalid GitLab repository file path or ref."
            )
        encoded_path = quote(path, safe="")
        response = await self._request(
            token,
            "GET",
            f"/projects/{self._project_path(repository)}/repository/files/{encoded_path}/raw",
            params={"ref": ref},
            headers={"Accept": "text/plain"},
        )
        return CiConfigFile(
            path=path,
            ref=ref,
            content=response.text,
            source_url=(
                f"{self.web_base_url}/{quote(repository.display_name, safe='/')}"
                f"/-/blob/{quote(ref, safe='')}/{quote(path, safe='/')}"
            ),
        )

    def _include_keys(self, path: str, content: str) -> list[str]:
        include_keys, _ = self._config_include_references(path, content)
        return include_keys

    def _config_include_references(self, path: str, content: str) -> tuple[list[str], list[str]]:
        references, notes = self._config_includes(path, content, 120)
        return [reference.key for reference in references], notes

    def _config_includes(
        self, path: str, content: str, limit: int
    ) -> tuple[list[GitLabIncludeReference], list[str]]:
        if len(content) > self._max_yaml_characters:
            return [], ["CI YAML parsing truncated at the source-size safety limit."]
        output: list[GitLabIncludeReference] = []
        notes: list[str] = []
        parser = YAML(typ="rt")
        parser.version = (1, 2)
        try:
            for index, document in enumerate(parser.load_all(content)):
                if index >= 20:
                    notes.append("CI YAML documents truncated at the inspection safety limit.")
                    break
                if document is None:
                    continue
                if not isinstance(document, dict):
                    notes.append("CI YAML document is not a mapping; its includes are unresolved.")
                    continue
                references, unsupported = collect_gitlab_includes(
                    document.get("include"), path, max_includes=max(0, limit - len(output))
                )
                output.extend(references)
                notes.extend(unsupported)
        except (YAMLError, RecursionError, ValueError, TypeError):
            notes.append("CI YAML could not be parsed; its remaining includes are unresolved.")
        return output, list(dict.fromkeys(notes))

    @staticmethod
    def _config_access_failure_detail(error: ProviderError) -> str:
        if error.status_code == 401:
            return "GitLab rejected the supplied read-only token."
        if error.status_code == 403:
            return "The token can access the pipeline but cannot read this CI configuration source."
        if error.status_code == 404:
            return (
                "This CI configuration source was not found at the requested ref "
                "or is not visible to the token."
            )
        return "GitLab could not read this CI configuration source."

    def _config_access_source_url(self, request: _ConfigAccessRequest) -> str:
        return (
            f"{self.web_base_url}/{quote(request.repository.display_name, safe='/')}"
            f"/-/blob/{quote(request.ref, safe='')}"
            f"/{quote(request.physical_path, safe='/')}"
        )

    def _config_defines_job(self, content: str, target_job_name: str | None) -> bool:
        """Check whether a fetched CI file directly defines the selected GitLab job."""

        if not target_job_name:
            return False
        target_key = re.sub(r"[^a-z0-9]", "", target_job_name.lower())
        try:
            documents = [
                document for document in self._yaml.load_all(content) if document is not None
            ]
        except YAMLError:
            return False
        return any(
            isinstance(document, dict)
            and any(
                re.sub(r"[^a-z0-9]", "", str(key).lower()) == target_key
                and isinstance(value, dict)
                for key, value in document.items()
            )
            for document in documents
        )

    @staticmethod
    def _root_config_request(
        repository: RepositoryRef, ref: str
    ) -> _ConfigAccessRequest | _IncludeRequest:
        configured = (repository.ci_config_path or "").strip() or ".gitlab-ci.yml"
        placeholder = _ConfigAccessRequest(
            repository, ".gitlab-ci.yml", ref, ".gitlab-ci.yml", "root"
        )
        if "://" in configured or configured.startswith("//"):
            return _IncludeRequest(
                placeholder, GitLabIncludeReference(configured, "remote"), root=True
            )
        if "@" in configured:
            raw_path, _, project = configured.rpartition("@")
            project, separator, declared_ref = project.partition(":")
            declared_ref = declared_ref if separator else "HEAD"
            path = normalize_local_path(raw_path)
            if path and is_project_path(project) and is_concrete_ref(declared_ref):
                return _IncludeRequest(
                    placeholder,
                    GitLabIncludeReference(
                        project_include_key(project, path, declared_ref), "project",
                        path, project, declared_ref,
                    ),
                    root=True,
                )
        else:
            path = normalize_local_path(configured)
            if path:
                return replace(placeholder, physical_path=path, logical_path=path)
        raise _UnresolvedConfig(
            "The configured CI entry point is unsafe, unsupported or contains unknown variables."
        )

    async def _pin_include_ref(
        self,
        token: str,
        repository: RepositoryRef,
        ref: str,
        budget: _RequestBudget,
        notes: list[str],
    ) -> str:
        if _SHA.fullmatch(ref):
            return ref
        note = (
            "External include HEAD/branch/tag refs are mutable. Resolution to a current SHA "
            "does not guarantee the historical pipeline configuration."
        )
        if note not in notes:
            notes.append(note)
        try:
            return await self._cached_operation(
                token, ("commit", repository.external_id, ref),
                lambda: self.resolve_commit(token, repository, ref), budget,
            )
        except ProviderError:
            note = "An external ref could not be pinned to a SHA; the declared ref was used."
            if note not in notes:
                notes.append(note)
            return ref

    async def _resolve_config_request(
        self,
        token: str,
        request: _ConfigAccessRequest | _IncludeRequest,
        budget: _RequestBudget,
        notes: list[str],
    ) -> _ConfigAccessRequest:
        if isinstance(request, _ConfigAccessRequest):
            return request
        parent, include = request.parent, request.include
        ancestors = () if request.root else (
            *parent.ancestors,
            (parent.repository.external_id, parent.physical_path, parent.ref),
        )
        if len(ancestors) > self._max_include_depth:
            raise _InspectionLimit("Include traversal truncated at the depth safety limit.")
        if include.kind == "local":
            return _ConfigAccessRequest(
                parent.repository, include.file_path or "", parent.ref, include.key,
                "local_include", ancestors,
            )

        remote = None
        if include.kind == "remote":
            try:
                remote = parse_gitlab_url(include.key, self.web_base_url)
            except PipelineUrlError:
                raise _UnresolvedConfig(
                    "Remote include is external or unsafe; no token was sent to its host."
                ) from None
            if not remote.file_path or not remote.ref:
                raise _UnresolvedConfig("Remote include is not a GitLab raw/blob CI file URL.")
            project_path, declared_ref = remote.project_path, remote.ref
            path = remote.file_path
        else:
            project_path, declared_ref = include.project_path or "", include.ref or "HEAD"
            path = include.file_path or ""

        if project_path.lower() == parent.repository.display_name.lower():
            repository = parent.repository
        else:
            repository = await self._cached_operation(
                token, ("project", project_path.lower()),
                lambda: self.get_repository_by_path(token, project_path), budget,
            )
        if remote is not None:
            try:
                remote = await self._resolve_reference(token, repository, remote, budget)
            except ProviderError:
                raise _UnresolvedConfig(
                    "Remote CI include ref/file could not be disambiguated safely via GitLab."
                ) from None
            declared_ref, path = remote.ref or "HEAD", remote.file_path or ""
        if normalize_local_path(path) != path:
            raise _UnresolvedConfig("CI include file path is unsafe or unresolved.")
        physical_ref = await self._pin_include_ref(token, repository, declared_ref, budget, notes)
        # Only physical requests use the SHA. Logical keys keep the exact declared ref
        # (or original remote URL), which the graph's include_loader must still match.
        return _ConfigAccessRequest(
            repository, path, physical_ref, include.key,
            "root" if request.root else "project_include", ancestors,
        )

    async def load_ci_sources(
        self,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        max_files: int = 30,
    ) -> ConfigInspection:
        """Load a complete *declared* source chain once, never stopping at a selected job.

        Defaults: 30 unique file attempts, 120 include edges, depth 20, four concurrent
        HTTP requests, and 102 uncached API operations (each transport read may retry
        at most three times). Full results and denied reads are instance/token-scoped,
        expire after five minutes and are cleared on provider close. Limits are reported
        as partial access, never as proof of GitLab's effective historical configuration.
        """

        limit = max(0, min(max_files, self._max_ci_files))
        ref = run.commit_sha or run.ref_name or repository.default_branch or "HEAD"
        result = await self._cached_operation(
            token,
            ("inspection", repository.external_id, repository.display_name, ref,
             repository.ci_config_path or "", str(limit), str(bool(run.commit_sha))),
            lambda: self._load_ci_sources(token, repository, run, ref, limit),
        )
        return ConfigInspection(
            [config.model_copy(deep=True) for config in result.configs],
            result.access.model_copy(deep=True),
        )

    async def _load_ci_sources(
        self,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        ref: str,
        limit: int,
    ) -> ConfigInspection:
        configs: dict[str, CiConfigFile] = {}
        entries: list[CiConfigAccessEntry] = []
        notes: list[str] = []
        budget = _RequestBudget(3 * limit + self._max_ref_candidates)
        edge_limit = max(1, min(4 * limit, 400))
        physical_reads: set[tuple[str, str, str]] = set()
        expanded: set[tuple[str, str, str, str]] = set()
        scheduled: set[tuple[str, str, str, str]] = set()

        def note(message: str) -> None:
            if message not in notes:
                notes.append(message)

        def unresolved(path: str, detail: str, selected_ref: str | None = None) -> None:
            note(detail)
            if len(entries) < edge_limit + limit:
                entries.append(CiConfigAccessEntry(
                    path=path, ref=selected_ref, state="unresolved",
                    relationship="unsupported_include", detail=detail,
                ))

        if not run.commit_sha:
            note("Root CI ref is mutable; these sources are not guaranteed to be historical.")
        if repository.ci_config_path:
            note("The CI entry point uses the current project setting, not a historical setting.")
        if limit == 0 or not is_concrete_ref(ref):
            unresolved("CI entry point", "CI source inspection truncated or root ref is invalid.")
            return ConfigInspection(
                [], CiConfigAccessReport(entries=entries, complete=False, notes=notes)
            )
        try:
            pending = [self._root_config_request(repository, ref)]
        except _UnresolvedConfig as error:
            unresolved("CI entry point", str(error))
            return ConfigInspection(
                [], CiConfigAccessReport(entries=entries, complete=False, notes=notes)
            )

        async def read_source(
            request: _ConfigAccessRequest | _IncludeRequest,
        ) -> tuple[_ConfigAccessRequest | None, CiConfigFile | Exception]:
            current = None
            try:
                current = await self._resolve_config_request(token, request, budget, notes)
                physical_key = (current.repository.external_id, current.physical_path, current.ref)
                if physical_key in current.ancestors:
                    raise _UnresolvedConfig(
                        "Include cycle ignored; this source is already an ancestor."
                    )
                if physical_key not in physical_reads:
                    if len(physical_reads) >= limit:
                        raise _InspectionLimit(
                            "CI file reads truncated at the inspection safety limit."
                        )
                    physical_reads.add(physical_key)
                config = await self._cached_operation(
                    token, ("file", *physical_key),
                    lambda: self.fetch_file_at_ref(
                        token, current.repository, current.physical_path, current.ref
                    ),
                    budget,
                )
                return current, config
            except (ProviderError, ValueError, KeyError, TypeError) as error:
                return current, error

        processed = 0
        while pending and processed <= edge_limit:
            batch = pending[:self._max_parallel_requests]
            pending = pending[self._max_parallel_requests:]
            results = await asyncio.gather(*(read_source(request) for request in batch))
            for request, (current, result) in zip(batch, results, strict=True):
                processed += 1
                if isinstance(result, Exception):
                    # Never echo an unsafe configured URL or upstream exception payload.
                    path = current.logical_path if current else (
                        request.include.key
                        if isinstance(request, _IncludeRequest) and request.include.kind != "remote"
                        else "CI entry point" if processed == 1 else "Remote CI include"
                    )
                    if isinstance(result, ProviderError):
                        relationship: _Relationship = (
                            current.relationship if current else
                            "root" if isinstance(request, _IncludeRequest) and request.root
                            else "project_include"
                        )
                        entries.append(CiConfigAccessEntry(
                            path=path, ref=current.ref if current else None, state="unreadable",
                            relationship=relationship,
                            detail=self._config_access_failure_detail(result),
                            source_url=self._config_access_source_url(current) if current else None,
                        ))
                        note("Some declared CI sources are missing or inaccessible to this token.")
                    else:
                        detail = (
                            str(result) if isinstance(result, (_InspectionLimit, _UnresolvedConfig))
                            else "GitLab returned invalid source metadata; inspection is partial."
                        )
                        unresolved(path, detail, current.ref if current else None)
                    continue
                if current is None:
                    continue
                logical_key = (
                    current.repository.external_id, current.physical_path, current.ref,
                    current.logical_path,
                )
                if logical_key in expanded:
                    continue
                expanded.add(logical_key)
                configs[current.logical_path] = result.model_copy(
                    update={"path": current.logical_path}
                )
                entries.append(CiConfigAccessEntry(
                    path=current.logical_path, ref=current.ref, state="readable",
                    relationship=current.relationship,
                    detail=(
                        "Read at the pipeline commit." if current.ref == run.commit_sha else
                        "Read at the requested/resolved ref; historical configuration not verified."
                    ),
                    source_url=self._config_access_source_url(current),
                ))
                references, issues = self._config_includes(
                    current.logical_path, result.content, edge_limit
                )
                for issue in issues:
                    unresolved(f"{current.logical_path} (unresolved include)", issue, current.ref)
                for include in references:
                    edge = (
                        current.logical_path, current.repository.external_id,
                        current.ref, include.key,
                    )
                    if edge in scheduled:
                        continue
                    if len(scheduled) >= edge_limit:
                        unresolved(
                            "Additional CI includes",
                            "Include edges truncated at the inspection safety limit.",
                        )
                        break
                    scheduled.add(edge)
                    pending.append(_IncludeRequest(current, include))
        if pending:
            unresolved(
                "Additional CI includes",
                "Include traversal truncated at the inspection safety limit.",
            )
        return ConfigInspection(
            list(configs.values()),
            CiConfigAccessReport(
                entries=entries, notes=list(dict.fromkeys(notes)),
                complete=bool(entries) and not notes and all(
                    entry.state == "readable" for entry in entries
                ),
            ),
        )

    async def inspect_ci_config_access(
        self,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        max_files: int = 20,
    ) -> CiConfigAccessReport:
        """Legacy access-only view of the new shared source inspection."""

        return (await self.load_ci_sources(token, repository, run, max_files)).access

    async def fetch_ci_config_bundle(
        self,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        target_job_name: str | None = None,
    ) -> list[CiConfigFile]:
        # Preserve the legacy early-stop API, but honor custom entry points through
        # the full inspector. New inspection callers must use load_ci_sources.
        if repository.ci_config_path:
            return (await self.load_ci_sources(token, repository, run)).configs
        ref = run.commit_sha or run.ref_name or repository.default_branch or "HEAD"
        token_fingerprint = sha256(token.encode()).hexdigest()
        bundle_cache_key = (
            self.base_url,
            repository.external_id,
            ref,
            token_fingerprint,
            target_job_name or "__full_bundle__",
        )
        cached = self._config_bundle_cache.get(bundle_cache_key)
        if cached and cached.expires_at > monotonic():
            return [config.model_copy(deep=True) for config in cached.bundle]
        pending = [
            _ConfigRequest(
                repository=repository,
                physical_path=".gitlab-ci.yml",
                ref=ref,
                logical_path=".gitlab-ci.yml",
            )
        ]
        bundle: list[CiConfigFile] = []
        seen: set[tuple[str, str, str]] = set()
        project_cache = {repository.display_name.lower(): repository}
        denied_projects: set[str] = set()
        attempted_projects: set[str] = set()
        target_found = False
        while pending and len(bundle) < 20 and len(seen) < 20:
            batch: list[_ConfigRequest] = []
            while pending and len(batch) < 4 and len(seen) < 20:
                current = pending.pop(0)
                source_key = (
                    current.repository.external_id,
                    current.physical_path,
                    current.ref,
                )
                if source_key in seen:
                    continue
                seen.add(source_key)
                batch.append(current)
            if not batch:
                continue

            async def fetch_config(
                index: int,
                current: _ConfigRequest,
            ) -> tuple[int, _ConfigRequest, CiConfigFile | Exception]:
                try:
                    result = await self.fetch_file_at_ref(
                        token,
                        current.repository,
                        current.physical_path,
                        current.ref,
                    )
                except Exception as error:
                    return index, current, error
                return index, current, result

            fetch_tasks = [
                asyncio.create_task(fetch_config(index, current))
                for index, current in enumerate(batch)
            ]
            fetched_by_index: dict[int, CiConfigFile] = {}
            project_includes: list[tuple[str, str, str, str]] = []
            for completed_task in asyncio.as_completed(fetch_tasks):
                index, current, result = await completed_task
                if isinstance(result, ProviderError):
                    continue
                if isinstance(result, Exception):
                    for fetch_task in fetch_tasks:
                        if not fetch_task.done():
                            fetch_task.cancel()
                    await asyncio.gather(*fetch_tasks, return_exceptions=True)
                    raise result
                included = result.model_copy(update={"path": current.logical_path})
                fetched_by_index[index] = included
                if self._config_defines_job(included.content, target_job_name):
                    target_found = True
                    break
                for include_key in self._include_keys(current.logical_path, included.content)[:80]:
                    if len(pending) + len(project_includes) >= 80:
                        break
                    project_include = parse_project_include_key(include_key)
                    if project_include is None:
                        if normalize_local_path(include_key) != include_key:
                            continue
                        pending.append(
                            _ConfigRequest(
                                repository=current.repository,
                                physical_path=include_key,
                                ref=current.ref,
                                logical_path=include_key,
                            )
                        )
                    else:
                        project_includes.append(
                            (
                                project_include.project_path,
                                project_include.file_path,
                                project_include.ref,
                                include_key,
                            )
                        )

            if target_found:
                for fetch_task in fetch_tasks:
                    if not fetch_task.done():
                        fetch_task.cancel()
                await asyncio.gather(*fetch_tasks, return_exceptions=True)
            for index, _ in enumerate(batch):
                included = fetched_by_index.get(index)
                if included is not None:
                    bundle.append(included)

            if target_found:
                break

            missing_projects = sorted(
                {
                    project_path
                    for project_path, _, _, _ in project_includes
                    if project_path.lower() not in project_cache
                    and project_path.lower() not in denied_projects
                    and project_path.lower() not in attempted_projects
                }
            )[:max(0, 80 - len(attempted_projects))]
            attempted_projects.update(project.lower() for project in missing_projects)
            resolved_projects = await asyncio.gather(
                *(
                    self.get_repository_by_path(token, project_path)
                    for project_path in missing_projects
                ),
                return_exceptions=True,
            )
            for project_path, result in zip(missing_projects, resolved_projects, strict=True):
                if isinstance(result, ProviderError):
                    denied_projects.add(project_path.lower())
                    continue
                if isinstance(result, Exception):
                    raise result
                project_cache[project_path.lower()] = result

            for project_path, file_path, include_ref, include_key in project_includes:
                included_repository = project_cache.get(project_path.lower())
                if included_repository is None:
                    continue
                pending.append(
                    _ConfigRequest(
                        repository=included_repository,
                        physical_path=file_path,
                        ref=include_ref,
                        logical_path=include_key,
                    )
                )
        if len(self._config_bundle_cache) >= self._max_cache_entries:
            self._config_bundle_cache.pop(next(iter(self._config_bundle_cache)))
        self._config_bundle_cache[bundle_cache_key] = _CachedConfigBundle(
            expires_at=monotonic() + self._config_bundle_cache_ttl_seconds,
            bundle=tuple(config.model_copy(deep=True) for config in bundle),
        )
        return bundle
