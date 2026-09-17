"""Local single-user inspection, opt-in credential reuse, and redacted knowledge.

No LLM or private-corpus pipeline is invoked. Saved credentials are OS-protected
outside project data. Cache hits require fresh root project and resource access;
shared/downstream or unverifiable source evidence is never response-cached. Cached
trace/include evidence is explicitly labelled with its original inspection time.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from ipaddress import ip_address
from time import monotonic
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field, SecretStr, field_validator

from pipelinelens.config import Settings
from pipelinelens.providers.base import ProviderError
from pipelinelens.providers.gitlab import GitLabProvider
from pipelinelens.services.cloud_assist import (
    CloudAssistResult,
    resolve_cloud_assist_provider,
)
from pipelinelens.services.credentials import CredentialVault, CredentialVaultError
from pipelinelens.services.inspection import InspectionResult, _identifier, inspect_gitlab
from pipelinelens.services.local_knowledge import KnowledgeCacheError, LocalKnowledgeCache
from pipelinelens.services.pipeline_corpus import CorpusError, PipelineCorpus
from pipelinelens.services.pipeline_url import GitLabReference, _origin, parse_gitlab_url
from pipelinelens.services.redaction import redact_text
from pipelinelens.services.remediation import Remediation
from pipelinelens.services.repair_context import enrich_remediations


class InspectionRequest(BaseModel):
    url: str = Field(min_length=16, max_length=2048)
    token: SecretStr | None = None
    connection: Literal["auto", "request", "configured"] = "auto"
    remember_token: bool = False
    remember_analysis: bool = True
    refresh: bool = False
    max_jobs: int = Field(default=5, ge=1, le=8)
    ask_cloud_ai: bool = False

    @field_validator("token")
    @classmethod
    def validate_token(cls, token: SecretStr | None) -> SecretStr | None:
        if token is not None:
            text = token.get_secret_value().strip()
            if len(text) > 8192 or any(not 33 <= ord(char) <= 126 for char in text):
                raise ValueError("Enter a valid GitLab access token without whitespace.")
            return SecretStr(text) if text else None
        return None


class InspectionResponse(InspectionResult):
    submitted_url: str
    inspected_at: str
    cached: bool = False
    cache_age_seconds: int = 0
    elapsed_ms: int
    connection_used: str
    credential_saved: bool = False
    knowledge_saved: bool = False
    knowledge_summary: dict = Field(default_factory=dict)
    confirmed_resolutions: list[dict] = Field(default_factory=list)
    remediations: list[Remediation] = Field(default_factory=list)
    corpus_matches: dict[str, dict[str, int]] = Field(default_factory=dict)
    retention_notice: str = "Redacted diagnostic notes stay on this device when enabled."
    cloud_assist: CloudAssistResult | None = None
    mode: Literal["local_rules"] = "local_rules"


class ForgetRequest(BaseModel):
    credential_id: str = Field(min_length=36, max_length=36)


class ResolutionRequest(BaseModel):
    project_key: str = Field(min_length=16, max_length=2048)
    rule_id: str = Field(min_length=1, max_length=160, pattern=r"^[a-zA-Z0-9_.-]+$")
    resolution: str = Field(min_length=1, max_length=4000)
    confirmed: Literal[True]

    @field_validator("confirmed", mode="before")
    @classmethod
    def explicit_confirmation(cls, value: object) -> object:
        if value is not True:
            raise ValueError("Explicit human confirmation is required.")
        return value


@dataclass(frozen=True)
class _Candidate:
    token: str = field(repr=False)
    label: str
    credential_id: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _CachedResult:
    result: InspectionResult
    inspected_at: str
    created: float
    size: int


class _ResultCache:
    """Token-isolated root-only snapshots; dependent access requires a fresh inspection."""

    ttl = 120
    max_entries = 12
    max_bytes = 32 * 1024 * 1024

    def __init__(self) -> None:
        self.entries: OrderedDict[str, _CachedResult] = OrderedDict()

    def get(self, key: str) -> _CachedResult | None:
        now = monotonic()
        for old, entry in list(self.entries.items()):
            if now - entry.created >= self.ttl:
                del self.entries[old]
        entry = self.entries.get(key)
        if entry:
            self.entries.move_to_end(key)
        return entry

    @staticmethod
    def reusable(result: InspectionResult) -> bool:
        # Root metadata probes cannot authorize shared includes, external CI entry
        # points or child evidence. A new provider per request retries their actual
        # bounded reads, including denied/partial sources, without a second probe graph.
        access = result.ci_config_access
        if result.downstream or not access.complete or not access.entries:
            return False
        prefix = result.project_key.rstrip("/") + "/-/"

        def local_source(url: object) -> bool:
            return isinstance(url, str) and url.startswith(prefix)

        return (
            all(entry.relationship in {"root", "local_include"}
                and entry.state == "readable" and local_source(entry.source_url)
                for entry in access.entries)
            and all(local_source(config.source_url) for config in result.config_bundle)
            and all(local_source(item.get("web_url")) for item in result.merge_requests)
            and all(snapshot.repository.external_id == result.repository.external_id
                    and all(local_source(config.source_url) for config in snapshot.config_bundle)
                    for snapshot in result.analyses)
        )

    def put(self, key: str, result: InspectionResult, at: str) -> bool:
        # An uncached refresh must not leave an older, now-ineligible result reusable.
        self.entries.pop(key, None)
        if not self.reusable(result):
            return False
        size = len(result.model_dump_json().encode())
        if size > self.max_bytes:
            return False
        while self.entries and (
            len(self.entries) >= self.max_entries
            or sum(entry.size for entry in self.entries.values()) + size > self.max_bytes
        ):
            self.entries.popitem(last=False)
        self.entries[key] = _CachedResult(result.model_copy(deep=True), at, monotonic(), size)
        return True


def _local_host(host: str | None, *, testing: bool) -> bool:
    if host in {"localhost", "testserver" if testing else "localhost"}:
        return True
    try:
        return ip_address(host or "").is_loopback
    except ValueError:
        return False


def create_inspection_router(
    settings: Settings,
    vault: CredentialVault,
    knowledge: LocalKnowledgeCache,
) -> APIRouter:
    cache = _ResultCache()
    corpus = PipelineCorpus(knowledge.directory.parent / "corpus", settings=settings)
    # Keep concurrent investigations bounded; providers independently bound their reads.
    concurrent = asyncio.Semaphore(3)

    async def local_only(request: Request) -> None:
        testing = settings.environment == "test"
        client_host = request.client.host if request.client else None
        if settings.environment not in {"development", "test"} or not (
            _local_host(client_host, testing=testing) or testing and client_host == "testclient"
        ):
            raise HTTPException(403, "This single-user inspection API is localhost-only.")
        try:
            host = urlsplit(f"http://{request.headers.get('host', '')}").hostname
            origin = request.headers.get("origin")
            origin_host = urlsplit(origin).hostname if origin else None
        except ValueError:
            raise HTTPException(403, "Untrusted local request origin.") from None
        if (
            not _local_host(host, testing=testing)
            or origin and not _local_host(origin_host, testing=testing)
            or request.headers.get("sec-fetch-site") == "cross-site"
            or request.headers.get("x-pipelinelens-local") != "1"
        ):
            raise HTTPException(403, "Use the local PipelineLens dashboard for this request.")

    router = APIRouter(prefix="/api/v1/local", dependencies=[Depends(local_only)])

    def candidates(request: InspectionRequest, reference: GitLabReference) -> list[_Candidate]:
        if request.token:
            return [_Candidate(request.token.get_secret_value(), "Provided token")]
        if request.connection == "request":
            raise HTTPException(422, "Enter a read-only GitLab token for this connection.")
        available: list[_Candidate] = []
        if request.connection != "configured" and vault.available:
            available.extend(
                _Candidate(candidate.token, "Saved Windows connection", candidate.credential_id)
                for candidate in vault.candidates(reference.base_url, reference.project_path)
            )
        if (
            settings.environment in {"development", "test"}
            and settings.configured_gitlab_token
            and _origin(settings.configured_gitlab_base_url) == reference.base_url
            and not any(item.token == settings.configured_gitlab_token for item in available)
        ):
            available.append(_Candidate(settings.configured_gitlab_token, "Local connection"))
        if not available:
            raise HTTPException(
                422,
                "No verified connection is available for this GitLab host. Enter a token with "
                "read_api/read_repository access; it can be remembered securely on this laptop.",
            )
        return available

    async def verify_resource(
        provider: GitLabProvider, candidate: _Candidate, reference: GitLabReference,
    ) -> tuple[Any, str]:
        """Recheck resource access before saving an association or returning cached data."""
        token = candidate.token
        repository = await provider.get_repository_by_path(token, reference.project_path)
        fingerprint: list[Any] = [repository.model_dump()]
        run_id = reference.pipeline_id
        if reference.kind == "job":
            job = await provider.get_job(token, repository, "", reference.job_id or "")
            if job.external_id != reference.job_id:
                raise ProviderError("GitLab", 502, "Job identity could not be verified.")
            parent = job.raw.get("pipeline") or {}
            if not isinstance(parent, dict):
                raise ProviderError("GitLab", 502, "Job pipeline identity is unavailable.")
            if any(value is not None and _identifier(value) != repository.external_id for value in (
                job.raw.get("project_id"), parent.get("project_id"),
            )):
                raise ProviderError("GitLab", 502, "Job project identity could not be verified.")
            run_id = _identifier(parent.get("id"))
            if run_id is None:
                raise ProviderError("GitLab", 502, "Job pipeline identity is unavailable.")
            fingerprint.append(job.model_dump(mode="json"))
        elif reference.kind in {"branch", "repository"}:
            if reference.kind == "branch":
                reference = await provider.resolve_reference(token, repository, reference)
            ref = reference.ref or repository.default_branch or "HEAD"
            head, latest = await asyncio.gather(
                provider.resolve_commit(token, repository, ref),
                provider.latest_run_for_ref(token, repository, ref),
            )
            fingerprint.append(head)
            run_id = latest.external_id if latest else None
        if run_id:
            run, jobs = await asyncio.gather(
                provider.get_run(token, repository, run_id),
                provider.list_pipeline_jobs(token, repository, run_id, max_jobs=300),
            )
            if run.external_id != run_id or (
                run.raw.get("project_id") is not None
                and _identifier(run.raw["project_id"]) != repository.external_id
            ):
                raise ProviderError("GitLab", 502, "Pipeline identity could not be verified.")
            fingerprint.extend([run.model_dump(mode="json"), [
                [job.external_id, job.status, job.allow_failure, job.failure_reason]
                for job in jobs
            ]])
        return repository, hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True, default=str).encode()
        ).hexdigest()

    @router.get("/status")
    async def local_status() -> dict:
        notes = []
        saved = []
        summary: dict = {}
        try:
            saved = vault.metadata() if vault.available else []
        except CredentialVaultError as error:
            notes.append(str(error))
        try:
            summary = knowledge.summary()
        except KnowledgeCacheError as error:
            notes.append(str(error))
        return {
            "mode": "local_rules", "external_model_calls": False,
            "vault_available": vault.available, "saved_connections": saved,
            "configured_connection": bool(settings.configured_gitlab_token),
            "configured_host": settings.configured_gitlab_base_url,
            "knowledge": summary, "notes": notes,
            "cloud_assist_configured": (provider := resolve_cloud_assist_provider(settings))
            is not None,
            "cloud_assist_provider": provider.name if provider else None,
        }

    @router.post("/inspect", response_model=InspectionResponse)
    async def inspect(request: InspectionRequest) -> InspectionResponse:
        started = monotonic()
        reference = parse_gitlab_url(request.url)
        last_status = 401
        async with concurrent:
            for candidate in candidates(request, reference):
                async with GitLabProvider(reference.base_url) as provider:
                    try:
                        repository, freshness = await verify_resource(
                            provider, candidate, reference,
                        )
                    except ProviderError as error:
                        if error.status_code not in {401, 403, 404}:
                            raise
                        last_status = error.status_code
                        continue
                    key = hashlib.sha256(
                        f"{reference!r}|{candidate.token}|{freshness}|{request.max_jobs}".encode()
                    ).hexdigest()
                    cached = None if request.refresh else cache.get(key)
                    if cached:
                        result = cached.result.model_copy(deep=True)
                        inspected_at = cached.inspected_at
                        result.notes.append(
                            f"Cached evidence from {inspected_at}. Root resource metadata was "
                            "revalidated; traces, CI sources and change context were not reread. "
                            "Refresh to retry evidence reads."
                        )
                    else:
                        try:
                            result = await asyncio.wait_for(inspect_gitlab(
                                provider, candidate.token, repository, reference,
                                settings, max_jobs=request.max_jobs,
                            ), timeout=150)
                        except TimeoutError:
                            raise HTTPException(
                                504, "The bounded GitLab inspection timed out. Try a specific job "
                                "link or retry after checking GitLab/runner connectivity.",
                            ) from None
                        inspected_at = datetime.now(UTC).isoformat()
                        if not cache.put(key, result, inspected_at):
                            result.notes.append(
                                "This bounded inspection is not response-cached. Evidence access "
                                "will be retried on the next request; unavailable evidence remains "
                                "partial."
                            )
                    try:
                        remediations = await asyncio.wait_for(
                            enrich_remediations(provider, candidate.token, settings, result),
                            timeout=45,
                        )
                    except TimeoutError:
                        remediations = []
                        result.notes.append(
                            "Source proposal reads timed out; diagnosis remains usable, "
                            "but no source correction is claimed.",
                        )
                    saved = candidate.credential_id is not None
                    try:
                        if candidate.credential_id:
                            vault.mark_verified(
                                candidate.credential_id, reference.base_url,
                                repository.display_name,
                            )
                        elif request.remember_token:
                            if vault.available:
                                vault.save(
                                    reference.base_url, repository.display_name, candidate.token,
                                )
                                saved = True
                            else:
                                result.notes.append(
                                    "Secure OS credential storage is unavailable; token not saved."
                                )
                    except CredentialVaultError as error:
                        result.notes.append(str(error) + " The inspection result is still usable.")
                    secrets = tuple(value for value in (
                        candidate.token, settings.configured_gitlab_token, settings.llm_api_key,
                    ) if value)
                    summary = {}
                    confirmed = []
                    knowledge_saved = False
                    root_jobs = {job.external_id for job in result.jobs}
                    root_findings = [finding for finding in result.findings
                                     if not finding.job_id or finding.job_id in root_jobs]
                    try:
                        if request.remember_analysis:
                            knowledge.remember(
                                result.project_key,
                                (result.pipeline.commit_sha if result.pipeline
                                 else reference.ref or ""),
                                result.ci_config_access.model_dump(),
                                [finding.model_dump() for finding in root_findings],
                                secrets=secrets,
                            )
                            knowledge_saved = True
                        summary = knowledge.summary()
                        for rule in dict.fromkeys(finding.rule_id for finding in root_findings):
                            confirmed.extend(knowledge.lookup(result.project_key, rule))
                    except KnowledgeCacheError as error:
                        result.notes.append(str(error) + " No fix was auto-confirmed.")
                    corpus_matches = {}
                    try:
                        local_summary = await asyncio.to_thread(corpus.summary)
                        project_summary = next((item for item in local_summary.projects
                                                if item.project_key.casefold()
                                                == result.project_key.casefold()), None)
                        if project_summary:
                            rules = {finding.rule_id for finding in root_findings}
                            corpus_matches = {
                                item.rule_id: {
                                    "seen_failed_pipelines": item.seen_failed_pipelines,
                                    "failed_jobs": item.failed_jobs,
                                } for item in project_summary.rule_distribution
                                if item.rule_id in rules
                            }
                    except CorpusError:
                        result.notes.append(
                            "Local corpus coverage is unavailable; diagnostic scores "
                            "do not depend on historical frequency.",
                        )
                    cloud_assist: CloudAssistResult | None = None
                    cloud_provider = resolve_cloud_assist_provider(settings)
                    if request.ask_cloud_ai and cloud_provider is not None:
                        context_categories = {
                            "pipeline_status", "job_status", "ci_configuration", "ci_visibility",
                            "no_failure_observed", "downstream_pipeline",
                        }
                        primary = next((finding for finding in root_findings if (
                            finding.severity in {"error", "warning"}
                            and finding.category not in context_categories
                            and not finding.rule_id.startswith(("pipeline.", "ci.visibility"))
                        )), None)
                        if primary is not None and primary.confidence == "unknown":
                            try:
                                cloud_assist = await asyncio.wait_for(
                                    cloud_provider.ask(settings, primary), timeout=20,
                                )
                            except TimeoutError:
                                cloud_assist = None
                            if cloud_assist is None:
                                result.notes.append(
                                    f"Cloud assist ({cloud_provider.name}) was requested but "
                                    "returned nothing usable; the local diagnosis above is "
                                    "unaffected."
                                )
                    return InspectionResponse(
                        **result.model_dump(), submitted_url=request.url.strip(),
                        inspected_at=inspected_at, cached=cached is not None,
                        cache_age_seconds=int(monotonic() - cached.created) if cached else 0,
                        elapsed_ms=int((monotonic() - started) * 1000),
                        connection_used=candidate.label, credential_saved=saved,
                        knowledge_saved=knowledge_saved, knowledge_summary=summary,
                        confirmed_resolutions=confirmed[:6],
                        remediations=remediations, corpus_matches=corpus_matches,
                        cloud_assist=cloud_assist,
                    )
        raise HTTPException(
            last_status,
            "GitLab could not verify access to that project/link with the available connection. "
            "Check the link and token scope/expiry, or enter a different read-only token. "
            "No new project association was saved.",
        )

    @router.post("/connections/forget")
    async def forget(request: ForgetRequest) -> dict:
        removed = vault.forget(request.credential_id)
        cache.entries.clear()
        return {"removed": removed}

    @router.get("/knowledge/export")
    async def export_knowledge() -> dict:
        return knowledge.export()

    @router.post("/knowledge/confirm")
    async def confirm_resolution(request: ResolutionRequest) -> dict:
        reference = parse_gitlab_url(request.project_key)
        if reference.kind != "repository":
            raise HTTPException(422, "A resolution must be scoped to the inspected project.")
        secrets = tuple(value for value in (
            settings.configured_gitlab_token, settings.llm_api_key,
        ) if value)
        # Saved values also redact accidental credentials in user feedback, without exposing them.
        if vault.available:
            secrets += tuple(item.token for item in vault.candidates(
                reference.base_url, reference.project_path, limit=20,
            ))
        knowledge.record_resolution(
            request.project_key, request.rule_id,
            redact_text(request.resolution), secrets=secrets,
        )
        return {"saved": True, "human_confirmed": True}

    return router