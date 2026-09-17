"""Opt-in local corpus for failures from explicitly named public GitHub repositories.

This module is deliberately separate from the authenticated GitLab corpus. It uses
only GitHub's fixed public HTTPS API, never accepts credentials, follows no redirects,
and only records allowlisted, redacted data in an ignored local SQLite database.

The corpus is for deterministic local analysis, not model training. Public source and
log material can still be copyrighted and remains subject to its source license and
other obligations. Nothing is exported automatically.
"""

from __future__ import annotations

import base64
import json
import re
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from pipelinelens.services.redaction import SecretRedactor

GITHUB_API_ORIGIN = "https://api.github.com"
GITHUB_WEB_ORIGIN = "https://github.com"
DEFAULT_PUBLIC_CORPUS_DIRECTORY = Path(__file__).resolve().parents[3] / "data" / "public-corpus"

DEFAULT_RUNS_PER_REPOSITORY = 4
MAX_REPOSITORIES = 100
MAX_RUNS_PER_REPOSITORY = 10
MAX_RETAINED_RUNS = 500
MAX_LIST_PAGES = 2
MAX_JOB_PAGES = 2
JOBS_PER_PAGE = 100
MAX_LOG_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 256 * 1024
MAX_METADATA_BYTES = 512 * 1024
MAX_STORE_BYTES = 32 * 1024 * 1024
MAX_JOB_NAME_BYTES = 256

PUBLIC_CORPUS_NOTICE = (
    "Public-content local analysis only; this corpus is not model training. Public source "
    "and log material remains subject to its source license and other obligations and may be "
    "copyrighted. Retained data stays local, is ignored by Git, and is never auto-exported. "
    "Unauthenticated GitHub Actions job logs can be unavailable; signed redirects are not followed."
)

_APPLICATION_ID = 0x504C5055
_SCHEMA_VERSION = 2
_USER_AGENT = "PipelineLens-PublicCorpus/1.0"
_ID = re.compile(r"[1-9][0-9]{0,18}\Z")
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_OWNER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}\Z")
_WORKFLOW_PATH = re.compile(
    r"\.github/workflows/[A-Za-z0-9][A-Za-z0-9_.-]{0,199}\.ya?ml\Z",
    re.IGNORECASE,
)
_RULE_ID = re.compile(r"[A-Za-z0-9_.-]{1,120}\Z")
_CONFIG_STATES = frozenset({"captured", "missing", "unavailable", "invalid", "oversized"})
_JOB_STATES = frozenset({"captured", "none", "limited", "unavailable", "invalid"})
_LOG_STATES = frozenset(
    {"captured", "empty", "redirect", "forbidden", "unavailable", "oversized", "invalid"}
)
_CLASSIFICATION_STATES = frozenset({"classified", "unknown", "no_log", "analysis_error"})


class PublicCorpusError(RuntimeError):
    """Controlled public-corpus failure without remote or local sensitive detail."""


class PublicCorpusLimitError(PublicCorpusError):
    """A bounded corpus limit was reached without evicting prior observations."""


class PublicRepositoryRejected(PublicCorpusError):
    """The public API did not explicitly confirm the requested repository is public."""


class PublicRateLimitError(PublicCorpusError):
    """GitHub rate limiting stopped all further requests; no retry or wait is attempted."""


class _PublicApiError(PublicCorpusError):
    """An upstream response was malformed, unavailable, or unsafe to use."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PublicHarvestPlan(_Model):
    """Validated local plan. Constructing one performs neither writes nor requests."""

    repositories: tuple[str, ...]
    runs_per_repository: int = Field(ge=1, le=MAX_RUNS_PER_REPOSITORY)
    target_run_count: int = Field(ge=1, le=MAX_RETAINED_RUNS)
    max_listing_pages: Literal[2] = MAX_LIST_PAGES
    max_job_listing_pages: Literal[2] = MAX_JOB_PAGES
    max_jobs_per_run: Literal[1] = 1
    max_log_bytes: Literal[1048576] = MAX_LOG_BYTES
    max_config_bytes: Literal[262144] = MAX_CONFIG_BYTES
    notice: str = PUBLIC_CORPUS_NOTICE


class PublicRuleCount(_Model):
    rule_id: str
    count: int = Field(ge=0)


class PublicCorpusSummary(_Model):
    """Lifetime coverage only, never a training/accuracy claim or retained evidence export."""

    repository_count: int = Field(default=0, ge=0)
    run_count: int = Field(default=0, ge=0)
    job_count: int = Field(default=0, ge=0)
    no_job_run_count: int = Field(default=0, ge=0)
    limited_job_run_count: int = Field(default=0, ge=0)
    captured_log_job_count: int = Field(default=0, ge=0)
    classified_job_count: int = Field(default=0, ge=0)
    unknown_job_count: int = Field(default=0, ge=0)
    analysis_error_job_count: int = Field(default=0, ge=0)
    no_log_job_count: int = Field(default=0, ge=0)
    redirect_log_job_count: int = Field(default=0, ge=0)
    forbidden_log_job_count: int = Field(default=0, ge=0)
    oversized_log_job_count: int = Field(default=0, ge=0)
    config_count: int = Field(default=0, ge=0, description="Retained sources, including truncated.")
    captured_config_run_count: int = Field(
        default=0, ge=0, description="Fully captured sources; not a guarantee of valid YAML."
    )
    truncated_config_run_count: int = Field(default=0, ge=0)
    modified_config_run_count: int = Field(default=0, ge=0)
    no_config_run_count: int = Field(default=0, ge=0)
    rule_counts: tuple[PublicRuleCount, ...] = ()
    notice: str = PUBLIC_CORPUS_NOTICE


class PublicRepositoryReport(_Model):
    """Selected/new/already-retained are this invocation; retained/coverage counts are lifetime."""

    repository: str
    state: Literal["collected", "rejected", "api_error", "rate_limited"]
    selected_run_count: int = Field(default=0, ge=0)
    new_run_count: int = Field(default=0, ge=0)
    already_retained_run_count: int = Field(default=0, ge=0)
    retained_run_count: int = Field(default=0, ge=0)
    retained_job_count: int = Field(default=0, ge=0)
    no_job_run_count: int = Field(default=0, ge=0)
    limited_job_run_count: int = Field(default=0, ge=0)
    captured_log_job_count: int = Field(default=0, ge=0)
    captured_config_run_count: int = Field(default=0, ge=0)
    truncated_config_run_count: int = Field(default=0, ge=0)
    classified_job_count: int = Field(default=0, ge=0)
    unknown_job_count: int = Field(default=0, ge=0)
    no_log_job_count: int = Field(default=0, ge=0)
    no_config_run_count: int = Field(default=0, ge=0)


class PublicHarvestReport(_Model):
    """Invocation counts are separate from the lifetime local-corpus summary."""

    state: Literal["complete", "partial", "rate_limited"]
    plan: PublicHarvestPlan
    repositories: tuple[PublicRepositoryReport, ...]
    selected_run_count: int = Field(default=0, ge=0)
    new_run_count: int = Field(default=0, ge=0)
    already_retained_run_count: int = Field(default=0, ge=0)
    summary: PublicCorpusSummary
    notice: str = PUBLIC_CORPUS_NOTICE


class PublicReevaluationReport(_Model):
    """Result of deterministic offline reclassification of retained sanitized content."""

    reevaluated_job_count: int = Field(ge=0)
    classified_job_count: int = Field(ge=0)
    unknown_job_count: int = Field(ge=0)
    analysis_error_job_count: int = Field(ge=0)
    summary: PublicCorpusSummary
    notice: str = PUBLIC_CORPUS_NOTICE


@dataclass(frozen=True, slots=True)
class _HttpResponse:
    status_code: int
    content: bytes = b""
    oversized: bool = False
    invalid_encoding: bool = False
    incomplete: bool = False


@dataclass(frozen=True, slots=True)
class _RunDraft:
    run_id: int
    head_sha: str | None
    workflow_id: int | None
    workflow_path: str | None = None


@dataclass(frozen=True, slots=True)
class _JobDraft:
    job_id: int
    name: str


@dataclass(frozen=True, slots=True)
class _ConfigCapture:
    state: Literal["captured", "missing", "unavailable", "invalid", "oversized"]
    path: str | None = None
    source_url: str | None = None
    content: str = ""
    content_hash: str = ""
    truncated: bool = False
    source_modified: bool = False


@dataclass(frozen=True, slots=True)
class _LogCapture:
    state: Literal[
        "captured", "empty", "redirect", "forbidden", "unavailable", "oversized", "invalid"
    ]
    content: str = ""


@dataclass(frozen=True, slots=True)
class _JobCapture:
    job: _JobDraft | None
    state: Literal["captured", "none", "limited", "unavailable", "invalid"]


@dataclass(frozen=True, slots=True)
class _StoredObservation:
    repository: str
    run_id: int
    head_sha: str | None
    config_state: str
    config_path: str | None
    config_source_url: str | None
    config_content: str
    config_truncated: bool
    config_source_modified: bool
    job_id: int
    job_name: str
    log_state: str
    log_content: str


@dataclass(frozen=True, slots=True)
class _OfflineSettings:
    """The analyzer only uses this bound; no configured credentials or model are available."""

    max_log_bytes: int = MAX_LOG_BYTES
    llm_mode: str = "disabled"
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: None = None
    allow_private_context: bool = False


def _positive_id(value: object) -> int | None:
    if type(value) not in {int, str}:
        return None
    text = str(value)
    if not _ID.fullmatch(text):
        return None
    number = int(text)
    return number if number < 2**63 else None


def _head_sha(value: object) -> str | None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        return None
    return value.lower()


def _workflow_path(value: object) -> str | None:
    if not isinstance(value, str) or not _WORKFLOW_PATH.fullmatch(value):
        return None
    if any(part in {"", ".", ".."} for part in value.split("/")):
        return None
    return value


def _redacted_workflow_path(redactor: SecretRedactor, value: object) -> str | None:
    path = _workflow_path(value)
    if path is None or redactor.redact(path).content != path:
        return None
    return path


def _run_workflow_path(redactor: SecretRedactor, value: object) -> str | None:
    # Run metadata can qualify a workflow path with @ref. Never use that mutable ref
    # in a contents request; retain only the validated path and fetch at head_sha.
    if not isinstance(value, str):
        return None
    path, separator, ref = value.partition("@")
    if separator and not ref:
        return None
    return _redacted_workflow_path(redactor, path)


def parse_github_repository(value: object) -> str:
    """Return a canonical public GitHub owner/name identifier without accepting URLs."""

    if not isinstance(value, str) or len(value) > 140 or value.count("/") != 1:
        raise PublicCorpusError("Use an explicit GitHub owner/name repository identifier.")
    owner, name = value.split("/", 1)
    if (
        not _OWNER.fullmatch(owner)
        or not _REPOSITORY.fullmatch(name)
        or name in {".", ".."}
        or SecretRedactor().redact(value).content != value
    ):
        raise PublicCorpusError("Use an explicit GitHub owner/name repository identifier.")
    return f"{owner.lower()}/{name.lower()}"


def preview_public_harvest(
    repositories: Sequence[str],
    *,
    runs_per_repository: int = DEFAULT_RUNS_PER_REPOSITORY,
) -> PublicHarvestPlan:
    """Validate a no-network, no-write public corpus plan."""

    if (
        type(runs_per_repository) is not int
        or not 1 <= runs_per_repository <= MAX_RUNS_PER_REPOSITORY
    ):
        raise PublicCorpusError("runs_per_repository must be between 1 and 10.")
    if not 1 <= len(repositories) <= MAX_REPOSITORIES:
        raise PublicCorpusError("Supply between 1 and 100 explicit GitHub repositories.")
    canonical = tuple(dict.fromkeys(parse_github_repository(item) for item in repositories))
    target = len(canonical) * runs_per_repository
    if target > MAX_RETAINED_RUNS:
        raise PublicCorpusLimitError(
            "The requested public corpus run count exceeds local capacity."
        )
    return PublicHarvestPlan(
        repositories=canonical,
        runs_per_repository=runs_per_repository,
        target_run_count=target,
    )


def _truncated_redacted(content: str, limit: int) -> tuple[str, bool]:
    """Apply a UTF-8 byte cap only after a caller has redacted the whole input."""

    encoded = content.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return content, False
    marker = "\n[PIPELINELENS_PUBLIC_CORPUS_TRUNCATED]\n"
    budget = max(0, limit - len(marker.encode("utf-8")))
    return encoded[:budget].decode("utf-8", errors="ignore") + marker, True


def _safe_text(redactor: SecretRedactor, value: object, limit: int) -> tuple[str, bool]:
    if not isinstance(value, str):
        return "", False
    return _truncated_redacted(redactor.redact(value).content, limit)


def _safe_rule_id(redactor: SecretRedactor, value: object) -> str:
    rule_id, _ = _safe_text(redactor, value, 120)
    return rule_id if _RULE_ID.fullmatch(rule_id) else ""


def _public_repository_url(repository: str) -> str:
    return f"{GITHUB_WEB_ORIGIN}/{repository}"


def _public_source_url(repository: str, head_sha: str, path: str) -> str:
    return f"{_public_repository_url(repository)}/blob/{head_sha}/{quote(path, safe='/')}"


def _request_is_allowed(path: object, params: object) -> bool:
    """Reject URL injection, arbitrary API routes, and caller-supplied query strings."""

    if not isinstance(path, str) or not isinstance(params, dict):
        return False
    try:
        parsed = urlsplit(path)
    except ValueError:
        return False
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "\\" in path
        or "%" in path
        or not path.startswith("/repos/")
    ):
        return False
    pieces = path.split("/")
    if len(pieces) < 4 or pieces[:2] != ["", "repos"]:
        return False
    owner, name = pieces[2], pieces[3]
    if not _OWNER.fullmatch(owner) or not _REPOSITORY.fullmatch(name):
        return False
    tail = pieces[4:]
    if tail == []:
        return not params
    if tail == ["actions", "runs"]:
        return (
            set(params) == {"status", "per_page", "page"}
            and params["status"] == "failure"
            and type(params["per_page"]) is int
            and 1 <= params["per_page"] <= MAX_RUNS_PER_REPOSITORY
            and type(params["page"]) is int
            and 1 <= params["page"] <= MAX_LIST_PAGES
        )
    if len(tail) == 4 and tail[:2] == ["actions", "runs"] and tail[3] == "jobs":
        return (
            _positive_id(tail[2]) is not None
            and set(params) == {"per_page", "page"}
            and type(params["per_page"]) is int
            and params["per_page"] == JOBS_PER_PAGE
            and type(params["page"]) is int
            and 1 <= params["page"] <= MAX_JOB_PAGES
        )
    if len(tail) == 4 and tail[:2] == ["actions", "jobs"] and tail[3] == "logs":
        return _positive_id(tail[2]) is not None and not params
    if len(tail) == 3 and tail[:2] == ["actions", "workflows"]:
        return _positive_id(tail[2]) is not None and not params
    if len(tail) == 4 and tail[:1] == ["contents"]:
        workflow = _workflow_path("/".join(tail[1:]))
        return (
            workflow is not None and set(params) == {"ref"} and _head_sha(params["ref"]) is not None
        )
    return False


class PublicGitHubClient:
    """Fixed-origin, unauthenticated GitHub public API client for this corpus only."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._client = httpx.AsyncClient(
            base_url=GITHUB_API_ORIGIN,
            transport=transport,
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(connect=5.0, read=15.0, write=5.0, pool=5.0),
            headers={
                "Accept": "application/vnd.github+json",
                "Accept-Encoding": "identity",
                "User-Agent": _USER_AGENT,
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        self._redactor = SecretRedactor()
        self._rate_limited = False

    async def __aenter__(self) -> PublicGitHubClient:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(
        self,
        path: str,
        *,
        params: dict[str, object] | None = None,
        max_bytes: int = MAX_METADATA_BYTES,
    ) -> _HttpResponse:
        parameters = {} if params is None else params
        if self._rate_limited:
            raise PublicRateLimitError("GitHub rate limiting stopped public corpus collection.")
        if (
            not _request_is_allowed(path, parameters)
            or type(max_bytes) is not int
            or not 1 <= max_bytes <= MAX_LOG_BYTES
        ):
            raise PublicCorpusError("Only bounded approved GitHub public API reads are allowed.")
        # Do not turn public reads into a cookie-authenticated session after any response.
        self._client.cookies.clear()
        try:
            async with self._client.stream("GET", path, params=parameters) as response:
                status = response.status_code
                if status == 429 or (
                    status == 403
                    and (
                        response.headers.get("x-ratelimit-remaining") == "0"
                        or "retry-after" in response.headers
                    )
                ):
                    self._rate_limited = True
                    raise PublicRateLimitError(
                        "GitHub rate limiting stopped public corpus collection."
                    )
                if status != 200:
                    return _HttpResponse(status)
                if "content-range" in response.headers:
                    return _HttpResponse(status, incomplete=True)
                encoding = response.headers.get("content-encoding", "identity").lower()
                if encoding not in {"", "identity"}:
                    return _HttpResponse(status, invalid_encoding=True)
                length = response.headers.get("content-length", "")
                if length and not re.fullmatch(r"[0-9]{1,20}", length):
                    return _HttpResponse(status, incomplete=True)
                if length and int(length) > max_bytes:
                    return _HttpResponse(status, oversized=True)
                content = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=65536):
                    if len(content) + len(chunk) > max_bytes:
                        return _HttpResponse(status, oversized=True)
                    content.extend(chunk)
                if length and len(content) != int(length):
                    return _HttpResponse(status, incomplete=True)
                return _HttpResponse(status, bytes(content))
        except PublicRateLimitError:
            raise
        except httpx.HTTPError:
            raise _PublicApiError("GitHub public API read failed safely.") from None

    @staticmethod
    def _json_object(response: _HttpResponse) -> dict[str, Any] | None:
        if (
            response.status_code != 200 or response.oversized
            or response.invalid_encoding or response.incomplete
        ):
            return None
        try:
            value = json.loads(response.content)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    async def verify_public_repository(self, repository: str) -> None:
        response = await self._request(f"/repos/{repository}")
        payload = self._json_object(response)
        if response.status_code != 200 or payload is None:
            raise _PublicApiError("GitHub public repository metadata is unavailable.")
        # Forks and archived repositories remain eligible if GitHub explicitly says public.
        full_name = payload.get("full_name")
        if (
            payload.get("private") is not False
            or payload.get("visibility") != "public"
            or not isinstance(full_name, str)
            or full_name.lower() != repository
        ):
            raise PublicRepositoryRejected("GitHub did not confirm this repository is public.")

    async def list_failed_runs(self, repository: str, limit: int) -> list[_RunDraft]:
        selected: list[_RunDraft] = []
        seen: set[int] = set()
        for page in range(1, MAX_LIST_PAGES + 1):
            response = await self._request(
                f"/repos/{repository}/actions/runs",
                params={
                    "status": "failure",
                    "per_page": limit,
                    "page": page,
                },
            )
            payload = self._json_object(response)
            runs = payload.get("workflow_runs") if payload is not None else None
            if response.status_code != 200 or not isinstance(runs, list) or len(runs) > limit:
                raise _PublicApiError("GitHub failed-run metadata is unavailable.")
            for candidate in runs:
                if not isinstance(candidate, dict):
                    continue
                if (
                    candidate.get("status") != "completed"
                    or candidate.get("conclusion") != "failure"
                ):
                    continue
                run_id = _positive_id(candidate.get("id"))
                if run_id is None or run_id in seen:
                    continue
                workflow_id = _positive_id(candidate.get("workflow_id"))
                selected.append(
                    _RunDraft(
                        run_id=run_id,
                        head_sha=_head_sha(candidate.get("head_sha")),
                        workflow_id=workflow_id,
                        workflow_path=_run_workflow_path(
                            self._redactor, candidate.get("path")
                        ),
                    )
                )
                seen.add(run_id)
                if len(selected) == limit:
                    return selected
            if len(runs) < limit:
                break
        return selected

    async def failed_job(self, repository: str, run_id: int) -> _JobCapture:
        for page in range(1, MAX_JOB_PAGES + 1):
            response = await self._request(
                f"/repos/{repository}/actions/runs/{run_id}/jobs",
                params={"per_page": JOBS_PER_PAGE, "page": page},
            )
            if response.status_code != 200:
                return _JobCapture(job=None, state="unavailable")
            payload = self._json_object(response)
            jobs = payload.get("jobs") if payload is not None else None
            if not isinstance(jobs, list) or len(jobs) > JOBS_PER_PAGE:
                return _JobCapture(job=None, state="invalid")
            total = payload.get("total_count")
            if total is not None and (type(total) is not int or total < 0):
                return _JobCapture(job=None, state="invalid")
            for candidate in jobs:
                if not isinstance(candidate, dict):
                    continue
                if (
                    candidate.get("status") != "completed"
                    or candidate.get("conclusion") != "failure"
                ):
                    continue
                job_id = _positive_id(candidate.get("id"))
                name = candidate.get("name")
                if job_id is not None and isinstance(name, str):
                    redacted_name, _ = _safe_text(self._redactor, name, MAX_JOB_NAME_BYTES)
                    return _JobCapture(
                        job=_JobDraft(job_id=job_id, name=redacted_name), state="captured"
                    )
            if total is not None:
                if total <= (page - 1) * JOBS_PER_PAGE + len(jobs):
                    return _JobCapture(job=None, state="none")
            elif len(jobs) < JOBS_PER_PAGE:
                return _JobCapture(job=None, state="none")
        # A full last page without a total does not establish that no failed job exists.
        return _JobCapture(job=None, state="limited")

    async def failed_job_log(self, repository: str, job_id: int) -> _LogCapture:
        response = await self._request(
            f"/repos/{repository}/actions/jobs/{job_id}/logs",
            max_bytes=MAX_LOG_BYTES,
        )
        if response.status_code in {301, 302, 303, 307, 308}:
            # GitHub normally sends a signed external URL here. Deliberately do not read it.
            return _LogCapture(state="redirect")
        if response.status_code == 403:
            return _LogCapture(state="forbidden")
        if response.status_code != 200:
            return _LogCapture(state="unavailable")
        if response.oversized:
            return _LogCapture(state="oversized")
        if response.invalid_encoding or response.incomplete:
            return _LogCapture(state="invalid")
        # The full bounded response is redacted before it is examined, bounded, or persisted.
        try:
            text = response.content.decode("utf-8")
        except UnicodeDecodeError:
            return _LogCapture(state="invalid")
        redacted = self._redactor.redact(text).content
        if len(redacted.encode("utf-8", errors="replace")) > MAX_LOG_BYTES:
            return _LogCapture(state="oversized")
        return _LogCapture(state="captured" if redacted.strip() else "empty", content=redacted)

    async def workflow_config(self, repository: str, run: _RunDraft) -> _ConfigCapture:
        if run.head_sha is None:
            return _ConfigCapture(state="missing")
        # The run-specific path survives workflow renames/deletion in current metadata.
        path = _redacted_workflow_path(self._redactor, run.workflow_path)
        if path is None:
            if run.workflow_id is None:
                return _ConfigCapture(state="missing")
            workflow_response = await self._request(
                f"/repos/{repository}/actions/workflows/{run.workflow_id}",
            )
            if workflow_response.status_code != 200:
                return _ConfigCapture(state="unavailable")
            if workflow_response.oversized:
                return _ConfigCapture(state="oversized")
            workflow = self._json_object(workflow_response)
            path = (
                _redacted_workflow_path(self._redactor, workflow.get("path")) if workflow else None
            )
            if path is None:
                return _ConfigCapture(state="invalid")
        contents_response = await self._request(
            f"/repos/{repository}/contents/{path}",
            params={"ref": run.head_sha},
        )
        if contents_response.status_code != 200:
            return _ConfigCapture(state="unavailable")
        if contents_response.oversized:
            return _ConfigCapture(state="oversized")
        contents = self._json_object(contents_response)
        if (
            contents is None
            or contents.get("type") != "file"
            or contents.get("encoding") != "base64"
        ):
            return _ConfigCapture(state="invalid")
        encoded = contents.get("content")
        if not isinstance(encoded, str):
            return _ConfigCapture(state="invalid")
        try:
            decoded = base64.b64decode(encoded.replace("\n", "").replace("\r", ""), validate=True)
        except (ValueError, TypeError):
            return _ConfigCapture(state="invalid")
        # Redact the complete decoded source before truncating its locally retained form.
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            return _ConfigCapture(state="invalid")
        redacted = self._redactor.redact(text).content
        content, truncated = _truncated_redacted(redacted, MAX_CONFIG_BYTES)
        return _ConfigCapture(
            state="captured",
            path=path,
            source_url=_public_source_url(repository, run.head_sha, path),
            content=content,
            content_hash=sha256(redacted.encode("utf-8", errors="replace")).hexdigest(),
            truncated=truncated,
            source_modified=truncated or redacted != text,
        )


_SCHEMA = f"""
BEGIN IMMEDIATE;
CREATE TABLE corpus_meta (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    notice TEXT NOT NULL CHECK(length(CAST(notice AS BLOB)) <= 1024)
);
CREATE TABLE repositories (
    repository TEXT PRIMARY KEY CHECK(length(CAST(repository AS BLOB)) <= 140),
    public_url TEXT NOT NULL CHECK(length(CAST(public_url AS BLOB)) <= 256)
);
CREATE TABLE runs (
    repository TEXT NOT NULL,
    run_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status = 'completed'),
    conclusion TEXT NOT NULL CHECK(conclusion = 'failure'),
    head_sha TEXT,
    config_state TEXT NOT NULL,
    config_path TEXT,
    config_source_url TEXT,
    config_content TEXT NOT NULL CHECK(length(CAST(config_content AS BLOB)) <= {MAX_CONFIG_BYTES}),
    config_content_hash TEXT NOT NULL CHECK(length(config_content_hash) IN (0, 64)),
    config_truncated INTEGER NOT NULL CHECK(config_truncated IN (0, 1)),
    config_source_modified INTEGER NOT NULL CHECK(config_source_modified IN (0, 1)),
    job_state TEXT NOT NULL,
    PRIMARY KEY(repository, run_id),
    FOREIGN KEY(repository) REFERENCES repositories(repository)
);
CREATE TABLE jobs (
    repository TEXT NOT NULL,
    run_id INTEGER NOT NULL,
    job_id INTEGER NOT NULL,
    name TEXT NOT NULL CHECK(length(CAST(name AS BLOB)) <= {MAX_JOB_NAME_BYTES}),
    status TEXT NOT NULL CHECK(status = 'completed'),
    conclusion TEXT NOT NULL CHECK(conclusion = 'failure'),
    log_state TEXT NOT NULL,
    log_content TEXT NOT NULL CHECK(length(CAST(log_content AS BLOB)) <= {MAX_LOG_BYTES}),
    classification_state TEXT NOT NULL,
    rule_id TEXT NOT NULL CHECK(length(CAST(rule_id AS BLOB)) <= 120),
    category TEXT NOT NULL CHECK(length(CAST(category AS BLOB)) <= 120),
    PRIMARY KEY(repository, run_id),
    FOREIGN KEY(repository, run_id) REFERENCES runs(repository, run_id)
);
CREATE INDEX jobs_rule_index ON jobs(rule_id);
PRAGMA application_id = {_APPLICATION_ID};
PRAGMA user_version = {_SCHEMA_VERSION};
INSERT INTO corpus_meta VALUES (1, '{PUBLIC_CORPUS_NOTICE.replace("'", "''")}');
COMMIT;
"""


class PublicCorpus:
    """Lazy, bounded local storage for redacted observations from public repositories only."""

    def __init__(
        self,
        directory: Path | None = None,
        *,
        max_store_bytes: int = MAX_STORE_BYTES,
    ) -> None:
        if type(max_store_bytes) is not int or not 65536 <= max_store_bytes <= MAX_STORE_BYTES:
            raise PublicCorpusError("Invalid public corpus storage capacity.")
        self.directory = (
            Path(directory) if directory is not None else DEFAULT_PUBLIC_CORPUS_DIRECTORY
        )
        self.path = self.directory / "public-actions.sqlite3"
        self.max_store_bytes = max_store_bytes
        self._redactor = SecretRedactor()

    @contextmanager
    def _connection(self, *, write: bool = False) -> Iterator[sqlite3.Connection | None]:
        connection: sqlite3.Connection | None = None
        try:
            exists = self.path.exists()
            if not exists and not write:
                yield None
                return
            if self.path.is_symlink() or (exists and not self.path.is_file()):
                raise PublicCorpusError("Public corpus path must be a regular local database file.")
            if exists and (
                self.path.stat().st_size == 0 or self.path.stat().st_size > self.max_store_bytes
            ):
                raise PublicCorpusError(
                    "Public corpus size is invalid; existing data was preserved."
                )
            if write:
                if self.directory.exists() and self.directory.is_symlink():
                    raise PublicCorpusError("Public corpus directory must not be a symbolic link.")
                self.directory.mkdir(parents=True, exist_ok=True)
            mode = "rwc" if write and not exists else "rw" if write else "ro"
            connection = sqlite3.connect(
                self.path.absolute().as_uri() + f"?mode={mode}",
                uri=True,
                timeout=0,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            if write and not exists:
                connection.executescript(_SCHEMA)
            if not write:
                connection.execute("PRAGMA query_only = ON")
            self._validate(connection)
            if write:
                connection.execute("PRAGMA secure_delete = ON")
                page_size = connection.execute("PRAGMA page_size").fetchone()[0]
                connection.execute(f"PRAGMA max_page_count = {self.max_store_bytes // page_size}")
                connection.execute("BEGIN IMMEDIATE")
                if connection.execute("PRAGMA user_version").fetchone()[0] == 1:
                    # Legacy redaction provenance is unknown, never exact. Read-only operations
                    # keep version 1 untouched; this additive migration is an explicit write.
                    connection.execute(
                        "ALTER TABLE runs ADD COLUMN config_source_modified INTEGER NOT NULL "
                        "DEFAULT 1 CHECK(config_source_modified IN (0, 1))"
                    )
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            yield connection
            if write:
                connection.commit()
        except PublicCorpusError:
            raise
        except sqlite3.Error:
            raise PublicCorpusError(
                "Public corpus is corrupt, incompatible, locked, or unreadable; "
                "existing data was preserved."
            ) from None
        except (OSError, TypeError, ValueError):
            raise PublicCorpusError(
                "Public corpus is inaccessible; existing data was preserved."
            ) from None
        finally:
            if connection is not None:
                connection.close()

    def _validate(self, connection: sqlite3.Connection) -> None:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
            or version not in {1, _SCHEMA_VERSION}
            or connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok"
            or connection.execute("PRAGMA foreign_key_check").fetchone() is not None
        ):
            raise PublicCorpusError(
                "Public corpus is corrupt or incompatible; existing data was preserved."
            )
        tables = {
            row[0]
            for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        if (
            tables != {"corpus_meta", "repositories", "runs", "jobs"}
            or connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type IN ('trigger', 'view')"
            ).fetchone()
        ):
            raise PublicCorpusError(
                "Public corpus schema is unexpected; existing data was preserved."
            )
        run_columns = {row[1] for row in connection.execute("PRAGMA table_info(runs)")}
        if (version == _SCHEMA_VERSION) != ("config_source_modified" in run_columns):
            raise PublicCorpusError(
                "Public corpus source provenance is invalid; existing data was preserved."
            )
        meta = connection.execute("SELECT notice FROM corpus_meta WHERE id = 1").fetchone()
        if (
            meta is None
            or meta["notice"] != PUBLIC_CORPUS_NOTICE
            or connection.execute("SELECT COUNT(*) FROM corpus_meta").fetchone()[0] != 1
        ):
            raise PublicCorpusError(
                "Public corpus metadata is invalid; existing data was preserved."
            )
        if (
            connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0]
            > MAX_REPOSITORIES
        ):
            raise PublicCorpusLimitError("Existing public corpus exceeds repository capacity.")
        if (
            connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            > MAX_RETAINED_RUNS
        ):
            raise PublicCorpusLimitError("Existing public corpus exceeds run capacity.")
        self._validate_repositories(connection)
        self._validate_runs(connection)
        self._validate_jobs(connection)

    def _validate_repositories(self, connection: sqlite3.Connection) -> None:
        for row in connection.execute("SELECT repository, public_url FROM repositories"):
            try:
                repository = parse_github_repository(row["repository"])
            except PublicCorpusError:
                raise PublicCorpusError(
                    "Public corpus repository data is invalid; existing data was preserved."
                ) from None
            if repository != row["repository"] or row["public_url"] != _public_repository_url(
                repository
            ):
                raise PublicCorpusError(
                    "Public corpus repository data is invalid; existing data was preserved."
                )

    def _validate_runs(self, connection: sqlite3.Connection) -> None:
        for row in connection.execute("SELECT * FROM runs"):
            config_state = row["config_state"]
            head_sha = row["head_sha"]
            source_modified = (
                row["config_source_modified"] if "config_source_modified" in row.keys() else 1
            )
            valid = (
                _positive_id(row["run_id"]) is not None
                and row["status"] == "completed"
                and row["conclusion"] == "failure"
                and (head_sha is None or _head_sha(head_sha) == head_sha)
                and config_state in _CONFIG_STATES
                and row["job_state"] in _JOB_STATES
                and row["config_truncated"] in {0, 1}
                and source_modified in {0, 1}
                and (not row["config_truncated"] or source_modified == 1)
                and isinstance(row["config_content"], str)
                and len(row["config_content"].encode("utf-8", errors="replace")) <= MAX_CONFIG_BYTES
                and self._redactor.redact(row["config_content"]).content == row["config_content"]
            )
            if config_state == "captured":
                expected_hash = sha256(
                    row["config_content"].encode("utf-8", errors="replace")
                ).hexdigest()
                valid = valid and (
                    head_sha is not None
                    and row["config_path"] is not None
                    and _redacted_workflow_path(self._redactor, row["config_path"])
                    == row["config_path"]
                    and row["config_source_url"]
                    == _public_source_url(
                        row["repository"],
                        head_sha,
                        row["config_path"],
                    )
                    and _HASH.fullmatch(row["config_content_hash"]) is not None
                    and (
                        row["config_truncated"]
                        or row["config_content_hash"] == expected_hash
                    )
                )
            else:
                valid = valid and (
                    not row["config_content"]
                    and not row["config_content_hash"]
                    and row["config_path"] is None
                    and row["config_source_url"] is None
                )
            if not valid:
                raise PublicCorpusError(
                    "Public corpus run data is invalid; existing data was preserved."
                )
            job_count = connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE repository = ? AND run_id = ?",
                (row["repository"], row["run_id"]),
            ).fetchone()[0]
            if job_count != int(row["job_state"] == "captured"):
                raise PublicCorpusError(
                    "Public corpus run/job data is invalid; existing data was preserved."
                )

    def _validate_jobs(self, connection: sqlite3.Connection) -> None:
        for row in connection.execute("SELECT * FROM jobs"):
            log_state = row["log_state"]
            classification = row["classification_state"]
            log = row["log_content"]
            name = row["name"]
            rule_id = row["rule_id"]
            category = row["category"]
            valid = (
                _positive_id(row["job_id"]) is not None
                and row["status"] == "completed"
                and row["conclusion"] == "failure"
                and log_state in _LOG_STATES
                and classification in _CLASSIFICATION_STATES
                and isinstance(name, str)
                and isinstance(log, str)
                and len(name.encode("utf-8", errors="replace")) <= MAX_JOB_NAME_BYTES
                and len(log.encode("utf-8", errors="replace")) <= MAX_LOG_BYTES
                and self._redactor.redact(name).content == name
                and self._redactor.redact(log).content == log
                and isinstance(rule_id, str)
                and isinstance(category, str)
                and len(category.encode("utf-8", errors="replace")) <= 120
                and self._redactor.redact(category).content == category
            )
            if log_state == "captured":
                valid = (
                    valid
                    and bool(log.strip())
                    and classification in {"classified", "unknown", "analysis_error"}
                )
            else:
                valid = valid and not log and classification == "no_log"
            if classification in {"classified", "unknown"}:
                valid = valid and _safe_rule_id(self._redactor, rule_id) == rule_id
            else:
                valid = valid and not rule_id
            if not valid:
                raise PublicCorpusError(
                    "Public corpus job data is invalid; existing data was preserved."
                )

    def initialize(self) -> None:
        """Create and validate storage only at an explicit write boundary."""

        with self._connection(write=True):
            pass

    def has_run(self, repository: str, run_id: int) -> bool:
        with self._connection() as connection:
            if connection is None:
                return False
            return (
                connection.execute(
                    "SELECT 1 FROM runs WHERE repository = ? AND run_id = ?",
                    (repository, run_id),
                ).fetchone()
                is not None
            )

    def record_run(
        self,
        repository: str,
        run: _RunDraft,
        *,
        job_capture: _JobCapture,
        log_capture: _LogCapture,
        config_capture: _ConfigCapture,
        classification: tuple[str, str, str] | None,
    ) -> None:
        """Persist a fully redacted run atomically, with at most one failed job."""

        repository = parse_github_repository(repository)
        if (
            _positive_id(run.run_id) != run.run_id
            or (run.head_sha is not None and _head_sha(run.head_sha) != run.head_sha)
            or job_capture.state not in _JOB_STATES
            or log_capture.state not in _LOG_STATES
            or config_capture.state not in _CONFIG_STATES
            or type(config_capture.truncated) is not bool
            or type(config_capture.source_modified) is not bool
        ):
            raise PublicCorpusError("Invalid local public corpus run metadata.")
        config_content, config_truncated = _safe_text(
            self._redactor,
            config_capture.content,
            MAX_CONFIG_BYTES,
        )
        config_hash = config_capture.content_hash
        config_path = _redacted_workflow_path(self._redactor, config_capture.path)
        source_modified = (
            config_capture.source_modified or config_capture.truncated or config_truncated
            or config_content != config_capture.content
        )
        config_truncated = config_truncated or config_capture.truncated
        if config_capture.state != "captured" or run.head_sha is None or config_path is None:
            config_content, config_hash, config_truncated = "", "", False
            config_path = None
            config_source_url = None
            config_state = "invalid" if config_capture.state == "captured" else config_capture.state
        else:
            config_state = "captured"
            config_source_url = _public_source_url(repository, run.head_sha, config_path)
            if not config_capture.truncated or not _HASH.fullmatch(config_hash):
                config_hash = sha256(config_content.encode("utf-8", errors="replace")).hexdigest()
        job = job_capture.job
        if (job is None and job_capture.state == "captured") or (
            job is not None and job_capture.state != "captured"
        ):
            raise PublicCorpusError("Invalid local public corpus job metadata.")
        if job is not None:
            if _positive_id(job.job_id) is None:
                raise PublicCorpusError("Invalid local public corpus job metadata.")
            name, _ = _safe_text(self._redactor, job.name, MAX_JOB_NAME_BYTES)
            log, log_truncated = _safe_text(self._redactor, log_capture.content, MAX_LOG_BYTES)
            if log_capture.state != "captured" or log_truncated:
                log = ""
                log_state = "oversized" if log_truncated else log_capture.state
            elif not log.strip():
                log, log_state = "", "empty"
            else:
                log_state = log_capture.state
            classification_state, rule_id, category = classification or ("no_log", "", "")
            if log_state != "captured":
                classification_state, rule_id, category = "no_log", "", ""
            if classification_state not in _CLASSIFICATION_STATES:
                raise PublicCorpusError("Invalid local public corpus classification.")
            if classification_state in {"classified", "unknown"}:
                rule_id = _safe_rule_id(self._redactor, rule_id)
                if not rule_id:
                    classification_state, rule_id, category = (
                        "unknown",
                        "job.insufficient_evidence",
                        "unknown",
                    )
            else:
                rule_id, category = "", ""
            if not isinstance(category, str):
                category = ""
            category, _ = _safe_text(self._redactor, category, 120)
        else:
            name = log = log_state = classification_state = rule_id = category = ""
        with self._connection(write=True) as connection:
            assert connection is not None
            known_repository = connection.execute(
                "SELECT 1 FROM repositories WHERE repository = ?",
                (repository,),
            ).fetchone()
            if (
                known_repository is None
                and connection.execute("SELECT COUNT(*) FROM repositories").fetchone()[0]
                >= MAX_REPOSITORIES
            ):
                raise PublicCorpusLimitError(
                    "Public corpus repository capacity reached; no records were evicted."
                )
            known_run = connection.execute(
                "SELECT 1 FROM runs WHERE repository = ? AND run_id = ?",
                (repository, run.run_id),
            ).fetchone()
            if (
                known_run is None
                and connection.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
                >= MAX_RETAINED_RUNS
            ):
                raise PublicCorpusLimitError(
                    "Public corpus run capacity reached; no records were evicted."
                )
            connection.execute(
                "INSERT INTO repositories(repository, public_url) VALUES (?, ?) "
                "ON CONFLICT(repository) DO NOTHING",
                (repository, _public_repository_url(repository)),
            )
            connection.execute(
                "INSERT INTO runs("
                "repository, run_id, status, conclusion, head_sha, config_state, config_path, "
                "config_source_url, config_content, config_content_hash, config_truncated, "
                "config_source_modified, job_state"
                ") VALUES (?, ?, 'completed', 'failure', ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(repository, run_id) DO UPDATE SET "
                "head_sha=excluded.head_sha, config_state=excluded.config_state, "
                "config_path=excluded.config_path, config_source_url=excluded.config_source_url, "
                "config_content=excluded.config_content, "
                "config_content_hash=excluded.config_content_hash, "
                "config_truncated=excluded.config_truncated, "
                "config_source_modified=excluded.config_source_modified, "
                "job_state=excluded.job_state",
                (
                    repository,
                    run.run_id,
                    run.head_sha,
                    config_state,
                    config_path,
                    config_source_url,
                    config_content,
                    config_hash,
                    int(config_truncated),
                    int(source_modified),
                    job_capture.state,
                ),
            )
            connection.execute(
                "DELETE FROM jobs WHERE repository = ? AND run_id = ?",
                (repository, run.run_id),
            )
            if job is not None:
                connection.execute(
                    "INSERT INTO jobs("
                    "repository, run_id, job_id, name, status, conclusion, log_state, log_content, "
                    "classification_state, rule_id, category"
                    ") VALUES (?, ?, ?, ?, 'completed', 'failure', ?, ?, ?, ?, ?)",
                    (
                        repository,
                        run.run_id,
                        job.job_id,
                        name,
                        log_state,
                        log,
                        classification_state,
                        rule_id,
                        category,
                    ),
                )

    def _where(self, repository: str | None) -> tuple[str, tuple[str, ...]]:
        if repository is None:
            return "", ()
        return " WHERE repository = ?", (parse_github_repository(repository),)

    def summary(self, repository: str | None = None) -> PublicCorpusSummary:
        """Read local coverage metadata without creating or modifying storage."""

        where, parameters = self._where(repository)
        with self._connection() as connection:
            if connection is None:
                return PublicCorpusSummary()
            repository_count = connection.execute(
                "SELECT COUNT(*) FROM repositories" + where,
                parameters,
            ).fetchone()[0]
            run_count = connection.execute(
                "SELECT COUNT(*) FROM runs" + where, parameters
            ).fetchone()[0]
            job_count = connection.execute(
                "SELECT COUNT(*) FROM jobs" + where, parameters
            ).fetchone()[0]
            job_where = where
            classified = connection.execute(
                "SELECT COUNT(*) FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " classification_state = 'classified'",
                parameters,
            ).fetchone()[0]
            unknown = connection.execute(
                "SELECT COUNT(*) FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " classification_state = 'unknown'",
                parameters,
            ).fetchone()[0]
            analysis_errors = connection.execute(
                "SELECT COUNT(*) FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " classification_state = 'analysis_error'",
                parameters,
            ).fetchone()[0]
            no_log = connection.execute(
                "SELECT COUNT(*) FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " log_state != 'captured'",
                parameters,
            ).fetchone()[0]
            redirects = connection.execute(
                "SELECT COUNT(*) FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " log_state = 'redirect'",
                parameters,
            ).fetchone()[0]
            forbidden = connection.execute(
                "SELECT COUNT(*) FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " log_state = 'forbidden'",
                parameters,
            ).fetchone()[0]
            oversized = connection.execute(
                "SELECT COUNT(*) FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " log_state = 'oversized'",
                parameters,
            ).fetchone()[0]
            config_count = connection.execute(
                "SELECT COUNT(*) FROM runs"
                + where
                + (" AND" if where else " WHERE")
                + " config_state = 'captured'",
                parameters,
            ).fetchone()[0]
            truncated_configs = connection.execute(
                "SELECT COUNT(*) FROM runs" + where + (" AND" if where else " WHERE")
                + " config_state = 'captured' AND config_truncated = 1",
                parameters,
            ).fetchone()[0]
            captured_configs = config_count - truncated_configs
            no_config = run_count - captured_configs
            modified_filter = (
                "config_source_modified = 1"
                if connection.execute("PRAGMA user_version").fetchone()[0] == _SCHEMA_VERSION
                else "1 = 1"
            )
            modified_configs = connection.execute(
                "SELECT COUNT(*) FROM runs" + where + (" AND" if where else " WHERE")
                + " config_state = 'captured' AND " + modified_filter,
                parameters,
            ).fetchone()[0]
            limited_jobs = connection.execute(
                "SELECT COUNT(*) FROM runs" + where + (" AND" if where else " WHERE")
                + " job_state = 'limited'",
                parameters,
            ).fetchone()[0]
            rule_rows = connection.execute(
                "SELECT rule_id, COUNT(*) AS count FROM jobs"
                + job_where
                + (" AND" if job_where else " WHERE")
                + " classification_state IN ('classified', 'unknown') "
                "GROUP BY rule_id ORDER BY count DESC, rule_id ASC",
                parameters,
            )
            rule_counts = tuple(
                PublicRuleCount(rule_id=row["rule_id"], count=row["count"])
                for row in rule_rows
                if _RULE_ID.fullmatch(row["rule_id"])
            )
            return PublicCorpusSummary(
                repository_count=repository_count,
                run_count=run_count,
                job_count=job_count,
                no_job_run_count=run_count - job_count,
                limited_job_run_count=limited_jobs,
                captured_log_job_count=job_count - no_log,
                classified_job_count=classified,
                unknown_job_count=unknown,
                analysis_error_job_count=analysis_errors,
                no_log_job_count=no_log,
                redirect_log_job_count=redirects,
                forbidden_log_job_count=forbidden,
                oversized_log_job_count=oversized,
                config_count=config_count,
                captured_config_run_count=captured_configs,
                truncated_config_run_count=truncated_configs,
                modified_config_run_count=modified_configs,
                no_config_run_count=no_config,
                rule_counts=rule_counts,
            )

    def match(self, rule_id: str) -> int:
        """Return only the exact global occurrence count for a local diagnostic rule."""

        if _safe_rule_id(self._redactor, rule_id) != rule_id:
            return 0
        with self._connection() as connection:
            if connection is None:
                return 0
            return connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE rule_id = ? "
                "AND classification_state IN ('classified', 'unknown')",
                (rule_id,),
            ).fetchone()[0]

    def _observations(self) -> Iterator[_StoredObservation]:
        with self._connection() as connection:
            if connection is None:
                return
            modified_column = (
                "runs.config_source_modified"
                if connection.execute("PRAGMA user_version").fetchone()[0] == _SCHEMA_VERSION
                else "1 AS config_source_modified"
            )
            rows = list(
                connection.execute(
                    "SELECT runs.repository, runs.run_id, runs.head_sha, runs.config_state, "
                    "runs.config_path, runs.config_source_url, runs.config_content, "
                    f"runs.config_truncated, {modified_column}, "
                    "jobs.job_id, jobs.name, jobs.log_state, "
                    "jobs.log_content FROM jobs JOIN runs ON jobs.repository = runs.repository "
                    "AND jobs.run_id = runs.run_id ORDER BY jobs.repository, runs.run_id, "
                    "jobs.job_id",
                )
            )
        for row in rows:
            config, _ = _safe_text(self._redactor, row["config_content"], MAX_CONFIG_BYTES)
            name, _ = _safe_text(self._redactor, row["name"], MAX_JOB_NAME_BYTES)
            log, _ = _safe_text(self._redactor, row["log_content"], MAX_LOG_BYTES)
            yield _StoredObservation(
                repository=row["repository"],
                run_id=row["run_id"],
                head_sha=row["head_sha"],
                config_state=row["config_state"],
                config_path=row["config_path"],
                config_source_url=row["config_source_url"],
                config_content=config,
                config_truncated=bool(row["config_truncated"]),
                config_source_modified=bool(row["config_source_modified"]),
                job_id=row["job_id"],
                job_name=name,
                log_state=row["log_state"],
                log_content=log,
            )

    def _update_classification(
        self,
        observation: _StoredObservation,
        classification: tuple[str, str, str],
    ) -> None:
        state, rule_id, category = classification
        if state not in _CLASSIFICATION_STATES:
            raise PublicCorpusError("Invalid local public corpus classification.")
        if state in {"classified", "unknown"}:
            rule_id = _safe_rule_id(self._redactor, rule_id)
            if not rule_id:
                state, rule_id, category = "unknown", "job.insufficient_evidence", "unknown"
        if state not in {"classified", "unknown"}:
            rule_id, category = "", ""
        category, _ = _safe_text(self._redactor, category, 120)
        with self._connection(write=True) as connection:
            assert connection is not None
            connection.execute(
                "UPDATE jobs SET classification_state = ?, rule_id = ?, category = ? "
                "WHERE repository = ? AND run_id = ? AND job_id = ?",
                (
                    state,
                    rule_id,
                    category,
                    observation.repository,
                    observation.run_id,
                    observation.job_id,
                ),
            )


def _classify(
    repository: str,
    run: _RunDraft,
    job: _JobDraft,
    log: _LogCapture,
    config: _ConfigCapture,
) -> tuple[str, str, str]:
    """Use the normal deterministic analyzer locally; source is never fetched here."""

    if log.state != "captured" or not log.content.strip():
        return "no_log", "", ""
    # Keep preview/summary independent of application configuration imports. These
    # normal classifiers are needed only after an explicit local write path. The analysis
    # module still imports config (and may load dotenv); only offline settings are passed.
    from pipelinelens.domain import (
        CiConfigFile,
        DownloadState,
        PipelineGraph,
        PipelineJob,
        PipelineRun,
        ProviderName,
        RepositoryRef,
    )
    from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
    from pipelinelens.services.findings import diagnose_job
    from pipelinelens.services.yaml_graph import analyze_github_workflow

    owner, name = repository.split("/", 1)
    try:
        configs = []
        if (
            config.state == "captured" and not config.truncated
            and config.path and config.source_url
        ):
            content = SecretRedactor().redact(config.content).content
            source = CiConfigFile(
                path=config.path,
                ref=run.head_sha or "HEAD",
                content=content,
                source_url=config.source_url,
                source_modified=config.source_modified or content != config.content,
            )
            try:
                analyze_github_workflow(source)
            except Exception:
                # Malformed/unsupported source must not suppress independent log diagnosis.
                pass
            else:
                configs.append(source)
        synthetic_config = not configs
        if synthetic_config:
            # The GitHub parser requires a jobs mapping, not empty YAML. This parser-only
            # shim is never stored and is removed before it could become finding evidence.
            configs = [CiConfigFile(path="", ref="", content="jobs: {}\n", source_modified=True)]
        snapshot = PipelineAnalyzer(_OfflineSettings()).analyze_input(
            AnalysisInput(
                repository=RepositoryRef(
                    provider=ProviderName.GITHUB,
                    external_id=repository,
                    owner=owner,
                    name=name,
                    web_url=_public_repository_url(repository),
                ),
                run=PipelineRun(
                    external_id=str(run.run_id),
                    name="Public workflow run",
                    status="completed",
                    conclusion="failure",
                    commit_sha=run.head_sha,
                ),
                job=PipelineJob(
                    external_id=str(job.job_id),
                    name=job.name,
                    key=job.name,
                    status="completed",
                    conclusion="failure",
                ),
                configs=configs,
                raw_log=log.content,
            )
        )
        if synthetic_config:
            snapshot = snapshot.model_copy(update={
                "config": CiConfigFile(path="", ref="", content="", source_modified=True),
                "config_bundle": [],
                "graph": PipelineGraph(provider=ProviderName.GITHUB, config_files=[]),
                "job_source": None,
                "progress": snapshot.progress.model_copy(update={
                    "ci_configuration": DownloadState.FAILED,
                    "graph_analysis": DownloadState.FAILED,
                }),
            })
        finding = diagnose_job(snapshot)
    except Exception:
        # Analyzer exceptions can contain source/log fragments, so never persist their details.
        return "analysis_error", "", ""
    rule_id = finding.rule_id if isinstance(finding.rule_id, str) else "job.insufficient_evidence"
    category = finding.category if isinstance(finding.category, str) else "unknown"
    state = "unknown" if finding.confidence == "unknown" or category == "unknown" else "classified"
    return state, rule_id, category


class _PublicHarvester:
    def __init__(
        self, plan: PublicHarvestPlan, corpus: PublicCorpus, client: PublicGitHubClient
    ) -> None:
        self.plan = plan
        self.corpus = corpus
        self.client = client
        self.partial = False

    def _report(
        self,
        repository: str,
        state: Literal["collected", "rejected", "api_error", "rate_limited"],
        selected: int = 0,
        new: int = 0,
        already_retained: int = 0,
    ) -> PublicRepositoryReport:
        summary = self.corpus.summary(repository)
        return PublicRepositoryReport(
            repository=repository,
            state=state,
            selected_run_count=selected,
            new_run_count=new,
            already_retained_run_count=already_retained,
            retained_run_count=summary.run_count,
            retained_job_count=summary.job_count,
            no_job_run_count=summary.no_job_run_count,
            limited_job_run_count=summary.limited_job_run_count,
            captured_log_job_count=summary.captured_log_job_count,
            captured_config_run_count=summary.captured_config_run_count,
            truncated_config_run_count=summary.truncated_config_run_count,
            classified_job_count=summary.classified_job_count,
            unknown_job_count=summary.unknown_job_count,
            no_log_job_count=summary.no_log_job_count,
            no_config_run_count=summary.no_config_run_count,
        )

    async def _capture_run(self, repository: str, run: _RunDraft) -> None:
        try:
            job_capture = await self.client.failed_job(repository, run.run_id)
        except _PublicApiError:
            job_capture = _JobCapture(job=None, state="unavailable")
            self.partial = True
        if job_capture.state != "captured":
            self.partial = True
        if job_capture.job is None:
            log_capture = _LogCapture(state="unavailable")
            classification: tuple[str, str, str] | None = None
        else:
            try:
                log_capture = await self.client.failed_job_log(repository, job_capture.job.job_id)
            except _PublicApiError:
                log_capture = _LogCapture(state="unavailable")
                self.partial = True
            if log_capture.state != "captured":
                self.partial = True
        try:
            config_capture = await self.client.workflow_config(repository, run)
        except _PublicApiError:
            config_capture = _ConfigCapture(state="unavailable")
            self.partial = True
        if config_capture.state != "captured" or config_capture.truncated:
            self.partial = True
        if job_capture.job is not None:
            classification = _classify(
                repository, run, job_capture.job, log_capture, config_capture
            )
            if classification[0] == "analysis_error":
                self.partial = True
        self.corpus.record_run(
            repository,
            run,
            job_capture=job_capture,
            log_capture=log_capture,
            config_capture=config_capture,
            classification=classification,
        )

    async def collect_repository(self, repository: str) -> PublicRepositoryReport:
        selected = new = already_retained = 0
        try:
            await self.client.verify_public_repository(repository)
            runs = await self.client.list_failed_runs(repository, self.plan.runs_per_repository)
            selected = len(runs)
            for run in runs:
                if self.corpus.has_run(repository, run.run_id):
                    already_retained += 1
                    continue
                await self._capture_run(repository, run)
                new += 1
        except PublicRepositoryRejected:
            self.partial = True
            return self._report(repository, "rejected")
        except _PublicApiError:
            self.partial = True
            return self._report(repository, "api_error", selected, new, already_retained)
        except PublicRateLimitError:
            self.partial = True
            return self._report(repository, "rate_limited", selected, new, already_retained)
        return self._report(repository, "collected", selected, new, already_retained)

    async def run(self) -> PublicHarvestReport:
        reports: list[PublicRepositoryReport] = []
        for repository in self.plan.repositories:
            report = await self.collect_repository(repository)
            reports.append(report)
            if report.state == "rate_limited":
                break
        return PublicHarvestReport(
            state=("rate_limited" if reports[-1].state == "rate_limited"
                   else "partial" if self.partial else "complete"),
            plan=self.plan,
            repositories=tuple(reports),
            selected_run_count=sum(report.selected_run_count for report in reports),
            new_run_count=sum(report.new_run_count for report in reports),
            already_retained_run_count=sum(report.already_retained_run_count for report in reports),
            summary=self.corpus.summary(),
        )


async def harvest_public_repositories(
    repositories: Sequence[str],
    *,
    runs_per_repository: int = DEFAULT_RUNS_PER_REPOSITORY,
    corpus: PublicCorpus | None = None,
    client: PublicGitHubClient | None = None,
) -> PublicHarvestReport:
    """Explicitly collect bounded public metadata/content; previews must call the plan function."""

    plan = preview_public_harvest(repositories, runs_per_repository=runs_per_repository)
    active_corpus = corpus if corpus is not None else PublicCorpus()
    active_corpus.initialize()
    if client is not None:
        return await _PublicHarvester(plan, active_corpus, client).run()
    async with PublicGitHubClient() as owned_client:
        return await _PublicHarvester(plan, active_corpus, owned_client).run()


def reevaluate_public_corpus(corpus: PublicCorpus) -> PublicReevaluationReport:
    """Use offline settings and no provider/model I/O; analyzer imports may still load dotenv."""

    corpus.initialize()
    reevaluated = classified = unknown = errors = 0
    for observation in corpus._observations():
        if observation.log_state != "captured" or not observation.log_content.strip():
            continue
        run = _RunDraft(run_id=observation.run_id, head_sha=observation.head_sha, workflow_id=None)
        job = _JobDraft(job_id=observation.job_id, name=observation.job_name)
        config = _ConfigCapture(
            state="captured" if observation.config_state == "captured" else "missing",
            path=observation.config_path,
            source_url=observation.config_source_url,
            content=observation.config_content,
            truncated=observation.config_truncated,
            source_modified=observation.config_source_modified,
        )
        result = _classify(
            observation.repository,
            run,
            job,
            _LogCapture(state="captured", content=observation.log_content),
            config,
        )
        corpus._update_classification(observation, result)
        reevaluated += 1
        classified += result[0] == "classified"
        unknown += result[0] == "unknown"
        errors += result[0] == "analysis_error"
    return PublicReevaluationReport(
        reevaluated_job_count=reevaluated,
        classified_job_count=classified,
        unknown_job_count=unknown,
        analysis_error_job_count=errors,
        summary=corpus.summary(),
    )
