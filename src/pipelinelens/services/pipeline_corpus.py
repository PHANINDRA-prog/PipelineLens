"""Bounded, local observations of failed GitLab pipelines, NOT model training.

Integration API:
* ``preview_harvest(settings, projects, ...)`` is network/file-write free.
* ``await harvest_pipelines(settings, projects, corpus=..., ...)`` explicitly writes.
* ``PipelineCorpus.summary()`` reports coverage, unknowns and rule distributions.
* ``PipelineCorpus.match(project_key, rule_id)`` returns occurrence counts ONLY.
* ``reevaluate_corpus(corpus)`` reclassifies retained sanitized traces, offline.

The default store is ignored ``data/corpus/pipelines.sqlite3``. SQLite transactions
checkpoint every selected pipeline and every sampled job. Resuming starts listing
at page one (offsets can move), deduplicates numeric IDs, and reuses completed jobs.
429 leaves unfinished work pending; there are no automatic retries or sleeps.
Completed unreadable/empty samples are observations, not automatic retry targets.

Only two failed jobs per pipeline are sampled, blocking jobs first, from at most
300 enumerated jobs. Configs, source, trees, MRs, diffs and downstream pipelines are
deliberately NOT fetched. A failed-only sample cannot estimate success probability
or establish a confirmed fix. Collection is not an atomic GitLab snapshot.

The DB is capped at 512 MiB / 1,000 pipelines / 2,000 jobs / 20 projects. A full or
corrupt store fails closed without eviction or replacement. SQLite's temporary
rollback journal can use up to roughly another database-size of disk space.
Readable traces are retained in full up to 1,000,000 bytes. Oversized downloads
are discarded, rather than persisting a partial opaque secret across a cutoff.
Sanitization ALWAYS precedes any retained-text truncation. The local corpus is
unencrypted and may still contain business-sensitive, non-credential information.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from collections.abc import Generator, Iterator, Sequence
from contextlib import asynccontextmanager, contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import IO, Any, Literal, TypeVar
from urllib.parse import quote, quote_plus, unquote, urlsplit
from uuid import uuid4

import httpx
from pydantic import BaseModel, ConfigDict, Field

from pipelinelens.config import Settings, get_settings
from pipelinelens.domain import PipelineJob, PipelineRun, ProviderName, RepositoryRef
from pipelinelens.providers.base import ProviderError
from pipelinelens.providers.gitlab import GitLabProvider
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.findings import diagnose_job
from pipelinelens.services.inspection import _Scrubber
from pipelinelens.services.pipeline_url import PipelineUrlError, _origin, parse_gitlab_url

DEFAULT_CORPUS_DIRECTORY = Path(__file__).resolve().parents[3] / "data" / "corpus"
MAX_TRACE_BYTES = 1_000_000
MAX_STORE_BYTES = 512 * 1024 * 1024
MAX_PIPELINES = 1_000
MAX_PROJECTS = 20
MAX_LIST_PAGES = 25
RULE_VERSION = "trace-only-v1"
_APPLICATION_ID = 0x504C4350
_SCHEMA_VERSION = 1
_MAX_METADATA_BYTES = 2_000_000
_MAX_RECORD_BYTES = 16_384
_MAX_CHECKPOINT_BYTES = 65_536
_RULE = re.compile(r"[a-zA-Z0-9_.-]{1,120}\Z")
_ID = re.compile(r"[1-9][0-9]{0,18}\Z")
_TRUNCATED = "\n[PIPELINELENS_LOG_TRUNCATED]\n"
_NOTICE = (
    "Trace-only observations, not source verification, confirmed fixes, model training, "
    "or success probabilities. Configurations are omitted. Sanitized local data is "
    "unencrypted and can remain business-sensitive. No model requests or uploads."
)
_State = Literal[
    "collecting", "complete", "shortfall", "rate_limited", "interrupted", "capacity",
    "access_denied", "provider_error",
]
_JobState = Literal[
    "pending", "analyzed", "unknown", "empty", "unreadable", "oversized", "analysis_error",
]
_ListingState = Literal["pending", "listed", "exhausted", "unreadable", "invalid", "page_limit"]


class CorpusError(RuntimeError):
    """Controlled, credential-free configuration, storage or protocol failure."""


class CorpusLimitError(CorpusError):
    """A hard bound was reached; existing observations were not evicted."""


class _TraceTooLarge(ProviderError):
    def __init__(self) -> None:
        super().__init__("GitLab", 413, "Trace exceeds the corpus download limit.")


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class HarvestPlan(_Model):
    """An offline plan; ``token_configured`` reveals presence, never the value."""

    origin: str
    projects: tuple[str, ...]
    per_project: int
    concurrency: Literal[2, 3] = 2
    target_distinct_pipelines: int
    token_configured: bool
    jobs_per_pipeline: Literal[2] = 2
    max_trace_bytes: Literal[1_000_000] = MAX_TRACE_BYTES
    max_listing_pages: int = MAX_LIST_PAGES
    pipeline_order: Literal["id desc"] = "id desc"
    notice: str = _NOTICE


class CorpusMatch(_Model):
    """Exact project/rule failed-sample counts; never a confidence or a resolution."""

    seen_failed_pipelines: int = 0
    failed_jobs: int = 0


class RuleCount(CorpusMatch):
    rule_id: str


class UnknownExcerpt(_Model):
    pipeline_id: int
    job_id: int
    rule_id: str
    text: str = Field(max_length=800)


class ProjectCorpusSummary(_Model):
    """Unknowns are analyzed logs; unreadable and no-log counts can overlap."""

    project_key: str
    retained_pipeline_count: int = 0
    retained_job_count: int = 0
    complete_pipeline_count: int = 0
    analyzed_pipeline_count: int = 0
    analyzed_job_count: int = 0
    unknown_pipeline_count: int = 0
    unknown_job_count: int = 0
    no_logs_pipeline_count: int = 0
    unreadable_pipeline_count: int = 0
    unreadable_job_count: int = 0
    oversized_job_count: int = 0
    empty_job_count: int = 0
    analysis_error_job_count: int = 0
    pending_pipeline_count: int = 0
    pending_job_count: int = 0
    job_enumeration_capped_pipeline_count: int = 0
    newest_pipeline_id: int | None = None
    oldest_pipeline_id: int | None = None
    rule_distribution: tuple[RuleCount, ...] = ()
    unknown_excerpts: tuple[UnknownExcerpt, ...] = ()


class ProjectProgress(_Model):
    project_key: str
    project_id: int | None = None
    requested: int
    selected: int = 0
    listing_state: _ListingState = "pending"
    skipped_metadata: int = 0


class HarvestCheckpoint(_Model):
    """Last explicit run. IDs in the store, not stale page offsets, drive resumes."""

    batch_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    state: _State
    started_at: datetime
    updated_at: datetime
    plan: HarvestPlan
    projects: tuple[ProjectProgress, ...]


class CorpusSummary(_Model):
    retained_pipeline_count: int = 0
    retained_job_count: int = 0
    collected_at: datetime | None = None
    first_collected_at: datetime | None = None
    rule_version: str = RULE_VERSION
    rule_checksums: tuple[str, ...] = ()
    projects: tuple[ProjectCorpusSummary, ...] = ()
    checkpoint: HarvestCheckpoint | None = None
    evidence_scope: Literal["trace_only"] = "trace_only"
    configuration: Literal["omitted"] = "omitted"
    source_verified: Literal[False] = False
    notice: str = _NOTICE


class HarvestReport(_Model):
    """Selected counts refer to THIS run, never inflated by historical retention."""

    state: _State
    target_met: bool
    selected_distinct_pipeline_count: int
    completed_distinct_pipeline_count: int
    over_200_distinct_failed_pipelines: bool
    plan: HarvestPlan
    projects: tuple[ProjectCorpusSummary, ...]
    progress: tuple[ProjectProgress, ...]
    summary: CorpusSummary


class ReevaluationReport(_Model):
    """Offline classification counts using the current source-code checksum."""

    reevaluated_job_count: int
    unknown_job_count: int
    analysis_error_job_count: int
    rule_version: str
    rule_checksum: str
    summary: CorpusSummary


class CorpusPipeline(_Model):
    """Allowlisted pipeline metadata, excluding refs, configs, users and raw payloads."""

    origin: str
    project_id: int = Field(gt=0, lt=2**63)
    project_key: str = Field(max_length=1024)
    pipeline_id: int = Field(gt=0, lt=2**63)
    status: Literal["failed"] = "failed"
    pipeline_timestamp: datetime | None = None
    collected_at: datetime
    last_seen_at: datetime
    batch_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    listing_state: Literal["pending", "listed", "unreadable"] = "pending"
    selected_job_ids: tuple[int, ...] = Field(default=(), max_length=2)
    jobs_enumeration_capped: bool = False
    complete: bool = False
    http_status: int | None = Field(default=None, ge=100, le=599)
    evidence_scope: Literal["trace_only"] = "trace_only"
    configuration: Literal["omitted"] = "omitted"
    source_verified: Literal[False] = False


class CorpusJob(_Model):
    """Sanitized failed-job observation. ``log`` is excluded from report metadata."""

    origin: str
    project_id: int = Field(gt=0, lt=2**63)
    pipeline_id: int = Field(gt=0, lt=2**63)
    job_id: int = Field(gt=0, lt=2**63)
    name: str = Field(max_length=256)
    status: Literal["failed"] = "failed"
    allow_failure: bool = False
    failure_reason: str | None = Field(default=None, max_length=256)
    collected_at: datetime
    state: _JobState = "pending"
    http_status: int | None = Field(default=None, ge=100, le=599)
    log: str = Field(default="", exclude=True, repr=False, max_length=MAX_TRACE_BYTES)
    log_bytes: int = Field(default=0, ge=0, le=MAX_TRACE_BYTES)
    log_truncated: bool = False
    rule_id: str = Field(default="", max_length=120)
    category: str = Field(default="unknown", max_length=120)
    excerpt: str = Field(default="", max_length=800)
    analyzed_at: datetime | None = None
    rule_version: str = RULE_VERSION
    rule_checksum: str = Field(default="", max_length=64)
    evidence_scope: Literal["trace_only"] = "trace_only"
    configuration: Literal["omitted"] = "omitted"
    source_verified: Literal[False] = False


def _now() -> datetime:
    return datetime.now(UTC)


def _analysis_settings() -> Settings:
    # No application storage, retrieval, configured credentials or model are used.
    return Settings(
        environment="local-corpus", database_url="sqlite://", redis_url="",
        max_log_bytes=MAX_TRACE_BYTES, max_context_chars=0, llm_mode="disabled",
        llm_base_url="", llm_model="", llm_api_key=None, allow_private_context=False,
    )


def rule_checksum() -> str:
    """SHA-256 of local classifier/sanitizer source, not a model or training version."""

    digest = sha256(RULE_VERSION.encode())
    try:
        for name in (
            "analysis.py", "diagnosis.py", "findings.py", "logs.py", "redaction.py",
            "inspection.py", "pipeline_corpus.py",
        ):
            digest.update(name.encode() + b"\0" + Path(__file__).with_name(name).read_bytes())
    except OSError:
        raise CorpusError("Cannot read local diagnostic source for its checksum.") from None
    return digest.hexdigest()


def _scrubber(settings: Settings) -> _Scrubber:
    try:
        origin = _origin(settings.configured_gitlab_base_url)
    except (PipelineUrlError, ValueError):
        raise CorpusError("Configure a canonical, approved HTTPS GitLab origin.") from None
    secrets = {settings.configured_gitlab_token, settings.llm_api_key} - {None, ""}
    if any(not isinstance(value, str) or len(value) > 8192 for value in secrets):
        raise CorpusError("A configured credential exceeds the supported safety limit.")
    scrub = _Scrubber(origin, settings.configured_gitlab_token or "", settings)
    variants: set[str] = set()
    for secret in secrets:
        if secret is None:
            continue
        variants.update((secret, json.dumps(secret, ensure_ascii=True)[1:-1]))
        for encoder in (base64.b64encode, base64.urlsafe_b64encode):
            encoded = encoder(secret.encode()).decode("ascii")
            variants.update((encoded, encoded.rstrip("=")))
        # Include full-percent, URL/form, double URL, and mixed percent-case forms.
        variants.add("".join(f"%{byte:02X}" for byte in secret.encode()))
        for encoder in (quote, quote_plus):
            encoded = encoder(secret, safe="")
            variants.update((encoded, encoder(encoded, safe="")))
    patterns = []
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            pieces = re.split(r"(%[0-9A-Fa-f]{2})", variant)
            patterns.append("".join(
                f"(?i:{re.escape(piece)})" if re.fullmatch(r"%[0-9A-Fa-f]{2}", piece)
                else re.escape(piece) for piece in pieces
            ))
    scrub.exact = re.compile("|".join(patterns))
    if scrub.text(origin) != origin:
        raise CorpusError("The configured origin contains sensitive content.")
    return scrub


def _bounded(value: str, limit: int, *, log: bool = False) -> tuple[str, bool]:
    """Bound ALREADY sanitized UTF-8, accounting for the omission marker itself."""

    encoded = value.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return value, False
    marker = _TRUNCATED if log else " [truncated]"
    budget = limit - len(marker.encode())
    if log:
        head = budget // 5
        value = (encoded[:head].decode("utf-8", errors="ignore") + marker
                 + encoded[-(budget - head):].decode("utf-8", errors="ignore"))
    else:
        value = encoded[:budget].decode("utf-8", errors="ignore") + marker
    return value, True


def _text(scrub: _Scrubber, value: object, limit: int) -> str:
    return _bounded(scrub.text(value), limit)[0] if isinstance(value, str) else ""


def _identifier(value: object, scrub: _Scrubber | None = None) -> int:
    if type(value) not in {str, int}:
        raise CorpusError("GitLab returned invalid numeric metadata.")
    text = str(value)
    if (not _ID.fullmatch(text) or int(text) >= 2**63
            or (scrub is not None and scrub.text(text) != text)):
        raise CorpusError("GitLab returned invalid numeric metadata.")
    return int(text)


def _project(value: str, origin: str, scrub: _Scrubber) -> str:
    if not isinstance(value, str) or len(value) > 1024 or scrub.text(value) != value:
        raise CorpusError("A project identifier is invalid or contains sensitive content.")
    try:
        reference = parse_gitlab_url(
            value if "://" in value else f"{origin}/{value}", expected_base_url=origin,
        )
        if reference.kind != "repository":
            raise PipelineUrlError("Not a project path.")
    except (PipelineUrlError, ValueError):
        raise CorpusError("Use project paths on the configured GitLab host only.") from None
    if len(f"{origin}/{reference.project_path}") > 1024:
        raise CorpusError("The canonical project key exceeds the supported size.")
    return reference.project_path.lower()


def preview_harvest(
    settings: Settings, projects: Sequence[str], *, per_project: int = 75, concurrency: int = 2,
) -> HarvestPlan:
    """Validate the local plan only. No API calls, token validation request or writes."""

    scrub = _scrubber(settings)
    if type(per_project) is not int or not 1 <= per_project <= 500:
        raise CorpusError("per_project must be between 1 and 500.")
    if concurrency not in (2, 3):
        raise CorpusError("Pipeline concurrency must be 2 or 3.")
    if not 1 <= len(projects) <= MAX_PROJECTS:
        raise CorpusError("Supply between 1 and 20 project paths.")
    paths = tuple(dict.fromkeys(_project(path, scrub.origin, scrub) for path in projects))
    if len(paths) * per_project > MAX_PIPELINES:
        raise CorpusLimitError("The requested distinct pipeline count exceeds corpus capacity.")
    return HarvestPlan(
        origin=scrub.origin, projects=paths, per_project=per_project, concurrency=concurrency,
        target_distinct_pipelines=len(paths) * per_project,
        token_configured=bool(settings.configured_gitlab_token),
    )


class CorpusGitLabProvider(GitLabProvider):
    """Harvest-only GET adapter: same origin, inherited semaphore(4), no retries.

    Uses the existing project/job parsers and ``list_pipeline_jobs`` pagination.
    Only project metadata, pipeline listings, job listings and traces are allowed.
    It never follows redirects or environment proxies. An oversized trace is wholly
    discarded before sanitization/storage; this avoids retaining cutoff secrets.
    """

    def __init__(self, base_url: str, transport: httpx.AsyncBaseTransport | None = None) -> None:
        super().__init__(base_url, transport)
        self.rate_limited = False

    async def _request(
        self, token: str, method: str, path: str, *, params: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response:
        decoded = unquote(path)
        if (
            method != "GET" or urlsplit(path).netloc or urlsplit(path).query
            or urlsplit(path).fragment or "\\" in decoded
            or any(part in {".", ".."} for part in decoded.split("/"))
            or not re.fullmatch(
                r"/projects/[^/?#]+(?:/pipelines(?:/[1-9][0-9]*/jobs)?"
                r"|/jobs/[1-9][0-9]*/trace)?", path,
            )
        ):
            raise ProviderError("GitLab", 400, "Only approved harvest GET paths are allowed.")
        is_trace = path.endswith("/trace")
        limit = MAX_TRACE_BYTES if is_trace else _MAX_METADATA_BYTES
        request_headers = {**self._headers(token), **(headers or {}), "Accept-Encoding": "identity"}
        async with self._request_semaphore:
            if self.rate_limited:
                raise ProviderError("GitLab", 429, "Harvest stopped at the rate limit.")
            client = self._shared_client or self._new_client()
            try:
                async with client.stream(
                    "GET", path, params=params, headers=request_headers,
                ) as response:
                    if response.status_code == 429:
                        self.rate_limited = True
                    if response.is_error or response.is_redirect:
                        raise ProviderError(
                            "GitLab", response.status_code, "GitLab rejected a harvest read.",
                        )
                    if response.headers.get("content-encoding", "identity").lower() != "identity":
                        raise ProviderError("GitLab", 502, "Unexpected encoded response omitted.")
                    length = response.headers.get("content-length", "")
                    if length.isdecimal() and int(length) > limit:
                        if is_trace:
                            raise _TraceTooLarge()
                        raise ProviderError("GitLab", 502, "Metadata exceeds the download limit.")
                    content = bytearray()
                    async for chunk in response.aiter_bytes(chunk_size=65536):
                        if len(content) + len(chunk) > limit:
                            if is_trace:
                                raise _TraceTooLarge()
                            raise ProviderError("GitLab", 502, "Metadata exceeds download limit.")
                        content.extend(chunk)
                    return httpx.Response(
                        response.status_code, content=bytes(content), request=response.request,
                        headers={name: response.headers[name] for name in
                                 ("x-next-page", "content-type") if name in response.headers},
                    )
            except httpx.HTTPError:
                raise ProviderError(
                    "GitLab", 502, "Harvest read failed; no retry attempted.",
                ) from None
            finally:
                if self._shared_client is None:
                    await client.aclose()


_SCHEMA = f"""
BEGIN IMMEDIATE;
CREATE TABLE pipelines (
    origin TEXT NOT NULL, project_id INTEGER NOT NULL, pipeline_id INTEGER NOT NULL,
    project_key TEXT NOT NULL, batch_id TEXT NOT NULL,
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) <= {_MAX_RECORD_BYTES}),
    PRIMARY KEY (origin, project_id, pipeline_id)
);
CREATE TABLE jobs (
    origin TEXT NOT NULL, project_id INTEGER NOT NULL, pipeline_id INTEGER NOT NULL,
    job_id INTEGER NOT NULL, rule_id TEXT NOT NULL,
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) <= {_MAX_RECORD_BYTES}),
    log TEXT NOT NULL CHECK(length(CAST(log AS BLOB)) <= {MAX_TRACE_BYTES}),
    PRIMARY KEY (origin, project_id, pipeline_id, job_id),
    FOREIGN KEY (origin, project_id, pipeline_id)
        REFERENCES pipelines (origin, project_id, pipeline_id)
);
CREATE TABLE checkpoint (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    record TEXT NOT NULL CHECK(length(CAST(record AS BLOB)) <= {_MAX_CHECKPOINT_BYTES})
);
CREATE INDEX jobs_rule ON jobs (origin, project_id, rule_id);
PRAGMA application_id = {_APPLICATION_ID};
PRAGMA user_version = {_SCHEMA_VERSION};
COMMIT;
"""
_Record = TypeVar("_Record", CorpusPipeline, CorpusJob)


def _lock_writer(handle: IO[bytes], *, release: bool = False) -> None:
    """OS locks are released on crash; acquisition is non-blocking, never a retry."""

    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK if release else msvcrt.LK_NBLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN if release else fcntl.LOCK_EX | fcntl.LOCK_NB)


class PipelineCorpus:
    """Lazy SQLite store. Readers create nothing; all returned text is re-sanitized.

    Pass explicit ``settings`` to share configured-key redaction with the API.
    ``iter_jobs`` exposes only sanitized retained traces for local reevaluation.
    Every writer uses a transaction and immediate lock failure (no busy retries).
    Harvest/reevaluation additionally hold a crash-released OS writer lease so two
    runs cannot overwrite each other's job samples or checkpoints. Readers do not
    create the lock file, and no manual stale-lock deletion is needed after a crash.
    This cache never stores credentials, raw metadata or a human-confirmed fix.
    """

    def __init__(
        self, directory: Path | None = None, *, settings: Settings | None = None,
        max_pipelines: int = MAX_PIPELINES, max_store_bytes: int = MAX_STORE_BYTES,
    ) -> None:
        if not 1 <= max_pipelines <= MAX_PIPELINES:
            raise CorpusError("Invalid corpus pipeline capacity.")
        if not 65536 <= max_store_bytes <= MAX_STORE_BYTES:
            raise CorpusError("Invalid corpus byte capacity.")
        self.directory = Path(directory) if directory is not None else DEFAULT_CORPUS_DIRECTORY
        self.path = self.directory / "pipelines.sqlite3"
        self.settings = settings if settings is not None else get_settings()
        self.scrub = _scrubber(self.settings)
        self.max_pipelines = max_pipelines
        self.max_store_bytes = max_store_bytes
        self._validated_signature: tuple[int, int, int] | None = None

    def _signature(self) -> tuple[int, int, int]:
        stat = self.path.stat()
        return stat.st_ino, stat.st_size, stat.st_mtime_ns

    @contextmanager
    def _writer(self) -> Generator[None]:
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
            path = self.directory / ".writer.lock"
            if path.is_symlink():
                raise CorpusError("Corpus writer lock must be a regular local file.")
            handle = path.open("a+b")
            if path.stat().st_size == 0:
                handle.write(b"\0")
                handle.flush()
        except OSError:
            raise CorpusError("Corpus writer lock is inaccessible.") from None
        try:
            try:
                _lock_writer(handle)
            except OSError:
                raise CorpusError("Another corpus writer is active; no retry attempted.") from None
            try:
                yield
            finally:
                _lock_writer(handle, release=True)
        finally:
            handle.close()

    @contextmanager
    def _connection(self, *, write: bool = False) -> Generator[sqlite3.Connection | None]:
        connection = None
        committed = False
        try:
            exists = self.path.exists()
            if not exists and not write:
                yield None
                return
            if self.path.is_symlink() or (exists and not self.path.is_file()):
                raise CorpusError("Corpus path must be a regular local database file.")
            if exists and (self.path.stat().st_size == 0
                           or self.path.stat().st_size > self.max_store_bytes):
                raise CorpusError("Corpus size is invalid; existing data was preserved.")
            if write:
                self.directory.mkdir(parents=True, exist_ok=True)
            mode = "rwc" if write and not exists else "rw" if write else "ro"
            connection = sqlite3.connect(
                self.path.absolute().as_uri() + f"?mode={mode}", uri=True, timeout=0,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            if write:
                connection.execute("PRAGMA secure_delete = ON")
                page_size = connection.execute("PRAGMA page_size").fetchone()[0]
                connection.execute(f"PRAGMA max_page_count = {self.max_store_bytes // page_size}")
                if not exists:
                    # A racing creator must never have its schema/data replaced.
                    if not connection.execute("SELECT name FROM sqlite_master").fetchone():
                        connection.executescript(_SCHEMA)
            else:
                connection.execute("PRAGMA query_only = ON")
            signature = self._signature()
            if signature != self._validated_signature:
                self._validate(connection)
                self._validated_signature = signature
            if write:
                connection.execute("BEGIN IMMEDIATE")
            yield connection
            if write:
                connection.commit()
                committed = True
        except sqlite3.Error as error:
            if getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_FULL:
                raise CorpusLimitError(
                    "Corpus byte capacity reached; previous commits kept.",
                ) from None
            raise CorpusError(
                "Corpus is corrupt, incompatible, locked or unreadable; data was not replaced."
            ) from None
        except (OSError, ValueError, TypeError, RecursionError):
            raise CorpusError("Corpus is invalid or inaccessible; data was not replaced.") from None
        finally:
            if connection is not None:
                connection.close()  # Rolls back an unfinished write transaction.
            if committed:
                # Revalidate external edits/replacements, without rescanning every
                # trace after this object's own validated transactional writes.
                try:
                    self._validated_signature = self._signature()
                except OSError:
                    self._validated_signature = None

    def _validate(self, connection: sqlite3.Connection) -> None:
        if (
            connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID
            or connection.execute("PRAGMA user_version").fetchone()[0] != _SCHEMA_VERSION
            or connection.execute("PRAGMA quick_check(1)").fetchone()[0] != "ok"
            or connection.execute("PRAGMA foreign_key_check").fetchone() is not None
        ):
            raise CorpusError("Corpus is corrupt or incompatible; data was not replaced.")
        tables = {row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'",
        )}
        if tables != {"pipelines", "jobs", "checkpoint"} or connection.execute(
            "SELECT name FROM sqlite_master WHERE type IN ('trigger', 'view')",
        ).fetchone():
            raise CorpusError("Unexpected corpus schema; data was not replaced.")
        for table, limit in (("pipelines", _MAX_RECORD_BYTES), ("jobs", _MAX_RECORD_BYTES),
                             ("checkpoint", _MAX_CHECKPOINT_BYTES)):
            if connection.execute(
                f"SELECT 1 FROM {table} WHERE length(CAST(record AS BLOB)) > ? LIMIT 1", (limit,),
            ).fetchone():
                raise CorpusError("Corpus metadata exceeds the supported bounds.")
        if connection.execute("SELECT COUNT(*) FROM pipelines").fetchone()[0] > self.max_pipelines:
            raise CorpusLimitError("Existing corpus exceeds the selected pipeline capacity.")
        if connection.execute(
            "SELECT COUNT(*) FROM (SELECT DISTINCT origin, project_id FROM pipelines)",
        ).fetchone()[0] > MAX_PROJECTS:
            raise CorpusLimitError("Existing corpus exceeds the project capacity.")
        if connection.execute(
            "SELECT 1 FROM jobs GROUP BY origin, project_id, pipeline_id HAVING COUNT(*) > 2",
        ).fetchone():
            raise CorpusError("Corpus contains too many sampled jobs for a pipeline.")
        pipelines = [self._decode(row, CorpusPipeline) for row in
                     connection.execute("SELECT * FROM pipelines")]
        jobs: dict[tuple[str, int, int], list[CorpusJob]] = defaultdict(list)
        for row in connection.execute(
            "SELECT origin, project_id, pipeline_id, job_id, rule_id, record, "
            "length(CAST(log AS BLOB)) AS actual_log_bytes FROM jobs",
        ):
            job = self._decode(row, CorpusJob)
            if job.log_bytes != row["actual_log_bytes"] or (
                job.log_bytes and job.state in {"pending", "unreadable", "empty", "oversized"}
            ):
                raise CorpusError("Corpus log length/state mismatch; data was not replaced.")
            jobs[self._key(job)].append(job)
        for pipeline in pipelines:
            sampled = jobs[self._key(pipeline)]
            if (len(set(pipeline.selected_job_ids)) != len(pipeline.selected_job_ids)
                    or set(pipeline.selected_job_ids) != {job.job_id for job in sampled}
                    or (pipeline.complete and any(job.state == "pending" for job in sampled))
                    or (pipeline.listing_state != "listed" and sampled)
                    or (pipeline.listing_state == "pending" and pipeline.complete)):
                raise CorpusError("Corpus checkpoint/sample mismatch; data was not replaced.")
        row = connection.execute("SELECT record FROM checkpoint WHERE id=1").fetchone()
        if row:
            HarvestCheckpoint.model_validate_json(row[0])

    def _decode(self, row: sqlite3.Row, model: type[_Record], *, with_log: bool = False) -> _Record:
        data = json.loads(row["record"])
        if not isinstance(data, dict) or "log" in data:
            raise CorpusError("Unexpected corpus record shape; data was not replaced.")
        if model is CorpusJob and with_log:
            data["log"] = row["log"]
        record = model.model_validate(data)
        keys = ("origin", "project_id", "pipeline_id")
        if isinstance(record, CorpusJob):
            keys += ("job_id", "rule_id")
        else:
            keys += ("project_key", "batch_id")
        if any(getattr(record, key) != row[key] for key in keys):
            raise CorpusError("Corpus metadata/key mismatch; data was not replaced.")
        for key in keys:
            if self.scrub.text(str(getattr(record, key))) != str(getattr(record, key)):
                raise CorpusError("Sensitive corpus identifiers require manual local review.")
        return record

    def _safe_job(self, job: CorpusJob, *, with_log: bool = True) -> CorpusJob:
        log, truncated = _bounded(self.scrub.text(job.log), MAX_TRACE_BYTES, log=True)
        rule = _text(self.scrub, job.rule_id, 120)
        return job.model_copy(update={
            "name": _text(self.scrub, job.name, 256),
            "failure_reason": _text(self.scrub, job.failure_reason, 256) or None,
            "log": log, "log_bytes": len(log.encode()) if with_log else job.log_bytes,
            "log_truncated": job.log_truncated or truncated,
            "rule_id": rule if not rule or _RULE.fullmatch(rule) else "unknown",
            "category": _text(self.scrub, job.category, 120),
            "excerpt": _text(self.scrub, job.excerpt, 800),
        })

    def initialize(self) -> None:
        """Explicit write boundary; re-scrub older observations with current known keys."""

        with self._connection(write=True) as connection:
            assert connection is not None
            cursor = connection.execute("SELECT * FROM jobs")
            for row in cursor:
                previous = self._decode(row, CorpusJob, with_log=True)
                sanitized = self._safe_job(previous)
                if sanitized != previous:
                    self._save_job(connection, sanitized)

    @staticmethod
    def _key(record: CorpusPipeline | CorpusJob) -> tuple[str, int, int]:
        return record.origin, record.project_id, record.pipeline_id

    def _save_pipeline(self, connection: sqlite3.Connection, pipeline: CorpusPipeline) -> None:
        if not connection.execute(
            "SELECT 1 FROM pipelines WHERE origin=? AND project_id=? AND pipeline_id=?",
            self._key(pipeline),
        ).fetchone():
            count = connection.execute("SELECT COUNT(*) FROM pipelines").fetchone()[0]
            if count >= self.max_pipelines:
                raise CorpusLimitError("Corpus pipeline capacity reached; no records were evicted.")
            projects = {row[0] for row in connection.execute(
                "SELECT DISTINCT project_key FROM pipelines",
            )}
            if pipeline.project_key not in projects and len(projects) >= MAX_PROJECTS:
                raise CorpusLimitError("Corpus project capacity reached; no records were evicted.")
        connection.execute(
            "INSERT INTO pipelines VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(origin, project_id, pipeline_id) DO UPDATE SET "
            "project_key=excluded.project_key, batch_id=excluded.batch_id, record=excluded.record",
            (*self._key(pipeline), pipeline.project_key, pipeline.batch_id,
             pipeline.model_dump_json()),
        )

    def _save_job(self, connection: sqlite3.Connection, job: CorpusJob) -> None:
        job = self._safe_job(job)
        connection.execute(
            "INSERT INTO jobs VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(origin, project_id, pipeline_id, job_id) DO UPDATE SET "
            "rule_id=excluded.rule_id, record=excluded.record, log=excluded.log",
            (*self._key(job), job.job_id, job.rule_id, job.model_dump_json(), job.log),
        )

    def _put_pipeline(self, pipeline: CorpusPipeline, jobs: Sequence[CorpusJob] = ()) -> None:
        if len(jobs) > 2 or len({job.job_id for job in jobs}) != len(jobs):
            raise CorpusError("Invalid failed-job sample.")
        with self._connection(write=True) as connection:
            assert connection is not None
            self._save_pipeline(connection, pipeline)
            for job in jobs:
                self._save_job(connection, job)

    def _put_job(self, job: CorpusJob) -> None:
        with self._connection(write=True) as connection:
            assert connection is not None
            self._save_job(connection, job)

    def _pipeline(self, origin: str, project_id: int, pipeline_id: int) -> CorpusPipeline | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM pipelines WHERE origin=? AND project_id=? AND pipeline_id=?",
                (origin, project_id, pipeline_id),
            ).fetchone() if connection is not None else None
            return self._decode(row, CorpusPipeline) if row else None

    def _jobs(self, pipeline: CorpusPipeline, *, with_log: bool = True) -> list[CorpusJob]:
        with self._connection() as connection:
            if connection is None:
                return []
            columns = (
                "*" if with_log else "origin, project_id, pipeline_id, job_id, rule_id, record"
            )
            rows = connection.execute(
                f"SELECT {columns} FROM jobs WHERE origin=? AND project_id=? AND pipeline_id=? "
                "ORDER BY job_id DESC", self._key(pipeline),
            )
            return [self._safe_job(
                self._decode(row, CorpusJob, with_log=with_log), with_log=with_log,
            ) for row in rows]

    def _pipelines(self, batch_id: str | None = None) -> list[CorpusPipeline]:
        with self._connection() as connection:
            if connection is None:
                return []
            rows = connection.execute(
                "SELECT * FROM pipelines" + (" WHERE batch_id=?" if batch_id else "")
                + " ORDER BY pipeline_id DESC", (batch_id,) if batch_id else (),
            )
            return [self._decode(row, CorpusPipeline) for row in rows]

    def iter_jobs(self, project_key: str | None = None) -> Iterator[CorpusJob]:
        """Read sanitized, bounded logs one pipeline (up to two jobs) at a time."""

        for pipeline in self._pipelines():
            if project_key is None or pipeline.project_key == project_key:
                yield from self._jobs(pipeline)

    def _put_checkpoint(self, checkpoint: HarvestCheckpoint) -> None:
        with self._connection(write=True) as connection:
            assert connection is not None
            connection.execute(
                "INSERT INTO checkpoint VALUES (1, ?) ON CONFLICT(id) DO UPDATE "
                "SET record=excluded.record", (checkpoint.model_dump_json(),),
            )

    def checkpoint(self) -> HarvestCheckpoint | None:
        with self._connection() as connection:
            row = connection.execute("SELECT record FROM checkpoint WHERE id=1").fetchone() \
                if connection is not None else None
            if row is None:
                return None
            # Re-sanitize returned text without writing during a read/preview.
            return HarvestCheckpoint.model_validate(self.scrub.data(json.loads(row[0])))

    def _project_summaries(self, batch_id: str | None = None) -> tuple[ProjectCorpusSummary, ...]:
        grouped: dict[str, list[CorpusPipeline]] = defaultdict(list)
        for pipeline in self._pipelines(batch_id):
            grouped[pipeline.project_key].append(pipeline)
        output = []
        for project_key, pipelines in sorted(grouped.items()):
            totals: Counter[str] = Counter()
            rules: Counter[str] = Counter()
            rule_pipelines: dict[str, set[tuple[str, int, int]]] = defaultdict(set)
            unknown: list[UnknownExcerpt] = []
            for pipeline in pipelines:
                jobs = self._jobs(pipeline, with_log=False)
                # Read metadata byte counts, not full traces, for report coverage.
                states = {job.state for job in jobs}
                totals["retained_job_count"] += len(jobs)
                totals["complete_pipeline_count"] += pipeline.complete
                totals["pending_pipeline_count"] += not pipeline.complete
                totals["analyzed_pipeline_count"] += bool(states & {"analyzed", "unknown"})
                totals["unknown_pipeline_count"] += "unknown" in states
                totals["no_logs_pipeline_count"] += pipeline.complete and not any(
                    job.state in {"analyzed", "unknown", "analysis_error"} for job in jobs
                )
                totals["unreadable_pipeline_count"] += (
                    pipeline.listing_state == "unreadable"
                    or bool(states & {"unreadable", "oversized"})
                )
                totals["job_enumeration_capped_pipeline_count"] += pipeline.jobs_enumeration_capped
                for job in jobs:
                    totals["analyzed_job_count"] += job.state in {"analyzed", "unknown"}
                    totals["unreadable_job_count"] += job.state in {"unreadable", "oversized"}
                    for state in ("unknown", "oversized", "empty", "analysis_error", "pending"):
                        totals[f"{state}_job_count"] += job.state == state
                    if job.state in {"analyzed", "unknown"}:
                        rules[job.rule_id] += 1
                        rule_pipelines[job.rule_id].add(self._key(job))
                    if job.state == "unknown" and len(unknown) < 5:
                        unknown.append(UnknownExcerpt(
                            pipeline_id=job.pipeline_id, job_id=job.job_id,
                            rule_id=job.rule_id, text=job.excerpt,
                        ))
            output.append(ProjectCorpusSummary(
                project_key=_text(self.scrub, project_key, 1024),
                retained_pipeline_count=len(pipelines), **totals,
                newest_pipeline_id=max(p.pipeline_id for p in pipelines),
                oldest_pipeline_id=min(p.pipeline_id for p in pipelines),
                rule_distribution=tuple(RuleCount(
                    rule_id=rule, failed_jobs=count,
                    seen_failed_pipelines=len(rule_pipelines[rule]),
                ) for rule, count in sorted(rules.items(), key=lambda item: (-item[1], item[0]))),
                unknown_excerpts=tuple(unknown),
            ))
        return tuple(output)

    def summary(self) -> CorpusSummary:
        """Coverage/unknown summary, bounded excerpts and last checkpoint; no writes."""

        pipelines = self._pipelines()
        projects = self._project_summaries()
        checksums: set[str] = set()
        for pipeline in pipelines:
            checksums.update(job.rule_checksum for job in self._jobs(pipeline, with_log=False)
                             if job.rule_checksum)
        return CorpusSummary(
            retained_pipeline_count=len(pipelines),
            retained_job_count=sum(project.retained_job_count for project in projects),
            collected_at=max((p.last_seen_at for p in pipelines), default=None),
            first_collected_at=min((p.collected_at for p in pipelines), default=None),
            rule_checksums=tuple(sorted(checksums)), projects=projects,
            checkpoint=self.checkpoint(),
        )

    def match(self, project_key: str, rule_id: str) -> CorpusMatch:
        """Exact canonical host/path + rule match; only seen pipeline/job counts."""

        try:
            reference = parse_gitlab_url(project_key)
        except PipelineUrlError:
            return CorpusMatch()
        if reference.kind != "repository" or not _RULE.fullmatch(rule_id):
            return CorpusMatch()
        key = f"{reference.base_url}/{reference.project_path.lower()}"
        pipelines: set[tuple[str, int, int]] = set()
        jobs = 0
        for pipeline in self._pipelines():
            if pipeline.project_key != key:
                continue
            for job in self._jobs(pipeline, with_log=False):
                if job.state in {"analyzed", "unknown"} and job.rule_id == rule_id:
                    pipelines.add(self._key(job))
                    jobs += 1
        return CorpusMatch(seen_failed_pipelines=len(pipelines), failed_jobs=jobs)


def _timestamp(value: object, scrub: _Scrubber) -> datetime | None:
    if not isinstance(value, str) or scrub.text(value) != value or len(value) > 64:
        return None
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return result.replace(tzinfo=UTC) if result.tzinfo is None else result.astimezone(UTC)
    except ValueError:
        return None


def _excerpt(log: str, scrub: _Scrubber) -> str:
    # Scrub complete text before selecting lines or cutting diagnostic excerpts.
    lines = [line.strip() for line in scrub.text(log).splitlines() if line.strip()]
    diagnostic = [line for line in lines if re.search(
        r"error|exception|fail|fatal|denied|timed?\s*out|invalid|unable", line, re.I,
    )]
    return _bounded("\n".join((diagnostic or lines)[-6:]), 800)[0]


def _classify(
    corpus: PipelineCorpus, pipeline: CorpusPipeline, job: CorpusJob, checksum: str,
) -> CorpusJob:
    job = corpus._safe_job(job)
    owner, _, name = pipeline.project_key.removeprefix(pipeline.origin + "/").rpartition("/")
    repository = RepositoryRef(
        provider=ProviderName.GITLAB, external_id=str(pipeline.project_id),
        owner=owner, name=name, web_url=pipeline.project_key,
    )
    updates: dict[str, Any] = {
        "analyzed_at": _now(), "rule_checksum": checksum, "rule_version": RULE_VERSION,
        "excerpt": _excerpt(job.log, corpus.scrub),
    }
    try:
        snapshot = PipelineAnalyzer(_analysis_settings()).analyze_input(AnalysisInput(
            repository=repository,
            run=PipelineRun(
                external_id=str(pipeline.pipeline_id), name=f"Pipeline #{pipeline.pipeline_id}",
                status="failed", started_at=pipeline.pipeline_timestamp,
            ),
            job=PipelineJob(
                external_id=str(job.job_id), name=job.name, key=job.name, status="failed",
                allow_failure=job.allow_failure, failure_reason=job.failure_reason,
            ),
            configs=[], raw_log=job.log,
        ))
        finding = diagnose_job(snapshot)
        rule = _text(corpus.scrub, finding.rule_id, 120)
        updates.update(
            state="unknown" if finding.confidence == "unknown" or finding.category == "unknown"
            else "analyzed",
            rule_id=rule if _RULE.fullmatch(rule) else "unknown",
            category=_text(corpus.scrub, finding.category, 120),
        )
    except Exception:
        # Do not persist exception text: classifier exceptions may contain a trace.
        updates.update(state="analysis_error", rule_id="corpus.analysis_error", category="unknown")
    return corpus._safe_job(job.model_copy(update=updates))


class _Harvest:
    def __init__(
        self, settings: Settings, plan: HarvestPlan, corpus: PipelineCorpus,
        provider: GitLabProvider,
    ) -> None:
        self.plan, self.corpus, self.provider = plan, corpus, provider
        self.token = settings.configured_gitlab_token or ""
        self.scrub = corpus.scrub
        self.checksum = rule_checksum()
        self.state: _State = "collecting"
        now = _now()
        self.checkpoint = HarvestCheckpoint(
            batch_id=uuid4().hex, state=self.state, started_at=now, updated_at=now, plan=plan,
            projects=tuple(ProjectProgress(
                project_key=f"{plan.origin}/{path}", requested=plan.per_project,
            ) for path in plan.projects),
        )

    def save(self, index: int | None = None, **updates: Any) -> None:
        projects = list(self.checkpoint.projects)
        if index is not None:
            projects[index] = projects[index].model_copy(update=updates)
        self.checkpoint = self.checkpoint.model_copy(update={
            "projects": tuple(projects), "updated_at": _now(), "state": self.state,
        })
        self.corpus._put_checkpoint(self.checkpoint)

    def _stop_for(self, error: ProviderError) -> bool:
        if error.status_code == 429:
            self.state = "rate_limited"
        elif error.status_code == 401:
            self.state = "access_denied"
        return self.state != "collecting"

    async def discover(self, index: int, repository: RepositoryRef) -> None:
        selected: set[int] = set()
        skipped = 0
        project_id = _identifier(repository.external_id, self.scrub)
        per_page = min(100, self.plan.per_project)
        previous_floor: int | None = None
        for page in range(1, MAX_LIST_PAGES + 1):
            if self.state != "collecting":
                return
            response = await self.provider._request(
                self.token, "GET", f"/projects/{project_id}/pipelines",
                params={"status": "failed", "order_by": "id", "sort": "desc",
                        "per_page": per_page, "page": page},
            )
            try:
                payload = response.json()
                if not isinstance(payload, list) or len(payload) > per_page:
                    raise ValueError
                candidates = []
                for item in payload:
                    if not isinstance(item, dict) or item.get("status") != "failed":
                        skipped += 1
                        continue
                    candidates.append((_identifier(item.get("id"), self.scrub), item))
            except (ValueError, CorpusError):
                self.save(index, listing_state="invalid", skipped_metadata=skipped)
                return
            new = sorted({identifier: item for identifier, item in candidates
                          if identifier not in selected}.items(), reverse=True)
            if previous_floor is not None and any(
                identifier > previous_floor for identifier, _ in new
            ):
                self.save(index, listing_state="invalid", skipped_metadata=skipped)
                return
            for pipeline_id, item in new:
                previous = self.corpus._pipeline(self.plan.origin, project_id, pipeline_id)
                now = _now()
                pipeline = previous.model_copy(update={
                    "batch_id": self.checkpoint.batch_id, "last_seen_at": now,
                }) if previous else CorpusPipeline(
                    origin=self.plan.origin, project_id=project_id,
                    project_key=f"{self.plan.origin}/{self.plan.projects[index]}",
                    pipeline_id=pipeline_id,
                    pipeline_timestamp=_timestamp(item.get("created_at"), self.scrub),
                    collected_at=now, last_seen_at=now, batch_id=self.checkpoint.batch_id,
                )
                self.corpus._put_pipeline(pipeline)
                selected.add(pipeline_id)
                if len(selected) == self.plan.per_project:
                    break
            self.save(index, selected=len(selected), skipped_metadata=skipped)
            if len(selected) == self.plan.per_project:
                self.save(index, listing_state="listed")
                return
            next_page = response.headers.get("x-next-page")
            if not payload or next_page == "" or (next_page is None and len(payload) < per_page):
                self.save(index, listing_state="exhausted")
                return
            if (not new or (next_page is not None and next_page != str(page + 1))):
                self.save(index, listing_state="invalid")
                return
            if selected:
                previous_floor = min(selected)
        self.save(index, listing_state="page_limit")

    async def collect(self, pipeline: CorpusPipeline) -> None:
        if pipeline.complete or self.state != "collecting":
            return
        owner, _, name = pipeline.project_key.removeprefix(pipeline.origin + "/").rpartition("/")
        repository = RepositoryRef(
            provider=ProviderName.GITLAB, external_id=str(pipeline.project_id), owner=owner,
            name=name, web_url=pipeline.project_key,
        )
        if pipeline.listing_state == "pending":
            try:
                jobs = await self.provider.list_pipeline_jobs(
                    self.token, repository, str(pipeline.pipeline_id), max_jobs=300,
                )
                failed = {}
                for job in jobs[:300]:
                    if job.status == "failed":
                        failed[_identifier(job.external_id, self.scrub)] = job
                selected = sorted(
                    failed.items(), key=lambda item: (item[1].allow_failure, -item[0]),
                )[:2]
                sampled = [CorpusJob(
                    origin=pipeline.origin, project_id=pipeline.project_id,
                    pipeline_id=pipeline.pipeline_id, job_id=job_id,
                    name=_text(self.scrub, job.name, 256), allow_failure=job.allow_failure,
                    failure_reason=_text(self.scrub, job.failure_reason, 256) or None,
                    collected_at=_now(),
                ) for job_id, job in selected]
            except ProviderError as error:
                if self._stop_for(error):
                    return
                self.corpus._put_pipeline(pipeline.model_copy(update={
                    "listing_state": "unreadable", "http_status": error.status_code,
                    "complete": True,
                }))
                return
            except (CorpusError, ValueError, TypeError, KeyError):
                # Only provider parsing/metadata selection is inside this try.
                # DB writes happen outside it so corruption/capacity never looks
                # like an unreadable remote job list.
                self.corpus._put_pipeline(pipeline.model_copy(update={
                    "listing_state": "unreadable", "http_status": 502, "complete": True,
                }))
                return
            pipeline = pipeline.model_copy(update={
                "listing_state": "listed",
                "selected_job_ids": tuple(job.job_id for job in sampled),
                "jobs_enumeration_capped": len(jobs) >= 300, "complete": not sampled,
            })
            self.corpus._put_pipeline(pipeline, sampled)
        sampled_by_id = {job.job_id: job for job in self.corpus._jobs(pipeline)}
        for job_id in pipeline.selected_job_ids:
            if self.state != "collecting":
                return
            job = sampled_by_id[job_id]
            if job.state != "pending":
                continue
            try:
                raw = await self.provider.fetch_job_log(
                    self.token, repository, str(pipeline.pipeline_id), str(job.job_id),
                )
                # Injected/mock adapters get the same fail-closed retention boundary.
                if not isinstance(raw, str):
                    raise ProviderError("GitLab", 502, "Invalid trace response.")
                if len(raw.encode("utf-8", errors="replace")) > MAX_TRACE_BYTES:
                    raise _TraceTooLarge()
                log, truncated = _bounded(self.scrub.text(raw), MAX_TRACE_BYTES, log=True)
                job = job.model_copy(update={
                    "log": log, "log_truncated": truncated, "collected_at": _now(),
                })
                job = _classify(self.corpus, pipeline, job, self.checksum) if log.strip() else (
                    job.model_copy(update={"state": "empty", "log": ""})
                )
            except ProviderError as error:
                if self._stop_for(error):
                    return
                job = job.model_copy(update={
                    "state": "oversized" if isinstance(error, _TraceTooLarge) else "unreadable",
                    "http_status": error.status_code, "collected_at": _now(),
                })
            self.corpus._put_job(job)
        self.corpus._put_pipeline(pipeline.model_copy(update={
            "complete": True, "last_seen_at": _now(),
        }))

    async def run(self) -> HarvestReport:
        self.save()
        resolved: set[int] = set()
        try:
            for index, path in enumerate(self.plan.projects):
                if self.state != "collecting":
                    break
                try:
                    repository = await self.provider.get_repository_by_path(self.token, path)
                    project_id = _identifier(repository.external_id, self.scrub)
                    # Never trust a provider-returned URL as a new request destination.
                    if (repository.provider != ProviderName.GITLAB
                            or _project(repository.web_url, self.plan.origin, self.scrub) != path
                            or project_id in resolved):
                        raise CorpusError("Project resolution is inconsistent or duplicated.")
                    resolved.add(project_id)
                    self.save(index, project_id=project_id)
                    await self.discover(index, repository)
                except ProviderError as error:
                    self._stop_for(error)
                    self.save(index, listing_state="unreadable")
            pipelines = self.corpus._pipelines(self.checkpoint.batch_id)
            for offset in range(0, len(pipelines), self.plan.concurrency):
                if self.state != "collecting":
                    break
                # Small batches avoid hundreds of queued tasks after a 429.
                tasks = [asyncio.create_task(self.collect(pipeline)) for pipeline in
                         pipelines[offset:offset + self.plan.concurrency]]
                try:
                    await asyncio.gather(*tasks)
                finally:
                    for task in tasks:
                        if not task.done():
                            task.cancel()
                    await asyncio.gather(*tasks, return_exceptions=True)
                self.save()
        except CorpusLimitError:
            self.state = "capacity"
        except (CorpusError, ValueError, TypeError, KeyError):
            self.state = "provider_error"
        except asyncio.CancelledError:
            self.state = "interrupted"
            self.save()
            raise
        selected_by_key = {project.project_key: project for project in
                           self.corpus._project_summaries(self.checkpoint.batch_id)}
        selected = tuple(selected_by_key.get(
            progress.project_key, ProjectCorpusSummary(project_key=progress.project_key),
        ) for progress in self.checkpoint.projects)
        self.checkpoint = self.checkpoint.model_copy(update={
            "projects": tuple(progress.model_copy(update={
                "selected": project.retained_pipeline_count,
            }) for progress, project in zip(self.checkpoint.projects, selected, strict=True)),
        })
        selected_count = sum(project.retained_pipeline_count for project in selected)
        completed_count = sum(project.complete_pipeline_count for project in selected)
        target_met = (
            all(project.listing_state == "listed" for project in self.checkpoint.projects)
            and selected_count == completed_count == self.plan.target_distinct_pipelines
        )
        if self.state == "collecting":
            self.state = "complete" if target_met else "shortfall"
        try:
            self.save()
        except CorpusLimitError:
            self.state = "capacity"  # Existing per-job checkpoints remain durable.
        return HarvestReport(
            state=self.state, target_met=target_met and self.state == "complete",
            selected_distinct_pipeline_count=selected_count,
            completed_distinct_pipeline_count=completed_count,
            over_200_distinct_failed_pipelines=completed_count > 200,
            plan=self.plan, projects=selected, progress=self.checkpoint.projects,
            summary=self.corpus.summary(),
        )


@asynccontextmanager
async def _provider_scope(origin: str, provider: GitLabProvider | None):
    if provider is not None:
        # Injection is for caller-owned offline mocks / the bounded adapter only.
        if type(provider) is GitLabProvider:
            raise CorpusError("Use CorpusGitLabProvider for bounded, no-retry harvesting.")
        if provider.web_base_url != origin:
            raise CorpusError("Provider host differs from the configured credential host.")
        yield provider
    else:
        async with CorpusGitLabProvider(origin) as owned:
            yield owned


async def harvest_pipelines(
    settings: Settings, projects: Sequence[str], *, per_project: int = 75,
    concurrency: int = 2, corpus: PipelineCorpus | None = None,
    provider: GitLabProvider | None = None,
) -> HarvestReport:
    """Explicit bounded collection. Injected providers are caller-owned (for tests).

    The ONLY remote credential is ``settings.configured_gitlab_token``. Successful
    3 x 75 collection means 225 distinct failed pipeline IDs, not 225 job traces.
    Insufficient listings/unreadable traces are reported, never filled with copies.
    """

    plan = preview_harvest(settings, projects, per_project=per_project, concurrency=concurrency)
    if not plan.token_configured or any(char in (settings.configured_gitlab_token or "")
                                        for char in "\r\n"):
        raise CorpusError("Configure a valid GitLab token in settings before execution.")
    corpus = corpus if corpus is not None else PipelineCorpus(settings=settings)
    corpus.settings, corpus.scrub = settings, _scrubber(settings)
    async with _provider_scope(plan.origin, provider) as active:
        with corpus._writer():
            corpus.initialize()
            return await _Harvest(settings, plan, corpus, active).run()


def reevaluate_corpus(corpus: PipelineCorpus) -> ReevaluationReport:
    """Explicit LOCAL write; no provider, source lookup, token requirement or model.

    Reuses retained sanitized full/bounded traces, including unknowns and prior
    analysis errors. Empty/unreadable/oversized samples remain separately counted.
    Commits each job so interruption cannot discard previously reclassified jobs.
    """

    checksum = rule_checksum()
    count = unknown = errors = 0
    with corpus._writer():
        corpus.initialize()
        for pipeline in corpus._pipelines():
            for job in corpus._jobs(pipeline):
                if not job.log.strip():
                    continue
                classified = _classify(corpus, pipeline, job, checksum)
                corpus._put_job(classified)
                count += 1
                unknown += classified.state == "unknown"
                errors += classified.state == "analysis_error"
    return ReevaluationReport(
        reevaluated_job_count=count, unknown_job_count=unknown, analysis_error_job_count=errors,
        rule_version=RULE_VERSION, rule_checksum=checksum, summary=corpus.summary(),
    )