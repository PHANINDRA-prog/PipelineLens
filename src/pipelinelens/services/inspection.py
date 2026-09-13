"""Bounded, read-only GitLab inspection without a vault, cache, retrieval, or LLM.

Mutable project/pipeline/job metadata is refreshed on every call. CI source reads
are shared within the inspection (and may use the provider's immutable-source
cache). Counts cover enumerated root and followed child jobs, including metadata-
only analyses when a trace is unavailable; they never imply exhaustive coverage.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import partial
from typing import Any, Literal, TypeVar
from urllib.parse import quote, quote_plus, unquote, urlsplit, urlunsplit

from pydantic import BaseModel, Field

from pipelinelens.config import Settings
from pipelinelens.domain import (
    AnalysisSnapshot,
    CiConfigAccessReport,
    CiConfigFile,
    DownloadState,
    PipelineJob,
    PipelineRun,
    ProviderName,
    RepositoryRef,
    RepositoryTreeEntry,
)
from pipelinelens.providers.base import ProviderError
from pipelinelens.providers.gitlab import ConfigInspection, GitLabProvider
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.findings import (
    Finding,
    FindingEvidence,
    analyze_change_risks,
    diagnose_job,
)
from pipelinelens.services.gitlab_includes import normalize_local_path
from pipelinelens.services.logs import redact_log
from pipelinelens.services.pipeline_url import GitLabReference, PipelineUrlError, _origin
from pipelinelens.services.redaction import SecretRedactor
from pipelinelens.services.yaml_graph import CiConfigParseError, analyze_ci_config

_T = TypeVar("_T")
_Model = TypeVar("_Model", bound=BaseModel)
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_ID = re.compile(r"[1-9][0-9]*\Z")
_SUCCESS = {"success", "succeeded", "passed"}
_FAILED = {"failed", "failure", "timed_out"}
_ACTIVE = {
    "created", "waiting_for_resource", "preparing", "pending", "running", "scheduled",
    "canceling",
}
_INTERESTING = ("deploy", "package", "validat", "build", "sonar")
_MAX_JOBS = 300
_MAX_CHANGES = 100
_MAX_FINDINGS = 80
_MAX_NOTES = 100
_MAX_DIFF_CHARS = 100_000
_MAX_CONFIG_CHARS = 1_000_000


class InspectionResult(BaseModel):
    """Sanitized evidence; ``submitted_url`` is deliberately owned by the caller."""

    repository: RepositoryRef
    pipeline: PipelineRun | None = None
    selected_job: PipelineJob | None = None
    resolved_url: str
    reference_kind: Literal["pipeline", "job", "branch", "repository"]
    project_key: str
    findings: list[Finding] = Field(default_factory=list)
    jobs: list[PipelineJob] = Field(default_factory=list)
    analyses: list[AnalysisSnapshot] = Field(default_factory=list)
    ci_config_access: CiConfigAccessReport
    config_bundle: list[CiConfigFile] = Field(default_factory=list)
    project_structure: list[RepositoryTreeEntry] = Field(default_factory=list)
    merge_requests: list[dict] = Field(default_factory=list)
    changes: list[dict] = Field(default_factory=list)
    downstream: list[dict] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    analyzed_job_count: int = Field(default=0, ge=0)
    skipped_job_count: int = Field(default=0, ge=0)
    status: Literal["failed", "warning", "passed", "in_progress", "configuration_only"]


def _outcome(item: PipelineJob | PipelineRun) -> str:
    return (item.conclusion or item.status).lower() if item.status == "completed" else (
        item.status.lower()
    )


def _identifier(value: object) -> str | None:
    return str(value) if type(value) in {str, int} and _ID.fullmatch(str(value)) else None


def _path(value: object) -> str | None:
    return value if isinstance(value, str) and normalize_local_path(value) == value else None


def _bridge_problem(bridge: dict) -> bool:
    child = bridge.get("downstream_pipeline")
    statuses = (
        bridge.get("status"), child.get("status") if isinstance(child, dict) else None,
    )
    return any(isinstance(status, str) and status.lower() in _FAILED | {"warning"}
               for status in statuses)


class _Scrubber:
    def __init__(self, origin: str, token: str, settings: Settings) -> None:
        self.origin = origin
        secrets = {token, settings.configured_gitlab_token, settings.llm_api_key} - {None, ""}
        variants: set[str] = set()
        for secret in secrets:
            if secret is not None:
                variants.update((secret, quote(secret, safe=""), quote_plus(secret, safe=""),
                                 json.dumps(secret, ensure_ascii=True)[1:-1]))
        variants.update(
            re.sub(r"%[0-9A-F]{2}", lambda match: match[0].lower(), value)
            for value in tuple(variants)
        )
        self.exact = re.compile("|".join(map(re.escape, sorted(variants, key=len, reverse=True))))
        self.redactor = SecretRedactor()

    def text(self, value: str) -> str:
        def exact(text: str) -> str:
            if not self.exact.pattern:
                return text
            # Keep physical trace/YAML lines, including multiline explicit secrets.
            return self.exact.sub(
                lambda match: "[REDACTED]" + "\n" * match[0].count("\n"), text,
            )

        # ANSI stripping can join pieces of an opaque credential, so match again
        # after generic/log sanitization and before handing anything to analysis.
        return exact(redact_log(exact(value), self.redactor).content)

    def url(self, value: object) -> str | None:
        if not isinstance(value, str) or len(value) > 8192:
            return None
        try:
            parts = urlsplit(value)
            if (
                _origin(f"{parts.scheme}://{parts.netloc}") != self.origin
                or self.text(parts.netloc) != parts.netloc
            ):
                return None
            decoded = unquote(parts.path, errors="strict")
            if (
                self.text(parts.path) != parts.path or self.text(decoded) != decoded
                or "%" in decoded or "\\" in decoded
                or re.search(r"[\x00-\x20\x7f]", decoded)
                or any(part in {".", ".."} for part in decoded.split("/"))
                or not decoded.startswith("/") or "//" in decoded
            ):
                return None
            fragment = (
                parts.fragment if re.fullmatch(r"L[1-9]\d*(?:-[1-9]\d*)?", parts.fragment) else ""
            )
            # Never publish signed/query-bearing links or arbitrary fragments.
            return urlunsplit((parts.scheme, parts.netloc, parts.path, "", fragment))
        except (ValueError, UnicodeError):
            return None

    def data(self, value: Any, key: str = "") -> Any:
        if isinstance(value, BaseModel):
            value = value.model_dump()  # Excluded raw metadata must never be traversed.
        if isinstance(value, dict):
            return {self.text(str(name)): self.data(item, str(name))
                    for name, item in value.items() if name != "raw"}
        if isinstance(value, (list, tuple)):
            return [self.data(item, key) for item in value]
        if isinstance(value, str):
            if key in {"web_url", "source_url", "resolved_url"}:
                safe = self.url(value)
                # RepositoryRef.web_url and resolved_url are required strings;
                # optional source links may be None. Never retain an unsafe link.
                return safe if safe or key == "source_url" else ""
            return self.text(value)
        return value

    def model(self, value: _Model) -> _Model:
        return type(value).model_validate(self.data(value))


@dataclass
class _Changes:
    merge_requests: list[dict] = field(default_factory=list)
    changes: list[dict] = field(default_factory=list)  # Diff text stays in memory only.


class _Inspection:
    def __init__(self, provider: GitLabProvider, token: str, settings: Settings) -> None:
        self.provider = provider
        self.token = token
        self.settings = settings
        self.scrub = _Scrubber(provider.web_base_url, token, settings)
        self.semaphore = asyncio.Semaphore(4)
        self.notes: list[str] = []
        self.partial = False
        self.unavailable: set[str] = set()
        self.findings: list[Finding] = []
        self.sources: dict[tuple[str, str], asyncio.Task[ConfigInspection]] = {}

    def note(self, text: str) -> None:
        text = self.scrub.text(text)
        if text not in self.notes:
            self.notes.append(text)

    async def read(self, label: str, operation: Callable[[], Awaitable[_T]]) -> _T | None:
        try:
            async with self.semaphore:
                return await operation()
        except ProviderError as error:
            self.partial = True
            self.unavailable.add(label)
            self.note(f"{label} unavailable (HTTP {error.status_code}); inspection is partial. "
                      "Missing or denied evidence does not establish a job's failure cause.")
            return None

    async def api(
        self, label: str, path: str, *, limit: int | None = None,
    ) -> Any:
        async def request() -> Any:
            response = await self.provider._request(
                self.token, "GET", path,
                params={"per_page": limit, "page": 1} if limit else None,
            )
            try:
                payload = response.json()
            except json.JSONDecodeError:
                raise ProviderError("GitLab", 502, "Invalid JSON metadata.") from None
            if not isinstance(payload, list if limit is not None else dict):
                raise ProviderError("GitLab", 502, "Invalid metadata shape.")
            if limit is not None:
                if len(payload) > limit or response.headers.get("x-next-page"):
                    self.note(f"{label} is bounded to {limit} entries; additional context omitted.")
                payload = [item for item in payload[:limit] if isinstance(item, dict)]
            return payload

        return await self.read(label, request)

    def repository_url(self, repository: RepositoryRef) -> str:
        return f"{self.provider.web_base_url}/{quote(repository.display_name, safe='/')}"

    def run_url(self, repository: RepositoryRef, run: PipelineRun) -> str:
        return f"{self.repository_url(repository)}/-/pipelines/{quote(run.external_id, safe='')}"

    def job_url(self, repository: RepositoryRef, job: PipelineJob) -> str:
        return f"{self.repository_url(repository)}/-/jobs/{quote(job.external_id, safe='')}"

    def blob_url(self, repository: RepositoryRef, sha: str, path: str, line: int | None) -> str:
        base = (
            f"{self.repository_url(repository)}/-/blob/{quote(sha, safe='')}/"
            f"{quote(path, safe='/')}"
        )
        return base + (f"#L{line}" if line is not None else "")

    def public_run(self, repository: RepositoryRef, run: PipelineRun) -> PipelineRun:
        return self.scrub.model(run.model_copy(update={"web_url": self.run_url(repository, run)}))

    def public_job(self, repository: RepositoryRef, job: PipelineJob) -> PipelineJob:
        return self.scrub.model(job.model_copy(update={"web_url": self.job_url(repository, job)}))

    def public_config(self, config: CiConfigFile) -> CiConfigFile:
        result = self.scrub.model(config)
        if len(result.content) > _MAX_CONFIG_CHARS:
            self.partial = True
            self.note(f"Oversized CI source {result.path} omitted at the source-size safety limit.")
            result.content = "[PIPELINELENS_CONFIG_OMITTED: source-size safety limit]"
        return result

    async def load_sources(self, repository: RepositoryRef, run: PipelineRun) -> ConfigInspection:
        async def load() -> ConfigInspection:
            bundle = await self.read("CI sources", lambda: self.provider.load_ci_sources(
                self.token, repository, run,
            ))
            if bundle is None:
                bundle = ConfigInspection([], CiConfigAccessReport(
                    complete=False,
                    notes=["CI sources unavailable; only other evidence is usable."],
                ))
            return bundle

        key = (repository.external_id, run.commit_sha or "")
        if key not in self.sources:
            self.sources[key] = asyncio.create_task(load())
        bundle = await self.sources[key]
        access = self.scrub.model(bundle.access)
        configs = [self.public_config(config) for config in bundle.configs]
        sources = {entry.path: entry.source_url for entry in access.entries if entry.source_url}
        for config in configs:
            if not config.source_url:
                config.source_url = sources.get(config.path)
                if not config.source_url and _path(config.path) and config.ref == run.commit_sha:
                    config.source_url = self.scrub.url(self.blob_url(
                        repository, config.ref, config.path, None,
                    ))
        return ConfigInspection(configs, access)

    async def usable_configs(self, bundle: ConfigInspection) -> list[CiConfigFile]:
        for note in bundle.access.notes:
            self.note(note)
        if not bundle.access.complete:
            self.findings.append(Finding(
                rule_id="ci.sources_partial", severity="warning", category="ci_configuration",
                title="CI source inspection is partial",
                explanation="Not all declared sources are readable or historically verified. "
                "This is an evidence limitation, not proof that the pipeline configuration failed.",
                fix=["Review the CI source access report and immutable include refs."],
                evidence=[], confidence="unknown",
            ))
        if not bundle.configs:
            return []

        def parse() -> bool:
            by_path = {config.path: config.content for config in bundle.configs}
            try:
                graph = analyze_ci_config(
                    ProviderName.GITLAB, bundle.configs[0], by_path.get,
                )
            except CiConfigParseError:
                return False
            return not any(note.startswith("Invalid YAML;") for note in graph.unresolved_includes)

        if await asyncio.to_thread(parse):
            return bundle.configs
        message = (
            "CI YAML parse failure; job analyses use log-only evidence, not a guessed CI graph."
        )
        self.note(message)
        bundle.access.complete = False
        bundle.access.notes.append(message)
        self.findings.append(Finding(
            rule_id="ci.configuration_unparseable", severity="warning", category="ci_configuration",
            title="CI configuration could not be parsed", explanation=message,
            fix=["Validate the source YAML at the inspected commit before relying on its graph."],
            evidence=[], confidence="observed",
        ))
        return []

    async def change_context(self, repository: RepositoryRef, run: PipelineRun) -> _Changes:
        sha = run.commit_sha
        if not sha or not _SHA.fullmatch(sha):
            return _Changes()
        project = quote(repository.external_id, safe="")
        base = f"/projects/{project}"
        linked = await self.api(
            "Linked merge requests",
            f"{base}/pipelines/{quote(run.external_id, safe='')}/merge_requests",
            limit=2,
        )
        if not linked:
            self.note("No linked merge-request context was available. This is not a failure; "
                      "the pipeline commit diff is used when readable.")
        references = []
        for item in linked or []:
            iid = _identifier(item.get("iid"))
            project_id = _identifier(item.get("project_id")) or repository.external_id
            if iid:
                references.append((
                    item, f"/projects/{quote(project_id, safe='')}/merge_requests/{iid}",
                ))
        details = await asyncio.gather(*(
            self.api(f"Merge request !{item['iid']} detail", path) for item, path in references
        ))
        output = _Changes()
        use_commit = not references
        for (linked_item, _), detail in zip(references, details, strict=True):
            metadata = detail or linked_item
            refs = (detail or {}).get("diff_refs")
            head = refs.get("head_sha") if isinstance(refs, dict) else None
            same_head = isinstance(head, str) and head.lower() == sha.lower()
            use_commit |= not same_head
            if not same_head:
                self.note(f"Merge request !{linked_item['iid']}: current MR head changed or could "
                          "not be verified against the pipeline SHA. Current MR diffs are not "
                          "historical evidence; using the exact pipeline commit diff instead.")
            allowed = {
                "iid": metadata.get("iid") if _identifier(metadata.get("iid")) else None,
                "title": metadata.get("title"), "status": metadata.get("state"),
                "source": metadata.get("source_branch"), "target": metadata.get("target_branch"),
                "web_url": self.scrub.url(metadata.get("web_url")),
                "head_sha": head if isinstance(head, str) and _SHA.fullmatch(head) else None,
                "source_type": "merge_request" if same_head else "pipeline_commit",
            }
            output.merge_requests.append({
                key: self.scrub.text(value) if isinstance(value, str) else value
                for key, value in allowed.items() if value is None or type(value) in {str, int}
            })
        rows: list[dict] = []
        if not use_commit:
            for _, path in references:
                if len(rows) >= _MAX_CHANGES:
                    self.note("Changed paths are bounded to 100; additional MR diffs omitted.")
                    break
                diffs = await self.api("Merge-request diffs", f"{path}/diffs",
                                       limit=_MAX_CHANGES - len(rows))
                if diffs is None:
                    use_commit = True
                    break
                rows.extend(diffs)
        if use_commit:
            rows = await self.api(
                "Pipeline commit diff", f"{base}/repository/commits/{quote(sha, safe='')}/diff",
                limit=_MAX_CHANGES,
            ) or []
            for item in output.merge_requests:
                item["source_type"] = "pipeline_commit"
        seen: set[tuple[str | None, str | None]] = set()
        diff_budget = 1_000_000
        for item in rows[:_MAX_CHANGES]:
            old, new = _path(item.get("old_path")), _path(item.get("new_path"))
            if not (old or new) or (old, new) in seen:
                continue
            seen.add((old, new))
            change = {"old_path": old, "new_path": new}
            change.update({key: item.get(key) is True for key in (
                "new_file", "renamed_file", "deleted_file", "collapsed", "too_large",
            )})
            diff = (
                self.scrub.text(item["diff"]) if isinstance(item.get("diff"), str) else ""
            )
            if len(diff) > min(_MAX_DIFF_CHARS, diff_budget):
                diff = ""
                self.note("Oversized diff text omitted; static file risks are not proof that a "
                          "particular changed line ran. Changed-path metadata remains available.")
            diff_budget -= len(diff)
            change["diff"] = diff
            output.changes.append(self.scrub.data(change))
        return output

    async def changed_configs(
        self, repository: RepositoryRef, sha: str, context: _Changes, configs: list[CiConfigFile],
    ) -> list[CiConfigFile]:
        loaded = {config.path for config in configs}
        paths = sorted({path for change in context.changes
                        if not change.get("deleted_file")
                        and (path := _path(change.get("new_path")))
                        and path.endswith((".yml", ".yaml")) and path not in loaded})
        if len(paths) > 3:
            self.note(
                "Changed YAML reads are bounded to three additional files at the pipeline SHA."
            )
        extra = await asyncio.gather(*(self.read(
            f"Changed YAML {path}", lambda path=path: self.provider.fetch_file_at_ref(
                self.token, repository, path, sha,
            ),
        ) for path in paths[:3]))
        return [self.public_config(config) for config in extra if config is not None]

    def select_jobs(
        self, jobs: list[PipelineJob], selected: PipelineJob | None, budget: int,
    ) -> list[PipelineJob]:
        chosen = [selected] if selected else []
        chosen.extend(job for job in jobs if _outcome(job) in _FAILED
                      and (not selected or job.external_id != selected.external_id))
        selected_ids = {job.external_id for job in chosen}
        successful = [job for job in jobs if _outcome(job) in _SUCCESS
                      and job.external_id not in selected_ids]
        successful.sort(key=lambda job: (
            next((index for index, word in enumerate(_INTERESTING)
                  if word in f"{job.name} {job.stage or ''}".lower()), len(_INTERESTING)),
            job.name, job.external_id,
        ))
        # This is a sample, not a claim that every successful job was checked.
        chosen.extend(successful[:3])
        return chosen[:budget]

    def evidence_location(
        self, repository: RepositoryRef, sha: str, path: str, line: int | None,
        known: set[str], sources: dict[str, str],
    ) -> tuple[str, str | None, str]:
        if path in sources:
            return path, sources[path].split("#", 1)[0] + (f"#L{line}" if line else ""), ""
        if path in known and _path(path):
            return path, self.blob_url(repository, sha, path, line), ""
        matches = sorted(candidate for candidate in known if candidate.endswith("/" + path))
        if _path(path) and len(matches) == 1:
            marker = "Inferred repository path from a unique inventory suffix match; verify it. "
            return matches[0], self.blob_url(repository, sha, matches[0], line), marker
        return path, None, "Unverified repository location from the trace; inventory is bounded. "

    def job_finding(
        self, snapshot: AnalysisSnapshot, *, inherited_allow_failure: bool,
        parent_successful: bool,
    ) -> Finding:
        finding = diagnose_job(snapshot)
        allowed = snapshot.job.allow_failure or inherited_allow_failure
        if allowed and _outcome(snapshot.job) in _FAILED:
            finding.severity = "warning"
            finding.explanation += (
                " This job or its parent bridge has allow_failure=true, so its failure is a "
                "warning and need not fail the overall pipeline."
            )
            if _outcome(snapshot.run) in _SUCCESS:
                finding.explanation += " GitLab reports the overall pipeline successful."
        elif finding.severity == "error" and (
            _outcome(snapshot.run) in _SUCCESS or parent_successful
        ):
            finding.severity = "warning"
            finding.explanation += (
                " GitLab reports the overall parent/pipeline successful; this evidence does not "
                "override that pipeline outcome. Review the status/policy discrepancy."
            )
        return finding

    async def analyze_job(
        self, repository: RepositoryRef, run: PipelineRun, job: PipelineJob,
        configs: list[CiConfigFile], trace: str | None, known: set[str],
        *, inherited_allow_failure: bool = False, parent_successful: bool = False,
    ) -> AnalysisSnapshot:
        public_repository = self.scrub.model(repository)
        safe_run, safe_job = self.public_run(repository, run), self.public_job(repository, job)
        analysis_input = AnalysisInput(
            public_repository, safe_run, safe_job, configs, self.scrub.text(trace or ""),
        )
        analyzer = PipelineAnalyzer(self.settings)
        try:
            snapshot = await asyncio.to_thread(analyzer.analyze_input, analysis_input)
        except CiConfigParseError:
            self.partial = True
            self.note("CI YAML parse failure during analysis; falling back to log-only evidence.")
            snapshot = await asyncio.to_thread(analyzer.analyze_input, AnalysisInput(
                public_repository, safe_run, safe_job, [], analysis_input.raw_log,
            ))
        if trace is None:
            snapshot.progress.job_log = DownloadState.FAILED
        if not trace or not trace.strip():
            self.note(f"Job {job.external_id} has no usable trace. Its status is metadata, not "
                      "proof that an intended package was deployed or a causal error occurred.")
        if not configs:
            self.note(
                "Log-only analyses contain an empty CI placeholder, not a verified source file."
            )
        sources = {config.path: config.source_url for config in configs if config.source_url}
        for node in snapshot.graph.nodes:
            if node.source.path in sources:
                node.source.source_url = sources[node.source.path].split("#", 1)[0] + (
                    f"#L{node.source.line_start}"
                )
        if snapshot.job_source and snapshot.job_source.match_confidence < 1:
            self.note(
                f"Job {job.external_id}: its CI source match is inferred "
                f"(confidence {snapshot.job_source.match_confidence:.2f}), not an exact match."
            )
        finding = self.job_finding(
            snapshot, inherited_allow_failure=inherited_allow_failure,
            parent_successful=parent_successful,
        )
        sha = run.commit_sha or ""
        for reference in snapshot.code_references:
            path, url, marker = self.evidence_location(
                repository, sha, reference.path, reference.line, known, sources,
            )
            reference.path, reference.source_url = path, url if sha else None
            if marker:
                reference.message = marker + (reference.message or "")
                self.note(f"Job {job.external_id}: {marker.strip()}")
        for evidence in finding.evidence:
            if evidence.path:
                path, url, marker = self.evidence_location(
                    repository, sha, evidence.path, evidence.line, known, sources,
                )
                evidence.path, evidence.source_url = path, url if sha else None
                evidence.text = marker + evidence.text
        self.findings.append(self.scrub.model(finding))
        # The legacy diagnosis has no job status. Keep its prose consistent with
        # the status-aware finding rather than displaying an error for empty success.
        snapshot.diagnosis.failure_category = finding.category
        snapshot.diagnosis.summary = finding.title
        snapshot.diagnosis.likely_root_cause = finding.explanation
        snapshot.diagnosis.safe_next_steps = finding.fix.copy()
        snapshot.diagnosis.confidence = {"observed": 0.96, "likely": 0.65, "unknown": 0.3}[
            finding.confidence
        ]
        return self.scrub.model(snapshot)

    def pipeline_finding(self, repository: RepositoryRef, run: PipelineRun) -> None:
        outcome = _outcome(run)
        if outcome in _SUCCESS:
            return
        severity = "error" if outcome in _FAILED else "info" if outcome in _ACTIVE else "warning"
        self.findings.append(Finding(
            rule_id="pipeline.failed" if outcome in _FAILED else "pipeline.not_completed",
            severity=severity, category="pipeline_status",
            title=f"GitLab pipeline status: {outcome}",
            explanation="The pipeline API reports this outcome. Status alone does not establish "
            "an authentication, build, deployment, or quality-gate cause.",
            fix=["Use the job and downstream evidence below; retain existing CI execution policy."],
            evidence=[FindingEvidence(text=f"Pipeline {run.external_id}: {outcome}",
                                      source_url=self.run_url(repository, run))],
        ))

    async def downstream_context(
        self, repository: RepositoryRef, run: PipelineRun, bridges: list[dict], budget: int,
    ) -> tuple[list[dict], list[AnalysisSnapshot], int]:
        candidates = []
        seen: set[tuple[str, str]] = set()
        for bridge in bridges[:300]:
            child = bridge.get("downstream_pipeline")
            child = child if isinstance(child, dict) else {}
            if not _bridge_problem(bridge):
                continue
            key = (str(child.get("project_id")), str(child.get("id")))
            if key == (repository.external_id, run.external_id):
                self.note(
                    "A self-referencing bridge was not followed; downstream reads never recurse."
                )
                continue
            if child and key in seen:
                continue
            seen.add(key)
            candidates.append((bridge, child))
        if len(candidates) > 2:
            self.note(
                "Downstream traversal is bounded to two failed/warning pipelines, "
                "without recursion."
            )
        output: list[dict] = []
        analyses: list[AnalysisSnapshot] = []
        total_jobs = 0
        for bridge, child in candidates[:2]:
            allowed = bridge.get("allow_failure") is True or _outcome(run) in _SUCCESS
            entry = {key: bridge[key] for key in ("id", "name", "status")
                     if type(bridge.get(key)) in {str, int}}
            entry.update({"allow_failure": bridge.get("allow_failure") is True,
                          "access": "unavailable", "analyzed_job_id": None})
            entry["downstream_pipeline"] = {
                key: child[key] for key in ("id", "project_id", "status", "ref", "sha")
                if type(child.get(key)) in {str, int}
            }
            child_link = self.scrub.url(child.get("web_url"))
            if child_link:
                entry["downstream_pipeline"]["web_url"] = child_link
            project_id = _identifier(child.get("project_id"))
            pipeline_id = _identifier(child.get("id"))
            child_repository = None
            if project_id and pipeline_id:
                payload = await self.api("Downstream project", f"/projects/{project_id}")
                if payload is not None:
                    child_repository = self.provider._repository(payload)
                    if child_repository.external_id != project_id:
                        raise ProviderError("GitLab", 502, "Downstream project identity mismatch.")
                    child_repository.web_url = self.repository_url(child_repository)
            child_run, child_jobs = None, None
            if child_repository is not None and pipeline_id:
                child_run, child_jobs = await asyncio.gather(
                    self.read("Downstream pipeline", partial(self.provider.get_run,
                        self.token, child_repository, pipeline_id,
                    )),
                    self.read("Downstream jobs", partial(self.provider.list_pipeline_jobs,
                        self.token, child_repository, pipeline_id, max_jobs=_MAX_JOBS,
                    )),
                )
            if child_repository is None or child_run is None:
                self.findings.append(Finding(
                    rule_id="downstream.unavailable", severity="warning" if allowed else "error",
                      category="downstream_pipeline",
                      title="Failed/warning trigger lacks child evidence",
                    explanation="The bridge reports a failed/warning relationship, but the child "
                    "project or pipeline is unavailable or lacks explicit IDs. No repository was "
                      "guessed from a folder or untrusted URL; the child failure cause is unknown. "
                      + ("Parent success or bridge allow_failure makes this a warning."
                         if allowed else ""),
                    fix=["Request read access to the explicitly linked child pipeline and inspect "
                         "its job diagnostics; do not change trigger or allow_failure policy."],
                    evidence=[FindingEvidence(
                        text=f"Bridge status: {bridge.get('status', 'unknown')}",
                        source_url=child_link or self.run_url(repository, run),
                    )],
                    confidence="unknown",
                ))
            else:
                if child_run.external_id != pipeline_id:
                    raise ProviderError("GitLab", 502, "Downstream pipeline identity mismatch.")
                jobs_available = child_jobs is not None
                child_jobs = (child_jobs or [])[:_MAX_JOBS]
                total_jobs += len(child_jobs)
                entry["access"] = "readable" if jobs_available else "partial"
                entry["repository"] = self.scrub.model(child_repository).model_dump()
                entry["downstream_pipeline"] = {
                    "id": child_run.external_id, "project_id": child_repository.external_id,
                    "status": child_run.status, "ref": child_run.ref_name,
                    "sha": child_run.commit_sha,
                    "web_url": self.run_url(child_repository, child_run),
                }
                entry["job_count"] = len(child_jobs)
                child_failed = _outcome(child_run) in _FAILED | {"warning"}
                if child_failed:
                    self.findings.append(Finding(
                        rule_id="downstream.failed", severity="warning" if allowed else "error",
                        category="downstream_pipeline",
                        title="Downstream pipeline reports a failure/warning",
                        explanation="Fresh child pipeline metadata confirms this status. "
                        + ("Parent success or bridge allow_failure makes this a warning. "
                           if allowed else "")
                        + "A child-job diagnostic is separate from the parent pipeline's cause.",
                        fix=["Inspect child evidence without altering trigger execution policy."],
                        evidence=[FindingEvidence(
                            text=f"Child status: {child_run.status}",
                            source_url=self.run_url(child_repository, child_run),
                        )],
                    ))
                else:
                    self.findings.append(Finding(
                        rule_id="downstream.bridge_failed",
                        severity="warning" if allowed else "error",
                        category="downstream_pipeline",
                        title="Trigger reports failure/warning but child status differs",
                        explanation="The trigger status is failure/warning, but the fresh child "
                        f"pipeline status is {child_run.status}. The child is not declared failed "
                        "from stale bridge metadata; no cause is inferred.",
                        fix=["Compare the trigger result with the fresh child pipeline evidence."],
                        evidence=[FindingEvidence(
                            text=f"Bridge: {bridge.get('status')}; child: {child_run.status}",
                            source_url=self.run_url(child_repository, child_run),
                        )],
                    ))
                failed = next((job for job in child_jobs if _outcome(job) in _FAILED), None)
                if failed and budget > 0 and not analyses:
                    sha = child_run.commit_sha
                    bundle = ConfigInspection([], CiConfigAccessReport(complete=False))
                    trace_task = self.read("Downstream job trace", partial(
                        self.provider.fetch_job_log,
                        self.token, child_repository, child_run.external_id, failed.external_id,
                    ))
                    if sha and _SHA.fullmatch(sha):
                        bundle, trace = await asyncio.gather(
                            self.load_sources(child_repository, child_run), trace_task,
                        )
                    else:
                        trace = await trace_task
                        self.note(
                            "Downstream pipeline SHA unavailable; child analysis is log-only."
                        )
                    configs = await self.usable_configs(bundle)
                    analyses.append(await self.analyze_job(
                        child_repository, child_run, failed, configs, trace, set(),
                        inherited_allow_failure=bridge.get("allow_failure") is True,
                        parent_successful=_outcome(run) in _SUCCESS,
                    ))
                    entry["analyzed_job_id"] = failed.external_id
                elif failed:
                    self.note("Additional child traces omitted: at most one child job is analyzed, "
                              "within the overall trace budget.")
            output.append(self.scrub.data(entry))
        if candidates:
            self.note(
                "Downstream evidence is one level only: at most two pipelines and one child "
                "job analysis. Counts include enumerated child jobs; jobs lists the root only."
            )
        return output, analyses, total_jobs


async def inspect_gitlab(
    provider: GitLabProvider,
    token: str,
    repository: RepositoryRef,
    reference: GitLabReference,
    settings: Settings,
    max_jobs: int = 5,
) -> InspectionResult:
    """Inspect fresh GitLab metadata and bounded, sanitized evidence through ``provider`` only."""

    if (
        reference.base_url != provider.web_base_url
        or reference.project_path.casefold() != repository.display_name.casefold()
        or repository.provider != ProviderName.GITLAB
    ):
        raise PipelineUrlError(
            "The GitLab reference does not match the validated repository/server."
        )
    inspection = _Inspection(provider, token, settings)
    budget = max(1, min(max_jobs, 8))
    fresh = await inspection.read("Project metadata", lambda: provider.get_repository_by_path(
        token, reference.project_path,
    ))
    if fresh is not None:
        if fresh.external_id != repository.external_id:
            raise ProviderError(
                "GitLab", 409, "The project identity changed; validate access again."
            )
        repository = fresh
    else:
        inspection.note(
            "Using the caller's validated repository metadata; its settings may be stale."
        )
    repository = repository.model_copy(update={"web_url": inspection.repository_url(repository)})
    selected: PipelineJob | None = None
    run: PipelineRun | None = None
    head: str | None = None
    configuration_only = False
    pipeline_id = reference.pipeline_id
    if reference.kind == "job" and reference.job_id:
        selected = await inspection.read("Selected job", lambda: provider.get_job(
            token, repository, "", reference.job_id or "",
        ))
        if selected is not None:
            if selected.external_id != reference.job_id:
                raise ProviderError("GitLab", 502, "Selected job identity mismatch.")
            parent = selected.raw.get("pipeline")
            parent = parent if isinstance(parent, dict) else {}
            pipeline_id = _identifier(parent.get("id"))
            if any(value is not None and str(value) != repository.external_id for value in (
                selected.raw.get("project_id"), parent.get("project_id"),
            )):
                raise ProviderError("GitLab", 502, "Selected job parent project mismatch.")
            if not pipeline_id:
                inspection.note(
                    "Selected job has no verifiable parent pipeline ID; no parent was guessed."
                )
    if reference.kind in {"branch", "repository"}:
        resolved = reference
        if reference.kind == "branch":
            resolved = await inspection.read(
                "Branch/blob reference", lambda: provider.resolve_reference(
                    token, repository, reference,
                ),
            )
        ref = resolved.ref if resolved and reference.kind == "branch" else repository.default_branch
        if resolved and ref:
            head, latest = await asyncio.gather(
                inspection.read("Current branch HEAD", lambda: provider.resolve_commit(
                    token, repository, ref,
                )),
                inspection.read("Latest branch pipeline", lambda: provider.latest_run_for_ref(
                    token, repository, ref,
                )),
            )
            if latest is not None:
                run = latest
                pipeline_id = latest.external_id
                inspection.note(f"Inspecting the latest pipeline for resolved branch '{ref}'.")
            elif head and "Latest branch pipeline" not in inspection.unavailable:
                configuration_only = True
                inspection.note(
                    f"No pipeline exists for '{ref}'; configuration-only snapshot at {head}."
                )
            if resolved.file_path:
                inspection.note(
                    f"The submitted file/directory is '{resolved.file_path}'; CI sources "
                    "still use the project's configured entry point, not a guessed file."
                )
            reference = resolved
        else:
            inspection.note(
                "The branch/default branch could not be resolved; no current SHA was guessed."
            )
    if pipeline_id:
        detailed = await inspection.read("Pipeline metadata", lambda: provider.get_run(
            token, repository, pipeline_id,
        ))
        if detailed is not None:
            if detailed.external_id != pipeline_id or (
                detailed.raw.get("project_id") is not None
                and str(detailed.raw["project_id"]) != repository.external_id
            ):
                raise ProviderError("GitLab", 502, "Pipeline identity mismatch.")
            run = detailed
        elif run is not None:
            inspection.note(
                "Pipeline detail unavailable; using this call's fresh pipeline-list summary."
            )
    sha = run.commit_sha if run else head if configuration_only else None
    if sha and not _SHA.fullmatch(sha):
        sha = None
    if run and head and sha and head.lower() != sha.lower():
        inspection.note(
            f"Current branch HEAD {head} differs from pipeline SHA {sha}. Root CI sources, "
            "repository tree and change context use the pipeline SHA, not current HEAD."
        )
    if run:
        inspection.pipeline_finding(repository, run)
    if not sha:
        inspection.note(
            "No verified snapshot SHA is available; historical CI/tree/change evidence is "
            "unavailable rather than replaced with current HEAD."
        )

    jobs, bridges = [], []
    if pipeline_id:
        jobs_result, bridges_result = await asyncio.gather(
            inspection.read("Pipeline jobs", lambda: provider.list_pipeline_jobs(
                token, repository, pipeline_id, max_jobs=_MAX_JOBS,
            )),
            inspection.read("Pipeline bridges", lambda: provider.list_pipeline_bridges(
                token, repository, pipeline_id,
            )),
        )
        jobs, bridges = jobs_result or [], bridges_result or []
    # Preserve the explicit job even when successful, retried, or outside the bounded listing.
    by_id = {job.external_id: job for job in jobs[:_MAX_JOBS]}
    if selected:
        by_id[selected.external_id] = selected
    jobs = list(by_id.values())
    primary = {job.external_id for job in jobs if _outcome(job) in _FAILED}
    if selected:
        primary.add(selected.external_id)
    reserve_child = bool(run and len(primary) < budget
                         and any(_bridge_problem(bridge) for bridge in bridges[:300]))
    chosen = inspection.select_jobs(jobs, selected, budget - int(reserve_child)) if run else []
    if reserve_child:
        inspection.note(
            "One trace slot is reserved for a failed child before sampling successful root jobs; "
            "explicit selections and root failures retain priority."
        )
    inspection.note(
        f"Trace inspection is a bounded sample (budget {budget}; at most three additional "
        "successful jobs, prioritizing deploy/package/validate/build/sonar). It is not a "
        "complete pipeline audit or proof of the intended package/deployment receipt."
    )
    if len(jobs) >= _MAX_JOBS:
        inspection.note(
            "Root job inventory is bounded to 300 jobs plus any explicitly selected job."
        )
    bundle = ConfigInspection([], CiConfigAccessReport(complete=False))
    tree: list[RepositoryTreeEntry] = []
    context = _Changes()
    traces: list[str | None] = []

    async def sources_and_tree() -> tuple[ConfigInspection, list[RepositoryTreeEntry]]:
        if not sha:
            return bundle, []
        source_run = run or PipelineRun(
            external_id="", name="Configuration snapshot (no pipeline)",
            status="configuration_only",
            commit_sha=sha, ref_name=reference.ref or repository.default_branch,
        )
        sources, entries = await asyncio.gather(
            inspection.load_sources(repository, source_run),
            inspection.read("Repository tree", lambda: provider.list_repository_tree(
                token, repository, ref=sha, max_depth=6, max_entries=300,
            )),
        )
        inspection.note(
            "Repository tree is bounded to 300 entries and depth 6; absence is not proof "
            "that a required input is missing or that a different package was deployed."
        )
        return sources, (entries or [])[:300]

    async def changes() -> _Changes:
        return await inspection.change_context(repository, run) if run and sha else _Changes()

    async def logs() -> list[str | None]:
        if not run:
            return []
        return list(await asyncio.gather(*(inspection.read(
            f"Job {job.external_id} trace", lambda job=job: provider.fetch_job_log(
                token, repository, run.external_id, job.external_id,
            ),
        ) for job in chosen)))

    (bundle, tree), context, traces = await asyncio.gather(sources_and_tree(), changes(), logs())
    usable = await inspection.usable_configs(bundle)
    extra = (
        await inspection.changed_configs(repository, sha, context, bundle.configs) if sha else []
    )
    all_configs = [*bundle.configs, *extra]
    tree = [inspection.scrub.model(entry) for entry in tree]
    known = {entry.path for entry in tree if entry.entry_type == "file"}
    known.update(config.path for config in all_configs if _path(config.path) and config.ref == sha)
    # The risk analyzer adds diff paths itself. Feeding them into its baseline
    # would hide a change whose path differs in case from the observed inventory.
    risk_paths = sorted(known | {entry.path for entry in tree})
    known.update(path for change in context.changes if not change.get("deleted_file")
                 and (path := _path(change.get("new_path"))))
    risks = await asyncio.to_thread(
        analyze_change_risks, context.changes, all_configs, risk_paths,
    )
    for finding in risks:
        for evidence in finding.evidence:
            if not evidence.source_url and evidence.path and evidence.path in known and sha:
                evidence.source_url = inspection.blob_url(
                    repository, sha, evidence.path, evidence.line,
                )
    inspection.findings.extend(risks)
    analyses = []
    if run:
        for job, trace in zip(chosen, traces, strict=True):
            analyses.append(await inspection.analyze_job(
                repository, run, job, usable, trace, known,
            ))
        skipped_failed = [job for job in jobs if _outcome(job) in _FAILED and job not in chosen]
        if skipped_failed:
            allowed = all(job.allow_failure for job in skipped_failed) or _outcome(run) in _SUCCESS
            inspection.findings.append(Finding(
                rule_id="jobs.unanalyzed_failures", severity="warning" if allowed else "error",
                category="job_status", title="Additional failed jobs were not trace-analyzed",
                explanation=f"{len(skipped_failed)} failed jobs remain outside the trace budget. "
                     + ("allow_failure or the successful pipeline outcome makes this a warning. "
                         if allowed else "")
                + "Their status is observed, but their causes are unknown.",
                fix=["Select a remaining failed job explicitly for a focused inspection."],
                evidence=[FindingEvidence(
                    text=f"{job.name}: failed; allow_failure={job.allow_failure}",
                    source_url=inspection.job_url(repository, job),
                ) for job in skipped_failed[:3]],
            ))
    downstream, child_analyses, child_job_count = await inspection.downstream_context(
        repository, run, bridges, budget - len(chosen),
    ) if run else ([], [], 0)
    analyses.extend(child_analyses)
    if configuration_only:
        status = "configuration_only"
    elif run and _outcome(run) in _FAILED:
        status = "failed"
    elif run and _outcome(run) in _ACTIVE:
        status = "in_progress"
    elif run and _outcome(run) in _SUCCESS and not inspection.partial and not any(
        finding.severity != "info" for finding in inspection.findings
    ):
        status = "passed"
    else:
        status = "warning"
    if reference.kind == "job" and reference.job_id:
        resolved_url = f"{repository.web_url}/-/jobs/{quote(reference.job_id, safe='')}"
    elif selected:
        resolved_url = inspection.job_url(repository, selected)
    elif run:
        resolved_url = inspection.run_url(repository, run)
    elif pipeline_id:
        resolved_url = f"{repository.web_url}/-/pipelines/{quote(pipeline_id, safe='')}"
    elif sha:
        resolved_url = (inspection.blob_url(repository, sha, reference.file_path, None)
                        if reference.file_path and _path(reference.file_path)
                        else f"{repository.web_url}/-/tree/{quote(sha, safe='')}")
    else:
        resolved_url = repository.web_url
    inspection.findings.sort(key=lambda finding: (
        {"error": 0, "warning": 1, "info": 2}[finding.severity],
        {"observed": 0, "likely": 1, "unknown": 2}[finding.confidence],
        finding.rule_id, finding.job_id or "",
    ))
    if len(inspection.findings) > _MAX_FINDINGS:
        inspection.note(
            f"Findings truncated to {_MAX_FINDINGS}; highest-severity observed evidence first."
        )
    notes = inspection.notes[:_MAX_NOTES]
    if len(inspection.notes) > _MAX_NOTES:
        notes[-1] = "Additional inspection notes omitted at the safety limit."
    result = InspectionResult(
        repository=inspection.scrub.model(repository),
        pipeline=inspection.public_run(repository, run) if run else None,
        selected_job=inspection.public_job(repository, selected) if selected else None,
        resolved_url=resolved_url, reference_kind=reference.kind,
        project_key=inspection.repository_url(repository),
        findings=inspection.findings[:_MAX_FINDINGS],
        jobs=[inspection.public_job(repository, job) for job in jobs],
        analyses=analyses, ci_config_access=bundle.access, config_bundle=all_configs,
        project_structure=tree, merge_requests=context.merge_requests,
        changes=[{key: value for key, value in change.items() if key != "diff"}
                 for change in context.changes],
        downstream=downstream, notes=notes, status=status,
        analyzed_job_count=len(analyses),
        skipped_job_count=max(0, len(jobs) + child_job_count - len(analyses)),
    )
    return inspection.scrub.model(result)