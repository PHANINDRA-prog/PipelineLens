"""Fetch only candidate source files and produce review-only, exact-source proposals.

No mutations or model calls. Parent inspection already established project/job
access. Additional source access is checked at the pipeline SHA on every request.
Public runbook references are static; no company data is sent to a search engine.
"""

from __future__ import annotations

import asyncio
import re

from pipelinelens.config import Settings
from pipelinelens.domain import AnalysisSnapshot, CiConfigFile
from pipelinelens.providers.base import ProviderError
from pipelinelens.providers.gitlab import GitLabProvider
from pipelinelens.services.findings import Finding
from pipelinelens.services.inspection import InspectionResult, _Scrubber
from pipelinelens.services.remediation import (
    Remediation,
    build_remediation,
    build_verified_json_hunk,
    candidate_source_paths,
)
from pipelinelens.services.runbooks import runbook_for

MAX_SOURCE_READS = 8
MAX_SOURCE_BYTES = 250_000
MAX_REMEDIATIONS = 8
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_CONTEXT = {"pipeline_status", "job_status", "ci_configuration", "ci_visibility"}


def _selected_findings(result: InspectionResult) -> list[Finding]:
    return sorted(
        (item for item in result.findings if item.category not in _CONTEXT),
        key=lambda item: (
            {"error": 0, "warning": 1, "info": 2}[item.severity],
            item.category in {"unknown", "no_failure_observed"},
        ),
    )[:MAX_REMEDIATIONS]


async def enrich_remediations(
    provider: GitLabProvider,
    token: str,
    settings: Settings,
    result: InspectionResult,
) -> list[Remediation]:
    """Bind proposals to authentic source reads without changing the input result."""
    scrub = _Scrubber(provider.web_base_url, token, settings)
    semaphore = asyncio.Semaphore(2)
    requests: dict[tuple[str, str, str], asyncio.Task[CiConfigFile | None]] = {}
    failures: dict[tuple[str, str, str], str] = {}
    originals: dict[tuple[str, str, str], CiConfigFile] = {}

    async def fetch(snapshot: AnalysisSnapshot, path: str) -> CiConfigFile | None:
        sha = snapshot.run.commit_sha or ""
        key = (snapshot.repository.external_id, sha, path)
        try:
            async with semaphore:
                source = await provider.fetch_file_at_ref(token, snapshot.repository, path, sha)
        except ProviderError as error:
            failures[key] = (
                f"{path}: source read unavailable (HTTP {error.status_code}); no diff inferred."
            )
            return None
        if source.path != path or source.ref != sha:
            failures[key] = f"{path}: source identity differs from the requested pipeline commit."
            return None
        is_data_config = bool(re.fullmatch(r"asfdx-project[^/]*\.json", path.rsplit("/", 1)[-1]))
        max_bytes = 1_000_000 if is_data_config else MAX_SOURCE_BYTES
        if len(source.content.encode("utf-8", errors="replace")) > max_bytes:
            failures[key] = f"{path}: source exceeds the proposal size limit; no diff generated."
            return None
        if is_data_config:
            # Ephemeral, fresh source only. Never store originals on the result,
            # cache, log or model context; return only verified secret-free hunks.
            originals[key] = source
        return scrub.model(source)

    work = []
    for finding in _selected_findings(result):
        snapshot = next((item for item in result.analyses
                         if item.job.external_id == finding.job_id), None)
        if not finding.job_id:
            snapshot = next((item for item in result.analyses
                             if item.repository.external_id == result.repository.external_id), None)
        root = snapshot is not None and (
            snapshot.repository.external_id == result.repository.external_id
        )
        changes = result.changes if root else []
        known = [entry.path for entry in result.project_structure] if root else []
        sources = list(result.config_bundle) if root else list(
            snapshot.config_bundle if snapshot else [],
        )
        keys = []
        limited = False
        if snapshot and _SHA.fullmatch(snapshot.run.commit_sha or ""):
            loaded = {(source.path, source.ref) for source in sources}
            for path in candidate_source_paths(finding, snapshot, changes, known):
                sha = snapshot.run.commit_sha or ""
                if (path, sha) in loaded:
                    continue
                key = (snapshot.repository.external_id, sha, path)
                if key not in requests:
                    if len(requests) >= MAX_SOURCE_READS:
                        limited = True
                        continue
                    requests[key] = asyncio.create_task(fetch(snapshot, path))
                keys.append(key)
        work.append((finding, snapshot, changes, known, sources, keys, limited))
    try:
        if requests:
            await asyncio.gather(*requests.values())
    finally:
        for task in requests.values():
            if not task.done():
                task.cancel()
        if requests:
            await asyncio.gather(*requests.values(), return_exceptions=True)

    output = []
    for finding, snapshot, changes, known, sources, keys, limited in work:
        sources.extend(requests[key].result() for key in keys if requests[key].result() is not None)
        plan = await asyncio.to_thread(
            build_remediation, finding, snapshot, sources, changes, known,
        )
        if snapshot is not None and finding.rule_id == "salesforce.csv_as_sobject":
            for key in keys:
                original = originals.get(key)
                if original is None:
                    continue
                hunk = await asyncio.to_thread(
                    build_verified_json_hunk, finding, snapshot, original,
                )
                if hunk is not None:
                    plan = hunk
                    break
        cited_paths = {item.path for item in finding.evidence if item.path}
        job_source = snapshot.job_source if snapshot else None
        source_url = (job_source.source_url or "").split("#", 1)[0] if job_source else ""
        plan.source_blocks.sort(key=lambda block: (
            block.path not in cited_paths,
            finding.rule_id == "compiler.cs0161" and block.language != "csharp",
            bool(source_url) and (block.source_url or "").split("#", 1)[0] != source_url,
        ))
        # Static change findings have no job_id even when they use a root snapshot
        # to prove commit/repository identity. Preserve that public association.
        plan.job_id = finding.job_id
        plan.missing_information.extend(failures[key] for key in keys if key in failures)
        if limited:
            plan.missing_information.append(
                "Additional candidate files omitted at the eight-source request limit.",
            )
        book = runbook_for(finding.rule_id, finding.category)
        plan.documentation = list(dict.fromkeys([*book.urls, *plan.documentation]))[:6]
        plan.confidence_basis.append(
            f"Documentation topic reviewed {book.reviewed_on}; not runtime evidence or a fix test.",
        )
        # Frequency does not alter either score. Keep the more specific existing
        # rule's steps when no exact code patch can responsibly be offered.
        if not plan.proposals and finding.fix:
            plan.actions = finding.fix.copy()
        safe_plan = scrub.model(plan)
        if any(a.diff != b.diff for a, b in zip(plan.proposals, safe_plan.proposals, strict=True)):
            safe_plan.proposals = []
            safe_plan.fix_confidence = min(safe_plan.fix_confidence, 20)
            safe_plan.missing_information.append(
                "The generated hunk required credential redaction; no exact diff is shown.",
            )
        output.append(safe_plan)
    originals.clear()
    return output