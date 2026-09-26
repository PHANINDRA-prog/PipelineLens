"""Local history (RAG) for the investigation agent: what happened before, and what fixed it.

Three existing, already-sanitized local stores are searched, nothing new is collected:

  1. Human-confirmed resolutions for this project and rule (``LocalKnowledgeCache``).
     These are the strongest signal and always rank first.
  2. Past failed jobs harvested into the local pipeline corpus (``PipelineCorpus``):
     rule, category, job name and the sanitized error excerpt.
  3. Past incidents saved by the RAG analysis path (``IncidentStore.find_similar``),
     including any confirmed resolution recorded against them.

Everything is loaded once, bounded, before the agent starts; ranking is lexical and
deterministic (``storage._hybrid_similarity``), so the same query always returns the
same hits. No network calls, no embeddings service, no writes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Literal

from pipelinelens.domain import AnalysisSnapshot
from pipelinelens.services.findings import Finding
from pipelinelens.services.local_knowledge import KnowledgeCacheError, LocalKnowledgeCache
from pipelinelens.services.pipeline_corpus import CorpusError, PipelineCorpus
from pipelinelens.storage import IncidentStore, _hybrid_similarity

MAX_CORPUS_JOBS_SCANNED = 500
MAX_HITS = 6
MIN_SCORE = 0.12

HitKind = Literal["confirmed_resolution", "past_failure", "past_incident"]


@dataclass(frozen=True, slots=True)
class HistoryHit:
    evidence_id: str
    kind: HitKind
    text: str
    rule_id: str = ""
    category: str = ""
    boost: float = 0.0


@dataclass
class AgentHistory:
    rule_id: str
    category: str
    items: list[HistoryHit] = field(default_factory=list)

    @property
    def confirmed_count(self) -> int:
        return sum(item.kind == "confirmed_resolution" for item in self.items)

    def hint(self) -> str:
        if not self.items:
            return "No local history is available for this failure."
        past = sum(item.kind != "confirmed_resolution" for item in self.items)
        parts = []
        if self.confirmed_count:
            parts.append(f"{self.confirmed_count} human-confirmed resolution(s) for this rule")
        if past:
            parts.append(f"{past} past failure record(s)")
        return "Local history has " + " and ".join(parts) + ". Call search_history."

    def search(self, query: str = "") -> list[tuple[float, HistoryHit]]:
        """Confirmed resolutions first, then the most similar past failures."""
        scored = []
        for item in self.items:
            if item.kind == "confirmed_resolution":
                scored.append((2.0, item))
                continue
            score = _hybrid_similarity(query, item.text) if query.strip() else 0.0
            if item.rule_id and item.rule_id == self.rule_id:
                score += 0.25
            elif item.category and item.category == self.category and item.category != "unknown":
                score += 0.1
            score += item.boost
            if score >= MIN_SCORE:
                scored.append((round(min(score, 1.0), 3), item))
        scored.sort(key=lambda pair: (-pair[0], pair[1].evidence_id))
        return scored[:MAX_HITS]


def _short(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def finding_query(finding: Finding) -> str:
    return "\n".join([finding.title, *(item.text for item in finding.evidence[:6])])


def build_history(
    project_key: str,
    finding: Finding,
    *,
    snapshot: AnalysisSnapshot | None = None,
    knowledge: LocalKnowledgeCache | None = None,
    corpus: PipelineCorpus | None = None,
    store: IncidentStore | None = None,
) -> AgentHistory:
    """Collect bounded local history for one finding. Store errors are skipped, not raised."""
    history = AgentHistory(rule_id=finding.rule_id, category=finding.category)
    if knowledge is not None:
        try:
            for item in knowledge.lookup(project_key, finding.rule_id):
                text = str(item.get("resolution") or "").strip()
                if text:
                    history.items.append(HistoryHit(
                        evidence_id=f"history:resolution:{_short(str(item.get('id') or text))}",
                        kind="confirmed_resolution", rule_id=finding.rule_id,
                        text=f"Human-confirmed resolution ({item.get('recorded_at', 'undated')})"
                             f" for rule {finding.rule_id}:\n{text}",
                    ))
        except KnowledgeCacheError:
            pass
    if corpus is not None:
        query = finding_query(finding)
        try:
            # Same scoping as confirmed resolutions: only this project's own history.
            corpus_key = next((item.project_key for item in corpus.summary().projects
                               if item.project_key.casefold() == project_key.casefold()), None)
            jobs = corpus.iter_jobs(corpus_key) if corpus_key else iter(())
            for index, job in enumerate(jobs):
                if index >= MAX_CORPUS_JOBS_SCANNED:
                    break
                if not job.excerpt and not job.rule_id:
                    continue
                history.items.append(HistoryHit(
                    evidence_id=f"history:job:{job.job_id}", kind="past_failure",
                    rule_id=job.rule_id, category=job.category,
                    boost=_hybrid_similarity(query, job.excerpt) if job.excerpt else 0.0,
                    text=(f"Past failed job {job.name} (pipeline {job.pipeline_id}, "
                          f"{job.collected_at:%Y-%m-%d}) rule={job.rule_id or 'none'} "
                          f"category={job.category} failure_reason={job.failure_reason}\n"
                          f"{job.excerpt}"),
                ))
        except (CorpusError, OSError, ValueError):
            pass
    if store is not None and snapshot is not None:
        try:
            for incident in store.find_similar(snapshot, limit=5):
                resolution = incident.confirmed_resolution
                history.items.append(HistoryHit(
                    evidence_id=f"history:incident:{incident.incident_id[:16]}",
                    kind="past_incident", category=incident.category,
                    boost=incident.similarity,
                    text=(f"Past incident ({incident.category}, similarity "
                          f"{incident.similarity:.2f}): {incident.summary}"
                          + (f"\nConfirmed resolution: {resolution}" if resolution else "")),
                ))
        except Exception:  # noqa: BLE001 - optional history must never block an analysis.
            pass
    return history
