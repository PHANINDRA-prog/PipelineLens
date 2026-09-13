"""Bounded retrieval context assembled from evidence, incident history, and skill packs."""

from __future__ import annotations

from dataclasses import dataclass

from pipelinelens.domain import (
    AnalysisSnapshot,
    KnowledgeDocument,
    RagEvidenceSource,
    SimilarIncident,
)
from pipelinelens.services.gitlab_includes import display_include_path
from pipelinelens.services.skills import SkillPack, matching_skill_packs
from pipelinelens.storage import IncidentStore


@dataclass(frozen=True, slots=True)
class RetrievalBundle:
    similar_incidents: list[SimilarIncident]
    skill_packs: list[SkillPack]
    knowledge_documents: list[KnowledgeDocument]
    sources: list[RagEvidenceSource]
    context: str
    allowed_evidence_ids: set[str]


class HybridRetriever:
    """Fetch a compact, auditable context bundle instead of unbounded agent memory."""

    def __init__(
        self,
        store: IncidentStore,
        max_context_chars: int = 18000,
        include_private_context: bool = False,
    ) -> None:
        self.store = store
        self.max_context_chars = max_context_chars
        self.include_private_context = include_private_context

    def retrieve(
        self, snapshot: AnalysisSnapshot, exclude_incident_id: str | None = None
    ) -> RetrievalBundle:
        similar_incidents = self.store.find_similar(
            snapshot, exclude_incident_id=exclude_incident_id, limit=5
        )
        skill_packs = matching_skill_packs(snapshot.fingerprint.category)
        knowledge_documents = self.store.find_relevant_knowledge(
            snapshot.fingerprint.normalized_message,
            include_private_context=self.include_private_context,
            limit=2,
        )
        sections: list[tuple[str, str, str]] = []
        allowed_ids: set[str] = set()
        sources: list[RagEvidenceSource] = []

        for chunk in snapshot.chunks[:3]:
            sections.append((chunk.chunk_id, "current job log", chunk.content))
            allowed_ids.add(chunk.chunk_id)
            sources.append(
                RagEvidenceSource(
                    evidence_id=chunk.chunk_id,
                    source_type="job_log",
                    label=(
                        f"Redacted {chunk.chunk_type.replace('_', ' ')} trace "
                        f"lines {chunk.line_start}-{chunk.line_end}"
                    ),
                    verified=True,
                )
            )
        if snapshot.job_source:
            yaml_id = (
                f"yaml:{snapshot.job_source.path}:"
                f"{snapshot.job_source.line_start}-{snapshot.job_source.line_end}"
            )
            sections.append(
                (
                    yaml_id,
                    "CI configuration",
                    f"Job `{snapshot.job_source.job_key}` in {snapshot.job_source.path} "
                    f"lines {snapshot.job_source.line_start}-{snapshot.job_source.line_end}",
                )
            )
            allowed_ids.add(yaml_id)
            sources.append(
                RagEvidenceSource(
                    evidence_id=yaml_id,
                    source_type="ci_yaml",
                    label=(
                        f"{display_include_path(snapshot.job_source.path)} lines "
                        f"{snapshot.job_source.line_start}-{snapshot.job_source.line_end}"
                    ),
                    verified=True,
                )
            )
        for incident in similar_incidents[:2]:
            incident_id = f"incident:{incident.incident_id}"
            resolution = incident.confirmed_resolution or "No confirmed resolution is available."
            sections.append(
                (
                    incident_id,
                    "historical incident",
                    f"{incident.summary}\nResolution: {resolution}",
                )
            )
            allowed_ids.add(incident_id)
            sources.append(
                RagEvidenceSource(
                    evidence_id=incident_id,
                    source_type="historical_incident",
                    label=f"Historical {incident.category.replace('_', ' ')} incident",
                    verified=incident.confirmed_resolution is not None,
                )
            )
        for skill in skill_packs[:1]:
            sections.append((skill.evidence_id, "skill pack", f"{skill.title}\n{skill.runbook}"))
            allowed_ids.add(skill.evidence_id)
            sources.append(
                RagEvidenceSource(
                    evidence_id=skill.evidence_id,
                    source_type="skill_pack",
                    label=f"Skill pack: {skill.title} v{skill.version}",
                    verified=True,
                )
            )
        for document in knowledge_documents:
            document_id = f"knowledge:{document.document_id}"
            sections.append(
                (
                    document_id,
                    "local sanitized corpus",
                    f"{document.source_label}/{document.source_path}\n{document.content}",
                )
            )
            allowed_ids.add(document_id)
            sources.append(
                RagEvidenceSource(
                    evidence_id=document_id,
                    source_type="local_corpus",
                    label=f"Local corpus: {document.source_label}/{document.source_path}",
                    verified=False,
                )
            )

        context_parts: list[str] = []
        remaining = self.max_context_chars
        for evidence_id, source_type, content in sections:
            rendered = f"[{evidence_id}] {source_type}\n{content.strip()}\n"
            if remaining <= 0:
                break
            context_parts.append(rendered[:remaining])
            remaining -= len(rendered)
        return RetrievalBundle(
            similar_incidents=similar_incidents,
            skill_packs=skill_packs,
            knowledge_documents=knowledge_documents,
            sources=sources,
            context="\n".join(context_parts),
            allowed_evidence_ids=allowed_ids,
        )
