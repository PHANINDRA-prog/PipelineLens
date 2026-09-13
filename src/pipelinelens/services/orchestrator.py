"""Application workflow that retrieves evidence before storing a sanitized analysis result."""

from __future__ import annotations

from pipelinelens.demo import get_demo_incident
from pipelinelens.domain import (
    AnalysisSnapshot,
    PipelineJob,
    PipelineRun,
    RagSummary,
    RepositoryRef,
)
from pipelinelens.providers.base import CiProvider
from pipelinelens.services.analysis import PipelineAnalyzer, stable_incident_id
from pipelinelens.services.llm import EvidenceConstrainedDiagnoser
from pipelinelens.services.retrieval import HybridRetriever
from pipelinelens.storage import IncidentStore


class PipelineLensOrchestrator:
    """Coordinate deterministic analysis, bounded retrieval, LLM synthesis, and feedback storage."""

    def __init__(
        self,
        analyzer: PipelineAnalyzer,
        store: IncidentStore,
        retriever: HybridRetriever,
        diagnoser: EvidenceConstrainedDiagnoser,
    ) -> None:
        self.analyzer = analyzer
        self.store = store
        self.retriever = retriever
        self.diagnoser = diagnoser

    async def _complete_snapshot(self, snapshot: AnalysisSnapshot) -> tuple[str, AnalysisSnapshot]:
        current_id = stable_incident_id(snapshot.repository, snapshot.run, snapshot.job)
        bundle = self.retriever.retrieve(snapshot, exclude_incident_id=current_id)
        enriched_snapshot = snapshot.model_copy(
            update={"similar_incidents": bundle.similar_incidents}
        )
        diagnosis = await self.diagnoser.diagnose(enriched_snapshot, bundle)
        if diagnosis.generation == "llm":
            llm_message = "The LLM synthesized a diagnosis from the cited RAG evidence bundle."
        elif self.diagnoser.settings.llm_mode == "disabled":
            llm_message = (
                "RAG retrieval completed, but no LLM endpoint is enabled. "
                "The deterministic evidence-based diagnosis is shown."
            )
        else:
            llm_message = (
                "RAG retrieval completed, but the LLM response was unavailable "
                "or failed evidence validation. "
                "The deterministic evidence-based diagnosis is shown."
            )
        rag = RagSummary(
            context_char_count=len(bundle.context),
            sources=bundle.sources,
            llm_mode=self.diagnoser.settings.llm_mode,
            llm_model=self.diagnoser.settings.llm_model,
            llm_used=diagnosis.generation == "llm",
            llm_message=llm_message,
        )
        completed_snapshot = enriched_snapshot.model_copy(
            update={"diagnosis": diagnosis, "rag": rag}
        )
        return self.store.save_snapshot(completed_snapshot), completed_snapshot

    async def analyze_demo(self, fixture_id: str) -> tuple[str, AnalysisSnapshot]:
        fixture = get_demo_incident(fixture_id)
        snapshot = self.analyzer.analyze_fixture(fixture)
        return await self._complete_snapshot(snapshot)

    async def analyze_live(
        self,
        provider: CiProvider,
        token: str,
        repository: RepositoryRef,
        run_id: str,
        job_id: str,
    ) -> tuple[str, AnalysisSnapshot]:
        snapshot = await self.analyzer.analyze_live(provider, token, repository, run_id, job_id)
        return await self._complete_snapshot(snapshot)

    async def analyze_resolved(
        self,
        provider: CiProvider,
        token: str,
        repository: RepositoryRef,
        run: PipelineRun,
        job: PipelineJob,
        resolve_job_source: bool = True,
    ) -> tuple[str, AnalysisSnapshot]:
        """Complete analysis without repeating pipeline/job lookups performed by the caller."""

        snapshot = await self.analyzer.analyze_resolved(
            provider,
            token,
            repository,
            run,
            job,
            resolve_job_source=resolve_job_source,
        )
        return await self._complete_snapshot(snapshot)
