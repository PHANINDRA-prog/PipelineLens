"""Dramatiq tasks that never receive or persist provider access tokens."""

from __future__ import annotations

import asyncio

import dramatiq
from dramatiq.brokers.redis import RedisBroker

from pipelinelens.config import get_settings
from pipelinelens.services.analysis import PipelineAnalyzer
from pipelinelens.services.llm import EvidenceConstrainedDiagnoser
from pipelinelens.services.orchestrator import PipelineLensOrchestrator
from pipelinelens.services.retrieval import HybridRetriever
from pipelinelens.storage import IncidentStore

settings = get_settings()
broker = RedisBroker(url=settings.redis_url)
dramatiq.set_broker(broker)


def _orchestrator() -> PipelineLensOrchestrator:
    store = IncidentStore(settings.database_url)
    store.initialize()
    return PipelineLensOrchestrator(
        analyzer=PipelineAnalyzer(settings),
        store=store,
        retriever=HybridRetriever(
            store,
            max_context_chars=settings.max_context_chars,
            include_private_context=settings.allow_private_context,
        ),
        diagnoser=EvidenceConstrainedDiagnoser(settings),
    )


@dramatiq.actor(queue_name="sanitized-analysis", max_retries=2, min_backoff=5000)
def analyze_demo_fixture(fixture_id: str) -> str:
    """Queue a token-free sanitized fixture analysis for smoke tests and demos."""

    incident_id, _ = asyncio.run(_orchestrator().analyze_demo(fixture_id))
    return incident_id
