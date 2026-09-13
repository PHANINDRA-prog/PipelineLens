import json

import pytest

from pipelinelens.config import Settings
from pipelinelens.services.analysis import PipelineAnalyzer
from pipelinelens.services.llm import EvidenceConstrainedDiagnoser, get_llm_runtime_status
from pipelinelens.services.orchestrator import PipelineLensOrchestrator
from pipelinelens.services.retrieval import HybridRetriever
from pipelinelens.storage import IncidentStore


class StaticLlmClient:
    def __init__(self, payload: dict) -> None:
        self.payload = payload

    async def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        assert "evidence-first" in system_prompt
        assert "Retrieved evidence" in user_prompt
        return json.dumps(self.payload)


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_url="sqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        max_log_bytes=500000,
        max_context_chars=18000,
        llm_mode="openai-compatible",
        llm_base_url="https://example.test/v1",
        llm_model="test-model",
        llm_api_key="test-key",
        allow_private_context=False,
    )


@pytest.mark.asyncio
async def test_disabled_llm_status_still_reports_active_rag_retrieval() -> None:
    status = await get_llm_runtime_status(
        _settings().__class__(
            environment="test",
            database_url="sqlite:///:memory:",
            redis_url="redis://localhost:6379/0",
            max_log_bytes=500000,
            max_context_chars=18000,
            llm_mode="disabled",
            llm_base_url="http://localhost:11434",
            llm_model="qwen2.5:3b",
            llm_api_key=None,
            allow_private_context=False,
        )
    )

    assert status.ready is False
    assert "RAG retrieval is active" in status.message


@pytest.mark.asyncio
async def test_llm_diagnosis_is_accepted_only_with_retrieved_evidence() -> None:
    store = IncidentStore("sqlite:///:memory:")
    store.initialize()
    snapshot = PipelineAnalyzer(settings=_settings()).analyze_demo("gitlab-auth-expired")
    bundle = HybridRetriever(store).retrieve(snapshot)
    payload = {
        "failure_category": "authentication_failure",
        "confidence": 0.9,
        "summary": "The deployment credential was rejected.",
        "likely_root_cause": "The cited log contains an HTTP 401 expiration signal.",
        "evidence": [
            {
                "evidence_chunk_id": snapshot.chunks[0].chunk_id,
                "source_type": "job_log",
                "explanation": "The job trace reports HTTP 401 and credential expiration.",
            }
        ],
        "safe_next_steps": ["Verify the protected credential expiry date."],
        "missing_information": [],
        "similar_incident_ids": [],
        "auto_remediation_allowed": False,
    }

    diagnosis = await EvidenceConstrainedDiagnoser(
        settings=_settings(), client=StaticLlmClient(payload)
    ).diagnose(snapshot, bundle)

    assert diagnosis.generation == "llm"
    assert diagnosis.auto_remediation_allowed is False


@pytest.mark.asyncio
async def test_llm_diagnosis_falls_back_when_it_cites_unknown_evidence() -> None:
    store = IncidentStore("sqlite:///:memory:")
    store.initialize()
    snapshot = PipelineAnalyzer(settings=_settings()).analyze_demo("gitlab-auth-expired")
    bundle = HybridRetriever(store).retrieve(snapshot)
    payload = {
        "failure_category": "authentication_failure",
        "confidence": 0.9,
        "summary": "Unsupported claim.",
        "likely_root_cause": "Unsupported claim.",
        "evidence": [
            {
                "evidence_chunk_id": "invented-evidence",
                "source_type": "job_log",
                "explanation": "This must be rejected.",
            }
        ],
        "safe_next_steps": [],
        "missing_information": [],
        "similar_incident_ids": [],
        "auto_remediation_allowed": False,
    }

    diagnosis = await EvidenceConstrainedDiagnoser(
        settings=_settings(), client=StaticLlmClient(payload)
    ).diagnose(snapshot, bundle)

    assert diagnosis.generation == "deterministic"
    assert diagnosis.failure_category == "authentication_failure"


@pytest.mark.asyncio
async def test_rag_orchestration_marks_a_valid_cited_llm_result_as_used(tmp_path) -> None:
    store = IncidentStore(f"sqlite:///{tmp_path / 'llm-orchestration.db'}")
    store.initialize()
    analyzer = PipelineAnalyzer(settings=_settings())
    provisional_snapshot = analyzer.analyze_demo("gitlab-auth-expired")
    payload = {
        "failure_category": "authentication_failure",
        "confidence": 0.91,
        "summary": "The deployment credential was rejected.",
        "likely_root_cause": "The cited HTTP 401 signals an expired deployment credential.",
        "evidence": [
            {
                "evidence_chunk_id": provisional_snapshot.chunks[0].chunk_id,
                "source_type": "job_log",
                "explanation": "The trace contains an HTTP 401 credential-expiration signal.",
            }
        ],
        "safe_next_steps": ["Verify the protected credential expiry date."],
        "missing_information": [],
        "similar_incident_ids": [],
        "auto_remediation_allowed": False,
    }
    orchestrator = PipelineLensOrchestrator(
        analyzer=analyzer,
        store=store,
        retriever=HybridRetriever(store),
        diagnoser=EvidenceConstrainedDiagnoser(
            settings=_settings(),
            client=StaticLlmClient(payload),
        ),
    )

    _, snapshot = await orchestrator.analyze_demo("gitlab-auth-expired")

    assert snapshot.diagnosis.generation == "llm"
    assert snapshot.rag is not None
    assert snapshot.rag.llm_used is True
    assert "synthesized" in snapshot.rag.llm_message
