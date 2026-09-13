from pipelinelens.services.analysis import PipelineAnalyzer
from pipelinelens.services.retrieval import HybridRetriever
from pipelinelens.services.skills import matching_skill_packs
from pipelinelens.storage import IncidentStore


def test_resolved_incidents_are_retrievable_as_historical_evidence(tmp_path) -> None:
    store = IncidentStore(f"sqlite:///{tmp_path / 'pipelinelens.db'}")
    store.initialize()
    analyzer = PipelineAnalyzer()
    snapshot = analyzer.analyze_demo("gitlab-auth-expired")
    incident_id = store.save_snapshot(snapshot)
    store.record_feedback(
        incident_id,
        "resolved",
        "Rotate the protected deployment credential through the approved secret store.",
    )

    retriever = HybridRetriever(store)
    bundle = retriever.retrieve(snapshot, exclude_incident_id="another-incident")

    assert bundle.similar_incidents[0].incident_id == incident_id
    assert "Rotate the protected deployment credential" in bundle.context
    assert f"incident:{incident_id}" in bundle.allowed_evidence_ids
    assert any(source.verified for source in bundle.sources)
    assert any(source.source_type == "skill_pack" for source in bundle.sources)


def test_skill_packs_are_versioned_and_category_matched() -> None:
    skills = matching_skill_packs("artifact_missing")

    assert len(skills) == 1
    assert skills[0].skill_id == "artifact-missing"
    assert skills[0].evidence_id == "skill:artifact-missing:v1"
