"""Local history (RAG) for the investigation agent: confirmed fixes, corpus, past incidents."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

from pipelinelens.domain import SimilarIncident
from pipelinelens.services.agent import investigate
from pipelinelens.services.agent_memory import AgentHistory, HistoryHit, build_history
from pipelinelens.services.local_knowledge import LocalKnowledgeCache
from test_agent import PROJECT, Script, call, final, finding, result, settings, tools


def _job(job_id: int, rule: str, excerpt: str, category: str = "test_failure"):
    return SimpleNamespace(
        job_id=job_id, pipeline_id=job_id * 10, name=f"job-{job_id}", rule_id=rule,
        category=category, failure_reason="script_failure", excerpt=excerpt,
        collected_at=datetime(2026, 9, 1, tzinfo=UTC),
    )


class FakeCorpus:
    def __init__(self, project_key: str, jobs: list) -> None:
        self.project_key = project_key
        self.jobs = jobs
        self.requested: list[str | None] = []

    def summary(self):
        return SimpleNamespace(projects=[SimpleNamespace(project_key=self.project_key)])

    def iter_jobs(self, project_key=None):
        self.requested.append(project_key)
        return iter(self.jobs)


class FakeStore:
    def find_similar(self, snapshot, *, limit=5):
        return [SimilarIncident(
            incident_id="incident-0123456789abcdef", fingerprint="f", category="test_failure",
            summary="test_total failed after a refactor of calc.py",
            confirmed_resolution="Reverted the off-by-one in total().", similarity=0.8,
        )]


def test_confirmed_resolutions_rank_first_then_similar_failures(tmp_path) -> None:
    knowledge = LocalKnowledgeCache(tmp_path / "knowledge")
    knowledge.record_resolution(PROJECT, "job.insufficient_evidence",
                                "Removed the stray - 1 in src/calc.py total().")
    corpus = FakeCorpus(PROJECT.upper(), [
        _job(1, "test.failed", "FAILED tests/test_calc.py::test_total - assert 41 == 42"),
        _job(2, "runner.timeout", "Job timed out after 3600 seconds", "timeout"),
    ])

    history = build_history(PROJECT, finding(), snapshot=result().analyses[0],
                            knowledge=knowledge, corpus=corpus, store=FakeStore())
    hits = history.search("assert 41 == 42 test_total")

    assert corpus.requested == [PROJECT.upper()]  # Case-insensitive, same project only.
    assert hits[0][1].kind == "confirmed_resolution"
    assert "stray - 1" in hits[0][1].text
    kinds = [hit.kind for _, hit in hits]
    assert "past_incident" in kinds and "past_failure" in kinds
    assert hits[kinds.index("past_failure")][1].evidence_id == "history:job:1"
    assert "history:job:2" not in [hit.evidence_id for _, hit in hits]  # Unrelated timeout.
    assert history.hint().startswith("Local history has 1 human-confirmed resolution(s)")


def test_missing_or_broken_stores_give_empty_history() -> None:
    class Broken:
        def lookup(self, *args):
            from pipelinelens.services.local_knowledge import KnowledgeCacheError
            raise KnowledgeCacheError("corrupt")

        def summary(self):
            from pipelinelens.services.pipeline_corpus import CorpusError
            raise CorpusError("locked")

        def find_similar(self, *args, **kwargs):
            raise RuntimeError("db down")

    history = build_history(PROJECT, finding(), snapshot=result().analyses[0],
                            knowledge=Broken(), corpus=Broken(), store=Broken())
    assert history.items == [] and history.search("anything") == []
    assert history.hint() == "No local history is available for this failure."


async def test_agent_can_search_history_and_cite_a_confirmed_fix() -> None:
    history = AgentHistory(rule_id="job.insufficient_evidence", category="unknown", items=[
        HistoryHit(evidence_id="history:resolution:abc123", kind="confirmed_resolution",
                   text="Human-confirmed: removed the - 1 in total()."),
    ])
    script = Script(
        tools(call("search_history", query="assert 41 == 42")),
        final(patch=None, evidence=[{"evidence_id": "history:resolution:abc123",
                                     "explanation": "Same fix was confirmed before."}]),
    )

    outcome = await investigate(settings(), result(), finding(), history=history,
                                client=script)

    assert outcome is not None
    assert outcome.evidence[0].evidence_id == "history:resolution:abc123"
    task = script.sent[0][0][1]["content"]
    assert "History: Local history has 1 human-confirmed resolution(s)" in task
    tool_reply = script.sent[1][0][-1]["content"]
    assert "[history:resolution:abc123] (confirmed_resolution, confirmed)" in tool_reply
    assert "search_history" in json.dumps(script.sent[0][1])


async def test_without_history_the_tool_says_so() -> None:
    script = Script(tools(call("search_history")), final(patch=None, evidence=[
        {"evidence_id": "history:none", "explanation": "No history."}]))
    outcome = await investigate(settings(), result(), finding(), client=script)
    assert outcome is not None
    assert script.sent[1][0][-1]["content"] == "[history:none]\nNo local history."
