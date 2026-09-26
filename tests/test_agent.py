"""Read-only investigation agent: scripted synthetic models, never a live endpoint."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import httpx
import pytest

from pipelinelens.config import Settings
from pipelinelens.demo import get_demo_incident
from pipelinelens.domain import CiConfigAccessReport, CiConfigFile, RepositoryTreeEntry
from pipelinelens.services import agent as agent_module
from pipelinelens.services.agent import (
    MAX_CAUSE_CONFIDENCE,
    MAX_FIX_CONFIDENCE_UNVERIFIED,
    MAX_FIX_CONFIDENCE_VERIFIED,
    AgentLimits,
    OpenAICompatibleAgentClient,
    agent_configured,
    investigate,
    verify_patch,
)
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.findings import Finding, FindingEvidence
from pipelinelens.services.inspection import InspectionResult
from pipelinelens.services.prompts import load_prompt
from pipelinelens.services.skills import load_skill_packs

SHA = "b" * 40
ORIGIN = "https://gitlab.test"
PROJECT = ORIGIN + "/fixtures/calc"
AGENT_KEY = "synthetic-agent-key-never-real-7731"
LLM_KEY = "synthetic-llm-key-never-real-5519"
LOG_SECRET = "abcd1234efgh5678ijkl"
TRACE = "\n".join([
    "$ pip install -r requirements.txt",
    "Successfully installed pytest",
    f"export API_TOKEN={LOG_SECRET}",
    "$ pytest -q",
    "F.",
    "FAILED tests/test_calc.py::test_total - assert 41 == 42",
    "1 failed, 1 passed in 0.02s",
    "ERROR: Job failed: exit code 1",
])
CALC = "def total(values):\n    return sum(values) - 1\n\n\ndef mean(values):\n    return 0\n"
GOOD_PATCH = (
    "--- a/src/calc.py\n+++ b/src/calc.py\n@@ -1,2 +1,2 @@\n def total(values):\n"
    "-    return sum(values) - 1\n+    return sum(values)\n"
)


def settings(**changes: Any) -> Settings:
    return replace(Settings(
        environment="test", database_url="sqlite://", redis_url="", max_log_bytes=500_000,
        max_context_chars=0, llm_mode="disabled", llm_base_url="https://llm.invalid/v1",
        llm_model="llm-model", llm_api_key=LLM_KEY, allow_private_context=False,
        configured_gitlab_base_url=ORIGIN, configured_gitlab_token=None,
        agent_mode="openai-compatible", agent_base_url="https://agent.invalid/v1",
        agent_model="agent-model", agent_api_key=AGENT_KEY,
    ), **changes)


def result() -> InspectionResult:
    fixture = get_demo_incident("gitlab-auth-expired")
    repository = fixture.repository.model_copy(update={
        "owner": "fixtures", "name": "calc", "web_url": PROJECT,
    })
    run = fixture.run.model_copy(update={"commit_sha": SHA, "status": "failed"})
    job = fixture.job.model_copy(update={
        "external_id": "501", "name": "unit", "stage": "test", "status": "failed",
        "web_url": PROJECT + "/-/jobs/501",
    })
    snapshot = PipelineAnalyzer(settings()).analyze_input(AnalysisInput(
        repository=repository, run=run, job=job, configs=[], raw_log=TRACE,
    ))
    return InspectionResult(
        repository=repository, pipeline=run, jobs=[job], analyses=[snapshot],
        findings=[finding()], resolved_url=PROJECT + "/-/pipelines/10",
        reference_kind="pipeline", project_key=PROJECT,
        ci_config_access=CiConfigAccessReport(complete=True),
        config_bundle=[CiConfigFile(path=".gitlab-ci.yml", ref=SHA,
                                    content="unit:\n  script: pytest -q\n")],
        project_structure=[RepositoryTreeEntry(path=path, entry_type="file") for path in
                           ("src/calc.py", "tests/test_calc.py", "README.md")],
        changes=[{"new_path": "src/calc.py"}], status="failed",
    )


def finding(**changes: Any) -> Finding:
    base = dict(
        rule_id="job.insufficient_evidence", severity="error", category="unknown",
        title="Cause not established", explanation="No specific diagnostic was found.",
        fix=["Inspect the complete trace."], job_id="501", confidence="unknown",
        evidence=[FindingEvidence(text="ERROR: Job failed: exit code 1", line=8)],
    )
    base.update(changes)
    return Finding(**base)


class Reader:
    def __init__(self, content: str = CALC, modified: bool = False) -> None:
        self.content = content
        self.modified = modified
        self.calls: list[str] = []

    async def __call__(self, path: str) -> CiConfigFile | None:
        self.calls.append(path)
        return CiConfigFile(path=path, ref=SHA, content=self.content,
                            source_modified=self.modified)


def call(name: str, index: int = 0, **args: Any) -> dict:
    return {"id": f"call-{name}-{index}", "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)}}


def final(**changes: Any) -> dict:
    body: dict[str, Any] = {
        "failure_category": "test_failure",
        "summary": "test_total fails because total() subtracts one.",
        "likely_root_cause": "src/calc.py returns sum(values) - 1.",
        "cause_confidence": 95, "fix_confidence": 90,
        "evidence": [
            {"evidence_id": "logsearch:501:" + agent_module._short_hash("failed"),
             "explanation": "Assertion 41 == 42."},
            {"evidence_id": "src:src/calc.py:1-6", "explanation": "Off-by-one in total()."},
        ],
        "next_steps": ["Run pytest tests/test_calc.py locally."],
        "missing_information": [],
        "patch": {"path": "src/calc.py", "diff": GOOD_PATCH},
    }
    body.update(changes)
    return {"role": "assistant", "content": json.dumps(body)}


class Script:
    """A synthetic model that replays fixed replies and records what it was sent."""

    model = "scripted-model"

    def __init__(self, *replies: dict) -> None:
        self.replies = list(replies)
        self.sent: list[tuple[list[dict], list[dict]]] = []

    async def chat(self, messages: list[dict], tools: list[dict]) -> dict:
        self.sent.append((json.loads(json.dumps(messages)), tools))
        if not self.replies:
            raise AssertionError("The agent called the model more often than scripted.")
        return self.replies.pop(0)


def tools(*calls: dict) -> dict:
    return {"role": "assistant", "content": None, "tool_calls": list(calls)}


def investigation_script(*extra_final: dict) -> Script:
    return Script(
        tools(call("search_log", job_id="501", text="FAILED")),
        tools(call("read_source", 1, path="src/calc.py")),
        *(extra_final or (final(),)),
    )


async def test_investigation_reads_evidence_and_returns_a_verified_patch() -> None:
    reader = Reader()
    script = investigation_script()
    notes: list[str] = []

    outcome = await investigate(settings(), result(), finding(), read_source=reader,
                                client=script, notes=notes)

    assert notes == []
    assert outcome is not None
    assert reader.calls == ["src/calc.py"]
    assert [step.tool for step in outcome.steps] == ["search_log", "read_source"]
    assert outcome.patch is not None and outcome.patch.verified
    assert "-    return sum(values) - 1\n+    return sum(values)" in outcome.patch.diff
    assert outcome.patch.diff.startswith("--- a/src/calc.py\n+++ b/src/calc.py")
    assert outcome.cause_confidence == MAX_CAUSE_CONFIDENCE
    assert outcome.fix_confidence == MAX_FIX_CONFIDENCE_VERIFIED
    assert outcome.auto_apply_allowed is False
    assert outcome.model == "scripted-model"
    assert set(outcome.prompt_versions) == {"agent_system", "agent_task"}
    # The first request carries the tools and the rendered, editable task prompt.
    first_messages, first_tools = script.sent[0]
    assert {spec["function"]["name"] for spec in first_tools} >= {"read_source", "search_log"}
    assert "Rule: job.insufficient_evidence" in first_messages[1]["content"]
    # Tool results reached the model with an evidence id and line numbers.
    tool_reply = script.sent[1][0][-1]
    assert tool_reply["role"] == "tool"
    assert tool_reply["content"].startswith("[logsearch:501:")
    assert "    6| FAILED tests/test_calc.py::test_total" in tool_reply["content"]


async def test_log_secrets_never_reach_the_model() -> None:
    script = Script(tools(call("get_log_window", job_id="501", start_line=1, end_line=20)),
                    final(patch=None, evidence=[{"evidence_id": "log:501:1-8",
                                                 "explanation": "Whole log."}]))

    outcome = await investigate(settings(), result(), finding(), client=script)

    assert outcome is not None
    assert LOG_SECRET not in json.dumps(script.sent)
    assert "[REDACTED]" in json.dumps(script.sent)


async def test_citing_an_unissued_id_gets_one_repair_round_then_succeeds() -> None:
    bad = final(evidence=[{"evidence_id": "src:invented.py:1-9", "explanation": "?"}])
    script = investigation_script(bad, final())

    outcome = await investigate(settings(), result(), finding(), read_source=Reader(),
                                client=script)

    assert outcome is not None
    repair_prompt = script.sent[-1][0][-1]["content"]
    assert "never issued" in repair_prompt and "src:src/calc.py:1-6" in repair_prompt


async def test_repeated_fabricated_citations_fail_closed_with_a_note() -> None:
    bad = final(evidence=[{"evidence_id": "log:999:1-2", "explanation": "?"}])
    notes: list[str] = []

    outcome = await investigate(settings(), result(), finding(), read_source=Reader(),
                                client=investigation_script(bad, bad), notes=notes)

    assert outcome is None
    assert notes == ["The investigation agent stopped: The answer cited evidence ids that "
                     "were never issued."]


async def test_an_answer_without_citations_is_rejected() -> None:
    notes: list[str] = []
    outcome = await investigate(settings(), result(), finding(), client=Script(
        final(evidence=[]), final(evidence=[]),
    ), notes=notes)
    assert outcome is None
    assert "schema" in notes[0]


async def test_patch_for_a_file_the_agent_never_read_is_dropped() -> None:
    script = Script(tools(call("search_log", job_id="501", text="failed")), final(evidence=[
        {"evidence_id": "logsearch:501:" + agent_module._short_hash("failed"),
         "explanation": "Assertion."}]))

    outcome = await investigate(settings(), result(), finding(), client=script)

    assert outcome is not None and outcome.patch is None
    assert outcome.patch_rejected_reason and "did not read" in outcome.patch_rejected_reason
    assert outcome.fix_confidence == MAX_FIX_CONFIDENCE_UNVERIFIED


async def test_patch_whose_context_does_not_match_the_source_is_dropped() -> None:
    wrong = GOOD_PATCH.replace("sum(values) - 1", "sum(values) - 2")
    outcome = await investigate(
        settings(), result(), finding(), read_source=Reader(),
        client=investigation_script(final(patch={"path": "src/calc.py", "diff": wrong})),
    )
    assert outcome is not None and outcome.patch is None
    assert "does not match" in (outcome.patch_rejected_reason or "")


async def test_patch_against_redacted_source_is_never_verified() -> None:
    outcome = await investigate(settings(), result(), finding(),
                                read_source=Reader(modified=True),
                                client=investigation_script())
    assert outcome is not None and outcome.patch is None
    assert "redaction" in (outcome.patch_rejected_reason or "")


async def test_read_source_is_limited_to_known_paths_and_a_read_budget() -> None:
    reader = Reader()
    script = Script(
        tools(call("read_source", 0, path="../../etc/passwd"),
              call("read_source", 1, path="src/calc.py"),
              call("read_source", 2, path="tests/test_calc.py"),
              call("read_source", 3, path="README.md")),
        final(patch=None, evidence=[{"evidence_id": "src:src/calc.py:1-6",
                                     "explanation": "Off by one."}]),
    )

    outcome = await investigate(settings(), result(), finding(), read_source=reader,
                                client=script, limits=AgentLimits(max_source_reads=2))

    assert outcome is not None
    assert reader.calls == ["src/calc.py", "tests/test_calc.py"]
    replies = [message["content"] for message in script.sent[1][0] if message["role"] == "tool"]
    assert replies[0].startswith("Tool error: Only files listed")
    assert replies[3] == ("Tool error: The source read budget for this investigation is used "
                          "up.")


async def test_the_loop_forces_a_final_answer_within_the_turn_budget() -> None:
    endless = [tools(call("list_jobs", index)) for index in range(3)]
    closing = final(patch=None, evidence=[{"evidence_id": "jobs", "explanation": "Jobs."}])
    script = Script(*endless, closing)

    outcome = await investigate(settings(), result(), finding(), client=script,
                                limits=AgentLimits(max_turns=4))

    assert outcome is not None and outcome.turns == 4
    assert script.sent[-1][1] == []  # No tools offered on the forced final turn.
    assert "budget reached" in script.sent[-1][0][-1]["content"]


async def test_tool_call_budget_stops_further_tools() -> None:
    many = tools(*(call("list_jobs", index) for index in range(5)))
    closing = final(patch=None, evidence=[{"evidence_id": "jobs", "explanation": "Jobs."}])
    script = Script(many, closing)

    outcome = await investigate(settings(), result(), finding(), client=script,
                                limits=AgentLimits(max_tool_calls=3))

    assert outcome is not None and script.sent[-1][1] == []


async def test_model_errors_and_bad_tool_arguments_fail_closed() -> None:
    class Broken:
        model = "broken"

        async def chat(self, messages, tools):
            raise httpx.ConnectError("offline")

    notes: list[str] = []
    assert await investigate(settings(), result(), finding(), client=Broken(),
                             notes=notes) is None
    assert notes == ["The investigation agent failed and returned nothing usable."]

    bad_args = {"id": "x", "function": {"name": "get_log_window", "arguments": "not json"}}
    script = Script(tools(bad_args), final(patch=None, evidence=[
        {"evidence_id": "finding:job.insufficient_evidence", "explanation": "Rule."}]))
    outcome = await investigate(settings(), result(), finding(), client=script)
    assert outcome is not None
    assert script.sent[1][0][-1]["content"] == "Tool error: arguments must be a JSON object."


async def test_unconfigured_agent_never_calls_anything() -> None:
    notes: list[str] = []
    assert await investigate(settings(agent_mode="disabled"), result(), finding(),
                             notes=notes) is None
    assert "not configured" in notes[0]


def test_agent_configured_requires_mode_and_model() -> None:
    assert agent_configured(settings())
    assert not agent_configured(settings(agent_mode="disabled"))
    assert not agent_configured(settings(agent_model="", llm_model=""))


async def test_http_client_sends_tools_and_never_leaks_the_llm_key_to_another_host() -> None:
    seen: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    transport = httpx.MockTransport(handle)
    explicit = OpenAICompatibleAgentClient(settings(agent_api_key=None), transport=transport)
    await explicit.chat([{"role": "user", "content": "hi"}], agent_module.TOOL_SPECS)
    inherited = OpenAICompatibleAgentClient(
        settings(agent_base_url="", agent_api_key=None), transport=transport,
    )
    await inherited.chat([{"role": "user", "content": "hi"}], [])

    assert str(seen[0].url) == "https://agent.invalid/v1/chat/completions"
    assert "authorization" not in seen[0].headers
    body = json.loads(seen[0].content)
    assert body["model"] == "agent-model" and body["tool_choice"] == "auto"
    assert str(seen[1].url) == "https://llm.invalid/v1/chat/completions"
    assert seen[1].headers["authorization"] == f"Bearer {LLM_KEY}"
    assert "tools" not in json.loads(seen[1].content)


async def test_http_errors_from_the_endpoint_fail_closed() -> None:
    client = OpenAICompatibleAgentClient(
        settings(), transport=httpx.MockTransport(lambda request: httpx.Response(500)),
    )
    notes: list[str] = []
    assert await investigate(settings(), result(), finding(), client=client,
                             notes=notes) is None
    assert notes == ["The investigation agent stopped: The agent endpoint returned HTTP 500."]


async def test_editing_the_prompt_file_changes_what_the_model_is_told(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = Path(__file__).resolve().parents[1] / "prompts"
    for item in source.glob("*.md"):
        (tmp_path / item.name).write_text(item.read_text(encoding="utf-8"), encoding="utf-8")
    (tmp_path / "agent_system.md").write_text("House rules: check the Makefile first.\n",
                                              encoding="utf-8")
    monkeypatch.setenv("PIPELINELENS_PROMPTS_DIR", str(tmp_path))
    script = Script(final(patch=None, evidence=[
        {"evidence_id": "finding:job.insufficient_evidence", "explanation": "Rule."}]))

    outcome = await investigate(settings(), result(), finding(), client=script)

    assert outcome is not None
    assert script.sent[0][0][0]["content"] == "House rules: check the Makefile first."
    assert outcome.prompt_versions["agent_system"] == load_prompt(
        "agent_system", tmp_path).version


def test_every_skill_pack_ships_investigation_steps() -> None:
    packs = load_skill_packs()
    assert packs and all(pack.investigate for pack in packs)


@pytest.mark.parametrize(("diff", "reason"), [
    ("no hunks here", "no hunks"),
    ("--- a/other.py\n+++ b/other.py\n@@ -1 +1 @@\n-x\n+y\n", "different file"),
    ("@@ -1,1 +1,1 @@\n-def total(values):\n+def total(values):\n", "no change"),
    ("@@ -1,0 +1,1 @@\n+import os\n", "Pure insertions"),
    ("@@ -1,1 +1,1 @@\n-    return 0\n+    return 1\n", None),
])
def test_verify_patch_rules(diff: str, reason: str | None) -> None:
    source = CiConfigFile(path="src/calc.py", ref=SHA, content=CALC)
    canonical, why = verify_patch("src/calc.py", diff, source)
    if reason is None:
        assert canonical is not None and "+    return 1" in canonical and why == ""
    else:
        assert canonical is None and reason in why


def test_verify_patch_rejects_ambiguous_context_and_credential_content() -> None:
    source = CiConfigFile(path="a.py", ref=SHA, content="x = 1\nx = 1\n")
    assert verify_patch("a.py", "@@ -9,1 +9,1 @@\n-x = 1\n+x = 2\n", source)[1] == (
        "The patch context is ambiguous.")
    single = CiConfigFile(path="a.py", ref=SHA, content="x = 1\n")
    leaked = f"@@ -1,1 +1,1 @@\n-x = 1\n+API_TOKEN={LOG_SECRET}\n"
    assert "credential" in verify_patch("a.py", leaked, single)[1]


def test_verify_patch_applies_multiple_hunks_with_shifted_line_numbers() -> None:
    content = "\n".join(f"line {number}" for number in range(1, 31)) + "\n"
    source = CiConfigFile(path="big.txt", ref=SHA, content=content)
    diff = ("@@ -2,1 +2,2 @@\n-line 2\n+line 2a\n+line 2b\n"
            "@@ -25,1 +26,1 @@\n-line 25\n+line 25 changed\n")
    canonical, why = verify_patch("big.txt", diff, source)
    assert why == "" and canonical is not None
    assert "+line 2b" in canonical and "+line 25 changed" in canonical
