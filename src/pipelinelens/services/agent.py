"""Opt-in, read-only investigation agent for findings the deterministic rules cannot resolve.

The agent runs a bounded tool-calling loop against any OpenAI-compatible chat endpoint
(OpenAI, Ollama's ``/v1``, vLLM, LiteLLM, Gemini's OpenAI endpoint, ...). It can only *read*
evidence PipelineLens already holds or is allowed to fetch: redacted job logs, CI
configuration, the changed-file list, the repository tree, skill packs, and source files at
the failed pipeline commit. There is no tool that writes, reruns, approves or deploys.

Guarantees, enforced in code rather than by the prompt:
  - Every tool result is redacted and size-bounded, and receives an evidence id.
  - The final answer must cite at least one id, and only ids actually issued in this run.
  - A patch is kept only if it applies exactly to a source file the agent read at the
    pipeline commit, that read needed no redaction, and the resulting diff contains nothing
    redaction would alter. Otherwise it is dropped and the reason recorded.
  - Confidences are capped; the result never changes the deterministic finding or its
    remediation and is labelled as a separate, model-generated investigation.
  - Any error, timeout, malformed reply or exhausted budget fails closed to ``None``.

Prompts live in ``prompts/agent_system.md`` and ``prompts/agent_task.md``; per-category
investigation hints live in each skill pack's ``investigate:`` list.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from pipelinelens.config import Settings
from pipelinelens.domain import AnalysisSnapshot, CiConfigFile
from pipelinelens.services.agent_memory import AgentHistory
from pipelinelens.services.findings import Finding
from pipelinelens.services.inspection import InspectionResult
from pipelinelens.services.prompts import PromptError, load_prompt
from pipelinelens.services.redaction import redact_text
from pipelinelens.services.remediation import Remediation
from pipelinelens.services.skills import load_skill_packs

AGENT_NOTICE = (
    "Model-generated investigation from redacted, read-only evidence. It is separate from "
    "the local rule-based diagnosis, is not a calibrated probability, and any patch is "
    "unapplied and untested. Review every cited item before acting."
)
MAX_CAUSE_CONFIDENCE = 70
MAX_FIX_CONFIDENCE_VERIFIED = 50
MAX_FIX_CONFIDENCE_UNVERIFIED = 25
MAX_TOOL_RESULT_CHARS = 6_000
MAX_LOG_WINDOW_LINES = 150
MAX_SOURCE_WINDOW_LINES = 250
MAX_SEARCH_MATCHES = 30
MAX_DIFF_CHARS = 12_000
MAX_TEXT_CHARS = 2_000
MAX_LIST_ITEMS = 8

SourceReader = Callable[[str], Awaitable[CiConfigFile | None]]


class AgentError(RuntimeError):
    """Internal failure; the message is static and safe to show."""


@dataclass(frozen=True, slots=True)
class AgentLimits:
    max_turns: int = 8
    max_tool_calls: int = 16
    max_source_reads: int = 6
    max_context_chars: int = 80_000


class AgentCitation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: str
    explanation: str


class AgentPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    path: str
    diff: str
    verified: Literal[True] = True
    basis: str = (
        "Applies exactly to the file read at the failed pipeline commit. Not applied, "
        "built or tested."
    )


class AgentStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str
    arguments: str
    evidence_id: str | None = None
    result_chars: int = 0


class AgentInvestigation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model: str
    rule_id: str
    job_id: str | None = None
    failure_category: str
    summary: str
    likely_root_cause: str
    cause_confidence: int = Field(ge=0, le=100)
    fix_confidence: int = Field(ge=0, le=100)
    evidence: list[AgentCitation]
    next_steps: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    patch: AgentPatch | None = None
    patch_rejected_reason: str | None = None
    steps: list[AgentStep] = Field(default_factory=list)
    turns: int = 0
    prompt_versions: dict[str, str] = Field(default_factory=dict)
    notice: str = AGENT_NOTICE
    auto_apply_allowed: Literal[False] = False


class _AnswerPatch(BaseModel):
    path: str
    diff: str


class _Answer(BaseModel):
    """What the model must return. Extra keys are ignored, not trusted."""

    failure_category: str = Field(min_length=1, max_length=80)
    summary: str = Field(min_length=1)
    likely_root_cause: str = Field(min_length=1)
    cause_confidence: int = Field(ge=0, le=100)
    fix_confidence: int = Field(ge=0, le=100)
    evidence: list[AgentCitation] = Field(min_length=1)
    next_steps: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    patch: _AnswerPatch | None = None


class AgentChatClient(Protocol):
    model: str

    async def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict:
        """Return one assistant message in OpenAI chat format (content and/or tool_calls)."""
        ...


class OpenAICompatibleAgentClient:
    """Minimal tool-calling client for any ``/chat/completions`` endpoint."""

    def __init__(self, settings: Settings, *, transport: httpx.AsyncBaseTransport | None = None):
        explicit = bool(settings.agent_base_url)
        self.base_url = (settings.agent_base_url or settings.llm_base_url).rstrip("/")
        self.model = settings.agent_model or settings.llm_model
        # Never send the generic LLM key to a different, explicitly configured agent host.
        self._api_key = settings.agent_api_key or (None if explicit else settings.llm_api_key)
        self._transport = transport

    async def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> dict:
        payload: dict[str, Any] = {"model": self.model, "temperature": 0.1, "messages": messages}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        async with httpx.AsyncClient(
            timeout=60.0, trust_env=False, follow_redirects=False, transport=self._transport,
        ) as client:
            response = await client.post(
                f"{self.base_url}/chat/completions", json=payload, headers=headers,
            )
        if response.status_code != 200:
            raise AgentError(f"The agent endpoint returned HTTP {response.status_code}.")
        choices = response.json().get("choices")
        message = choices[0].get("message") if isinstance(choices, list) and choices else None
        if not isinstance(message, dict):
            raise AgentError("The agent endpoint returned no message.")
        return message


def agent_configured(settings: Settings) -> bool:
    """True when agent mode is enabled with a model and somewhere to send it. No I/O."""
    if settings.agent_mode != "openai-compatible":
        return False
    return bool((settings.agent_model or settings.llm_model)
                and (settings.agent_base_url or settings.llm_base_url))


def _tool(name: str, description: str, properties: dict[str, Any] | None = None,
          required: tuple[str, ...] = ()) -> dict[str, Any]:
    return {"type": "function", "function": {
        "name": name, "description": description,
        "parameters": {"type": "object", "properties": properties or {},
                       "required": list(required), "additionalProperties": False},
    }}


_INT = {"type": "integer", "minimum": 1}
TOOL_SPECS: list[dict[str, Any]] = [
    _tool("list_jobs", "List the pipeline's jobs with stage, status and failure reason."),
    _tool("get_log_window", "Read numbered lines of one job's redacted log (max 150 lines).",
          {"job_id": {"type": "string"}, "start_line": _INT, "end_line": _INT},
          ("job_id", "start_line", "end_line")),
    _tool("search_log", "Case-insensitive literal text search in one job's redacted log.",
          {"job_id": {"type": "string"}, "text": {"type": "string", "minLength": 2}},
          ("job_id", "text")),
    _tool("get_ci_config", "Without path: list CI config files. With path: read that file.",
          {"path": {"type": "string"}}),
    _tool("list_changed_files", "List files changed by the pipeline's commit or merge request."),
    _tool("list_repository_files", "List repository file paths, optionally under a prefix.",
          {"prefix": {"type": "string"}}),
    _tool("read_source", "Read numbered lines of a repository file at the failed pipeline "
          "commit (max 250 lines per call). Required before proposing a patch to it.",
          {"path": {"type": "string"}, "start_line": _INT, "end_line": _INT}, ("path",)),
    _tool("get_skill_pack", "Curated runbook, safe actions and investigation steps for a "
          "failure category.", {"category": {"type": "string"}}, ("category",)),
    _tool("search_history", "Search this project's local history: human-confirmed fixes "
          "for this rule (always first), similar past failed jobs, and past incidents. "
          "Optional query text narrows similarity ranking.", {"query": {"type": "string"}}),
]


def _numbered(lines: list[str], start: int) -> str:
    return "\n".join(f"{start + index:>5}| {line}" for index, line in enumerate(lines))


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]


@dataclass
class _Toolbox:
    result: InspectionResult
    read_source_at_sha: SourceReader | None
    limits: AgentLimits
    history: AgentHistory | None = None
    evidence: dict[str, str] = field(default_factory=dict)
    sources: dict[str, CiConfigFile] = field(default_factory=dict)
    source_reads: int = 0

    def issue(self, evidence_id: str, label: str) -> str:
        self.evidence[evidence_id] = label
        return evidence_id

    def _snapshot(self, job_id: object) -> AnalysisSnapshot:
        for snapshot in self.result.analyses:
            if snapshot.job.external_id == str(job_id):
                return snapshot
        known = ", ".join(item.job.external_id for item in self.result.analyses) or "none"
        raise AgentError(f"No log is available for that job. Jobs with logs: {known}.")

    def _known_paths(self) -> set[str]:
        paths = {entry.path for entry in self.result.project_structure
                 if entry.entry_type == "file"}
        paths.update(item.path for item in self.result.config_bundle)
        for change in self.result.changes:
            paths.update(str(change[key]) for key in ("new_path", "path")
                         if isinstance(change.get(key), str))
        return paths

    async def call(self, name: str, args: dict[str, Any]) -> tuple[str | None, str]:
        """Return (evidence_id, text). Tool errors come back as text for the model."""
        try:
            evidence_id, text = await self._dispatch(name, args)
        except AgentError as error:
            return None, f"Tool error: {error}"
        except (TypeError, ValueError):
            return None, "Tool error: invalid arguments for this tool."
        text = redact_text(text)
        if len(text) > MAX_TOOL_RESULT_CHARS:
            text = text[:MAX_TOOL_RESULT_CHARS] + "\n[truncated; request a narrower range]"
        return evidence_id, f"[{evidence_id}]\n{text}"

    async def _dispatch(self, name: str, args: dict[str, Any]) -> tuple[str, str]:
        if name == "list_jobs":
            rows = [f"{job.external_id}\t{job.name}\tstage={job.stage}\tstatus={job.status}"
                    f"\tfailure_reason={job.failure_reason}\tallow_failure={job.allow_failure}"
                    for job in self.result.jobs]
            return self.issue("jobs", "Pipeline job list"), "\n".join(rows) or "No jobs."
        if name == "get_log_window":
            snapshot = self._snapshot(args["job_id"])
            lines = snapshot.redacted_log.splitlines()
            start = max(1, int(args["start_line"]))
            end = min(len(lines), int(args["end_line"]), start + MAX_LOG_WINDOW_LINES - 1)
            if start > len(lines):
                raise AgentError(f"The log has only {len(lines)} lines.")
            evidence_id = self.issue(f"log:{snapshot.job.external_id}:{start}-{end}",
                                     f"Job {snapshot.job.name} log lines {start}-{end}")
            return evidence_id, _numbered(lines[start - 1:end], start)
        if name == "search_log":
            snapshot = self._snapshot(args["job_id"])
            needle = str(args["text"]).casefold()
            if len(needle) < 2:
                raise AgentError("Search text must be at least 2 characters.")
            hits = [(number, line) for number, line in
                    enumerate(snapshot.redacted_log.splitlines(), 1) if needle in line.casefold()]
            evidence_id = self.issue(
                f"logsearch:{snapshot.job.external_id}:{_short_hash(needle)}",
                f"Job {snapshot.job.name} log search",
            )
            body = "\n".join(f"{number:>5}| {line}" for number, line in hits[:MAX_SEARCH_MATCHES])
            more = len(hits) - MAX_SEARCH_MATCHES
            suffix = f"\n[{more} more matches omitted]" if more > 0 else ""
            return evidence_id, (body + suffix) if hits else "No matches."
        if name == "get_ci_config":
            path = args.get("path")
            if not path:
                listing = "\n".join(item.path for item in self.result.config_bundle)
                return self.issue("ci:index", "CI configuration file list"), listing or "None."
            config = next((item for item in self.result.config_bundle if item.path == path), None)
            if config is None:
                raise AgentError("That CI file is not in the loaded configuration bundle.")
            evidence_id = self.issue(f"ci:{config.path}", f"CI configuration {config.path}")
            return evidence_id, _numbered(config.content.splitlines(), 1)
        if name == "list_changed_files":
            rows = []
            for change in self.result.changes[:200]:
                path = change.get("new_path") or change.get("path")
                flags = [flag for flag in ("new_file", "deleted_file", "renamed_file")
                         if change.get(flag)]
                rows.append(f"{path}{' (' + ', '.join(flags) + ')' if flags else ''}")
            return self.issue("changes", "Changed files"), "\n".join(rows) or "No changes known."
        if name == "list_repository_files":
            prefix = str(args.get("prefix") or "")
            paths = sorted(entry.path for entry in self.result.project_structure
                           if entry.entry_type == "file" and entry.path.startswith(prefix))
            body = "\n".join(paths[:300]) + (f"\n[{len(paths) - 300} more]" if len(paths) > 300
                                             else "")
            return self.issue(f"tree:{prefix or '/'}", "Repository file list"), body or "None."
        if name == "read_source":
            return await self._read_source(args)
        if name == "get_skill_pack":
            category = str(args["category"])
            packs = [pack for pack in load_skill_packs() if category in pack.categories]
            if not packs:
                names = sorted({item for pack in load_skill_packs() for item in pack.categories})
                raise AgentError(f"No skill pack for that category. Known: {', '.join(names)}.")
            pack = packs[0]
            body = "\n".join([
                f"Title: {pack.title}",
                "Required evidence: " + "; ".join(pack.required_evidence),
                "Investigate:\n" + "\n".join(f"- {step}" for step in pack.investigate),
                "Safe actions: " + "; ".join(pack.safe_actions),
                "Prohibited actions: " + "; ".join(pack.prohibited_actions),
                "Runbook:\n" + pack.runbook[:2_500],
            ])
            return self.issue(pack.evidence_id, f"Skill pack {pack.title}"), body
        if name == "search_history":
            if self.history is None or not self.history.items:
                return self.issue("history:none", "No local history"), "No local history."
            hits = self.history.search(str(args.get("query") or ""))
            if not hits:
                return self.issue("history:none", "No local history"), "No similar history."
            blocks = []
            for score, hit in hits:
                self.issue(hit.evidence_id, hit.kind.replace("_", " "))
                label = "confirmed" if hit.kind == "confirmed_resolution" else f"score {score}"
                blocks.append(f"[{hit.evidence_id}] ({hit.kind}, {label})\n{hit.text[:1_200]}")
            evidence_id = self.issue(
                f"history:search:{_short_hash(str(args.get('query') or ''))}", "History search",
            )
            return evidence_id, "\n\n".join(blocks)
        raise AgentError("Unknown tool.")

    async def _read_source(self, args: dict[str, Any]) -> tuple[str, str]:
        path = str(args["path"]).strip().lstrip("/")
        if path not in self._known_paths():
            raise AgentError("Only files listed in the repository tree, CI bundle or changed "
                             "files can be read. Use list_repository_files first.")
        source = self.sources.get(path)
        if source is None:
            bundled = next((item for item in self.result.config_bundle if item.path == path), None)
            if bundled is not None and self.result.pipeline and (
                bundled.ref == self.result.pipeline.commit_sha
            ):
                source = bundled
            else:
                if self.read_source_at_sha is None:
                    raise AgentError("Source reads are unavailable for this inspection.")
                if self.source_reads >= self.limits.max_source_reads:
                    raise AgentError("The source read budget for this investigation is used up.")
                self.source_reads += 1
                source = await self.read_source_at_sha(path)
                if source is None:
                    raise AgentError("That file could not be read at the pipeline commit.")
            self.sources[path] = source
        lines = source.content.splitlines()
        start = max(1, int(args.get("start_line") or 1))
        end = min(len(lines), int(args.get("end_line") or start + MAX_SOURCE_WINDOW_LINES - 1),
                  start + MAX_SOURCE_WINDOW_LINES - 1)
        evidence_id = self.issue(f"src:{path}:{start}-{end}", f"{path} lines {start}-{end}")
        header = f"{path} @ {source.ref[:12]} ({len(lines)} lines)"
        if source.source_modified:
            header += " -- contains redacted values; no patch can be verified for this file"
        return evidence_id, header + "\n" + _numbered(lines[start - 1:end], start)


_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def verify_patch(path: str, diff: str, source: CiConfigFile | None) -> tuple[str | None, str]:
    """Return (canonical_diff, "") if ``diff`` applies exactly to ``source``, else (None, why).

    The returned diff is regenerated from the applied result, so what is shown is exactly
    what the change does, whatever formatting the model used.
    """
    if source is None:
        return None, "The patch targets a file the agent did not read at the pipeline commit."
    if source.source_modified:
        return None, "The source needed redaction, so a patch cannot be verified against it."
    if len(diff) > MAX_DIFF_CHARS:
        return None, "The patch is larger than the review limit."
    original = source.content.splitlines()
    hunks: list[tuple[int, list[str], list[str]]] = []
    current: tuple[int, list[str], list[str]] | None = None
    for line in diff.replace("\r\n", "\n").split("\n"):
        if line.startswith(("--- ", "+++ ")) and current is None:
            named = line[4:].strip().split("\t")[0]
            if named not in {path, f"a/{path}", f"b/{path}", "/dev/null"}:
                return None, "The patch header names a different file."
            continue
        match = _HUNK.match(line)
        if match:
            current = (int(match[1]), [], [])
            hunks.append(current)
        elif current is None or line.startswith("\\"):
            continue
        elif line.startswith(" ") or line == "":
            current[1].append(line[1:])
            current[2].append(line[1:])
        elif line.startswith("-"):
            current[1].append(line[1:])
        elif line.startswith("+"):
            current[2].append(line[1:])
        else:
            return None, "The patch is not a valid unified diff."
    if not hunks:
        return None, "The patch has no hunks."
    updated = list(original)
    offset = 0
    floor = 0
    for start, old, new in hunks:
        while old and old[-1] == "" and new and new[-1] == "":  # trailing blank split artefact
            old, new = old[:-1], new[:-1]
        if not old:
            return None, "Pure insertions without context cannot be anchored safely."
        expected = start - 1 + offset
        if updated[expected:expected + len(old)] == old:
            at = expected
        else:
            found = [index for index in range(floor, len(updated) - len(old) + 1)
                     if updated[index:index + len(old)] == old]
            if len(found) != 1:
                return None, ("The patch context does not match the file at the pipeline "
                              "commit." if not found else "The patch context is ambiguous.")
            at = found[0]
        updated[at:at + len(old)] = new
        offset += len(new) - len(old)
        floor = at + len(new)
    if updated == original:
        return None, "The patch makes no change."
    canonical = "\n".join(difflib.unified_diff(
        original, updated, f"a/{source.path}", f"b/{source.path}", lineterm="", n=3,
    ))
    if redact_text(canonical) != canonical:
        return None, "The resulting diff contains credential-like content."
    return canonical, ""


def _parse_answer(content: str) -> _Answer:
    text = content.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fenced:
        text = fenced[1]
    elif not text.startswith("{"):
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            raise AgentError("The final answer was not a JSON object.")
        text = text[start:end + 1]
    try:
        return _Answer.model_validate(json.loads(text))
    except (ValueError, ValidationError) as error:
        raise AgentError("The final answer did not match the required schema.") from error


def _clip(value: str) -> str:
    return redact_text(value.strip())[:MAX_TEXT_CHARS]


def _task_values(result: InspectionResult, finding: Finding,
                 remediation: Remediation | None,
                 history: AgentHistory | None = None) -> dict[str, str]:
    evidence = "\n".join(
        f"- {'line ' + str(item.line) + ': ' if item.line else ''}"
        f"{'(' + item.path + ') ' if item.path else ''}{redact_text(item.text)[:800]}"
        for item in finding.evidence[:6]
    ) or "- none"
    if finding.confidence == "unknown":
        stop = "No deterministic rule matched this failure with enough evidence."
    elif remediation is not None and remediation.missing_information:
        stop = "The cause matched a rule, but no verified fix exists: " + "; ".join(
            remediation.missing_information[:3])
    else:
        stop = "The cause matched a rule, but no rule can produce a verified fix for it."
    failed = [f"{job.external_id} ({job.name}, stage {job.stage})" for job in result.jobs
              if job.status == "failed"]
    pipeline = result.pipeline
    return {
        "repository": result.repository.display_name,
        "pipeline_status": pipeline.status if pipeline else "unknown",
        "commit_sha": (pipeline.commit_sha or "unknown") if pipeline else "unknown",
        "failed_jobs": ", ".join(failed[:10]) or "none reported",
        "finding_id": f"finding:{finding.rule_id}",
        "rule_id": finding.rule_id, "category": finding.category,
        "title": redact_text(finding.title), "explanation": redact_text(finding.explanation),
        "confidence": finding.confidence, "evidence": evidence, "stop_reason": _clip(stop),
        "history_hint": history.hint() if history else "No local history is available.",
    }


class _Loop:
    def __init__(self, client: AgentChatClient, toolbox: _Toolbox, limits: AgentLimits):
        self.client = client
        self.toolbox = toolbox
        self.limits = limits
        self.steps: list[AgentStep] = []
        self.turns = 0
        self.chars = 0

    async def _chat(self, messages: list[dict[str, Any]], tools: bool) -> dict:
        self.turns += 1
        return await self.client.chat(messages, TOOL_SPECS if tools else [])

    async def run(self, messages: list[dict[str, Any]]) -> _Answer:
        repaired = False
        tool_calls = 0
        while True:
            last = self.turns >= self.limits.max_turns - 1
            out_of_budget = tool_calls >= self.limits.max_tool_calls or (
                self.chars >= self.limits.max_context_chars)
            if last or out_of_budget:
                messages.append({"role": "user", "content": (
                    "Investigation budget reached. Reply now with the final JSON object only, "
                    "citing only evidence ids you have been shown.")})
            reply = await self._chat(messages, tools=not (last or out_of_budget))
            calls = reply.get("tool_calls") or []
            if calls and not (last or out_of_budget):
                messages.append({"role": "assistant", "content": reply.get("content") or "",
                                 "tool_calls": calls})
                for call in calls:
                    tool_calls += 1
                    text = await self._run_tool(call)
                    self.chars += len(text)
                    messages.append({"role": "tool", "tool_call_id": str(call.get("id", "")),
                                     "content": text})
                continue
            content = reply.get("content")
            if not isinstance(content, str) or not content.strip():
                raise AgentError("The agent returned an empty final answer.")
            try:
                answer = _parse_answer(content)
                unknown = [item.evidence_id for item in answer.evidence
                           if item.evidence_id not in self.toolbox.evidence]
                if unknown:
                    raise AgentError("The answer cited evidence ids that were never issued.")
                return answer
            except AgentError as error:
                if repaired or self.turns >= self.limits.max_turns:
                    raise
                repaired = True
                messages.append({"role": "assistant", "content": content[:4_000]})
                messages.append({"role": "user", "content": (
                    f"{error} Valid ids: {', '.join(sorted(self.toolbox.evidence))}. "
                    "Reply with the corrected JSON object only.")})

    async def _run_tool(self, call: dict[str, Any]) -> str:
        function = call.get("function") if isinstance(call.get("function"), dict) else {}
        name = str(function.get("name", ""))
        raw = function.get("arguments") or "{}"
        try:
            args = json.loads(raw) if isinstance(raw, str) else dict(raw)
            if not isinstance(args, dict):
                raise ValueError
        except (ValueError, TypeError):
            args = None
        if args is None:
            evidence_id, text = None, "Tool error: arguments must be a JSON object."
        else:
            evidence_id, text = await self.toolbox.call(name, args)
        self.steps.append(AgentStep(
            tool=name[:60], arguments=redact_text(json.dumps(args, sort_keys=True)
                                                  if args is not None else str(raw))[:300],
            evidence_id=evidence_id, result_chars=len(text),
        ))
        return text


async def investigate(
    settings: Settings,
    result: InspectionResult,
    finding: Finding,
    remediation: Remediation | None = None,
    *,
    read_source: SourceReader | None = None,
    history: AgentHistory | None = None,
    client: AgentChatClient | None = None,
    limits: AgentLimits | None = None,
    notes: list[str] | None = None,
) -> AgentInvestigation | None:
    """Run one bounded, read-only investigation. Never raises; ``None`` on any failure.

    ``notes`` receives one safe sentence explaining a failure, when given.
    """
    active_limits = limits or AgentLimits(max_turns=settings.agent_max_turns)
    try:
        if client is None:
            if not agent_configured(settings):
                raise AgentError("The investigation agent is not configured.")
            client = OpenAICompatibleAgentClient(settings)
        system_prompt = load_prompt("agent_system")
        task_prompt = load_prompt("agent_task")
        toolbox = _Toolbox(result, read_source, active_limits, history)
        toolbox.issue(f"finding:{finding.rule_id}", f"Rule finding {finding.rule_id}")
        loop = _Loop(client, toolbox, active_limits)
        answer = await loop.run([
            {"role": "system", "content": system_prompt.render()},
            {"role": "user", "content": task_prompt.render(
                **_task_values(result, finding, remediation, history))},
        ])
        patch: AgentPatch | None = None
        rejected: str | None = None
        if answer.patch is not None:
            path = answer.patch.path.strip().lstrip("/")
            canonical, rejected = verify_patch(path, answer.patch.diff, toolbox.sources.get(path))
            if canonical is not None:
                patch, rejected = AgentPatch(path=path, diff=canonical), None
        fix_cap = MAX_FIX_CONFIDENCE_VERIFIED if patch else MAX_FIX_CONFIDENCE_UNVERIFIED
        return AgentInvestigation(
            model=_clip(getattr(client, "model", "") or "unknown")[:120],
            rule_id=finding.rule_id, job_id=finding.job_id,
            failure_category=_clip(answer.failure_category)[:80],
            summary=_clip(answer.summary), likely_root_cause=_clip(answer.likely_root_cause),
            cause_confidence=min(answer.cause_confidence, MAX_CAUSE_CONFIDENCE),
            fix_confidence=min(answer.fix_confidence, fix_cap),
            evidence=[AgentCitation(evidence_id=item.evidence_id,
                                    explanation=_clip(item.explanation))
                      for item in answer.evidence[:12]],
            next_steps=[_clip(item) for item in answer.next_steps[:MAX_LIST_ITEMS]],
            missing_information=[_clip(item)
                                 for item in answer.missing_information[:MAX_LIST_ITEMS]],
            patch=patch, patch_rejected_reason=rejected or None,
            steps=loop.steps, turns=loop.turns,
            prompt_versions={"agent_system": system_prompt.version,
                             "agent_task": task_prompt.version},
        )
    except AgentError as error:
        if notes is not None:
            notes.append(f"The investigation agent stopped: {error}")
    except PromptError as error:
        if notes is not None:
            notes.append(f"The investigation agent could not load its prompt: {error}")
    except Exception:  # noqa: BLE001 - fail closed; the local diagnosis must never break.
        if notes is not None:
            notes.append("The investigation agent failed and returned nothing usable.")
    return None
