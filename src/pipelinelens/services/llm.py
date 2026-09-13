"""Optional LLM synthesis constrained by redacted, retrieved evidence."""

from __future__ import annotations

import json
from typing import Protocol

import httpx

from pipelinelens.config import Settings, get_settings
from pipelinelens.domain import AnalysisSnapshot, DiagnosisResult, LlmRuntimeStatus
from pipelinelens.services.diagnosis import (
    build_deterministic_diagnosis,
    validate_diagnosis_citations,
)
from pipelinelens.services.retrieval import RetrievalBundle


class LlmClient(Protocol):
    async def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        """Return a JSON object string from a configured model endpoint."""


class LlmDiagnosisError(RuntimeError):
    """Raised when model output cannot be safely used as a diagnosis."""


class HttpLlmClient:
    """OpenAI-compatible and Ollama-compatible JSON completion client."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def complete_json(self, system_prompt: str, user_prompt: str) -> str:
        if self.settings.llm_mode == "openai-compatible":
            if not self.settings.llm_api_key:
                raise LlmDiagnosisError("An API key is required for openai-compatible mode.")
            return await self._openai_compatible(system_prompt, user_prompt)
        if self.settings.llm_mode == "ollama":
            return await self._ollama(system_prompt, user_prompt)
        raise LlmDiagnosisError(f"Unsupported LLM mode: {self.settings.llm_mode}")

    async def _openai_compatible(self, system_prompt: str, user_prompt: str) -> str:
        payload = {
            "model": self.settings.llm_model,
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        headers = {"Authorization": f"Bearer {self.settings.llm_api_key}"}
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                f"{self.settings.llm_base_url}/chat/completions", json=payload, headers=headers
            )
        response.raise_for_status()
        content = response.json().get("choices", [{}])[0].get("message", {}).get("content")
        if not isinstance(content, str):
            raise LlmDiagnosisError("The LLM response did not contain JSON content.")
        return content


async def get_llm_runtime_status(settings: Settings | None = None) -> LlmRuntimeStatus:
    """Report model readiness without sending any CI evidence to a provider."""

    active_settings = settings or get_settings()
    if active_settings.llm_mode == "disabled":
        return LlmRuntimeStatus(
            mode="disabled",
            model=active_settings.llm_model,
            ready=False,
            message=(
                "RAG retrieval is active, but LLM synthesis is disabled. "
                "Configure a local Ollama model or an approved OpenAI-compatible endpoint."
            ),
        )
    if active_settings.llm_mode == "openai-compatible":
        if active_settings.llm_api_key:
            return LlmRuntimeStatus(
                mode=active_settings.llm_mode,
                model=active_settings.llm_model,
                ready=True,
                message=(
                    "OpenAI-compatible synthesis is configured and will be validated on analysis."
                ),
            )
        return LlmRuntimeStatus(
            mode=active_settings.llm_mode,
            model=active_settings.llm_model,
            ready=False,
            message="Set PIPELINELENS_LLM_API_KEY to enable OpenAI-compatible synthesis.",
        )
    if active_settings.llm_mode == "ollama":
        base_url = active_settings.llm_base_url.rstrip("/").removesuffix("/api")
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                response = await client.get(f"{base_url}/api/tags")
            response.raise_for_status()
            model_names = {
                str(model.get("name"))
                for model in response.json().get("models", [])
                if isinstance(model, dict)
            }
        except (httpx.HTTPError, ValueError):
            return LlmRuntimeStatus(
                mode=active_settings.llm_mode,
                model=active_settings.llm_model,
                ready=False,
                message="Ollama is not reachable at the configured local endpoint.",
            )
        if active_settings.llm_model in model_names:
            return LlmRuntimeStatus(
                mode=active_settings.llm_mode,
                model=active_settings.llm_model,
                ready=True,
                message=(
                    "Local Ollama synthesis is ready. "
                    "Only the bounded redacted RAG context is sent."
                ),
            )
        return LlmRuntimeStatus(
            mode=active_settings.llm_mode,
            model=active_settings.llm_model,
            ready=False,
            message="Ollama is reachable, but the configured model has not been pulled.",
        )
    return LlmRuntimeStatus(
        mode=active_settings.llm_mode,
        model=active_settings.llm_model,
        ready=False,
        message="Unsupported LLM mode. Use disabled, ollama, or openai-compatible.",
    )

    async def _ollama(self, system_prompt: str, user_prompt: str) -> str:
        base_url = self.settings.llm_base_url.rstrip("/")
        endpoint = base_url if base_url.endswith("/api/chat") else f"{base_url}/api/chat"
        payload = {
            "model": self.settings.llm_model,
            "stream": False,
            "format": "json",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(endpoint, json=payload)
        response.raise_for_status()
        content = response.json().get("message", {}).get("content")
        if not isinstance(content, str):
            raise LlmDiagnosisError("The Ollama response did not contain JSON content.")
        return content


def _system_prompt() -> str:
    return "\n".join(
        [
            "You are PipelineLens, an evidence-first CI failure analyst.",
            "Return one valid JSON object only. Match this schema exactly:",
            '{"failure_category":"string","confidence":0.0,"summary":"string",'
            '"likely_root_cause":"string","evidence":[{"evidence_chunk_id":"string",'
            '"source_type":"job_log|ci_yaml|historical_incident|skill_pack|local_corpus","explanation":"string"}],'
            '"safe_next_steps":["string"],"missing_information":["string"],'
            '"similar_incident_ids":["string"],"auto_remediation_allowed":false}',
            (
                "Make claims only when cited evidence supports them. "
                "Every root-cause claim needs a citation."
            ),
            "Never reveal, infer, request, or fabricate secrets.",
            (
                "Never recommend automatic reruns, merges, approvals, deployments, "
                "credential updates, or config changes."
            ),
            "If evidence is insufficient, say so explicitly.",
        ]
    )


def _user_prompt(snapshot: AnalysisSnapshot, bundle: RetrievalBundle) -> str:
    return "\n".join(
        [
            f"Selected provider: {snapshot.repository.provider}",
            f"Selected repository: {snapshot.repository.display_name}",
            f"Selected job: {snapshot.job.name}",
            f"Deterministic category: {snapshot.fingerprint.category}",
            f"Fingerprint: {snapshot.fingerprint.normalized_message}",
            "Retrieved evidence follows. Cite only bracketed evidence IDs from this bundle.",
            bundle.context,
        ]
    )


class EvidenceConstrainedDiagnoser:
    """Use an LLM only when configured; otherwise retain the deterministic diagnosis."""

    def __init__(self, settings: Settings | None = None, client: LlmClient | None = None) -> None:
        self.settings = settings or get_settings()
        self.client = client or HttpLlmClient(self.settings)

    async def diagnose(
        self, snapshot: AnalysisSnapshot, bundle: RetrievalBundle
    ) -> DiagnosisResult:
        fallback = build_deterministic_diagnosis(
            snapshot.fingerprint,
            snapshot.chunks,
            snapshot.job_source,
            bundle.similar_incidents,
            snapshot.component_failures,
        )
        if self.settings.llm_mode == "disabled":
            return fallback
        try:
            raw_result = await self.client.complete_json(
                _system_prompt(), _user_prompt(snapshot, bundle)
            )
            diagnosis = DiagnosisResult.model_validate(json.loads(raw_result))
            if not diagnosis.evidence:
                raise LlmDiagnosisError("The LLM response did not cite evidence.")
            if not validate_diagnosis_citations(diagnosis, bundle.allowed_evidence_ids):
                raise LlmDiagnosisError(
                    "The LLM response cited evidence outside the retrieval bundle."
                )
            return diagnosis.model_copy(
                update={"generation": "llm", "auto_remediation_allowed": False}
            )
        except (LlmDiagnosisError, ValueError, httpx.HTTPError):
            return fallback
