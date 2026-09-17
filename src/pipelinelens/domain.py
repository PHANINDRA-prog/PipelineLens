"""Provider-neutral domain contracts used by API, analysis, and UI layers."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class ProviderName(StrEnum):
    GITHUB = "github"
    GITLAB = "gitlab"
    DEMO = "demo"


class DownloadState(StrEnum):
    PENDING = "pending"
    FETCHED = "fetched"
    REDACTED = "redacted"
    ANALYZED = "analyzed"
    FAILED = "failed"


class RepositoryRef(BaseModel):
    provider: ProviderName
    external_id: str
    owner: str
    name: str
    web_url: str
    default_branch: str | None = None
    ci_config_path: str | None = None

    @property
    def display_name(self) -> str:
        return f"{self.owner}/{self.name}"


class RepositoryTreeEntry(BaseModel):
    path: str
    entry_type: Literal["file", "directory"]


class ProviderIdentity(BaseModel):
    provider: ProviderName
    login: str
    display_name: str | None = None
    avatar_url: str | None = None


class CiConfigFile(BaseModel):
    path: str
    ref: str
    content: str
    content_sha: str | None = None
    source_url: str | None = None
    source_modified: bool = False


class CiConfigAccessEntry(BaseModel):
    """One CI configuration source inspected for read access at a pipeline ref."""

    path: str
    ref: str | None = None
    state: Literal["readable", "unreadable", "unresolved"]
    relationship: Literal["root", "local_include", "project_include", "unsupported_include"]
    detail: str
    source_url: str | None = None


class CiConfigAccessReport(BaseModel):
    """Bounded result of inspecting the CI YAML sources that control a pipeline."""

    entries: list[CiConfigAccessEntry] = Field(default_factory=list)
    complete: bool
    notes: list[str] = Field(default_factory=list)


class PipelineRun(BaseModel):
    external_id: str
    name: str
    status: str
    conclusion: str | None = None
    ref_name: str | None = None
    commit_sha: str | None = None
    web_url: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)


class PipelineJob(BaseModel):
    external_id: str
    name: str
    key: str | None = None
    stage: str | None = None
    status: str
    conclusion: str | None = None
    allow_failure: bool = False
    failure_reason: str | None = None
    web_url: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    raw: dict[str, Any] = Field(default_factory=dict, exclude=True)


class JobSourceLocation(BaseModel):
    path: str
    line_start: int
    line_end: int
    job_key: str
    source_url: str | None = None
    inherited_from: str | None = None
    match_confidence: float = Field(ge=0, le=1)


class PipelineNode(BaseModel):
    key: str
    display_name: str
    stage: str | None = None
    needs: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)
    script: list[str] = Field(default_factory=list)
    steps: list[str] = Field(default_factory=list)
    artifacts: list[str] = Field(default_factory=list)
    source: JobSourceLocation


class PipelineGraph(BaseModel):
    provider: ProviderName
    config_files: list[str]
    stages: list[str] = Field(default_factory=list)
    nodes: list[PipelineNode] = Field(default_factory=list)
    unresolved_includes: list[str] = Field(default_factory=list)


class LogChunk(BaseModel):
    chunk_id: str
    chunk_type: Literal["command", "error", "stack_trace", "test", "http", "context"]
    content: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    score: float = 0.0


class CodeReference(BaseModel):
    path: str
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=1)
    message: str | None = None
    source_url: str | None = None


class DeploymentComponentFailure(BaseModel):
    metadata_type: str
    component_name: str
    problem: str
    line: int | None = Field(default=None, ge=1)
    column: int | None = Field(default=None, ge=1)


class FailureFingerprint(BaseModel):
    digest: str
    category: str
    normalized_message: str
    command: str | None = None
    exit_code: int | None = None


class EvidenceCitation(BaseModel):
    evidence_chunk_id: str
    source_type: Literal["job_log", "ci_yaml", "historical_incident", "skill_pack", "local_corpus"]
    explanation: str


class DiagnosisResult(BaseModel):
    failure_category: str
    confidence: float = Field(ge=0, le=1)
    summary: str
    likely_root_cause: str
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    safe_next_steps: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    similar_incident_ids: list[str] = Field(default_factory=list)
    auto_remediation_allowed: Literal[False] = False
    generation: Literal["deterministic", "llm"] = "deterministic"


class AnalysisProgress(BaseModel):
    ci_configuration: DownloadState = DownloadState.PENDING
    job_log: DownloadState = DownloadState.PENDING
    sanitization: DownloadState = DownloadState.PENDING
    graph_analysis: DownloadState = DownloadState.PENDING
    retrieval: DownloadState = DownloadState.PENDING
    diagnosis: DownloadState = DownloadState.PENDING


class SimilarIncident(BaseModel):
    incident_id: str
    fingerprint: str
    category: str
    summary: str
    confirmed_resolution: str | None = None
    similarity: float = Field(ge=0, le=1)


class KnowledgeDocument(BaseModel):
    document_id: str
    source_label: str
    source_path: str
    content: str
    similarity: float = Field(ge=0, le=1)
    private_scope: bool = True


class RagEvidenceSource(BaseModel):
    evidence_id: str
    source_type: Literal["job_log", "ci_yaml", "historical_incident", "skill_pack", "local_corpus"]
    label: str
    verified: bool = False


class RagSummary(BaseModel):
    retrieval_enabled: bool = True
    context_char_count: int = Field(ge=0)
    sources: list[RagEvidenceSource] = Field(default_factory=list)
    llm_mode: str
    llm_model: str
    llm_used: bool = False
    llm_message: str


class LlmRuntimeStatus(BaseModel):
    mode: str
    model: str
    ready: bool
    message: str


class AnalysisSnapshot(BaseModel):
    analysis_id: str
    repository: RepositoryRef
    run: PipelineRun
    job: PipelineJob
    progress: AnalysisProgress
    config: CiConfigFile
    config_bundle: list[CiConfigFile] = Field(default_factory=list)
    graph: PipelineGraph
    job_source: JobSourceLocation | None = None
    redacted_log: str
    chunks: list[LogChunk]
    code_references: list[CodeReference] = Field(default_factory=list)
    component_failures: list[DeploymentComponentFailure] = Field(default_factory=list)
    fingerprint: FailureFingerprint
    similar_incidents: list[SimilarIncident] = Field(default_factory=list)
    diagnosis: DiagnosisResult
    rag: RagSummary | None = None
