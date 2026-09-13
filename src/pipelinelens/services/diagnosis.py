"""Evidence-constrained deterministic diagnosis used with or without an LLM."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import replace

from pipelinelens.domain import (
    DeploymentComponentFailure,
    DiagnosisResult,
    EvidenceCitation,
    FailureFingerprint,
    JobSourceLocation,
    LogChunk,
    SimilarIncident,
)
from pipelinelens.services.findings import FindingEvidence, _finding_for_signal
from pipelinelens.services.logs import FailureSignal, failure_signals, redact_log
from pipelinelens.services.redaction import redact_text


def _ranked_signals(chunks: list[LogChunk]) -> list[tuple[FailureSignal, LogChunk]]:
    ranked: list[tuple[FailureSignal, LogChunk]] = []
    for chunk in chunks:
        for signal in failure_signals(redact_log(chunk.content).content):
            original_line = (
                chunk.line_start + signal.index
                if signal.line is not None and not chunk.chunk_id.startswith("log-retained-")
                else None
            )
            ranked.append((replace(signal, line=original_line), chunk))
    return sorted(ranked, key=lambda item: (-item[0].priority, item[1].line_start, item[0].index))


def build_deterministic_diagnosis(
    fingerprint: FailureFingerprint,
    chunks: list[LogChunk],
    job_source: JobSourceLocation | None,
    similar_incidents: Iterable[SimilarIncident] = (),
    component_failures: list[DeploymentComponentFailure] | None = None,
) -> DiagnosisResult:
    """Adapt the same explicit evidence rules to the existing diagnosis contract.

    This legacy call has no job metadata. It does not infer job/pipeline outcome from
    names or historic fingerprints; ``diagnose_job`` is the status-aware public API.
    """

    ranked = _ranked_signals(chunks)
    citations: list[EvidenceCitation] = []
    for signal, chunk in ranked[:3]:
        if any(item.evidence_chunk_id == chunk.chunk_id for item in citations):
            continue
        location = (
            f"Original log line {signal.line}" if signal.line is not None
            else "Retained log excerpt; original line number unknown after truncation"
        )
        citations.append(EvidenceCitation(
            evidence_chunk_id=chunk.chunk_id, source_type="job_log",
            explanation=redact_text(f"{location}: {signal.text}"),
        ))
    if not ranked and chunks:
        citations.append(EvidenceCitation(
            evidence_chunk_id=chunks[0].chunk_id, source_type="job_log",
            explanation="The supplied log excerpt contains no explicit causal failure diagnostic.",
        ))
    if job_source:
        citations.append(
            EvidenceCitation(
                evidence_chunk_id=(
                    f"yaml:{job_source.path}:{job_source.line_start}-{job_source.line_end}"
                ),
                source_type="ci_yaml",
                explanation=(
                    f"The selected job maps to `{job_source.job_key}` in the selected "
                    "CI configuration."
                ),
            )
        )

    similar = list(similar_incidents)
    for incident in similar[:2]:
        citations.append(
            EvidenceCitation(
                evidence_chunk_id=f"incident:{incident.incident_id}",
                source_type="historical_incident",
                explanation=f"Similar incident with a {incident.similarity:.0%} retrieval score.",
            )
        )

    incident_ids = [incident.incident_id for incident in similar[:5]]
    if ranked:
        signal = ranked[0][0]
        finding = _finding_for_signal(signal, [FindingEvidence(text=signal.text, line=signal.line)])
        # A long Salesforce table can span bounded chunks. Use structured component details
        # only when the retained table header itself corroborates their origin.
        if signal.rule_id == "salesforce.component_failure" and component_failures:
            dependencies = [item for item in component_failures if "referenced by" in item.problem]
            if dependencies:
                detail = dependencies[0]
                finding = _finding_for_signal(
                    replace(signal, rule_id="salesforce.metadata_dependency", text=redact_text(
                        f"{detail.metadata_type} {detail.component_name}: {detail.problem}"
                    )), [],
                )
        return DiagnosisResult(
            failure_category=finding.category,
            confidence=0.42 if finding.confidence == "unknown" else 0.96,
            summary=finding.title,
            likely_root_cause=finding.explanation,
            evidence=citations,
            safe_next_steps=finding.fix,
            missing_information=["Original line numbering for omitted log spans."]
            if signal.line is None else [],
            similar_incident_ids=incident_ids,
        )
    no_failure = fingerprint.category == "no_failure_observed"
    return DiagnosisResult(
        failure_category="no_failure_observed" if no_failure else "unknown",
        confidence=0.9 if no_failure else 0.3,
        summary="No failure observed in the supplied log" if no_failure
        else "Insufficient evidence to establish a cause",
        likely_root_cause="No explicit causal error is present in the supplied evidence. "
        "Warning text, license numbers and test names are not failures. This limited trace "
        "does not verify the intended package or deployment outcome.",
        evidence=citations,
        safe_next_steps=["Compare the intended package parameter and deployment receipt; obtain "
                         "missing sanitized command output before proposing a correction."],
        missing_information=["Selected-job status and intended package/deployment receipt."],
        similar_incident_ids=incident_ids,
    )


def validate_diagnosis_citations(diagnosis: DiagnosisResult, allowed_ids: set[str]) -> bool:
    """Reject LLM output that cites evidence outside the retrieval bundle."""

    return all(citation.evidence_chunk_id in allowed_ids for citation in diagnosis.evidence)
