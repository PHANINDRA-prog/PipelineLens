"""Bounded, in-memory inspection of selected GitLab job artifact summaries.

The reader deliberately recognizes one public, static path and never extracts an
archive to disk. Malformed or unsafe input produces fixed notes rather than
upstream archive or JSON error text.
"""

from __future__ import annotations

import io
import json
import math
import re
import unicodedata
import zipfile
import zlib
from typing import Any
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from pipelinelens.services.findings import Finding, FindingEvidence
from pipelinelens.services.redaction import redact_text

__all__ = ("ArtifactInspection", "inspect_job_artifact")

_SUMMARY_PATH = "datasync/deploy-summary.json"
_MAX_ARCHIVE_BYTES = 2 * 1024 * 1024
_MAX_ARCHIVE_ENTRIES = 64
_MAX_ENTRY_BYTES = 1024 * 1024
# Deployment archives also contain larger receipts. They are CRC-checked in
# chunks, never interpreted or retained; keep the JSON summary's tighter limit.
_MAX_OTHER_ENTRY_BYTES = 8 * 1024 * 1024
_MAX_TOTAL_UNCOMPRESSED_BYTES = 16 * 1024 * 1024
_MAX_JSON_DEPTH = 64
_MAX_FAILURE_ROWS = 20
_MAX_ROWS_TO_SCAN = 10_000
_MAX_ERROR_TEXT = 400
_MAX_JOB_URL_CHARS = 2_048
_READ_CHUNK_BYTES = 64 * 1024
_MAX_COUNTER_VALUE = 1_000_000_000

_NON_FAILURE_STATUSES = frozenset({
    "success", "succeeded", "passed", "ok", "updated", "update", "deployed",
    "created", "complete", "completed", "skipped", "skip", "ignored", "dry-run",
    "dry_run", "not-applicable", "not_applicable",
})
_CONNECTION_RESET = re.compile(
    r"\bconnection\s*reset(?:\s+by\s+peer)?\b|\bconnectionreseterror\b", re.I
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SAFE_JOB_PATH = re.compile(
    r"(?:/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)+/-/jobs/[1-9][0-9]{0,19}\Z"
)
_ZIP_SIGNATURES = (b"PK\x03\x04", b"PK\x05\x06")

_EMPTY_ARCHIVE_NOTE = "No job artifact archive was available for inspection."
_UNSAFE_ARCHIVE_NOTE = "The job artifact archive could not be inspected safely."
_NO_SUMMARY_NOTE = "No supported DataSync deploy summary was found in the artifact archive."
_UNSAFE_SUMMARY_NOTE = "The DataSync deploy summary could not be parsed safely."
_BOUNDED_FAILURES_NOTE = "DataSync field-mapping failure details were bounded for inspection."


class ArtifactInspection(BaseModel):
    """Redacted, deterministic artifact findings for a single GitLab job."""

    model_config = ConfigDict(extra="forbid")
    findings: list[Finding] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    recognized_paths: tuple[str, ...] = ()


class _UnsafeArtifact(ValueError):
    """Internal marker whose details must never reach artifact inspection output."""


def _result(
    *,
    findings: list[Finding] | None = None,
    notes: list[str] | None = None,
    recognized_paths: tuple[str, ...] = (),
) -> ArtifactInspection:
    return ArtifactInspection(
        findings=findings or [],
        notes=list(dict.fromkeys(notes or [])),
        recognized_paths=recognized_paths,
    )


def _has_control(value: str) -> bool:
    return any(unicodedata.category(character).startswith("C") for character in value)


def _is_normal_archive_name(name: str) -> bool:
    if (
        not name
        or name.startswith("/")
        or "\\" in name
        or _has_control(name)
        or unicodedata.normalize("NFC", name) != name
        or re.match(r"^[A-Za-z]:", name) is not None
    ):
        return False
    directory = name.endswith("/")
    pieces = name[:-1].split("/") if directory else name.split("/")
    return bool(pieces) and all(piece and piece not in {".", ".."} for piece in pieces)


def _entry_limit(entry: zipfile.ZipInfo) -> int:
    return _MAX_ENTRY_BYTES if entry.filename == _SUMMARY_PATH else _MAX_OTHER_ENTRY_BYTES


def _validate_entries(entries: list[zipfile.ZipInfo]) -> None:
    if len(entries) > _MAX_ARCHIVE_ENTRIES:
        raise _UnsafeArtifact
    total_uncompressed = 0
    for entry in entries:
        original_name = entry.orig_filename
        if (
            original_name != entry.filename
            or not _is_normal_archive_name(original_name)
            or entry.flag_bits & 0x1
            or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
            or entry.compress_size < 0
            or entry.file_size < 0
            or entry.compress_size > _MAX_ARCHIVE_BYTES
            or entry.file_size > _entry_limit(entry)
        ):
            raise _UnsafeArtifact
        total_uncompressed += entry.file_size
        if total_uncompressed > _MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise _UnsafeArtifact


def _verify_archive_contents(archive: zipfile.ZipFile, entries: list[zipfile.ZipInfo]) -> None:
    """Read every member in bounded chunks so ZipFile verifies member CRCs."""

    total_uncompressed = 0
    for entry in entries:
        entry_uncompressed = 0
        with archive.open(entry, "r") as member:
            while chunk := member.read(_READ_CHUNK_BYTES):
                entry_uncompressed += len(chunk)
                total_uncompressed += len(chunk)
                if (
                    entry_uncompressed > _entry_limit(entry)
                    or total_uncompressed > _MAX_TOTAL_UNCOMPRESSED_BYTES
                ):
                    raise _UnsafeArtifact


def _read_summary(archive: zipfile.ZipFile, entry: zipfile.ZipInfo) -> bytes:
    content = bytearray()
    with archive.open(entry, "r") as member:
        while chunk := member.read(_READ_CHUNK_BYTES):
            content.extend(chunk)
            if len(content) > _MAX_ENTRY_BYTES:
                raise _UnsafeArtifact
    return bytes(content)


def _json_depth_is_safe(content: str) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in content:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
        elif character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > _MAX_JSON_DEPTH:
                return False
        elif character in "]}":
            depth -= 1
            if depth < 0:
                return False
    return not in_string and depth == 0


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _UnsafeArtifact
        result[key] = value
    return result


def _reject_nonfinite(value: str) -> None:
    del value
    raise _UnsafeArtifact


def _strict_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError as error:
        raise _UnsafeArtifact from error
    if not math.isfinite(number):
        raise _UnsafeArtifact
    return number


def _parse_summary(content: bytes) -> dict[str, Any]:
    if len(content) > _MAX_ENTRY_BYTES:
        raise _UnsafeArtifact
    try:
        decoded = content.decode("utf-8")
    except UnicodeDecodeError as error:
        raise _UnsafeArtifact from error
    if not _json_depth_is_safe(decoded):
        raise _UnsafeArtifact
    try:
        summary = json.loads(
            decoded,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_nonfinite,
            parse_float=_strict_float,
        )
    except (json.JSONDecodeError, RecursionError, TypeError, ValueError) as error:
        raise _UnsafeArtifact from error
    if not isinstance(summary, dict):
        raise _UnsafeArtifact
    return summary


def _count_value(value: Any) -> int | None:
    if type(value) is int and 0 <= value <= _MAX_COUNTER_VALUE:
        return value
    return None


def _counter_items(container: Any, names: tuple[str, ...]) -> list[tuple[str, int]]:
    if not isinstance(container, dict):
        return []
    items: list[tuple[str, int]] = []
    for name in names:
        value = _count_value(container.get(name))
        if value is not None:
            items.append((name, value))
    return items


def _counter_text(summary: dict[str, Any]) -> str:
    groups: list[str] = []
    sections = (
        (
            "DataSync deploy",
            summary,
            ("count", "successCount", "failedCount", "skippedCount"),
        ),
        (
            "field mappings",
            summary.get("fieldMappings"),
            (
                "deployed", "updated", "success", "succeeded", "failed", "failure", "skipped",
                "count",
            ),
        ),
        (
            "object mappings",
            summary.get("mappings"),
            (
                "updated", "deployed", "success", "succeeded", "failed", "failure", "skipped",
                "count",
            ),
        ),
        (
            "value transformations",
            summary.get("valueTransformations"),
            (
                "updated", "deployed", "success", "succeeded", "failed", "failure", "skipped",
                "count",
            ),
        ),
    )
    for label, container, names in sections:
        items = _counter_items(container, names)
        if items:
            groups.append(f"{label}: " + ", ".join(f"{name}={value}" for name, value in items))
    return "; ".join(groups)


def _field_mapping_rows(summary: dict[str, Any]) -> tuple[list[Any], bool, int | None]:
    field_mappings = summary.get("fieldMappings")
    if isinstance(field_mappings, list):
        return field_mappings, False, None
    if not isinstance(field_mappings, dict):
        return [], False, None
    rows = field_mappings.get("failures")
    failed_count = next(
        (
            count
            for count in (
                _count_value(field_mappings.get("failed")),
                _count_value(field_mappings.get("failure")),
            )
            if count is not None
        ),
        None,
    )
    return (rows if isinstance(rows, list) else []), isinstance(rows, list), failed_count


def _normalized_status(row: dict[str, Any]) -> str | None:
    value = row.get("status")
    if not isinstance(value, str):
        return None
    normalized = value[:128].strip().casefold()
    return normalized or None


def _safe_error_texts(row: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for name in ("error", "message"):
        value = row.get(name)
        if not isinstance(value, str) or not value:
            continue
        try:
            redacted = redact_text(value)
        except (RecursionError, TypeError, ValueError):
            continue
        texts.append(" ".join(_CONTROL.sub(" ", redacted).split())[:_MAX_ERROR_TEXT])
    return texts


def _actual_failure(row: dict[str, Any], failures_list: bool) -> bool:
    status = _normalized_status(row)
    if status in _NON_FAILURE_STATUSES:
        return False
    if status is not None:
        return True
    return failures_list and bool(_safe_error_texts(row))


def _failure_state(summary: dict[str, Any]) -> tuple[bool, bool, bool]:
    rows, failures_list, failed_count = _field_mapping_rows(summary)
    actual_rows = 0
    connection_reset = False
    bounded_rows = False
    all_rows_explicitly_non_failure = bool(rows)
    for index, row in enumerate(rows):
        if index >= _MAX_ROWS_TO_SCAN:
            bounded_rows = True
            all_rows_explicitly_non_failure = False
            break
        if not isinstance(row, dict):
            all_rows_explicitly_non_failure = False
            continue
        status = _normalized_status(row)
        if status not in _NON_FAILURE_STATUSES:
            all_rows_explicitly_non_failure = False
        if not _actual_failure(row, failures_list):
            continue
        actual_rows += 1
        if actual_rows > _MAX_FAILURE_ROWS:
            bounded_rows = True
            break
        connection_reset = connection_reset or any(
            _CONNECTION_RESET.search(text) is not None for text in _safe_error_texts(row)
        )
    return (
        actual_rows > 0
        or (
            failed_count is not None
            and failed_count > 0
            and not all_rows_explicitly_non_failure
        ),
        connection_reset,
        bounded_rows,
    )


def _safe_source_url(job_web_url: str | None) -> str | None:
    if (
        not isinstance(job_web_url, str)
        or not job_web_url
        or len(job_web_url) > _MAX_JOB_URL_CHARS
        or "\\" in job_web_url
        or _has_control(job_web_url)
    ):
        return None
    try:
        if redact_text(job_web_url) != job_web_url:
            return None
        parsed = urlsplit(job_web_url)
        decoded_path = unquote(parsed.path)
    except (TypeError, ValueError):
        return None
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.endswith("/")
        or "\\" in decoded_path
        or _has_control(decoded_path)
        or _SAFE_JOB_PATH.fullmatch(parsed.path) is None
    ):
        return None
    path_parts = decoded_path.split("/")[1:]
    if not path_parts or any(not part or part in {".", ".."} for part in path_parts):
        return None
    source_url = f"{job_web_url}/artifacts/file/{_SUMMARY_PATH}"
    try:
        return source_url if redact_text(source_url) == source_url else None
    except (TypeError, ValueError):
        return None


def _finding(
    *,
    connection_reset: bool,
    counter_text: str,
    source_url: str | None,
) -> Finding:
    evidence_text = (
        f"DataSync deploy summary counters: {counter_text}. "
        "A bounded actual field-mapping failure reports a connection reset."
        if connection_reset
        else f"DataSync deploy summary counters: {counter_text}. "
        "A bounded actual field-mapping failure has no recognized safe error classification."
    )
    if connection_reset:
        return Finding(
            rule_id="rlp.datasync_field_mapping_connection_reset",
            severity="error",
            category="deployment_transport_failure",
            title="DataSync field mapping deployment encountered a connection reset",
            explanation=(
                "The deploy artifact directly records a non-success, non-skipped field-mapping "
                "failure with a connection reset. The artifact does not establish the underlying "
                "network cause."
            ),
            fix=[
                "Have the RLP DataSync and target-platform owners review target connectivity and "
                "service diagnostics for the deployment.",
                "Confirm whether any partial target state needs review before a controlled retry.",
            ],
            evidence=[FindingEvidence(
                text=redact_text(evidence_text), path=_SUMMARY_PATH, source_url=source_url
            )],
            confidence="observed",
            owner="RLP DataSync / target platform",
        )
    return Finding(
        rule_id="rlp.datasync_field_mapping_artifact_failure",
        severity="error",
        category="deployment_failure",
        title="DataSync field mapping deployment recorded a failure",
        explanation=(
            "The deploy artifact records a non-success, non-skipped field-mapping failure, but "
            "its bounded safe fields do not identify a specific cause."
        ),
        fix=[
            "Review the target-platform DataSync deployment diagnostics for the earliest error.",
            "Confirm target state before retrying a deployment with an unknown artifact error.",
        ],
        evidence=[FindingEvidence(
            text=redact_text(evidence_text), path=_SUMMARY_PATH, source_url=source_url
        )],
        confidence="unknown",
        owner="RLP DataSync / target platform",
    )


def inspect_job_artifact(
    archive: bytes,
    *,
    job_web_url: str | None = None,
) -> ArtifactInspection:
    """Inspect a bounded GitLab artifact ZIP without file or network I/O.

    Only ``datasync/deploy-summary.json`` is interpreted. Archive metadata and every member are
    checked before the summary is parsed so corrupt ZIPs, unsupported compression and CRC errors
    remain fixed, non-sensitive notes.
    """

    if not isinstance(archive, bytes) or not archive:
        return _result(notes=[_EMPTY_ARCHIVE_NOTE])
    if len(archive) > _MAX_ARCHIVE_BYTES or not archive.startswith(_ZIP_SIGNATURES):
        return _result(notes=[_UNSAFE_ARCHIVE_NOTE])
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as zip_archive:
            entries = zip_archive.infolist()
            _validate_entries(entries)
            summaries = [entry for entry in entries if entry.filename == _SUMMARY_PATH]
            if len(summaries) > 1:
                raise _UnsafeArtifact
            _verify_archive_contents(zip_archive, entries)
            if not summaries:
                return _result(notes=[_NO_SUMMARY_NOTE])
            summary_content = _read_summary(zip_archive, summaries[0])
    except (
        _UnsafeArtifact,
        zipfile.BadZipFile,
        zipfile.LargeZipFile,
        RuntimeError,
        OSError,
        EOFError,
        NotImplementedError,
        zlib.error,
    ):
        return _result(notes=[_UNSAFE_ARCHIVE_NOTE])
    try:
        summary = _parse_summary(summary_content)
    except _UnsafeArtifact:
        return _result(notes=[_UNSAFE_SUMMARY_NOTE], recognized_paths=(_SUMMARY_PATH,))

    has_failure, connection_reset, bounded_rows = _failure_state(summary)
    notes = [_BOUNDED_FAILURES_NOTE] if bounded_rows else []
    if not has_failure:
        return _result(notes=notes, recognized_paths=(_SUMMARY_PATH,))
    counters = _counter_text(summary) or "no bounded numeric counters were available"
    finding = _finding(
        connection_reset=connection_reset,
        counter_text=counters,
        source_url=_safe_source_url(job_web_url),
    )
    return _result(findings=[finding], notes=notes, recognized_paths=(_SUMMARY_PATH,))