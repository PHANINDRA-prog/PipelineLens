"""Deterministic CI log parsing, chunking, categorization, and fingerprinting."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Literal

from pipelinelens.domain import (
    CodeReference,
    DeploymentComponentFailure,
    FailureFingerprint,
    LogChunk,
)
from pipelinelens.services.redaction import RedactionResult, SecretRedactor

_COMMAND_PATTERN = re.compile(r"^\s*(?:\$ |\+ |Run\s+|Executing\s+|> )(.+)$")
_EXIT_CODE_PATTERN = re.compile(
    r"(?i)\bexit(?:ed)?(?:\s+with)?(?:\s+(?:code|status))?\s*[:=]?\s*(\d+)\b"
)
_ANSI_ESCAPE_PATTERN = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\r\n]*?(?:\x07|\x1b\\)"
)
_TRACE_PREFIX_PATTERN = re.compile(
    r"^\s*\d{4}-\d{2}-\d{2}T\S+\s+(?:\d+[A-Z]\s+)?"
)
_OMISSION_PATTERN = re.compile(
    r"\[PIPELINELENS(?:_LOG)?_(?:TRUNCATED|BOUNDED|OMITTED)[^\]]*\]", re.IGNORECASE
)
_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
)
_WARNING_PATTERN = re.compile(
    r"(?i)^(?:(?:INFO|DEBUG|TRACE)\s*:?\s*)?\[?warn(?:ing)?\]?\b|:\s*warning\b"
)
_BENIGN_PATTERN = re.compile(
    r"(?i)^(?:(?:\[(?:INFO|DEBUG|TRACE|ERROR)\]|INFO|DEBUG|TRACE|ERROR)\s*:?\s*)?(?:"
    r"(?:\d+\s+warning\(s\)\s*)?0\s+(?:error(?:\(s\)|s)?|failures?|failed)\b|"
    r"(?:errors?|failures?|failed)\s*[:=]\s*0\b|"
    r"(?:component|test) failures\s*\[\s*0\s*\]|"
    r"(?:no|zero)\s+(?:errors?|failures?)\b|"
    r"(?:expected|expecting|assert(?:ing)?)\b|"
    r"[\u2713\u2714\u221a]\s|ok\s+\d+\b|"
    r"(?:PASSED|PASS|XFAIL|XFAILED|SKIPPED)\s|"
    r"(?:tests?/\S+|\S*test\S*|\S*spec\S*)\s+.*?\b(?:PASSED|XFAIL|SKIPPED)\b"
    r")"
)
_GENERIC_FOOTER_PATTERN = re.compile(
    r"(?i)^(?:ERROR:\s*)?(?:job failed|process completed)"
    r"(?::?\s+(?:with\s+)?exit (?:code|status) [1-9]\d*)?\.?$"
)
_SUCCESS_PATTERN = re.compile(
    r"(?i)^(?:job succeeded|build succeeded\.?|deployment (?:succeeded|successful)|"
    r"(?:INFO\s+)?EXECUTION SUCCESS)\s*$"
)
_COMPONENT_FAILURE_PATTERN = re.compile(r"(?i)\bcomponent failures\s*\[\s*[1-9]\d*\s*\]")
_TEST_FAILURE_SECTION_PATTERN = re.compile(r"(?i)\btest failures\s*\[\s*[1-9]\d*\s*\]")
DATASYNC_AMBIGUOUS_PATTERN = re.compile(
    r"^\s*\d+\s*\|\s*(?P<target>[^|]+?)\s*\|\s*FAIL\s*\|\s*AMBIGUOUS\b", re.IGNORECASE
)
_HTTP_STATUS_PREFIX = (
    r"\b(?:HTTP(?:/\d(?:\.\d)?)?\s+(?:status\s*)?|"
    r"(?:response\s*status|status[_ ]code)\s*[:=]?\s*)"
)
_CSHARP_LOCATION_PATTERN = re.compile(
    r"(?P<path>(?:[A-Za-z]:)?[^\n:]+?\.cs)\("
    r"(?P<line>\d+)(?:,(?P<column>\d+))?\)\s*:\s*"
    r"error\s*(?P<message>.*)",
    re.IGNORECASE,
)
_PYTHON_LOCATION_PATTERN = re.compile(
    r'File\s+["\'](?P<path>[^"\']+\.py)["\'],\s+line\s+(?P<line>\d+)',
    re.IGNORECASE,
)
_COLON_LOCATION_PATTERN = re.compile(
    r"(?P<path>(?:[A-Za-z]:)?[^\s:]+?\.(?:py|ts|tsx|js|jsx|java|go|rb|rs))"
    r":(?P<line>\d+)(?::(?P<column>\d+))?",
    re.IGNORECASE,
)
_PROJECT_PATH_MARKERS = ("platform-ext-app/", "src/", "tests/", "customcodes/", "apps/")
_COLON_LOCATION_SUFFIXES = (
    ".py:",
    ".ts:",
    ".tsx:",
    ".js:",
    ".jsx:",
    ".java:",
    ".go:",
    ".rb:",
    ".rs:",
)
_COMPONENT_ROW_PATTERN = re.compile(
    r"^\s*(?P<metadata_type>[A-Za-z][A-Za-z0-9_]*)\s{2,}"
    r"(?P<component_name>\S+)\s{2,}(?P<problem>.+?)\s*$"
)
_LINE_COLUMN_PATTERN = re.compile(r"\b(?P<line>\d+):(?P<column>\d+)\b")


@dataclass(frozen=True, slots=True)
class LogAnalysis:
    redaction: RedactionResult
    chunks: list[LogChunk]
    fingerprint: FailureFingerprint


@dataclass(frozen=True, slots=True)
class DiagnosticLine:
    text: str
    index: int
    line: int | None


@dataclass(frozen=True, slots=True)
class FailureSignal:
    rule_id: str
    category: str
    text: str
    index: int
    line: int | None
    priority: int
    chunk_type: Literal["error", "http", "test", "stack_trace"] = "error"


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    category: str
    priority: int
    pattern: re.Pattern[str]
    chunk_type: Literal["error", "http", "test", "stack_trace"] = "error"


def _rule(
    rule_id: str,
    category: str,
    priority: int,
    pattern: str,
    chunk_type: Literal["error", "http", "test", "stack_trace"] = "error",
) -> _Rule:
    return _Rule(rule_id, category, priority, re.compile(pattern, re.IGNORECASE), chunk_type)


# Only explicit diagnostics qualify. Job names, license prose, bare numbers, commands,
# warning diagnostics and test names are not failure evidence.
_RULES = (
    _rule(
        "runner.ssh_executor_unavailable", "runner_infrastructure_failure", 100,
        r"^(?=.*(?:preparation failed|preparing environment|system failure|docker tunnel))"
        r"(?=.*(?:\bssh\b|:22\b))"
        r"(?=.*(?:failed|error:|i/o timeout|timed out|connection refused|no route|unreachable))"
        r"(?=.*(?:timeout|timed out|connection refused|no route|unreachable)).+",
    ),
    _rule(
        "runner.preparation_failed", "runner_infrastructure_failure", 99,
        r"\bpreparation failed\b|\bjob failed \(system failure\)|"
        r"\bprepare environment:.*(?:error|failed|timeout|cannot)",
    ),
    _rule("compiler.cs0161", "build_failure", 98, r"\berror\s+CS0161\s*:"),
    _rule("compiler.error", "build_failure", 97, r"\berror\s+(?:CS\d{4}|TS\d+|MSB\d+)\s*:"),
    _Rule("rlp.datasync_ambiguous", "deployment_failure", 96, DATASYNC_AMBIGUOUS_PATTERN),
    _rule(
        "rlp.flow_group_filter_rejected", "deployment_failure", 96,
        r"^(?=.*\bflow(?:s|group(?:id)?|filter)?\b)"
        r"(?=.*\b(?:flowgroup(?:id)?|flowfilter|group(?:id)?|filter\w*)\b)"
        r"(?=.*\b(?:error|fail(?:ed)?|rejected)\b)"
        r"(?=.*(?:reject(?:ed)?|invalid|not found|does not exist|unsupported|not allowed)).+",
    ),
    _Rule("salesforce.component_failure", "deployment_failure", 95, _COMPONENT_FAILURE_PATTERN),
    _rule(
        "rlp.datasync_failed", "deployment_failure", 94,
        r"\bdatasync\s+(?:run|target|validation|pre-validation)\s+(?:failed|failure)\b",
    ),
    _Rule("salesforce.test_failure", "test_failure", 93, _TEST_FAILURE_SECTION_PATTERN, "test"),
    _rule(
        "salesforce.coverage_failure", "test_failure", 93,
        r"\b(?:code coverage failure|code coverage.*(?:below|less than|must be at least))\b",
        "test",
    ),
    _rule(
        "test.failed", "test_failure", 93,
        r"\b(?:AssertionError|assertion failed)\b|^FAILED\s+.*(?:tests?[/\\:]|::)|"
        r"\b[1-9]\d*\s+(?:tests? failed|failing)\b|"
        r"\b(?:tests? failed|failed tests?)\s*[:=]\s*[1-9]\d*\b|"
        r"^(?:=+\s*)?[1-9]\d*\s+failed(?:,|\s+in\b)|\b[1-9]\d* failed,.*\bpassed\b",
        "test",
    ),
    _rule(
        "sonar.quality_gate_failed", "quality_gate_failure", 92,
        r"\bquality gate(?:\s+status)?\s*[:=]\s*(?:FAILED|ERROR)\b|"
        r"\bquality gate\s+(?:has\s+)?failed\b",
    ),
    _rule(
        "sonar.scanner_configuration", "scanner_configuration_failure", 91,
        r"^(?=.*\bsonar\.(?:projectKey|sources|tests|java\.binaries|projectBaseDir)\b)"
        r"(?=.*(?:must define|mandatory|missing|not found|does not exist|invalid|not defined|"
        r"please provide compiled)).+",
    ),
    _rule(
        "auth.authentication_rejected", "authentication_failure", 90,
        _HTTP_STATUS_PREFIX + r"401\b|\b401\s+Unauthorized\b|"
        r"\bauthentication failed\b|\b(?:token|credential)s? (?:has |have |is |are )?expired\b|"
        r"\b(?:invalid or expired|invalid|expired) credentials\b|"
        r"^(?:ERROR\s*:?\s*)?unauthorized\s*[:.!]",
        "http",
    ),
    _rule(
        "auth.authorization_rejected", "authorization_failure", 90,
        _HTTP_STATUS_PREFIX + r"403\b|\b403\s+Forbidden\b|"
        r"\bpermission denied\b|\bpre-receive hook declined\b|\bnot allowed to push\b|"
        r"^(?:ERROR\s*:?\s*)?(?:forbidden|not authorized)\s*[:.!]",
        "http",
    ),
    _rule(
        "artifact.missing", "artifact_missing", 89,
        r"\bartifacts?\b.*(?:not found|missing)|could not download.*\bartifacts?\b|"
        r"\bno such artifact\b",
    ),
    _rule(
        "package.path_missing", "package_path_failure", 88,
        r"^(?=.*(?:\bpackage\b|MigrationManagerPackage[/\\]))"
        r"(?=.*(?:not found|does not exist|missing|no such file or directory|"
        r"could not find.*path|case mismatch|wrong case))"
        r"(?=.*(?:\berror\b|\bfatal\b|FileNotFoundError|no such file or directory|"
        r"could not find|required package)).+",
    ),
    _rule(
        "compiler.build_failed", "build_failure", 85,
        r"\b(?:syntax error|compilation failed|compile error|cannot find symbol|"
        r"module not found|ModuleNotFoundError)\b|^Build FAILED\.?$",
    ),
    _rule(
        "dependency.resolution_failed", "dependency_failure", 84,
        r"npm (?:ERR!|error) (?:404|E404|ERESOLVE)|could not resolve dependency|"
        r"unable to resolve (?:package|dependency)|no matching distribution found",
    ),
    _rule(
        "deployment.failed", "deployment_failure", 80,
        r"\b(?:deployment\s+status|status)\s*[\"']?\s*[:=]\s*[\"']?failed\b|"
        r"\bdeployment (?:step )?failed\b",
    ),
    _rule(
        "http.service_failure", "external_api_failure", 78,
        _HTTP_STATUS_PREFIX + r"(?:5\d{2}|429)\b|\b503 Service Unavailable\b|"
        r"\b502 Bad Gateway\b|\b429 Too Many Requests\b",
        "http",
    ),
    _rule(
        "operation.timeout", "timeout", 75,
        r"\b(?:i/o timeout|connection timed out|deadline exceeded)\b|"
        r"\b(?:error|failed|exception)\b.*\b(?:timeout|timed out)\b",
    ),
    _rule(
        "sonar.scanner_error", "scanner_failure", 65,
        r"\berror during (?:SonarScanner|sonar-scanner) execution\b",
    ),
    _rule(
        "log.explicit_error", "unknown", 50,
        r"^(?:\[?ERROR\]?|FATAL)\s*[:| ]\s*\S|\b\w*(?:Error|Exception)\s*:",
    ),
    _rule(
        "script.nonzero_exit", "unknown", 15,
        r"\bexit(?:ed)?(?:\s+with)?(?:\s+(?:code|status))?\s*[:=]?\s*[1-9]\d*\b",
    ),
)


def clean_log_line(line: str) -> str:
    """Remove presentation prefixes for matching, without changing physical line offsets."""

    cleaned = _ANSI_ESCAPE_PATTERN.sub("", line).rstrip("\r").rsplit("\r", 1)[-1]
    return _TRACE_PREFIX_PATTERN.sub("", cleaned).strip()


def _physical_lines(content: str) -> list[str]:
    # Carriage-return terminal controls are not new GitLab trace lines.
    return content.rstrip("\n").split("\n") if content else []


def iter_log_lines(content: str) -> Iterator[DiagnosticLine]:
    """Yield original line numbers only until an unmeasured omitted span is encountered."""

    known_offset = True
    for index, raw_line in enumerate(_physical_lines(content)):
        text = clean_log_line(raw_line)
        if _OMISSION_PATTERN.search(text):
            known_offset = False
        yield DiagnosticLine(text, index, index + 1 if known_offset else None)


def failure_signals(content: str) -> list[FailureSignal]:
    """Rank explicit causal diagnostics; ties prefer the earliest diagnostic, not the footer."""

    signals: list[FailureSignal] = []
    in_component_table = False
    for item in iter_log_lines(content):
        line = item.text
        if _COMPONENT_FAILURE_PATTERN.search(line):
            in_component_table = True
        elif line.lower().startswith(("test results summary", "test failures")):
            in_component_table = False
        if not line or _COMMAND_PATTERN.match(line) or _WARNING_PATTERN.search(line):
            continue
        if _BENIGN_PATTERN.search(line) or _OMISSION_PATTERN.search(line):
            if _OMISSION_PATTERN.search(line):
                in_component_table = False
            continue
        if _GENERIC_FOOTER_PATTERN.fullmatch(line):
            signals.append(FailureSignal(
                "script.nonzero_exit", "unknown", line, item.index, item.line, 15,
            ))
            continue
        if in_component_table and (row := _COMPONENT_ROW_PATTERN.match(line)):
            if row.group("metadata_type").lower() != "type":
                dependency = re.search(
                    r"(?i)referenced by|dependent metadata|no .*named .*found|"
                    r"invalid (?:type|reference)|does not exist|not found",
                    row.group("problem"),
                )
                signals.append(FailureSignal(
                    "salesforce.metadata_dependency" if dependency else "salesforce.metadata_error",
                    "deployment_failure", line, item.index, item.line, 96,
                ))
                continue
        for rule in _RULES:
            if rule.pattern.search(line):
                signals.append(FailureSignal(
                    rule.rule_id, rule.category, line, item.index, item.line,
                    rule.priority, rule.chunk_type,
                ))
                break
    return sorted(signals, key=lambda signal: (-signal.priority, signal.index))


def _merge_windows(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not windows:
        return []
    merged: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
            continue
        previous_start, previous_end = merged[-1]
        merged[-1] = (previous_start, max(previous_end, end))
    return merged


def chunk_log(content: str, context_before: int = 3, context_after: int = 7) -> list[LogChunk]:
    """Bound error windows and rank causal evidence ahead of footers and warning noise.

    ``log-retained-`` chunks use retained-buffer offsets, NOT original trace line numbers.
    Consumers must not turn those offsets into original-log citations.
    """

    lines = _physical_lines(content)
    if not lines:
        return []
    diagnostic_lines = list(iter_log_lines(content))
    signals = failure_signals(content)
    signals_by_index = {signal.index: signal for signal in signals}
    windows = [
        (max(0, signal.index - context_before), min(len(lines) - 1, signal.index + context_after))
        for signal in signals
    ]
    merged_windows = _merge_windows(windows)
    if not merged_windows:
        merged_windows = [(0, min(len(lines) - 1, 39))]

    chunks: list[LogChunk] = []
    bounded_windows: list[tuple[int, int]] = []
    for start, stop in merged_windows:
        while start <= stop:
            end = min(stop, start + 79)
            for offset in range(start + 1, end + 1):
                if (diagnostic_lines[offset].line is None) != (
                    diagnostic_lines[start].line is None
                ):
                    end = offset - 1
                    break
            bounded_windows.append((start, end))
            start = end + 1
    for start, end in bounded_windows:
        selected_lines = lines[start : end + 1]
        best = max(
            (signals_by_index[index] for index in range(start, end + 1)
             if index in signals_by_index),
            key=lambda signal: (signal.priority, -signal.index), default=None,
        )
        chunk_id = hashlib.sha256(f"{start}:{end}:{'|'.join(selected_lines)}".encode()).hexdigest()[
            :16
        ]
        prefix = "log-" if diagnostic_lines[start].line is not None else "log-retained-"
        chunks.append(
            LogChunk(
                chunk_id=f"{prefix}{chunk_id}",
                chunk_type=best.chunk_type if best else "context",
                content="\n".join(selected_lines),
                line_start=start + 1,
                line_end=end + 1,
                score=best.priority / 100 if best else 0.0,
            )
        )

    return sorted(chunks, key=lambda chunk: (-chunk.score, chunk.line_start))


def _latest_command(lines: list[str], error_index: int | None) -> str | None:
    upper_bound = len(lines) if error_index is None else error_index + 1
    for line in reversed(lines[:upper_bound]):
        match = _COMMAND_PATTERN.match(clean_log_line(line))
        if match:
            return match.group(1).strip()
    return None


def _normalize_message(message: str) -> str:
    normalized = re.sub(r"\b\d{4}-\d{2}-\d{2}[T ][0-9:.+-]+\b", "<timestamp>", message)
    normalized = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{18,}\b", "<id>", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"(?<!\w)(?:[A-Za-z]:)?(?:/|\\)[^\s:]+", "<path>", normalized)
    normalized = re.sub(r"\b\d{5,}\b", "<number>", normalized)
    return re.sub(r"\s+", " ", normalized).strip().lower()


def _normalize_source_path(raw_path: str) -> str:
    normalized = clean_log_line(raw_path).strip(" '\"").replace("\\", "/")
    if not re.match(r"^(?:[A-Za-z]:)?/", normalized):
        return normalized.removeprefix("./")
    lowered = normalized.lower()
    for marker in _PROJECT_PATH_MARKERS:
        match = re.search(r"(?:^|/)" + re.escape(marker), lowered)
        if match:
            return normalized[match.end() - len(marker):]
    if re.match(r"^(?:[A-Za-z]:)?/", normalized):
        return normalized.rsplit("/", maxsplit=1)[-1]
    return normalized.removeprefix("./")


def extract_code_references(content: str, limit: int = 10) -> list[CodeReference]:
    """Extract error locations, excluding compiler warnings and retaining repository prefixes."""

    if limit <= 0:
        return []
    references: list[CodeReference] = []
    seen: set[tuple[str, int, int | None]] = set()
    pattern_markers = (
        (_CSHARP_LOCATION_PATTERN, ".cs("),
        (_PYTHON_LOCATION_PATTERN, "file "),
        (_COLON_LOCATION_PATTERN, None),
    )
    for item in iter_log_lines(content):
        line = item.text
        if _WARNING_PATTERN.search(line) or _COMMAND_PATTERN.match(line):
            continue
        lowered_line = line.lower()
        for pattern, marker in pattern_markers:
            if marker and marker not in lowered_line:
                continue
            if pattern is _COLON_LOCATION_PATTERN and not any(
                suffix in lowered_line for suffix in _COLON_LOCATION_SUFFIXES
            ):
                continue
            for match in pattern.finditer(line):
                path = _normalize_source_path(match.group("path"))
                source_line = int(match.group("line"))
                column = int(match.group("column")) if match.groupdict().get("column") else None
                if source_line < 1 or column == 0:
                    continue
                key = (path, source_line, column)
                if key in seen:
                    continue
                seen.add(key)
                message = match.groupdict().get("message")
                references.append(
                    CodeReference(
                        path=path,
                        line=source_line,
                        column=column,
                        message=message.strip() if message else None,
                    )
                )
                if len(references) == limit:
                    return references
    return references


def extract_deployment_component_failures(
    content: str,
    limit: int = 10,
) -> list[DeploymentComponentFailure]:
    """Extract Salesforce metadata deployment failures from CLI component-failure tables."""

    if limit <= 0:
        return []
    failures: list[DeploymentComponentFailure] = []
    in_component_table = False
    for item in iter_log_lines(content):
        line = item.text
        if _COMPONENT_FAILURE_PATTERN.search(line):
            in_component_table = True
            continue
        if not in_component_table:
            continue
        if not line or line.lower().startswith("test results summary"):
            if failures or line.lower().startswith("test results summary"):
                break
            continue
        if line.lower().startswith("type") or set(line) == {"-"}:
            continue
        match = _COMPONENT_ROW_PATTERN.match(line)
        if match is None:
            continue
        problem = match.group("problem")
        location = _LINE_COLUMN_PATTERN.search(problem)
        failures.append(
            DeploymentComponentFailure(
                metadata_type=match.group("metadata_type"),
                component_name=match.group("component_name"),
                problem=problem,
                line=int(location.group("line")) if location else None,
                column=int(location.group("column")) if location else None,
            )
        )
        if len(failures) >= limit:
            break
    return failures


def fingerprint_log(content: str) -> FailureFingerprint:
    lines = _physical_lines(content)
    signals = failure_signals(content)
    primary = signals[0] if signals else None
    # Keep existing DataSync fingerprints stable while ranking the mapping row as evidence.
    if primary and primary.rule_id == "rlp.datasync_ambiguous":
        primary = next(
            (signal for signal in signals if signal.rule_id == "rlp.datasync_failed"), primary
        )
    message = primary.text if primary else "No explicit failure signal observed"
    error_index = primary.index if primary else None
    command = _latest_command(lines, error_index)
    exits = [
        int(match.group(1)) for item in iter_log_lines(content)
        if not _COMMAND_PATTERN.match(item.text)
        for match in _EXIT_CODE_PATTERN.finditer(item.text)
    ]
    exit_code = exits[-1] if exits else None
    category = primary.category if primary else "unknown"
    if not primary and any(_SUCCESS_PATTERN.match(item.text) for item in iter_log_lines(content)):
        category = "no_failure_observed"
    normalized_message = _normalize_message(message)
    normalized_command = _normalize_message(command or "")
    digest = hashlib.sha256(
        f"{category}|{normalized_command}|{normalized_message}".encode()
    ).hexdigest()[:20]
    return FailureFingerprint(
        digest=digest,
        category=category,
        normalized_message=normalized_message,
        command=command,
        exit_code=exit_code,
    )


def redact_log(content: str, redactor: SecretRedactor | None = None) -> RedactionResult:
    """Use the shared redactor without collapsing physical lines in multiline private keys."""

    active_redactor = redactor or SecretRedactor()
    block_replacements = 0

    def redact_block(match: re.Match[str]) -> str:
        nonlocal block_replacements
        result = active_redactor.redact(match.group())
        block_replacements += result.replacements
        return result.content + "\n" * (match.group().count("\n") - result.content.count("\n"))

    ansi_free = _ANSI_ESCAPE_PATTERN.sub("", content)
    sanitized = active_redactor.redact(_PRIVATE_KEY_PATTERN.sub(redact_block, ansi_free))
    return RedactionResult(sanitized.content, sanitized.replacements + block_replacements)


def analyze_log(content: str, redactor: SecretRedactor | None = None) -> LogAnalysis:
    """Redact, chunk, and fingerprint a CI log in that order."""

    sanitized = redact_log(content, redactor)
    return LogAnalysis(
        redaction=sanitized,
        chunks=chunk_log(sanitized.content),
        fingerprint=fingerprint_log(sanitized.content),
    )
