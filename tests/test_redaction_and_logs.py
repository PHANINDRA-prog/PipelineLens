import pytest

from pipelinelens.services.logs import (
    analyze_log,
    chunk_log,
    extract_code_references,
    extract_deployment_component_failures,
    failure_signals,
    iter_log_lines,
)
from pipelinelens.services.redaction import SecretRedactor


def _simulated_token(prefix: str) -> str:
    return prefix + "abcdefghijklmnopqrstuvwxyz123456"


def test_redactor_removes_common_ci_credentials() -> None:
    source = (
        f"Authorization: Bearer {_simulated_token('gl' + 'pat-')}\n"
        f"github={_simulated_token('g' + 'h' + 'p_')}\n"
        "client_secret=sensitive-value\n"
    )

    result = SecretRedactor().redact(source)

    assert "glpat-" not in result.content
    assert "ghp_" not in result.content
    assert "sensitive-value" not in result.content
    assert result.replacements == 3


def test_log_analysis_groups_an_authentication_failure() -> None:
    trace = "\n".join(
        [
            "Running deployment job",
            "$ ./scripts/deploy.sh production",
            "HTTP 401 Unauthorized: Invalid or expired credentials",
            "ERROR: Job failed: exit code 1",
        ]
    )

    analysis = analyze_log(trace)

    assert analysis.fingerprint.category == "authentication_failure"
    assert analysis.fingerprint.command == "./scripts/deploy.sh production"
    assert analysis.fingerprint.exit_code == 1
    assert analysis.chunks[0].chunk_type == "http"
    assert analysis.chunks[0].line_start == 1


def test_log_analysis_preserves_a_delayed_ambiguous_datasync_target() -> None:
    trace = "\n".join(
        [
            "Error: DataSync run failed for 1 target(s).",
            *[f"normal result row {index}" for index in range(60)],
            "2026-09-10T05:45:13.994801Z 01O  62 | ApprovalRuleAssignee | FAIL | AMBIGUOUS",
            "ERROR: Job failed: exit code 1",
        ]
    )

    analysis = analyze_log(trace)

    assert analysis.fingerprint.category == "deployment_failure"
    assert "datasync run failed" in analysis.fingerprint.normalized_message
    assert any("ApprovalRuleAssignee" in chunk.content for chunk in analysis.chunks)


def test_source_location_extraction_handles_compiler_and_python_trace_formats() -> None:
    trace = "\n".join(
        [
            r"C:\builds\sample\src\Pricing\QuoteEngine.cs(42,17): error CS0103: Missing name",
            '  File "src/pipelinelens/api/main.py", line 88, in analyze',
            "web/worker.ts:19:4: error: failed assertion",
        ]
    )

    references = extract_code_references(trace)

    assert [(item.path, item.line, item.column) for item in references] == [
        ("src/Pricing/QuoteEngine.cs", 42, 17),
        ("src/pipelinelens/api/main.py", 88, None),
        ("web/worker.ts", 19, 4),
    ]


def test_source_location_extraction_skips_large_non_source_trace_lines() -> None:
    trace = "diagnostic output " + ("x" * 200_000)

    assert extract_code_references(trace) == []


def test_salesforce_component_failure_table_extracts_metadata_and_dependency_reason() -> None:
    trace = "\n".join(
        [
            "2026-01-01T00:00:01.000Z 01E Component Failures [1]",
            "2026-01-01T00:00:01.000Z 01E Type  Name  Problem  Line:Column",
            (
                "2026-01-01T00:00:01.000Z 01E "
                "----------------------------------------------------------"
            ),
            (
                "2026-01-01T00:00:01.000Z 01E LightningComponentBundle  quoteWidget  "
                "The component is referenced by quoteWidget : Custom Tab Definition - quoteWidget."
            ),
            "2026-01-01T00:00:01.000Z 01E Test Results Summary",
        ]
    )

    failures = extract_deployment_component_failures(trace)

    assert len(failures) == 1
    assert failures[0].metadata_type == "LightningComponentBundle"
    assert failures[0].component_name == "quoteWidget"
    assert "Custom Tab Definition" in failures[0].problem


def test_component_deployment_failure_overrides_incidental_test_output_and_ansi_codes() -> None:
    trace = "\n".join(
        [
            "$ sf project deploy start --test-level RunLocalTests",
            "Running tests before metadata deployment",
            "\x1b[31mComponent Failures [2]\x1b[0m",
            "Status: Failed",
            "ERROR: Job failed: exit code 255",
        ]
    )

    analysis = analyze_log(trace)

    assert analysis.fingerprint.category == "deployment_failure"
    assert analysis.fingerprint.normalized_message == "component failures [2]"
    assert "\x1b" not in analysis.redaction.content


@pytest.mark.parametrize("line", [
    "TestUnauthorized403 PASSED",
    "Expected: HTTP 401 Unauthorized",
    "Component Failures [0]",
    "Test Failures [0]",
    "0 Error(s)",
    "0 failures",
    "Failed: 0",
    "Permission is hereby granted. License 403. Results: 401.",
    "Controller.cs(403,401): warning CS0161: sample warning",
    "WARNING: HTTP 503 Service Unavailable in optional probe",
    "$ echo 'ERROR: Job failed: exit code 1'",
])
def test_noncausal_noise_is_not_an_error_signal(line: str) -> None:
    assert failure_signals(line) == []


def test_causal_chunk_precedes_generic_footer_and_compiler_warning_noise() -> None:
    trace = "\n".join([
        "$ dotnet build",
        "API.cs(47,30): error CS0161: not all code paths return a value",
        *["API.cs(100,1): warning CS8604: null argument"] * 400,
        "ERROR: Job failed: exit code 1",
    ])
    analysis = analyze_log(trace)

    assert "error CS0161" in analysis.chunks[0].content
    assert analysis.chunks[0].score > analysis.chunks[-1].score
    assert len(analysis.chunks) == 2
    assert analysis.fingerprint.category == "build_failure"
    assert "warning" not in analysis.fingerprint.normalized_message


def test_error_dense_chunks_remain_bounded_and_ties_choose_the_first_error() -> None:
    trace = "\n".join(f"API.cs({line},1): error CS0103: unknown symbol" for line in range(1, 300))
    chunks = chunk_log(trace)
    assert all(len(chunk.content.splitlines()) <= 80 for chunk in chunks)
    assert chunks[0].line_start == 1
    assert failure_signals(trace)[0].line == 1


def test_timestamped_commands_and_ansi_errors_keep_the_original_positions() -> None:
    trace = "\n".join([
        "2026-09-10T05:45:13.994801Z 01O $ ./deploy.sh",
        "\x1b[31m2026-09-10T05:45:14.994801Z 01E HTTP 401 Unauthorized\x1b[0m",
        "2026-09-10T05:45:15.994801Z 01E ERROR: Job failed: exit code 1",
    ])
    analysis = analyze_log(trace)

    assert analysis.fingerprint.command == "./deploy.sh"
    signal = failure_signals(analysis.redaction.content)[0]
    assert signal.line == 2
    assert signal.text == "HTTP 401 Unauthorized"


def test_source_path_keeps_platform_root_and_ignores_warnings_before_errors() -> None:
    root = "platform-ext-app/resources/customcodes"
    trace = "\n".join([
        f"{root}/API.cs(9,1): warning CS8604: null argument",
        "2026-09-10T05:45:13.994801Z 01O "
        f"/builds/example/repo/{root}/Controller.cs(47,30): error CS0161: missing return",
    ])
    references = extract_code_references(trace)
    assert len(references) == 1
    assert references[0].path == f"{root}/Controller.cs"
    assert references[0].line == 47


def test_truncated_log_keeps_head_lines_but_marks_tail_offsets_as_retained() -> None:
    trace = "HTTP 401 Unauthorized\n[PIPELINELENS_LOG_TRUNCATED]\nERROR: tail failure"
    items = list(iter_log_lines(trace))
    assert [item.line for item in items] == [1, None, None]
    chunks = chunk_log(trace)
    tail = next(chunk for chunk in chunks if "tail failure" in chunk.content)
    assert tail.chunk_id.startswith("log-retained-")


def test_multiline_redaction_keeps_line_offsets_for_causal_evidence() -> None:
    trace = "\n".join([
        "-----BEGIN RSA PRIVATE KEY-----", "synthetic-not-a-key", "more-synthetic-text",
        "-----END RSA PRIVATE KEY-----", "HTTP 401 Unauthorized",
    ])
    analysis = analyze_log(trace)
    assert "synthetic-not-a-key" not in analysis.redaction.content
    assert analysis.redaction.content.count("\n") == trace.count("\n")
    assert failure_signals(analysis.redaction.content)[0].line == 5


def test_terminal_carriage_returns_are_not_counted_as_new_trace_lines() -> None:
    trace = "progress 10%\rprogress 100%\n\x1b[0Ksection\r\x1b[31mHTTP 401 Unauthorized\x1b[0m\n"
    signal = failure_signals(trace)[0]
    assert signal.line == 2
    assert signal.text == "HTTP 401 Unauthorized"


def test_a_specific_error_with_an_exit_code_still_ranks_ahead_of_generic_footer() -> None:
    trace = "ERROR: request payload rejected; exit code 2\nERROR: Job failed: exit code 1"
    signals = failure_signals(trace)
    assert signals[0].rule_id == "log.explicit_error"
    assert signals[0].line == 1
    assert signals[0].priority > signals[1].priority


def test_relative_code_paths_retain_their_existing_repository_prefixes() -> None:
    trace = "modules/src/API.cs(47,30): error CS0161: missing return"
    reference = extract_code_references(trace)[0]
    assert reference.path == "modules/src/API.cs"
