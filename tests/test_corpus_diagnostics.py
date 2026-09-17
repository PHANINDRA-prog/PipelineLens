"""Synthetic regressions for locally observed diagnostic formats, never private traces.

No corpus database, settings secrets, provider, network, or job mutations are needed.
Observed failures identify the rejected operation, not a verified fix or success rate.
"""

from dataclasses import replace

import pytest

from pipelinelens.config import Settings
from pipelinelens.demo import get_demo_incident
from pipelinelens.domain import AnalysisSnapshot
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.findings import Finding, _finding_for_signal, diagnose_job
from pipelinelens.services.logs import (
    FailureSignal,
    analyze_log,
    extract_deployment_component_failures,
    failure_signals,
)
from pipelinelens.services.redaction import SecretRedactor

_SETTINGS = Settings(
    environment="test", database_url="sqlite://", redis_url="", max_log_bytes=1_000_000,
    max_context_chars=0, llm_mode="disabled", llm_base_url="", llm_model="",
    llm_api_key=None, allow_private_context=False,
)
_APT = (
    "E: Release file for https://mirror.example/dists/stable/InRelease is expired "
    "(invalid since 2d 3h). Updates for this repository will not be applied."
)
_APPROVAL = (
    "Merge request status is still cannot_be_merged / detailed merge request status is still "
    "not_approved, cannot continue"
)
_CONFLICT = "VALIDATION FAILED - MERGE CONFLICT with target"
_EXEC = "exec /usr/local/bin/example-tool: exec format error"
_TAB_ROW = (
    "LightningComponentBundle  exampleWidget  The component is referenced by "
    "exampleTab : Custom Tab Definition - exampleTab."
)
_APEX_PROBLEM = (
    "Method does not exist or incorrect signature: void invoke() from the type ExampleHelper"
)
_APEX_TSV = f'"ExampleClass"\t"ApexClass"\t\t"{_APEX_PROBLEM}"'
_TABLE_HEADER = "ComponentName\t\tType\t\tErrorMessage"
_FAILED_FOOTER = "ERROR: Job failed: exit code 1"
_UPLOAD = "Uploading artifacts for failed job\nERROR: No files to upload"
_INCOMPLETE = {
    "git.merge_status_unresolved", "salesforce.metadata_request_failed",
    "salesforce.validation_failed",
}


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected_request(*args: object, **kwargs: object) -> None:
        raise AssertionError("Diagnostic regression attempted a network request")

    monkeypatch.setattr("httpx.Client.send", unexpected_request)
    monkeypatch.setattr("httpx.AsyncClient.send", unexpected_request)


def _table(row: str) -> str:
    return f"Component Failures [1]\nType  Name  Problem  Line:Column\n----------\n{row}"


def _validation(row: str = _APEX_TSV, count: int = 1) -> str:
    return f"Number of errors - {count}\n----------\n{_TABLE_HEADER}\n----------\n{row}"


def _snapshot(log: str, status: str = "failed", **metadata: object) -> AnalysisSnapshot:
    fixture = get_demo_incident("gitlab-auth-expired")
    return PipelineAnalyzer(_SETTINGS).analyze_input(AnalysisInput(
        repository=fixture.repository,
        run=fixture.run.model_copy(update={"status": status, "conclusion": status}),
        job=fixture.job.model_copy(update={
            "name": "generic-check", "status": status, "conclusion": status,
            "failure_reason": None, "raw": {}, **metadata,
        }),
        configs=[], raw_log=log,
    ))


def _finding(log: str, status: str = "failed") -> Finding:
    return diagnose_job(_snapshot(log, status))


_CASES = [
    pytest.param(_APT, "dependency.apt_release_expired", "dependency_failure", "UTC clock",
                 id="apt-release"),
    pytest.param(_CONFLICT, "git.merge_conflict", "merge_conflict", "reviewed merge",
                 id="validation-conflict"),
    pytest.param(_APPROVAL, "git.merge_approval_required", "merge_blocked", "latest merge-request",
                 id="approval"),
    pytest.param(_APPROVAL.replace("not_approved", "conflict"), "git.merge_conflict",
                 "merge_conflict", "reviewed merge", id="terminal-conflict"),
    pytest.param(_APPROVAL.replace("cannot_be_merged", "checking").replace(
        "not_approved", "checking"), "git.merge_status_unresolved", "merge_blocked",
        "pending checks", id="unresolved-check"),
    pytest.param(_EXEC, "script.exec_format", "script_execution_failure", "shebang",
                 id="exec-format"),
    pytest.param("/bin/bash: line 8: ./tool: cannot execute binary file: Exec format error",
                 "script.exec_format", "script_execution_failure", "architecture",
                 id="bash-exec-format"),
    pytest.param("TypeError: api.refresh is not a function", "script.not_callable",
                 "script_execution_failure", "stack frame", id="not-callable"),
    pytest.param("ERROR: Job failed: failed to pull image \"registry.example/tool:1\": "
                 "read: connection reset by peer", "runner.image_pull_failed",
                 "runner_infrastructure_failure", "registry/transport", id="image-pull"),
    pytest.param('target-org  build-org  false  Invalid config value: org "build-org" '
                 'is not authenticated', "salesforce.org_not_authenticated",
                 "authentication_failure", "CLI user/home context", id="sf-org"),
    pytest.param('Error (InvalidOrg): Invalid config value: org "build-org" is not authenticated',
                 "salesforce.org_not_authenticated", "authentication_failure",
                 "approved noninteractive", id="sf-org-error"),
    pytest.param("Error (MultipleErrors): Metadata API request failed: there are multiple errors; "
                 'refer to the "errors" property', "salesforce.metadata_request_failed",
                 "deployment_failure", "nested errors", id="sf-request-wrapper"),
    pytest.param(_table(f"ApexClass  ExampleClass  {_APEX_PROBLEM}"), "salesforce.apex_compile",
                 "deployment_failure", "originating error", id="sf-apex-standard"),
    pytest.param(_validation(), "salesforce.apex_compile", "deployment_failure",
                 "signature", id="sf-apex-tsv"),
    pytest.param(_validation(row=""), "salesforce.validation_failed", "deployment_failure",
                 "complete component validation rows", id="sf-nonzero-empty-table"),
    pytest.param(_table("LightningComponentBundle  exampleWidget  Error parsing file: "
                       "ParseError at [row,col]:[2,4]"), "salesforce.metadata_parse",
                 "deployment_failure", "parser location", id="sf-metadata-parse"),
    pytest.param(_table("FlexiPage  ExamplePage  Duplicate property [value] found on the "
                       "component [example:widget]"), "salesforce.metadata_duplicate",
                 "deployment_failure", "both definitions", id="sf-duplicate-property"),
    pytest.param(_table("CustomLabels  ExampleLabel  Duplicate name 'ExampleLabel' specified"),
                 "salesforce.metadata_duplicate", "deployment_failure", "both definitions",
                 id="sf-duplicate-name"),
    pytest.param(_table(_TAB_ROW), "salesforce.metadata_dependency", "deployment_failure",
                 "same deployment package", id="sf-dependent-tab"),
]


@pytest.mark.parametrize(("trace", "rule_id", "category", "advice"), _CASES)
@pytest.mark.parametrize("prefix", ["", "2026-01-01T00:00:00.000Z 01E ", "\x1b[31m"])
def test_explicit_causes_outrank_upload_footers_and_keep_offsets(
    trace: str, rule_id: str, category: str, advice: str, prefix: str,
) -> None:
    source = "\n".join(prefix + line for line in (trace + "\n" + _UPLOAD).split("\n"))
    snapshot = _snapshot(source + "\n" + _FAILED_FOOTER)
    before = snapshot.model_dump_json()
    finding = diagnose_job(snapshot)
    assert finding.rule_id == rule_id
    assert finding.category == category
    assert finding.confidence == ("unknown" if rule_id in _INCOMPLETE else "observed")
    assert finding.severity == "error"
    assert advice in " ".join(finding.fix)
    assert finding.evidence[0].line is not None
    assert finding.evidence[0].line <= len(trace.split("\n"))
    assert finding.evidence[0].source_url.endswith(f"#L{finding.evidence[0].line}")
    assert "No files to upload" not in finding.evidence[0].text
    assert snapshot.model_dump_json() == before
    assert snapshot.diagnosis.failure_category == category
    assert not snapshot.diagnosis.auto_remediation_allowed


@pytest.mark.parametrize(("trace", "rule_id", "category", "advice"), _CASES)
def test_successful_job_still_is_not_declared_failed(
    trace: str, rule_id: str, category: str, advice: str,
) -> None:
    result = _finding(trace + "\nJob succeeded", "success")
    assert result.rule_id == rule_id
    assert result.category == category
    assert result.severity == "warning" and result.confidence == "likely"
    assert advice in " ".join(result.fix)
    assert "does not make the job or pipeline failed" in result.explanation


@pytest.mark.parametrize(("trace", "rule_id", "category", "advice"), _CASES)
@pytest.mark.parametrize("prefix", ["$ echo ", "WARNING: ", "Example: "])
def test_each_rule_ignores_quoted_commands_warnings_and_documented_examples(
    trace: str, rule_id: str, category: str, advice: str, prefix: str,
) -> None:
    noise = "\n".join(prefix + line for line in trace.split("\n"))
    assert failure_signals(noise) == []
    assert _finding(noise + "\nJob succeeded", "success").rule_id == "job.no_failure_observed"


@pytest.mark.parametrize("noise", [
    "ERROR: Job failed: exit code 1",
    "ERROR: Job failed: exit code 100",
    "$ sf apex run test --result-format json\nERROR: Job failed: exit code 1",
    "$ ./deploy.sh\nStarting deployment\nERROR: Job failed: exit code 1",
    "ExitError: EEXIT: 130",
])
def test_exit_status_never_invents_a_cause(noise: str) -> None:
    result = _finding(noise)
    assert result.category == "unknown"
    assert result.confidence == "unknown"
    assert result.rule_id in {"script.nonzero_exit", "log.explicit_error"}


@pytest.mark.parametrize("noise", [
    f"$ echo '{_APT}'",
    f'printf "{_APT}"',
    f'Write-Host "{_EXEC}"',
    f'print("{_APPROVAL}")',
    f'logger.error("{_APT}")',
    f'sample = "{_EXEC}"',
    f"Example output: {_APT}",
    f"INFO: Example diagnostic: {_CONFLICT}",
    f"# {_CONFLICT}",
    f"// {_EXEC}",
    f"Expected: {_APT}",
    f"WARNING: {_APT}",
    f"[WARNING] {_EXEC}",
    "TestTypeError PASSED",
    "tests/test_behavior.py::test_error_message PASSED",
    "0 failures\n0 Error(s)",
    "0 failed, 12 passed in 0.1s",
    "Component Failures [0]\nTest Failures [0]",
    "release date expired; policy example only",
    "Invalid config value count=0",
    'target-org  build-org  true  Config value updated',
    "TypeError is mentioned in documentation, not a function result",
    f"```text\n{_APT}\n{_CONFLICT}\n{_EXEC}\n```",
    f"~~~log\n{_table(_TAB_ROW)}\n~~~",
    "Merge request status for execute task is cannot_be_merged / detailed merge request "
    "status is not_approved, waiting to get final status",
    "Merge request status is still cannot_be_merged / detailed merge request status is still "
    "conflict, waiting to get final status",
    "Updating commit message: fix validation failed issue",
    "Checked branch history: prior job failed yesterday",
    "Note: TypeError: api.invoke is not a function",
    '"example": "TypeError: api.invoke is not a function"',
    'const sample = "Error: example only";',
])
def test_inline_examples_warnings_passing_tests_and_polling_are_not_failures(noise: str) -> None:
    assert failure_signals(noise) == []
    assert _finding(noise + "\nJob succeeded", "success").rule_id == "job.no_failure_observed"


@pytest.mark.parametrize("noise", [
    _TAB_ROW,
    _APEX_TSV,
    _TABLE_HEADER + "\n" + _APEX_TSV,
    _validation(count=0),
    _validation().replace(_TABLE_HEADER, "OtherName\tType\tMessage"),
    "Number of errors - 1\n[PIPELINELENS_LOG_TRUNCATED]\n" + _TABLE_HEADER + "\n" + _APEX_TSV,
    "Number of errors - 1\n$ echo table\n" + _TABLE_HEADER + "\n" + _APEX_TSV,
    "Number of errors - 1\n" + "padding\n" * 7 + _TABLE_HEADER + "\n" + _APEX_TSV,
    "Component Failures [0]\n" + _TAB_ROW,
    "Component Failures [1]\nTest Results Summary\n" + _TAB_ROW,
    "Component Failures [1]\nTest Failures [0]\n" + _TAB_ROW,
    "Component Failures [1]\nComponent Failures [0]\n" + _TAB_ROW,
    "Component Failures [1]\nDeployment Status: Failed\n" + _TAB_ROW,
    "Component Failures [1]\n$ cat example.txt\n" + _TAB_ROW,
    "Component Failures [1]\n[PIPELINELENS_LOG_TRUNCATED]\n" + _TAB_ROW,
    "Component Failures [1]\nUploading artifacts for failed job\n" + _TAB_ROW,
    "Component Failures [1]\n```text\n" + _TAB_ROW + "\n```",
])
def test_metadata_rows_require_a_current_nonzero_failure_table(noise: str) -> None:
    assert extract_deployment_component_failures(noise) == []
    assert not any(signal.rule_id in {
        "salesforce.metadata_dependency", "salesforce.apex_compile", "salesforce.metadata_parse",
    } for signal in failure_signals(noise))


@pytest.mark.parametrize("problem", [
    _APEX_PROBLEM,
    "Variable does not exist: missingVariable",
    "Dependent class is invalid and needs recompilation: Class ExampleHelper: Invalid type: Item",
    "No such column 'Missing__c' on entity 'Example__c'. (7:2)",
    "Invalid type: ExampleHelper",
])
@pytest.mark.parametrize("quoted", [False, True])
def test_apex_compile_reports_keep_component_not_test_or_auth_failure(
    problem: str, quoted: bool,
) -> None:
    trace = _validation(f'"ExampleClass"\t"ApexClass"\t\t"{problem}"') if quoted else _table(
        f"ApexClass  ExampleClass  {problem}"
    )
    result = _finding(trace)
    assert result.rule_id == "salesforce.apex_compile"
    assert "ExampleClass" in result.title and "ApexClass" in result.explanation
    assert "same deployment package" in result.fix[1]
    assert "not evidence of a failed test assertion" in result.explanation
    components = extract_deployment_component_failures(trace)
    assert len(components) == 1
    assert components[0].problem == problem


def test_validation_zero_count_does_not_claim_deployment_failure() -> None:
    trace = _validation(row="", count=0)
    assert failure_signals(trace) == []
    assert _finding(trace + "\n" + _FAILED_FOOTER).confidence == "unknown"


def test_component_and_validation_counts_do_not_bleed_between_tables() -> None:
    trace = _table(_TAB_ROW) + "\n\n" + _validation(count=0)
    components = extract_deployment_component_failures(trace)
    assert [component.component_name for component in components] == ["exampleWidget"]


def test_quoted_validation_table_keeps_problem_quotes_locations_and_bounds() -> None:
    problem = "No such column 'Missing__c' on entity 'Example__c'. (7:2)"
    trace = _validation(f'"ExampleClass"\t"ApexClass"\t\t"{problem}"')
    components = extract_deployment_component_failures(trace)
    assert components[0].component_name == "ExampleClass"
    assert components[0].line == 7 and components[0].column == 2
    assert components[0].problem == problem
    assert extract_deployment_component_failures(trace, limit=0) == []
    assert len(extract_deployment_component_failures(trace + "\n" + _APEX_TSV, limit=1)) == 1


@pytest.mark.parametrize("suffix", ["", "\n[PIPELINELENS_LOG_TRUNCATED]"])
def test_tab_dependency_names_both_components_without_inventing_intent(suffix: str) -> None:
    finding = _finding(_table(_TAB_ROW) + suffix)
    assert finding.rule_id == "salesforce.metadata_dependency"
    assert "exampleWidget" in finding.title and "exampleTab" in finding.title
    assert "cannot be removed while custom tab 'exampleTab'" in finding.explanation
    assert "Custom Tab Definition" in finding.explanation
    assert "does not establish whether removal was intended" in finding.explanation
    assert "same deployment package" in finding.fix[0]
    assert "preserve 'exampleWidget'" in finding.fix[0]
    assert "If removal is intentional" in finding.fix[1]
    assert "before removing 'exampleWidget'" in finding.fix[1]
    assert "do not remove a tab just to make validation pass" in finding.fix[2]


def test_legacy_structured_component_gets_the_same_conditional_tab_guidance() -> None:
    signal = FailureSignal(
        "salesforce.metadata_dependency", "deployment_failure",
        "LightningComponentBundle exampleWidget: The component is referenced by "
        "exampleTab : Custom Tab Definition - exampleTab.", 0, 1, 96,
    )
    result = _finding_for_signal(signal, [])
    assert "exampleWidget" in result.title and "exampleTab" in result.title
    assert "same deployment package" in result.fix[0]
    assert "If removal is intentional" in result.fix[1]


def test_missing_dependency_is_not_asserted_to_be_a_removal_or_custom_tab() -> None:
    result = _finding(_table("CustomTab  exampleTab  In field: flexiPage - no FlexiPage named "
                             "ExamplePage found"))
    assert result.rule_id == "salesforce.metadata_dependency"
    assert "exampleTab" in result.title
    assert "cannot be removed" not in result.explanation
    assert "in the same deployment package" in result.fix[0]


def test_apt_fix_retains_security_checks_and_does_not_assume_clock_is_wrong() -> None:
    result = _finding(_APT)
    steps = " ".join(result.fix)
    assert "Check the runner/host UTC clock" in result.fix[0]
    assert "signed mirror" in steps and "supported base image" in steps
    assert "proxy/cache" in steps
    assert "Never bypass signatures or disable Check-Valid-Until" in steps
    assert "--allow-unauthenticated" not in steps
    assert "Check-Valid-Until=false" not in steps
    assert "Acquire::Check-Valid-Until=0" not in steps
    assert "clock is wrong" not in result.explanation


@pytest.mark.parametrize("status", ["checking", "unchecked", "blocked", "ci_still_running"])
def test_unresolved_merge_status_does_not_guess_a_conflict_or_missing_approval(status: str) -> None:
    trace = _APPROVAL.replace("not_approved", status)
    result = _finding(trace)
    assert result.rule_id == "git.merge_status_unresolved"
    assert result.confidence == "unknown"
    assert "does not prove a conflict, missing approval" in result.explanation


def test_terminal_merge_approval_outranks_earlier_transient_conflict_polling() -> None:
    trace = _APPROVAL.replace("not_approved", "conflict").replace(
        "cannot continue", "waiting to get final status"
    ) + "\n" + _APPROVAL
    result = _finding(trace)
    assert result.rule_id == "git.merge_approval_required"
    assert result.evidence[0].line == 2


@pytest.mark.parametrize("upload", [
    "ERROR: No files to upload",
    "ERROR: Uploading artifacts as archive: HTTP 403 Forbidden",
    "FATAL: failed to upload artifacts: required artifact missing",
    "Uploading artifacts for failed job\nHTTP 401 Unauthorized",
    "section_start:123:upload_artifacts_on_failure\nHTTP 503 Service Unavailable",
])
def test_artifact_upload_errors_are_unknown_symptoms_and_do_not_beat_an_upstream_cause(
    upload: str,
) -> None:
    standalone = _finding(upload + "\n" + _FAILED_FOOTER)
    assert standalone.rule_id == "artifact.upload_failed"
    assert standalone.confidence == "unknown"
    assert "input artifact" in standalone.explanation
    assert _finding(_EXEC + "\n" + upload).rule_id == "script.exec_format"
    # Even an unspecific upstream error takes precedence over the publisher footer.
    generic = _finding("Error: payload rejected\n" + upload)
    assert generic.rule_id == "log.explicit_error"
    assert generic.confidence == "unknown"


def test_missing_required_input_artifact_still_has_its_original_semantics() -> None:
    result = _finding("ERROR: could not download required artifact: not found")
    assert result.rule_id == "artifact.missing"
    assert result.category == "artifact_missing"


@pytest.mark.parametrize("boundary", [
    "$ ./check.sh", "Cleaning up project directory", "section_end:123:upload_artifacts_on_failure",
    "[PIPELINELENS_LOG_TRUNCATED]",
])
def test_upload_state_does_not_leak_past_a_known_boundary(boundary: str) -> None:
    result = _finding(_UPLOAD + "\n" + boundary + "\nHTTP 401 Unauthorized")
    assert result.rule_id == "auth.authentication_rejected"


def test_specific_evidence_after_omission_keeps_unknown_original_line() -> None:
    result = _finding("initial output\n[PIPELINELENS_LOG_TRUNCATED]\n" + _validation())
    assert result.rule_id == "salesforce.apex_compile"
    assert result.evidence[0].line is None
    assert "#L" not in result.evidence[0].source_url
    assert "original log line number" in result.explanation


def test_fenced_examples_do_not_hide_later_real_diagnostics() -> None:
    trace = f"```log\n{_APT}\n```\n{_EXEC}"
    result = _finding(trace)
    assert result.rule_id == "script.exec_format" and result.evidence[0].line == 4


@pytest.mark.parametrize("padding", [5, 90, 170])
def test_fence_opening_outside_chunk_does_not_promote_a_documented_error(padding: int) -> None:
    trace = (
        "```text\n" + "example line\n" * padding
        + "Example.cs(3,1): error CS0161: documented example only\n```\n" + _EXEC
    )
    snapshot = _snapshot(trace)
    result = diagnose_job(snapshot)
    assert result.rule_id == "script.exec_format"
    assert result.evidence[0].line == padding + 4
    assert snapshot.diagnosis.failure_category == "script_execution_failure"
    assert any(f"Original log line {padding + 4}" in evidence.explanation
               for evidence in snapshot.diagnosis.evidence)


@pytest.mark.parametrize("padding", [5, 90, 170])
def test_distant_upload_phase_is_preserved_in_standalone_legacy_chunks(padding: int) -> None:
    trace = (
        "Error: input rejected\n" + "output\n" * padding
        + "Uploading artifacts for failed job\n" + "upload output\n" * padding
        + "HTTP 403 Forbidden\n" + _FAILED_FOOTER
    )
    snapshot = _snapshot(trace)
    assert diagnose_job(snapshot).rule_id == "log.explicit_error"
    assert snapshot.diagnosis.failure_category == "unknown"
    for chunk in snapshot.chunks:
        assert len(chunk.content.split("\n")) <= 80
        assert not any(s.rule_id.startswith("auth.") for s in failure_signals(chunk.content))
        if "HTTP 403" in chunk.content:
            assert chunk.chunk_id.startswith("log-retained-")
            assert failure_signals(chunk.content)[0].line is None


def test_dense_validation_tables_are_bounded_and_keep_the_first_failure() -> None:
    trace = _validation("\n".join(_APEX_TSV for _ in range(120)))
    analysis = analyze_log(trace)
    assert all(len(chunk.content.split("\n")) <= 80 for chunk in analysis.chunks)
    assert failure_signals(trace)[0].line == 5
    assert len(extract_deployment_component_failures(trace)) == 10


def test_guarded_table_count_handles_large_untrusted_numeric_text() -> None:
    trace = _validation().replace("Number of errors - 1", "Number of errors - " + "9" * 5000)
    assert failure_signals(trace)[0].rule_id == "salesforce.apex_compile"


def test_not_authenticated_is_a_cli_context_problem_not_claimed_expiry() -> None:
    trace = 'defaultusername  build-org  false  Invalid config value: org "build-org" '
    result = _finding(trace + "is not authenticated")
    assert result.rule_id == "salesforce.org_not_authenticated"
    assert result.title == "Salesforce CLI has no authenticated target org"
    assert "does not prove that a token expired" in result.explanation


def test_cli_wrapper_suggestions_are_not_promoted_to_verified_fixes() -> None:
    result = _finding(
        "Error (MultipleErrors): Metadata API request failed: multiple errors.\n"
        "One possible reason is the number of files; try raising the open file limit."
    )
    assert result.rule_id == "salesforce.metadata_request_failed"
    assert result.confidence == "unknown"
    assert "not establish file-handle exhaustion" in result.explanation
    assert "not verified fixes" in result.explanation
    assert "specific diagnostic before changing resource limits" in " ".join(result.fix)


def test_auth_and_assertion_precedence_stays_causal_not_keyword_based() -> None:
    result = _finding("AssertionError: expected HTTP 401 Unauthorized, got 200\n" + _UPLOAD)
    assert result.rule_id == "test.failed"
    assert result.category == "test_failure"


@pytest.mark.parametrize("trace", [
    "FAILED tests/test_validation.py::test_schema - AssertionError: mismatch",
    "=================== 2 failed, 8 passed in 0.10s ===================",
])
def test_pytest_failure_diagnostics_survive_later_artifact_symptoms(trace: str) -> None:
    result = _finding(trace + "\n" + _UPLOAD)
    assert result.rule_id == "test.failed" and result.evidence[0].line == 1


def test_multiline_secret_redaction_preserves_cause_offsets_and_dynamic_guidance() -> None:
    token = "gl" + "pat-" + "s" * 24
    trace = "\n".join([
        "-----BEGIN PRIVATE KEY-----", "synthetic-private-material",
        "-----END PRIVATE KEY-----", _APT.replace("mirror.example", f"mirror.example/{token}"),
        f"TOKEN={token}", _UPLOAD,
    ])
    snapshot = _snapshot(trace)
    result = diagnose_job(snapshot)
    assert result.rule_id == "dependency.apt_release_expired"
    assert result.evidence[0].line == 4
    assert token not in snapshot.model_dump_json() + result.model_dump_json()
    assert "synthetic-private-material" not in result.model_dump_json()


def test_dynamic_component_and_tab_names_remain_redacted() -> None:
    token = "gl" + "pat-" + "v" * 24
    trace = _table(_TAB_ROW.replace("exampleTab", token))
    result = _finding(trace)
    assert result.rule_id == "salesforce.metadata_dependency"
    assert token not in result.model_dump_json()


def test_credential_scalar_is_sanitized_before_any_diagnostic_matching() -> None:
    secret = "fixture-only-custom-secret"
    safe = analyze_log(_APT + f"\nAPI_TOKEN={secret}", SecretRedactor())
    result = diagnose_job(_snapshot(safe.redaction.content))
    assert secret not in safe.redaction.content + result.model_dump_json()
    assert result.rule_id == "dependency.apt_release_expired"


def test_runner_metadata_and_allowed_failure_are_not_modified_by_new_rules() -> None:
    snapshot = _snapshot(
        "ERROR: Job failed: failed to pull image registry.example/tool:1", allow_failure=True,
        failure_reason="runner_system_failure",
    )
    original = snapshot.model_dump_json()
    result = diagnose_job(snapshot)
    assert result.rule_id == "runner.image_pull_failed"
    assert snapshot.model_dump_json() == original
    assert "allow_failure=True" in result.evidence[-1].text


def test_findings_do_not_depend_on_collection_frequency_or_configured_models() -> None:
    settings = replace(_SETTINGS, llm_mode="disabled")
    first = _finding(_APT)
    fixture = get_demo_incident("gitlab-auth-expired")
    snapshot = PipelineAnalyzer(settings).analyze_input(AnalysisInput(
        repository=fixture.repository, run=fixture.run, job=fixture.job,
        configs=[], raw_log=_APT,
    ))
    second = diagnose_job(snapshot)
    assert first.rule_id == second.rule_id
    assert first.fix == second.fix
    assert not snapshot.diagnosis.auto_remediation_allowed