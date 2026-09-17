"""Synthetic RLP/SFDX/Q2C regression cases; no private traces or network calls."""

from dataclasses import replace

import pytest

from pipelinelens.config import get_settings
from pipelinelens.demo import get_demo_incident
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.findings import diagnose_job
from pipelinelens.services.redaction import SecretRedactor

TIMEOUT = "ERROR: Job failed: execution took longer than 2h0m0s seconds"
APEX = "sf apex run test --target-org test-org --test-level RunLocalTests --synchronous"


def finding(trace: str, *, status: str = "failed"):
    fixture = get_demo_incident("gitlab-auth-expired")
    settings = replace(get_settings(), llm_mode="disabled", allow_private_context=False)
    snapshot = PipelineAnalyzer(settings).analyze_input(AnalysisInput(
        repository=fixture.repository,
        run=fixture.run.model_copy(update={"status": status, "conclusion": status}),
        job=fixture.job.model_copy(update={"status": status, "conclusion": status}),
        configs=fixture.configs, raw_log=trace,
    ))
    return diagnose_job(snapshot)


@pytest.mark.parametrize("prefix", ["", "2026-09-13T00:00:00.000Z 01E "])
def test_apex_timeout_beats_interruption_wrapper_and_keeps_exact_lines(prefix):
    result = finding("\n".join(prefix + line for line in (
        APEX, "ExitError: EEXIT: 130", "Node.js v22.0.0", TIMEOUT,
    )))
    assert result.rule_id == "runner.job_timeout"
    assert result.title == "Apex test job exceeded its execution time limit"
    assert result.evidence[0].text == TIMEOUT and result.evidence[0].line == 4
    assert result.evidence[1].text == APEX and result.evidence[1].line == 1
    assert "does not establish a failed Apex assertion" in result.explanation
    assert "existing Apex test run" in result.fix[0]
    assert "keep required tests enabled" in result.fix[-1]


def test_bare_exit_130_does_not_invent_timeout_or_apex_failure():
    result = finding(APEX + "\nExitError: EEXIT: 130")
    assert result.rule_id == "log.explicit_error" and result.confidence == "unknown"


def test_timeout_without_apex_command_remains_generic():
    result = finding("$ npm run slow-task\n" + TIMEOUT)
    assert result.rule_id == "runner.job_timeout"
    assert result.title == "Job exceeded its execution time limit"
    assert "Apex" not in result.explanation


def test_apex_command_after_timeout_does_not_describe_earlier_attempt():
    result = finding(TIMEOUT + "\n" + APEX)
    assert result.title == "Job exceeded its execution time limit"


def test_successful_job_with_timeout_evidence_is_warning_not_failed():
    result = finding(APEX + "\n" + TIMEOUT + "\nJob succeeded", status="success")
    assert result.severity == "warning"
    assert "reported successful" in result.explanation


def test_csv_object_error_beats_deployment_wrapper_and_keeps_actual_object():
    error = "InvalidJob : Unable to find object: CustomRouting__c.csv"
    result = finding("\n".join((
        "Error (SfError): Error loading data", error,
        "Error: SFDX Delta package deployment failed: 1",
        "ERROR: No files to upload", "ERROR: Job failed: exit code 255",
    )))
    assert result.rule_id == "salesforce.csv_as_sobject"
    assert result.title.endswith("CustomRouting__c.csv")
    assert result.evidence[0].text == error and result.evidence[0].line == 2
    assert "CustomRouting__c" in result.fix[0] and "--sobject" in result.fix[0]
    assert "Keep the CSV path on --file" in result.fix[1]
    assert "renaming the whole package" in result.fix[1]


@pytest.mark.parametrize("line", [
    "InvalidJob : Unable to find object: Unknown__c",
    "$ echo 'InvalidJob : Unable to find object: CustomRouting__c.csv'",
    "WARNING: InvalidJob : Unable to find object: CustomRouting__c.csv",
])
def test_csv_correction_requires_explicit_csv_object_diagnostic(line):
    assert finding(line).rule_id != "salesforce.csv_as_sobject"


def test_jq_invalid_escape_is_not_a_compiler_error():
    result = finding("jq: parse error: Invalid escape at line 1, column 68")
    assert result.rule_id == "script.invalid_json"
    assert "serializer" in result.fix[1] and "jq --arg" in result.fix[1]
    assert result.category == "script_input_failure"


def test_compiler_method_with_token_parameter_keeps_diagnostic_and_protects_real_values():
    diagnostic = (
        "src/Controller.cs(47,30): error CS0161: "
        "'Controller.GetItems(string, CancellationToken)': not all code paths return a value"
    )
    original = diagnostic + '\nVENDOR_TOKEN="fixture-only-opaque-value"'
    redacted = SecretRedactor().redact(original)
    assert redacted.content.splitlines()[0] == diagnostic
    assert "fixture-only-opaque-value" not in redacted.content
    assert redacted.replacements == 1
    result = finding(original)
    assert result.rule_id == "compiler.cs0161"
    assert result.evidence[0].text == diagnostic


def test_other_context_does_not_exempt_a_method_shaped_credential_key():
    source = "'vendor_token(value)': 'fixture-only-opaque-value'"
    assert "fixture-only-opaque-value" not in SecretRedactor().redact(source).content