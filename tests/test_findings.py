import copy
import inspect

import pytest
from pydantic import ValidationError

from pipelinelens.demo import get_demo_incident
from pipelinelens.domain import AnalysisSnapshot, CiConfigFile
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.findings import (
    Finding,
    FindingEvidence,
    analyze_change_risks,
    diagnose_job,
)

_SOURCE = "platform-ext-app/resources/customcodes/PlatformAPI/Controller.cs"
_CS0161 = (
    f"/builds/example/repo/{_SOURCE}(47,30): error CS0161: "
    "Controller.GetItems(string, bool): not all code paths return a value"
)
_RUNNER_FAILURE = (
    "ERROR: Preparation failed: creating docker connection: creating docker tunnel: "
    "preparing environment: dial ssh: after retrying 167 times during 10m0s timeout: "
    "dial tcp executor.invalid:22: i/o timeout"
)


def _snapshot(
    log: str, status: str = "failed", name: str = "deploy-production", **metadata: object
) -> AnalysisSnapshot:
    fixture = get_demo_incident("gitlab-auth-expired")
    return PipelineAnalyzer().analyze_input(AnalysisInput(
        repository=fixture.repository,
        run=fixture.run.model_copy(update={"status": "success", "conclusion": "success"}),
        job=fixture.job.model_copy(update={
            "status": status, "conclusion": status, "name": name, **metadata,
        }),
        configs=fixture.configs, raw_log=log,
    ))


def _config(path: str, content: str) -> CiConfigFile:
    return CiConfigFile(
        path=path, ref="abc123", content=content,
        source_url=f"https://gitlab.example/sample/repo/-/blob/abc123/{path}",
    )


def test_public_contract_and_mutable_defaults_are_independent() -> None:
    assert set(FindingEvidence.model_fields) == {"text", "line", "path", "source_url"}
    assert set(Finding.model_fields) == {
        "rule_id", "severity", "category", "title", "explanation", "fix", "evidence",
        "confidence", "owner", "job_id", "documentation",
    }
    assert list(inspect.signature(diagnose_job).parameters) == ["snapshot"]
    assert list(inspect.signature(analyze_change_risks).parameters) == [
        "changes", "configs", "known_paths",
    ]
    data = dict(rule_id="test", severity="info", category="test", title="test",
                explanation="test", fix=[], evidence=[])
    first, second = Finding(**data), Finding(**data)
    first.documentation.append("https://docs.gitlab.com/runner/faq/")
    assert second.documentation == []
    assert second.confidence == "observed"
    assert second.job_id is None
    assert FindingEvidence(text="bounded excerpt").line is None
    with pytest.raises(ValidationError):
        Finding.model_validate({**data, "confidence": "certain"})
    with pytest.raises(ValidationError):
        Finding.model_validate({**data, "severity": "critical"})


def test_allowed_to_fail_sonar_job_is_runner_ssh_failure_not_quality_gate() -> None:
    snapshot = _snapshot(
        "\n".join([
            "Running with gitlab-runner 17.8", "Preparing docker executor",
            _RUNNER_FAILURE,
            "ERROR: Job failed (system failure): preparing environment: dial ssh: i/o timeout",
        ]),
        name="sonarqube-check", allow_failure=True, failure_reason="runner_system_failure",
    )
    before = snapshot.model_dump_json()
    finding = diagnose_job(snapshot)

    assert finding.rule_id == "runner.ssh_executor_unavailable"
    assert finding.category == "runner_infrastructure_failure"
    assert finding.severity == "error"
    assert finding.evidence[0].line == 3
    assert finding.evidence[0].source_url.endswith("#L3")
    assert finding.confidence == "observed"
    assert "TCP 22" in finding.fix[0]
    assert "only after" in finding.fix[-1]
    assert "no scanner execution" in finding.explanation
    assert "sonar" not in " ".join(finding.fix).lower()
    assert "allow_failure=True" in finding.evidence[-1].text
    assert finding.job_id == snapshot.job.external_id
    assert snapshot.model_dump_json() == before


@pytest.mark.parametrize("raw_only", [False, True])
def test_runner_metadata_without_trace_is_honestly_incomplete(raw_only: bool) -> None:
    metadata = {"raw": {"failure_reason": "runner_system_failure"}} if raw_only else {
        "failure_reason": "runner_system_failure",
    }
    finding = diagnose_job(_snapshot(
        "ERROR: QUALITY GATE STATUS: FAILED", name="sonarqube-check", **metadata,
    ))

    assert finding.rule_id == "runner.reported_system_failure"
    assert finding.confidence == "unknown"
    assert finding.evidence[0].line is None
    assert "TCP 22" not in " ".join(finding.fix)


def test_early_compiler_error_beats_thousands_of_warnings_numbers_and_license_prose() -> None:
    trace = "\n".join([
        *[f"restore progress {index}" for index in range(43)],
        "\x1b[31m2026-09-10T05:45:13.994801Z 01O " + _CS0161 + "\x1b[0m",
        *[f"API.cs({index + 1},1): warning CS8604: argument may be null" for index in range(2000)],
        "Permission is hereby granted; 403 license clauses; 401 tests passed",
        "ERROR: Job failed: exit code 1",
    ])
    finding = diagnose_job(_snapshot(trace, name="build-job", failure_reason="script_failure"))

    assert finding.rule_id == "compiler.cs0161"
    assert finding.owner == "Developer"
    assert finding.category == "build_failure"
    assert finding.evidence[0].line == 44
    assert finding.evidence[0].text == _CS0161
    assert finding.evidence[1].path == _SOURCE
    assert finding.evidence[1].line == 47
    assert finding.evidence[1].source_url.endswith(f"/{_SOURCE}#L47")
    assert "every reachable branch" in finding.fix[0]
    assert "return null" not in " ".join(finding.fix)
    assert "cs0161" in finding.documentation[0]


@pytest.mark.parametrize("noise", [
    "API.cs(403,401): warning CS8604: permission argument may be null",
    "Tests run: 403; 0 failures; 0 errors",
    "Expected: HTTP 403 Forbidden",
    "TestUnauthorized401 PASSED\nTestPermissionDenied403 PASSED",
    "tests/test_auth.py::test_permission_denied PASSED",
    "WARNING: HTTP 403 Forbidden in optional probe",
    "Component Failures [0]\nTest Failures [0]\n0 Error(s)",
    "Permission is hereby granted free of charge; THE SOFTWARE IS PROVIDED AS IS",
    "Downloading 403 packages, 401 cached, timeout=503",
    "$ echo 'HTTP 401 Unauthorized'\n$ echo 'ERROR: quality gate failed'",
    "Deploying metadata\nRunning tests\nActivation release complete",
    "SonarScanner 6.0\nQUALITY GATE STATUS: PASSED",
    "\u2713 handles HTTP 403 Forbidden",
    "ok 12 - handles HTTP 401 Unauthorized",
    "INFO: Expected HTTP 403 Forbidden",
    "Preparing environment using ssh with timeout=10m0s",
    "Flow group filter: invalid count=0",
    "",
])
def test_successful_jobs_do_not_fail_from_noise(noise: str) -> None:
    finding = diagnose_job(_snapshot(noise + "\nJob succeeded", status="success"))

    assert finding.rule_id == "job.no_failure_observed"
    assert finding.category == "no_failure_observed"
    assert finding.severity == "info"
    assert "limited" in finding.explanation
    assert "intended package parameter" in finding.fix[0]
    assert "deployment receipt" in finding.fix[0]


def test_failed_sonar_job_name_does_not_establish_a_quality_gate_result() -> None:
    finding = diagnose_job(_snapshot(
        "ERROR: Job failed: exit code 1", name="sonarqube-check", failure_reason="script_failure",
    ))
    assert finding.category == "unknown"
    assert finding.confidence == "unknown"
    assert "quality gate" not in finding.title.lower()


@pytest.mark.parametrize(("trace", "rule_id", "category"), [
    ("ERROR: QUALITY GATE STATUS: FAILED", "sonar.quality_gate_failed", "quality_gate_failure"),
    ("ERROR: You must define the following mandatory properties: sonar.projectKey",
     "sonar.scanner_configuration", "scanner_configuration_failure"),
    ("ERROR: The folder specified by sonar.sources does not exist",
     "sonar.scanner_configuration", "scanner_configuration_failure"),
    ("ERROR: Your project contains .java files, please provide compiled classes with "
        "sonar.java.binaries property",
        "sonar.scanner_configuration", "scanner_configuration_failure"),
    ("ERROR: Error during SonarScanner execution", "sonar.scanner_error", "scanner_failure"),
    ("HTTP/1.1 401 Unauthorized", "auth.authentication_rejected", "authentication_failure"),
    ("HTTP status 403 Forbidden", "auth.authorization_rejected", "authorization_failure"),
    ("Error: Flow group 'QuoteFlow' rejected: invalid filter 'CountryCode'",
     "rlp.flow_group_filter_rejected", "deployment_failure"),
    ("Error: FlowGroupId rejected: group does not exist",
     "rlp.flow_group_filter_rejected", "deployment_failure"),
    ("Error: FlowFilter rejected: invalid selection",
     "rlp.flow_group_filter_rejected", "deployment_failure"),
    ("Error: DataSync run failed for 2 targets", "rlp.datasync_failed", "deployment_failure"),
    ("Test Failures [2]\nTest Results Summary", "salesforce.test_failure", "test_failure"),
    ("Code Coverage Failure: code coverage is 60%, must be at least 75%",
     "salesforce.coverage_failure", "test_failure"),
    ("Deployment Status: Failed", "deployment.failed", "deployment_failure"),
    ("ERROR: package path MigrationManagerPackage/missing does not exist",
     "package.path_missing", "package_path_failure"),
    ("FAILED tests/test_checkout.py::test_quote", "test.failed", "test_failure"),
    ("AssertionError: expected actual value", "test.failed", "test_failure"),
])
def test_explicit_diagnostics_are_distinguished(trace: str, rule_id: str, category: str) -> None:
    finding = diagnose_job(_snapshot(trace + "\nERROR: Job failed: exit code 1"))

    assert finding.rule_id == rule_id
    assert finding.category == category
    assert finding.evidence[0].line == 1


def test_scanner_auth_error_beats_generic_scanner_execution_footer() -> None:
    finding = diagnose_job(_snapshot(
        "HTTP 401 Unauthorized\nERROR: Error during SonarScanner execution",
        name="sonarqube-check",
    ))
    assert finding.category == "authentication_failure"


def test_auth_test_assertion_is_not_misclassified_as_an_authentication_problem() -> None:
    finding = diagnose_job(_snapshot(
        "AssertionError: expected HTTP 401 Unauthorized, received 200"
    ))
    assert finding.rule_id == "test.failed"
    assert finding.category == "test_failure"


def test_ssh_failure_then_scanner_output_does_not_claim_scanner_never_ran() -> None:
    finding = diagnose_job(_snapshot(
        _RUNNER_FAILURE + "\n2026-09-10T05:45:13.994801Z 01O INFO SonarScanner 6.0",
        status="success",
    ))
    assert finding.severity == "warning"
    assert "no scanner execution" not in finding.explanation


def test_selected_success_status_wins_over_a_stale_failure_conclusion() -> None:
    snapshot = _snapshot("WARNING: optional probe failed", status="success")
    snapshot.job.conclusion = "failed"
    assert diagnose_job(snapshot).rule_id == "job.no_failure_observed"


def test_github_completed_uses_the_success_conclusion() -> None:
    snapshot = _snapshot("TestUnauthorized403 PASSED", status="completed")
    snapshot.job.conclusion = "success"
    assert diagnose_job(snapshot).rule_id == "job.no_failure_observed"


@pytest.mark.parametrize("target", ["ApprovalAssignee", "CustomTargetSelection"])
def test_datasync_ambiguity_uses_the_actual_target_and_mapping_identifier(target: str) -> None:
    trace = "\n".join([
        "Error: DataSync run failed for 1 target(s).",
        "2026-09-10T05:45:13.994801Z 01O 62 | " + target + " | FAIL | AMBIGUOUS",
    ])
    finding = diagnose_job(_snapshot(trace))

    assert finding.rule_id == "rlp.datasync_ambiguous"
    assert target in finding.title
    assert "explicit mapping identifier" in finding.fix[1]
    assert finding.evidence[0].line == 2


def test_salesforce_dependency_retains_the_actual_component_problem() -> None:
    finding = diagnose_job(_snapshot("\n".join([
        "Component Failures [1]",
        "LightningComponentBundle  quoteWidget  The component is referenced by "
        "quoteWidget : Custom Tab Definition - quoteWidget.",
        "Test Results Summary",
    ])))

    assert finding.rule_id == "salesforce.metadata_dependency"
    assert "Custom Tab Definition" in finding.explanation
    assert "same deployment package" in finding.fix[0]
    assert finding.evidence[0].line == 2


def test_success_with_real_error_is_a_warning_not_a_claim_the_job_failed() -> None:
    finding = diagnose_job(_snapshot(_CS0161 + "\nJob succeeded", status="success"))

    assert finding.rule_id == "compiler.cs0161"
    assert finding.severity == "warning"
    assert finding.confidence == "likely"
    assert "reported successful" in finding.explanation
    assert "does not make the job or pipeline failed" in finding.explanation
    assert "swallowed" not in finding.title


@pytest.mark.parametrize("mask", ["|| true", "; exit 0", "|| :"])
def test_possible_swallowed_failure_requires_error_and_exit_suppression(mask: str) -> None:
    finding = diagnose_job(_snapshot(
        f"$ ./deploy.sh {mask}\nError: package folder is missing\nJob succeeded", status="success",
    ))

    assert finding.rule_id == "script.failure_masked"
    assert finding.severity == "warning"
    assert finding.confidence == "likely"
    assert finding.evidence[-1].line == 1
    assert "does not prove that branch executed" in finding.explanation


def test_exit_suppression_alone_is_not_an_observed_failure() -> None:
    finding = diagnose_job(_snapshot("$ ./optional.sh || true\nJob succeeded", status="success"))
    assert finding.rule_id == "job.no_failure_observed"


@pytest.mark.parametrize("command", [
    "$ echo 'documented workaround || true'",
    "$ printf 'sample || true'",
    "$ ./check.sh 'sample || true'",
    "$ ./check.sh # documented || true",
])
def test_printed_or_quoted_suppression_is_not_treated_as_an_executed_operator(command: str) -> None:
    finding = diagnose_job(_snapshot(command + "\nERROR: sample failure", status="success"))
    assert finding.rule_id != "script.failure_masked"


def test_ci_exit_suppression_evidence_is_scoped_to_the_selected_job() -> None:
    snapshot = _snapshot("ERROR: command rejected\nJob succeeded", status="success")
    config = snapshot.config_bundle[1].model_copy(update={
        "content": "deploy-production:\n  script: ./deploy.sh || true\n",
    })
    snapshot = snapshot.model_copy(update={"config_bundle": [snapshot.config_bundle[0], config]})
    finding = diagnose_job(snapshot)

    assert finding.rule_id == "script.failure_masked"
    assert finding.evidence[-1].path == config.path
    assert finding.evidence[-1].line == 2


def test_tail_evidence_after_truncation_does_not_fake_an_original_log_line() -> None:
    snapshot = _snapshot("restore progress\n[PIPELINELENS_LOG_TRUNCATED]\n" + _CS0161)
    finding = diagnose_job(snapshot)

    assert finding.rule_id == "compiler.cs0161"
    assert finding.evidence[0].line is None
    assert "#L" not in finding.evidence[0].source_url
    assert finding.evidence[1].line == 47
    assert finding.evidence[1].source_url.endswith("#L47")
    assert "original log line number" in finding.explanation


def test_head_evidence_before_truncation_keeps_its_original_line() -> None:
    finding = diagnose_job(_snapshot(_CS0161 + "\n[PIPELINELENS_LOG_TRUNCATED]\nJob failed"))
    assert finding.evidence[0].line == 1


def test_findings_redact_untrusted_snapshot_log_metadata_and_source_urls() -> None:
    token = "gl" + "pat-" + "x" * 24
    snapshot = _snapshot("normal output").model_copy(update={
        "redacted_log": f"HTTP 401 Unauthorized: token={token}",
    })
    snapshot.job.web_url = f"https://gitlab.example/job/1?token={token}"
    snapshot.job.raw = {"access_token": token}
    finding = diagnose_job(snapshot)
    assert token not in finding.model_dump_json()
    assert finding.evidence[0].line == 1


def test_changed_package_directory_case_mismatch_is_static_not_a_runtime_cause() -> None:
    changes = [{"new_path": "migrationmanagerpackage/Release/data.json", "diff": "+{}"}]
    known = ["MigrationManagerPackage/Release/manifest.json"]
    before = copy.deepcopy((changes, known))
    findings = analyze_change_risks(changes, [], known)

    assert len(findings) == 1
    assert findings[0].rule_id == "change.path_case_mismatch"
    assert findings[0].confidence == "observed"
    assert findings[0].severity == "warning"
    assert findings[0].evidence[0].line is None
    assert "static change evidence" in findings[0].explanation
    assert (changes, known) == before


def test_new_package_folder_or_arbitrary_changed_folder_does_not_imply_wrong_deployment() -> None:
    assert analyze_change_risks([
        {"new_path": "MigrationManagerPackage/NewRelease/data.json", "new_file": True},
        {"new_path": "other-folder/data.json", "new_file": True},
    ], [], ["MigrationManagerPackage/Existing/manifest.json"]) == []


def test_changed_yaml_include_case_mismatch_has_real_file_line_citation() -> None:
    content = "include:\n  - local: ci/Deploy.yml\n"
    findings = analyze_change_risks([{
        "new_path": ".gitlab-ci.yml",
        "diff": "@@ -1,2 +1,2 @@\n include:\n-  - local: ci/deploy.yml\n+  - local: ci/Deploy.yml",
    }], [_config(".gitlab-ci.yml", content)], [".gitlab-ci.yml", "ci/deploy.yml"])

    assert len(findings) == 1
    assert findings[0].rule_id == "change.ci_path_case_mismatch"
    assert findings[0].evidence[0].line == 2
    assert findings[0].evidence[0].path == ".gitlab-ci.yml"
    assert findings[0].evidence[0].source_url.endswith(".gitlab-ci.yml#L2")


@pytest.mark.parametrize("content", [
    "include:\n  - local: ci/missing.yml\n",
    "variables:\n  PACKAGE_FOLDER: MigrationManagerPackage/Missing\n",
    "deploy:\n  script: cd MigrationManagerPackage/Missing\n",
])
def test_changed_yaml_unverified_required_input_is_not_asserted_missing(content: str) -> None:
    findings = analyze_change_risks(
        [{"new_path": ".gitlab-ci.yml"}], [_config(".gitlab-ci.yml", content)],
        [".gitlab-ci.yml", "MigrationManagerPackage/Existing/data.json"],
    )

    assert len(findings) == 1
    assert findings[0].rule_id == "change.ci_path_unverified"
    assert findings[0].confidence == "unknown"
    assert "inventory may be bounded" in findings[0].explanation


def test_diff_only_references_have_hunk_lines_or_unknown_never_invented_lines() -> None:
    for diff, expected in [
        ("@@ -0,0 +20,2 @@\n+include:\n+  - local: ci/missing.yml", 21),
        ("+include:\n+  - local: ci/missing.yml", None),
    ]:
        findings = analyze_change_risks(
            [{"new_path": ".gitlab-ci.yml", "diff": diff}], [], ["ci/deploy.yml"],
        )
        assert len(findings) == 1
        assert findings[0].evidence[0].line == expected


@pytest.mark.parametrize("content", [
    "include:\n  - project: shared/templates\n    file: /missing.yml\n",
    "include:\n  - remote: https://ci.example/templates/build.yml\n",
    "include:\n  - local: ci/$ENV.yml\n",
    "include:\n  - local: ci/*.yml\n",
    "build:\n  artifacts:\n    paths: [dist/generated.zip]\n",
    "deploy:\n  rules:\n    - changes: [not-yet-created/**]\n",
    "# include: ci/missing.yml\ndeploy:\n  script: echo done\n",
    "deploy:\n  script: echo 'ci/missing.yml'\n",
    "deploy:\n  script: echo 'cd MigrationManagerPackage/Optional'\n",
    "deploy:\n  script: cd MigrationManagerPackage/release-$TARGET\n",
    "deploy:\n  script: python deploy.py --package-path MigrationManagerPackage/$TARGET\n",
    "include:\n  - local: ci/optional.yml\n    rules:\n      - exists: [ci/optional.yml]\n",
    "variables:\n  PACKAGE_FOLDER: '$PACKAGE'\n",
    "[malformed",
])
def test_dynamic_remote_generated_and_nonreference_yaml_are_not_missing_paths(content: str) -> None:
    assert analyze_change_risks(
        [{"new_path": ".gitlab-ci.yml"}], [_config(".gitlab-ci.yml", content)],
        [".gitlab-ci.yml", "ci/deploy.yml"],
    ) == []


def test_unchanged_yaml_reference_and_deleted_diff_lines_are_not_new_risks() -> None:
    config = _config(".gitlab-ci.yml", "include:\n  - local: ci/missing.yml\n# comment\n")
    assert analyze_change_risks([{
        "new_path": ".gitlab-ci.yml",
        "diff": "@@ -1,2 +1,3 @@\n include:\n   - local: ci/missing.yml\n+# comment",
    }], [config], [".gitlab-ci.yml", "ci/deploy.yml"]) == []
    assert analyze_change_risks([{
        "new_path": ".gitlab-ci.yml", "deleted_file": True,
        "diff": "-include: ci/missing.yml",
    }], [config], [".gitlab-ci.yml"]) == []


def test_added_echo_of_an_unchanged_missing_path_is_not_a_new_reference() -> None:
    config = _config(".gitlab-ci.yml", "include:\n  - local: ci/missing.yml\n"
                     "build:\n  script: echo ci/missing.yml\n")
    assert analyze_change_risks([{
        "new_path": config.path,
        "diff": "@@ -3,1 +3,2 @@\n build:\n+  script: echo ci/missing.yml",
    }], [config], [".gitlab-ci.yml", "ci/present.yml"]) == []


def test_block_script_case_mismatch_cites_the_actual_yaml_command_line() -> None:
    config = _config(".gitlab-ci.yml", "deploy:\n  script: |\n"
                     "    cd MigrationManagerPackage/release\n")
    findings = analyze_change_risks(
        [{"new_path": config.path}], [config], ["MigrationManagerPackage/Release/input.json"],
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "change.ci_path_case_mismatch"
    assert findings[0].evidence[0].line == 3


def test_config_can_prove_the_file_line_for_a_diff_fragment_without_hunk_offsets() -> None:
    config = _config(".gitlab-ci.yml", "include:\n  - local: ci/missing.yml\n")
    findings = analyze_change_risks([{
        "new_path": config.path, "diff": "+  - local: ci/missing.yml",
    }], [config], ["ci/present.yml"])
    assert len(findings) == 1
    assert findings[0].evidence[0].line == 2


def test_paths_added_in_the_same_change_are_not_reported_missing() -> None:
    assert analyze_change_risks([
        {"new_path": ".gitlab-ci.yml"}, {"new_path": "ci/new.yml", "new_file": True},
    ], [_config(".gitlab-ci.yml", "include:\n  - local: ci/new.yml\n")], [".gitlab-ci.yml"]) == []


def test_empty_known_inventory_does_not_assert_missing_references() -> None:
    assert analyze_change_risks(
        [{"new_path": ".gitlab-ci.yml"}],
        [_config(".gitlab-ci.yml", "include:\n  - local: ci/new.yml\n")], [],
    ) == []


def test_explicit_case_only_rename_is_not_assumed_a_mistake() -> None:
    assert analyze_change_risks([{
        "old_path": "ci/deploy.yml", "new_path": "ci/Deploy.yml", "renamed_file": True,
    }], [], ["ci/deploy.yml"]) == []


def test_case_sensitive_siblings_that_both_exist_are_not_case_mismatches() -> None:
    assert analyze_change_risks(
        [{"new_path": "ci/Deploy.yml"}], [], ["ci/Deploy.yml", "ci/deploy.yml"],
    ) == []


def test_change_risk_evidence_is_redacted_and_repeated_references_are_deduplicated() -> None:
    token = "gl" + "pat-" + "x" * 24
    config = _config(".gitlab-ci.yml", "include:\n"
                     f"  - local: ci/Missing.yml # token={token}\n"
                     "  - local: ci/Missing.yml\n")
    findings = analyze_change_risks(
        [{"new_path": config.path}], [config], [".gitlab-ci.yml", "ci/present.yml"],
    )
    assert len(findings) == 1
    assert token not in findings[0].model_dump_json()