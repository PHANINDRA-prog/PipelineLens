"""Deterministic, read-only findings grounded in job evidence or explicit path changes.

Log evidence has no ``path``; its ``line`` is an original trace line, or ``None``
after an unmeasured omission. File evidence uses repository paths and file lines.
Job selection and pipeline-level outcome interpretation belong to the caller.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal
from urllib.parse import quote, urldefrag

from pydantic import BaseModel, Field
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from pipelinelens.domain import AnalysisSnapshot, CiConfigFile, ProviderName
from pipelinelens.services.logs import (
    DATASYNC_AMBIGUOUS_PATTERN,
    FailureSignal,
    clean_log_line,
    extract_code_references,
    failure_signals,
    iter_log_lines,
    parse_component_failure,
    redact_log,
)
from pipelinelens.services.redaction import redact_text


class FindingEvidence(BaseModel):
    text: str
    line: int | None = None
    path: str | None = None
    source_url: str | None = None


class Finding(BaseModel):
    rule_id: str
    severity: Literal["error", "warning", "info"]
    category: str
    title: str
    explanation: str
    fix: list[str]
    evidence: list[FindingEvidence]
    confidence: Literal["observed", "likely", "unknown"] = "observed"
    owner: str = "Unknown"
    job_id: str | None = None
    documentation: list[str] = Field(default_factory=list)


def finding_identity(finding: Finding | dict) -> str:
    """Stable identity for one rule/job/location; different static files stay distinct."""
    value = finding.model_dump() if isinstance(finding, Finding) else finding
    evidence = value.get("evidence") or []
    content = {
        "rule_id": value.get("rule_id"), "job_id": value.get("job_id"),
        "evidence": [{key: item.get(key) for key in ("path", "line", "text")}
                     for item in evidence if isinstance(item, dict)],
    }
    return hashlib.sha256(json.dumps(content, sort_keys=True).encode()).hexdigest()[:24]


_RUNNER_DOC = "https://docs.gitlab.com/runner/faq/"
_CS0161_DOC = "https://learn.microsoft.com/en-us/dotnet/csharp/misc/cs0161"
_SONAR_GATE_DOC = (
    "https://docs.sonarsource.com/sonarqube-server/quality-standards-administration/"
    "managing-quality-gates/introduction-to-quality-gates/"
)
_SONAR_SCANNER_DOC = (
    "https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/scanners/sonarscanner/"
)
_SALESFORCE_DOC = (
    "https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/meta_deploy.htm"
)
_CI_DOC = "https://docs.gitlab.com/ci/yaml/#include"
_SUCCESS = {"success", "succeeded", "passed"}
_FAILED = {"failed", "failure", "timed_out"}
_MASK_PATTERN = re.compile(r"\|\|\s*(?:true\b|:(?:\s|$))|;\s*exit\s+0\b", re.IGNORECASE)
_HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_PACKAGE_KEY = re.compile(r"(?i)(?:package|migration)[_\w]*(?:path|folder|dir)$")
_SCRIPT_PATH = re.compile(
    r"(?:^\s*cd\s+|--package(?:-path|-folder)?(?:=|\s+))"
    r"(?:'(?P<single>[^']+)'|\"(?P<double>[^\"]+)\"|(?P<bare>[^\s;&|]+))"
)
_SHELL_QUOTED = re.compile(r"\"(?:\\.|[^\"\\])*\"|'[^']*'")
_CSV_OBJECT = re.compile(
    r"\bInvalidJob\s*:\s*Unable to find object:\s*(?P<object>[A-Za-z_]\w*)\.csv\b", re.I,
)
_APEX_TEST_COMMAND = re.compile(
    r"^(?:(?:\$|\+)\s*|Command:\s*)?(?:/[\w/.-]+/)?"
    r"(?:sf\s+apex\s+run\s+test|sfdx\s+force:apex:test:run)\b", re.I,
)
_REFERENCED_TAB = re.compile(
    r"\breferenced by\b.*?:\s*Custom Tab Definition\s*-\s*"
    r"(?P<tab>[A-Za-z_][\w.-]*)", re.I,
)
# These identify a stopped operation, but lack the detail needed for a causal conclusion.
_INCOMPLETE_CAUSE_RULES = {
    "git.merge_status_unresolved", "salesforce.metadata_request_failed",
    "salesforce.validation_failed",
}


@dataclass(frozen=True, slots=True)
class _Guidance:
    title: str
    explanation: str
    fix: tuple[str, ...]
    owner: str
    documentation: tuple[str, ...] = ()


_GUIDANCE = {
    "rlp.datasync_field_mapping_connection_reset": _Guidance(
        "DataSync field mapping deployment encountered a connection reset",
        "The DataSync deploy artifact records a non-success, non-skipped field-mapping "
        "request interrupted by a connection reset. This identifies a deployment transport "
        "failure but does not establish the underlying target-service or network cause.",
        (
            "Have the RLP DataSync and target-platform owners inspect target service and "
            "network diagnostics for the matching deployment window.",
            "Confirm whether any partial target state needs review before a controlled retry; "
            "do not treat compatibility skips as failed mappings.",
        ),
        "RLP DataSync / target platform",
    ),
    "rlp.datasync_field_mapping_artifact_failure": _Guidance(
        "DataSync field mapping artifact records an unclassified failure",
        "The DataSync deploy artifact reports a field-mapping failure, but its bounded safe "
        "details do not establish a specific target-side cause.",
        (
            "Inspect the matching target-platform deployment diagnostics for the earliest "
            "field-mapping error.",
            "Confirm target state before retrying an unclassified DataSync deployment failure.",
        ),
        "RLP DataSync / target platform",
    ),
    "dependency.apt_release_expired": _Guidance(
        "APT rejected expired repository metadata",
        "APT explicitly rejected an expired Release file and will not apply that repository's "
        "updates. This is repository-metadata freshness evidence, not a Salesforce error or "
        "proof that credentials expired.",
        (
            "Check the runner/host UTC clock and time synchronization first.",
            "Refresh package indexes from an approved, current signed mirror; check stale "
            "proxy/cache metadata and use a supported base image for that distribution.",
            "Keep signature verification and Valid-Until checks enabled. Never bypass "
            "signatures or disable Check-Valid-Until to accept expired metadata.",
        ),
        "CI image / dependency owner",
    ),
    "git.merge_conflict": _Guidance(
        "Merge validation reports a conflict",
        "The merge/validation diagnostic explicitly reports conflicting source and target "
        "changes. It does not establish a deployment, authentication or artifact-input failure.",
        (
            "Inspect the conflicting changes against the intended target revision with the "
            "source and target owners.",
            "Resolve the conflict through a reviewed merge or rebase, then rerun validation "
            "for the updated commit; retain the merge validator and approval policy.",
        ),
        "Change / merge-request owner",
    ),
    "git.merge_approval_required": _Guidance(
        "Merge stopped because required approval is not satisfied",
        "The terminal merge-readiness check reports not_approved and cannot continue. "
        "An earlier polling status alone would not establish a failure; this is not evidence "
        "of invalid credentials or a code conflict.",
        (
            "Check the required approvals and eligible approvers for the latest merge-request "
            "revision, including approvals reset by new commits.",
            "Obtain approval through the existing review workflow, then confirm merge "
            "readiness; do not bypass approvals or weaken merge/job policies.",
        ),
        "Change owner / required approvers",
    ),
    "git.merge_status_unresolved": _Guidance(
        "Merge-readiness check could not continue",
        "The terminal check stopped without an acceptable merge status. A checking or other "
        "unresolved state does not prove a conflict, missing approval, or GitLab outage.",
        (
            "Inspect the current detailed merge status and pending checks for the intended "
            "revision; obtain the check's full diagnostic if the status is still unresolved.",
            "Resolve the reported blocker with the merge/CI owner before an approved retry; "
            "do not force the merge or disable readiness checks.",
        ),
        "Change / CI owner",
    ),
    "script.exec_format": _Guidance(
        "The runner could not execute the file format",
        "The shell reports exec format error. An incompatible binary architecture or a "
        "script without a valid interpreter header can cause this, but the log alone does "
        "not establish which.",
        (
            "Compare the executable's format and architecture with the runner OS/CPU; for "
            "a script, inspect its shebang and line endings.",
            "Verify the executable came from the intended trusted build and select a "
            "compatible tool/image through review; validate in the same runner environment.",
        ),
        "CI tool / image owner",
    ),
    "script.not_callable": _Guidance(
        "JavaScript called a value that is not a function",
        "The runtime reports a TypeError at a function call. A changed API, incompatible "
        "plugin or incorrect value is possible; a particular dependency fix is not verified.",
        (
            "Inspect the first relevant stack frame and the value/method being called; "
            "reproduce with the same Node, CLI/plugin versions and lockfile.",
            "Check the expected API and supported version compatibility before correcting "
            "the caller or dependency; do not assume an arbitrary downgrade is a fix.",
        ),
        "Script / CLI dependency owner",
    ),
    "artifact.upload_failed": _Guidance(
        "Artifact upload failed; the job cause is not established",
        "The uploader could not publish output artifacts. Missing outputs can follow an "
        "earlier command failure; this footer does not prove that a required input artifact "
        "was missing or explain why the job's script failed.",
        (
            "Inspect the preceding command's complete sanitized output and exit result "
            "before changing artifact configuration.",
            "If no upstream failure is found, check which outputs were actually produced "
            "and the intended publishing paths; do not create dummy artifacts to hide a failure.",
        ),
        "Job / artifact owner",
    ),
    "runner.image_pull_failed": _Guidance(
        "Runner could not pull the job image",
        "The runner explicitly failed to pull its image. The cited registry/transport detail "
        "must distinguish connectivity, image availability and access problems.",
        (
            "Check the requested image/tag or digest and the cited registry/transport "
            "failure with the runner owner, without exposing registry credentials.",
            "Confirm the approved registry and runner route are healthy before retrying; "
            "retain image verification and the configured pull/access policy.",
        ),
        "Runner / image registry owner", (_RUNNER_DOC,),
    ),
    "runner.job_timeout": _Guidance(
        "Job exceeded its execution time limit",
        "GitLab explicitly stopped this job after its execution time limit. "
        "A preceding exit 130 can be an interruption symptom, not the underlying cause.",
        (
            "Identify the last running command and check its target-side execution status "
            "before starting a duplicate run.",
            "Investigate a blocking wait or excessive workload; split or optimize the work "
            "after confirming why it exceeded the limit.",
            "Review any timeout adjustment with the CI owner; do not silently bypass job limits.",
        ),
        "CI / job owner", (_RUNNER_DOC,),
    ),
    "script.invalid_json": _Guidance(
        "The script passed invalid JSON to jq",
        "jq rejected its input as malformed JSON. This is an input/quoting problem, "
        "not proof of invalid GitLab credentials or a compiler failure.",
        (
            "Inspect the input producer and JSON escaping before the cited jq invocation.",
            "Build JSON with a serializer or jq --arg instead of manual string interpolation; "
            "validate a sanitized fixture before rerunning.",
        ),
        "CI / script owner",
    ),
    "runner.ssh_executor_unavailable": _Guidance(
        "Runner cannot reach its SSH/docker executor",
        "Runner preparation could not establish the SSH/docker connection. "
        "The cited failure is infrastructure preparation, not a Sonar quality-gate result.",
        (
            "Check the runner-to-executor route, firewall access to TCP 22, and SSH availability.",
            "Check runner health and the docker executor/tunnel on the affected host.",
            "Retry manually only after executor connectivity and runner health are restored.",
        ),
        "Runner / infrastructure team", (_RUNNER_DOC,),
    ),
    "runner.preparation_failed": _Guidance(
        "Runner environment preparation failed",
        "The runner reported an environment/system failure; this is not evidence of a "
        "compiler or quality-gate failure. The exact infrastructure cause needs the cited detail.",
        (
            "Inspect the runner preparation error and executor health with the runner owner.",
            "Verify the affected dependency has recovered before considering a manual retry.",
        ),
        "Runner / infrastructure team", (_RUNNER_DOC,),
    ),
    "compiler.cs0161": _Guidance(
        "Developer build: CS0161 — not all code paths return a value",
        "The compiler rejected the cited method because at least one reachable path does not "
        "return its declared value. The log alone does not identify the correct business value.",
        (
            "Ensure every reachable branch returns a value compatible with the method's "
            "declared return type; inspect the cited file and method before choosing a patch.",
            "Validate the affected branches with tests and the same build command/toolchain.",
        ),
        "Developer", (_CS0161_DOC,),
    ),
    "sonar.quality_gate_failed": _Guidance(
        "Sonar quality gate explicitly failed",
        "The trace contains a failed quality-gate result, rather than merely a Sonar job name.",
        (
            "Inspect the failed gate conditions and measures for this analysis and commit.",
            "Address the cited code, test, or coverage condition through normal review; "
            "retain the quality gate and allow_failure policy.",
        ),
        "Developer / quality owner", (_SONAR_GATE_DOC,),
    ),
    "sonar.scanner_configuration": _Guidance(
        "Sonar scanner input/configuration rejected",
        "The scanner reports a missing or invalid analysis input/property. "
        "This is not a measured quality-gate failure.",
        (
            "Check the cited scanner property and source/binary paths at the run commit.",
            "Confirm build outputs and scanner working directory before an approved correction.",
        ),
        "CI / scanner configuration owner", (_SONAR_SCANNER_DOC,),
    ),
    "sonar.scanner_error": _Guidance(
        "Sonar scanner execution error; cause not established",
        "A scanner execution error is present, but no specific configuration, authentication, "
        "or quality-gate cause is established by this line.",
        ("Inspect the preceding sanitized scanner diagnostic before changing settings.",),
        "CI / scanner configuration owner", (_SONAR_SCANNER_DOC,),
    ),
    "rlp.flow_group_filter_rejected": _Guidance(
        "RLP flow group/filter rejected",
        "The deployment diagnostic rejects a flow group or filter selection. It does not "
        "establish an authentication or DataSync mapping problem.",
        (
            "Compare the cited flow group/filter with the intended deployment selection and "
            "the target's supported values.",
            "Have the flow owner validate the selection before an approved correction; "
            "do not remove filters or replay guards merely to force deployment.",
        ),
        "RLP deployment / flow owner",
    ),
    "salesforce.metadata_dependency": _Guidance(
        "Salesforce metadata dependency rejected",
        "Salesforce reports a missing or still-referenced metadata dependency. The exact "
        "component and dependent definition are recorded in the cited component-failure row.",
        (
            "For an intended addition or update, include the referenced components and dependents "
            "in the same deployment package when that matches the intended change.",
            "For an intentional removal, first coordinate removal or redirection of dependent "
            "references; do not delete dependencies merely to clear a validation error.",
            "Validate the package against the intended target before another deployment.",
        ),
        "Salesforce metadata developer", (_SALESFORCE_DOC,),
    ),
    "salesforce.apex_compile": _Guidance(
        "Salesforce Apex compilation rejected",
        "The component-failure report identifies an Apex compile-time reference or signature "
        "problem. A dependent-class error can cascade from another invalid class; it is not "
        "evidence of a failed test assertion.",
        (
            "Inspect the named class and the first missing field, variable, type or method "
            "signature in the validation report; compare API names and parameter types.",
            "Check that required classes/fields are present in the target or the same "
            "deployment package. Correct the originating error before dependent-class cascades.",
            "Validate the reviewed package against the intended org with required tests enabled.",
        ),
        "Salesforce Apex / metadata developer", (_SALESFORCE_DOC,),
    ),
    "salesforce.metadata_parse": _Guidance(
        "Salesforce metadata could not be parsed",
        "The component-failure row reports a metadata/XML parse error, not a credential "
        "failure. The row's parser detail and location identify what needs inspection.",
        (
            "Inspect the cited component metadata and parser location for malformed XML, "
            "encoding or schema-invalid content using the target API version.",
            "Correct and validate the metadata through review; do not delete the component "
            "or change deployment scope merely to avoid the parser error.",
        ),
        "Salesforce metadata developer", (_SALESFORCE_DOC,),
    ),
    "salesforce.metadata_duplicate": _Guidance(
        "Salesforce metadata contains a duplicate definition",
        "The component-failure row explicitly reports a duplicate name or property. "
        "It does not establish which definition is intended.",
        (
            "Locate both definitions of the cited name/property within the reported component "
            "and compare them with the intended metadata change.",
            "Reconcile only the unintended duplication through review, then validate the "
            "package; do not delete an unrelated target component.",
        ),
        "Salesforce metadata developer", (_SALESFORCE_DOC,),
    ),
    "salesforce.validation_failed": _Guidance(
        "Salesforce validation reports component errors",
        "A nonzero error count is paired with the component/type/error-message table. "
        "The count alone does not identify the rejected component or a verified correction.",
        (
            "Obtain the complete component validation rows for this deployment and inspect "
            "the named component and target-side error before changing the package.",
            "Retain required tests and approval controls while validating a reviewed correction.",
        ),
        "Salesforce metadata developer", (_SALESFORCE_DOC,),
    ),
    "salesforce.metadata_request_failed": _Guidance(
        "Salesforce Metadata API request failed; detail is incomplete",
        "The CLI reports that its Metadata API request failed. A multiple-errors wrapper "
        "does not establish file-handle exhaustion, credential rejection or a target-side "
        "metadata defect; generic CLI suggestions are not verified fixes.",
        (
            "Inspect the CLI's nested errors and complete sanitized stack/response for the "
            "same request and tool versions.",
            "Identify a specific diagnostic before changing resource limits, credentials "
            "or package contents; do not apply generic CLI workaround text blindly.",
        ),
        "Salesforce CLI / deployment owner", (_SALESFORCE_DOC,),
    ),
    "salesforce.org_not_authenticated": _Guidance(
        "Salesforce CLI has no authenticated target org",
        "The CLI rejected its org configuration because the selected org is not authenticated "
        "in this execution context. The line does not prove that a token expired.",
        (
            "Verify the intended org alias/target and that the approved noninteractive "
            "authorization step completed in this job's CLI user/home context.",
            "Check the configured secret's availability through the approved secret store; "
            "never print auth URLs, tokens or private keys. Confirm identity before retrying.",
        ),
        "Salesforce CI / credential owner", (_SALESFORCE_DOC,),
    ),
    "salesforce.test_failure": _Guidance(
        "Salesforce deployment tests failed",
        "The metadata deployment reports a nonzero test-failure count, not just test output.",
        (
            "Inspect failing Apex test names, assertions and stack locations in the test report.",
            "Validate test and metadata dependencies with the Salesforce developer; "
            "do not skip required tests to force deployment.",
        ),
        "Salesforce test / metadata developer", (_SALESFORCE_DOC,),
    ),
    "salesforce.coverage_failure": _Guidance(
        "Salesforce deployment coverage requirement not met",
        "The deployment reports insufficient code coverage; "
        "no unrelated credential issue is inferred.",
        (
            "Inspect the coverage report for the deployed Apex and add meaningful tests "
            "for the uncovered behavior.",
            "Retain the required deployment test and coverage policy.",
        ),
        "Salesforce test / metadata developer", (_SALESFORCE_DOC,),
    ),
}

_CATEGORY_GUIDANCE = {
    "build_failure": _Guidance(
        "Developer build error",
        "The cited compiler/build diagnostic identifies a development error.",
        (
            "Inspect the compiler error and source location before changing CI or credentials.",
            "Validate the correction with the same toolchain and targeted tests.",
        ), "Developer",
    ),
    "authentication_failure": _Guidance(
        "Authentication explicitly rejected", "The cited request/credential diagnostic reports "
        "authentication rejection. Credential expiry or invalidity "
        "is known only if explicitly logged.",
        (
            "Verify the job's configured credential source, availability and expiry through "
            "the approved secret-management path without exposing its value.",
            "Confirm the target accepts that identity; "
            "change credentials only if rejection is verified.",
        ), "Credential / service owner",
    ),
    "authorization_failure": _Guidance(
        "Access explicitly denied", "The cited operation was denied. The required scope and "
        "policy must be established from the operation, not inferred from license text or numbers.",
        (
            "Check the denied operation and identity, including file or service permissions.",
            "Confirm the required scope with the owner; do not weaken protected-resource controls.",
        ), "Resource / access owner",
    ),
    "artifact_missing": _Guidance(
        "Required artifact unavailable",
        "The job explicitly could not obtain its required artifact.",
        (
            "Confirm the upstream artifact producer completed and published the expected artifact.",
            "Check needs/dependencies, artifact paths and retention at the selected run.",
        ), "CI / artifact owner",
    ),
    "package_path_failure": _Guidance(
        "Required package folder/path unavailable", "The cited command explicitly reports a "
        "missing or case-mismatched package path; the intended package is not inferred.",
        (
            "Compare the package parameter, checkout path and directory case at the run commit.",
            "Request the intended package parameter and deployment receipt before proposing "
            "any package-selection change.",
        ), "Deployment package owner",
    ),
    "deployment_failure": _Guidance(
        "Deployment rejected", "The cited deployment step reports an explicit failure. "
        "The precise target-side cause requires the detailed deployment result.",
        (
            "Inspect the cited target validation and deployment receipt for the intended package.",
            "Validate inputs and dependencies before any approved change or redeployment.",
        ), "Deployment owner",
    ),
    "test_failure": _Guidance(
        "Test failure observed",
        "An assertion or nonzero test-failure result is present in the trace.",
        (
            "Inspect the failing test and assertion; reproduce with the same inputs/toolchain.",
            "Determine if the test or implementation needs correction before an approved change.",
        ), "Developer / test owner",
    ),
    "dependency_failure": _Guidance(
        "Dependency resolution failed", "The resolver explicitly rejected a package or dependency.",
        ("Check dependency name, lockfile and configured registry before changing versions.",),
        "Developer / dependency owner",
    ),
    "external_api_failure": _Guidance(
        "External service request failed",
        "The cited HTTP response reports a server or rate-limit error.",
        ("Check service health and response details before considering a safe retry.",),
        "Service owner",
    ),
    "timeout": _Guidance(
        "Operation timed out",
        "A timeout is explicit, but its underlying cause is not established.",
        ("Check the slow operation and dependency health before changing a timeout or retrying.",),
        "Operation / service owner",
    ),
    "unknown": _Guidance(
        "Error observed; cause not established", "An error or nonzero exit is recorded, "
        "but it does not establish a specific root cause.",
        ("Inspect the command's complete sanitized diagnostic before choosing a correction.",),
        "Job owner",
    ),
}


def _metadata_guidance(signal: FailureSignal, guidance: _Guidance) -> _Guidance:
    component = parse_component_failure(signal.text)
    if component is None:
        # The legacy adapter can provide a structured component as "Type Name: Problem".
        component = parse_component_failure(re.sub(
            r"^(\w+) (\S+): (.+)$", r"\1  \2  \3", signal.text,
        ))
    if component is None:
        return guidance
    name, kind = component.component_name, component.metadata_type
    if signal.rule_id == "salesforce.metadata_dependency" and (
        match := _REFERENCED_TAB.search(component.problem)
    ):
        tab = match["tab"].rstrip(".")
        return _Guidance(
            f"Salesforce dependency: {name} is still referenced by tab {tab}",
            f"Salesforce reports that '{name}' ({kind}) cannot be removed while custom tab "
            f"'{tab}' (Custom Tab Definition) still references it. The log does not establish "
            "whether removal was intended.",
            (
                f"If the component should remain, preserve '{name}' and keep '{tab}' consistent "
                "in the same deployment package; check for an unintended removal.",
                f"If removal is intentional, coordinate removal or redirection of '{tab}' "
                f"and any other dependent references before removing '{name}'. Obtain review; "
                "including a still-referenced bundle alone is not a deletion fix.",
                "Validate the coordinated package against the intended target before deployment; "
                "do not remove a tab just to make validation pass.",
            ),
            guidance.owner, guidance.documentation,
        )
    return _Guidance(
        f"{guidance.title}: {name}",
        f"The reported component is '{name}' ({kind}). {guidance.explanation}",
        guidance.fix, guidance.owner, guidance.documentation,
    )


def _finding_for_signal(signal: FailureSignal, evidence: list[FindingEvidence]) -> Finding:
    """Shared rule wording for snapshot findings and the legacy diagnosis adapter."""

    if signal.rule_id == "salesforce.csv_as_sobject" and (match := _CSV_OBJECT.search(signal.text)):
        name = match["object"]
        guidance = _Guidance(
            f"CSV filename used as Salesforce object: {name}.csv",
            f"The Bulk API received '{name}.csv' as the object name and rejected it. "
            "The CSV extension belongs on the file input, not the Salesforce object API name.",
            (
                f"Verify '{name}' is the intended object in the target org; use that API name "
                f"for the data-step object / --sobject value, not '{name}.csv'.",
                "Keep the CSV path on --file. Check the changed data-step configuration or "
                "loader's filename-to-object mapping rather than renaming the whole package.",
                "Validate the corrected step and intended target before another deployment.",
            ),
            "Salesforce data-step / deployment owner", (_SALESFORCE_DOC,),
        )
    elif signal.rule_id == "rlp.datasync_ambiguous":
        match = DATASYNC_AMBIGUOUS_PATTERN.match(signal.text)
        target = match.group("target").strip() if match else "the cited target"
        guidance = _Guidance(
            f"DataSync target pre-validation is ambiguous: {target}",
            "The target has multiple matching mappings; a bare name cannot uniquely "
            "select the intended mapping. No particular target environment is inferred.",
            (
                "Inspect the target's mappings and choose the mapping that should be synchronized.",
                "Use the intended explicit mapping identifier in the run-target file "
                "instead of a bare name, through the normal review process.",
                "Validate that selection before triggering any data movement.",
            ), "RLP DataSync / mapping owner",
        )
    else:
        guidance = _GUIDANCE.get(
            signal.rule_id, _CATEGORY_GUIDANCE.get(signal.category, _CATEGORY_GUIDANCE["unknown"])
        )
        if signal.rule_id in {
            "salesforce.metadata_dependency", "salesforce.metadata_error",
            "salesforce.apex_compile", "salesforce.metadata_parse", "salesforce.metadata_duplicate",
        }:
            guidance = _metadata_guidance(signal, guidance)
    return Finding(
        rule_id=signal.rule_id, severity="error", category=signal.category,
        title=redact_text(guidance.title),
        explanation=redact_text(f"{guidance.explanation} Observed: {signal.text}"),
        fix=[redact_text(step) for step in guidance.fix], evidence=evidence, owner=guidance.owner,
        confidence="unknown" if signal.category == "unknown" or signal.rule_id in
        _INCOMPLETE_CAUSE_RULES else "observed",
        documentation=list(guidance.documentation),
    )


def _url_line(url: str | None, line: int | None) -> str | None:
    if not url:
        return None
    base = urldefrag(redact_text(url))[0]
    return f"{base}#L{line}" if line is not None else base


def _job_evidence(snapshot: AnalysisSnapshot) -> FindingEvidence:
    reason = snapshot.job.failure_reason or snapshot.job.raw.get("failure_reason")
    return FindingEvidence(
        text=redact_text(
            f"Selected job status={snapshot.job.status}; conclusion={snapshot.job.conclusion}; "
            f"allow_failure={snapshot.job.allow_failure}; "
            f"failure_reason={reason or 'not provided'}."
        ),
        source_url=_url_line(snapshot.job.web_url, None),
    )


def _suppresses_exit(command: str, *, yaml_line: bool = False) -> bool:
    command = clean_log_line(command)
    if yaml_line:
        command = re.sub(r"^(?:-\s+|(?:script|before_script|after_script):\s*)", "", command)
        if len(command) > 1 and command[0] == command[-1] and command[0] in "'\"":
            command = command[1:-1]
    command = command.removeprefix("$ ").removeprefix("+ ").strip()
    if re.match(r"(?i)^(?:echo|printf|Write-Host|Write-Output|#)\b", command):
        return False
    unquoted = _SHELL_QUOTED.sub("", command).split("#", 1)[0]
    return _MASK_PATTERN.search(unquoted) is not None


def _masked_exit_evidence(snapshot: AnalysisSnapshot, content: str) -> FindingEvidence | None:
    for item in iter_log_lines(content):
        if item.text.startswith(("$ ", "+ ")) and _suppresses_exit(item.text):
            return FindingEvidence(
                text=item.text, line=item.line,
                source_url=_url_line(snapshot.job.web_url, item.line),
            )
    source = snapshot.job_source
    if not source:
        return None
    for config in snapshot.config_bundle or [snapshot.config]:
        if config.path != source.path:
            continue
        for line, text in enumerate(config.content.splitlines(), 1):
            if source.line_start <= line <= source.line_end and _suppresses_exit(
                text, yaml_line=True
            ):
                if text.lstrip().startswith("#"):
                    continue
                return FindingEvidence(
                    text=redact_text(text.strip()), path=config.path, line=line,
                    source_url=_url_line(config.source_url or source.source_url, line),
                )
    return None


def diagnose_job(snapshot: AnalysisSnapshot) -> Finding:
    """Return one best finding using selected-job status and explicit sanitized log evidence.

    No provider, model, repository read, mutation or retry is performed. Overall pipeline
    status is intentionally not interpreted here, including allowed-to-fail jobs.
    """

    content = redact_log(snapshot.redacted_log).content
    signals = failure_signals(content)
    outcome = snapshot.job.status.lower()
    if outcome == "completed":
        outcome = (snapshot.job.conclusion or outcome).lower()
    successful = outcome in _SUCCESS
    reason = snapshot.job.failure_reason or snapshot.job.raw.get("failure_reason")
    metadata = _job_evidence(snapshot)
    if reason == "runner_system_failure" and not successful:
        runner_signals = [item for item in signals if item.rule_id.startswith("runner.")]
        if not runner_signals:
            return Finding(
                rule_id="runner.reported_system_failure", severity="error",
                category="runner_infrastructure_failure", title="Runner system failure reported",
                explanation="Job metadata reports runner_system_failure, but the supplied log does "
                "not establish the infrastructure cause or a Sonar quality-gate result.",
                fix=["Obtain the sanitized runner preparation trace and check executor health "
                     "with the runner owner before considering a manual retry."],
                evidence=[metadata], confidence="unknown", owner="Runner / infrastructure team",
                job_id=snapshot.job.external_id, documentation=[_RUNNER_DOC],
            )
        signals = runner_signals
    if not signals:
        return Finding(
            rule_id="job.no_failure_observed" if successful else "job.insufficient_evidence",
            severity="info" if outcome not in _FAILED else "error",
            category="no_failure_observed" if successful else "unknown",
            title="No failure observed in the supplied evidence" if successful
            else "Job outcome lacks a causal error diagnostic",
            explanation=(
                "The selected job is reported successful. No explicit failure was found in the "
                "supplied log; warning, license and passing-test text are not failures. "
                if successful else
                "The available log does not establish a cause for the selected job's outcome. "
            ) + "Evidence is limited: it does not prove which intended package was deployed.",
            fix=["Compare the intended package parameter with the deployment receipt and selected "
                 "commit. Obtain missing sanitized diagnostics when needed; do not infer a failed "
                 "deployment from folder names alone."],
            evidence=[metadata], confidence="observed" if content and successful else "unknown",
            owner="Job / deployment package owner", job_id=snapshot.job.external_id,
        )
    signal = signals[0]
    evidence = [FindingEvidence(
        text=signal.text, line=signal.line, source_url=_url_line(snapshot.job.web_url, signal.line)
    )]
    for reference in extract_code_references(signal.text, limit=2):
        ref = snapshot.run.commit_sha
        path = redact_text(reference.path)
        source_url = None
        if ref and _literal_path(path) and snapshot.repository.provider in {
            ProviderName.GITLAB, ProviderName.GITHUB,
        }:
            separator = (
                "/-/blob/" if snapshot.repository.provider == ProviderName.GITLAB else "/blob/"
            )
            source_url = (
                f"{snapshot.repository.web_url.rstrip('/')}{separator}{quote(ref, safe='')}"
                f"/{quote(path, safe='/')}#L{reference.line}"
            )
        evidence.append(FindingEvidence(
            text=redact_text(reference.message or signal.text), path=path, line=reference.line,
            source_url=redact_text(source_url) if source_url else None,
        ))
    evidence.append(metadata)
    finding = _finding_for_signal(signal, evidence)
    finding.job_id = snapshot.job.external_id
    if signal.rule_id == "runner.job_timeout":
        command = next((item for item in reversed(list(iter_log_lines(content)))
                        if item.index < signal.index and _APEX_TEST_COMMAND.match(item.text)), None)
        if command:
            finding.title = "Apex test job exceeded its execution time limit"
            finding.explanation = (
                "The Salesforce Apex test command was still running when GitLab's job time "
                "limit was reached. Exit 130 is consistent with the runner interrupting the CLI; "
                "it does not establish a failed Apex assertion or completed test results. "
                f"Observed: {signal.text}"
            )
            finding.fix = [
                "Check the existing Apex test run, queue and results in the target org before "
                "launching another full test run.",
                "Identify slow tests or a blocking synchronous wait; verify whether asynchronous "
                "test submission and separate result collection fit the existing CI policy.",
                "Only adjust job/script time limits after measuring the run and reviewing the "
                "change with the CI owner; keep required tests enabled.",
            ]
            finding.evidence.insert(1, FindingEvidence(
                text=command.text, line=command.line,
                source_url=_url_line(snapshot.job.web_url, command.line),
            ))
    if signal.line is None:
        finding.explanation += (
            " The trace contains omitted spans; the original log line number for this evidence "
            "is unknown. A source-file location printed by the compiler remains valid."
        )
    if signal.rule_id == "runner.ssh_executor_unavailable":
        scanner_shown = any(
            re.match(r"(?i)^(?:\$\s*sonar|INFO\s+SonarScanner|SonarScanner\s+\d)", item.text)
            for item in iter_log_lines(content)
        )
        if not scanner_shown and "preparation failed" in signal.text.lower():
            finding.explanation += (
                " The cited attempt failed during preparation; no scanner execution is shown."
            )
    if successful:
        masking = _masked_exit_evidence(snapshot, content)
        finding.severity = "warning"
        finding.confidence = "likely"
        finding.title = "Error output in a successful job: " + finding.title
        finding.explanation += (
            " The selected job is reported successful; this diagnostic alone does not make the job "
            "or pipeline failed. Check whether the error was handled or recovered "
            "and verify the receipt."
        )
        finding.fix.insert(
            0, "Verify the command result and deployment receipt before applying a cause-specific "
            "fix; check whether the wrapper propagated native-process exit codes or recovered.",
        )
        if masking:
            finding.rule_id = "script.failure_masked"
            finding.category = "script_exit_masking"
            finding.title = "Possible swallowed script failure in a successful job"
            finding.explanation += (
                " An exit-suppression expression is present. It may hide the command's failure, "
                "but this evidence does not prove that branch executed."
            )
            finding.evidence.append(masking)
            finding.fix.insert(
                0, "Review the cited exit-suppression expression and native-process exit-code "
                "propagation with the script owner before any approved change.",
            )
    return finding


def _literal_path(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    path = value.strip().replace("\\", "/").removeprefix("./").rstrip("/")
    if not path or path.startswith("/") or re.search(r"[$*?{}\[\]:#\s]", path):
        return None
    if any(part in {"", ".", ".."} for part in path.split("/")):
        return None
    return path


def _path_index(paths: set[str]) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for path in paths:
        parts = path.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            index.setdefault(prefix.casefold(), set()).add(prefix)
    return index


def _case_mismatch(path: str, index: dict[str, set[str]]) -> str | None:
    if path in index.get(path.casefold(), set()):
        return None
    parts = path.split("/")
    for length in range(1, len(parts) + 1):
        prefix = "/".join(parts[:length])
        matches = index.get(prefix.casefold(), set())
        if prefix not in matches and len(matches) == 1:
            canonical = next(iter(matches))
            return "/".join([canonical, *parts[length:]])
    return None


def _added_lines(diff: str) -> list[tuple[int | None, str]]:
    result: list[tuple[int | None, str]] = []
    line: int | None = None
    for text in diff.splitlines():
        if match := _HUNK_PATTERN.match(text):
            line = int(match.group(1))
        elif text.startswith(("+++", "---", "diff ", "index ", "\\")):
            continue
        elif text.startswith("+"):
            result.append((line, text[1:]))
            if line is not None:
                line += 1
        elif text.startswith(" ") and line is not None:
            line += 1
    return result


def _yaml_paths(content: str) -> dict[str, set[int]]:
    """Only required local includes, literal package variables and explicit cd/package inputs.

    Artifacts, rules/changes globs, remote/project includes and arbitrary YAML strings
    are deliberately not treated as required repository inputs.
    """

    paths: dict[str, set[int]] = {}
    try:
        root = YAML(typ="rt").load(content)
    except (YAMLError, ValueError, RecursionError):
        return paths
    if not isinstance(root, Mapping):
        return paths

    def add(value: object, line: int | None) -> None:
        if path := _literal_path(value):
            if line is not None:
                paths.setdefault(path, set()).add(line + 1)

    def value_line(mapping: Mapping, key: object) -> int | None:
        location = getattr(mapping, "lc", None)
        if location is None:
            return None
        try:
            return location.value(key)[0]
        except (KeyError, TypeError):
            return None

    includes = root.get("include", [])
    for offset, item in enumerate(includes if isinstance(includes, list) else [includes]):
        if isinstance(item, Mapping):
            # Conditional and cross-project includes do not prove a required local input.
            if not any(key in item for key in {"project", "remote", "rules"}):
                add(item.get("local"), value_line(item, "local"))
        elif isinstance(item, str):
            location = getattr(includes, "lc", None)
            line = location.item(offset)[0] if location else value_line(root, "include")
            add(item, line)
    seen: set[int] = set()

    def visit(value: object) -> None:
        if id(value) in seen:
            return
        seen.add(id(value))
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key == "variables" and isinstance(child, Mapping):
                    for variable, variable_value in child.items():
                        if _PACKAGE_KEY.fullmatch(str(variable)):
                            add(variable_value, value_line(child, variable))
                if key in {"script", "before_script", "after_script", "run"}:
                    commands = child if isinstance(child, list) else [child]
                    for offset, command in enumerate(commands):
                        if isinstance(command, str):
                            location = getattr(child, "lc", None)
                            first_line = location.item(offset)[0] if location else value_line(
                                value, key
                            )
                            if first_line is None:
                                continue
                            for relative_line, statement in enumerate(command.splitlines()):
                                if re.match(r"^\s*(?:echo|printf|#)\b", statement):
                                    continue
                                if "#" in statement or re.search(r"[;&|`()]", statement):
                                    continue
                                for match in _SCRIPT_PATH.finditer(statement):
                                    # Block scalars begin on the line after their YAML key.
                                    block = getattr(command, "style", None) in {"|", ">"}
                                    if getattr(command, "style", None) == ">":
                                        continue
                                    add(next(part for part in match.groups() if part is not None),
                                        first_line + relative_line + int(block))
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    try:
        visit(root)
    except RecursionError:
        return {}
    return paths


def analyze_change_risks(
    changes: list[dict], configs: list[CiConfigFile], known_paths: list[str]
) -> list[Finding]:
    """Find literal case mismatches and unresolved inputs in changed YAML, never runtime causes.

    ``changes`` accepts GitLab-style old_path/new_path/diff/deleted_file/renamed_file
    dictionaries (``path`` is also accepted). ``known_paths`` may be bounded: absence
    is therefore a warning, not proof of a missing file. All inputs are read-only.
    """

    known = {path for value in known_paths if (path := _literal_path(value))}
    base_index = _path_index(known)
    deleted = {
        path for change in changes if change.get("deleted_file") or change.get("renamed_file")
        if (path := _literal_path(change.get("old_path") or change.get("new_path")))
    }
    current = (known - deleted) | {
        path for change in changes if not change.get("deleted_file")
        if (path := _literal_path(change.get("new_path") or change.get("path")))
    }
    current_index = _path_index(current)
    config_by_path = {config.path: config for config in configs}
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()

    def add(
        rule_id: str, file: str, referenced: str, text: str, line: int | None,
        source_url: str | None, canonical: str | None = None,
    ) -> None:
        key = (rule_id, file, referenced)
        if key in seen:
            return
        seen.add(key)
        explanation = (
            f"The literal path '{referenced}' differs in case from known repository path "
            f"'{canonical}'. Case-sensitive runners distinguish them."
            if canonical else
            f"The changed YAML references '{referenced}', which is absent from the supplied "
            "repository paths. The inventory may be bounded or the input generated; absence "
            "alone does not prove a runtime failure."
        )
        findings.append(Finding(
            rule_id=rule_id, severity="warning", category="repository_path_risk",
                 title=("Repository path case mismatch" if canonical
                     else "Unverified local CI input path"),
            explanation=redact_text(explanation + " This is static change evidence, not a claim "
                                    "that a job failed or the wrong package was deployed."),
            fix=["Compare the exact case and existence at the intended commit before an approved "
                 "path correction. For deployment selection, confirm the intended "
                 "package parameter and deployment receipt."],
            evidence=[FindingEvidence(text=redact_text(text), path=redact_text(file), line=line,
                                      source_url=_url_line(source_url, line))],
            confidence="observed" if canonical else "unknown", owner="CI / package owner",
            documentation=[_CI_DOC] if file.endswith((".yml", ".yaml")) else [],
        ))

    ordered_changes = sorted(
        changes, key=lambda item: str(item.get("new_path") or item.get("path", ""))
    )
    for change in ordered_changes:
        path = _literal_path(change.get("new_path") or change.get("path"))
        if not path or change.get("deleted_file"):
            continue
        old_path = _literal_path(change.get("old_path"))
        intentional_case_rename = bool(
            change.get("renamed_file") and old_path and old_path.casefold() == path.casefold()
        )
        canonical = _case_mismatch(path, base_index)
        if canonical and not intentional_case_rename:
            add("change.path_case_mismatch", path, path, f"Changed path: {path}",
                None, None, canonical)
        if not path.endswith((".yml", ".yaml")):
            continue
        config = config_by_path.get(path)
        diff = change.get("diff")
        added = _added_lines(diff) if isinstance(diff, str) and diff else []
        if config:
            referenced_paths = _yaml_paths(config.content)
            if not diff:
                added = list(enumerate(config.content.splitlines(), 1))
        else:
            # A fragment is sufficient only if it parses as an explicit supported YAML declaration.
            referenced_paths = _yaml_paths("\n".join(text for _, text in added))
        config_lines = config.content.splitlines() if config else []
        for added_index, (line, text) in enumerate(added, 1):
            if text.lstrip().startswith("#"):
                continue
            non_comment = re.split(r"\s+#", text, maxsplit=1)[0]
            for referenced in sorted(referenced_paths):
                location = line if config else added_index
                if config and line is None:
                    matching_lines = [
                        number for number in referenced_paths[referenced]
                        if number <= len(config_lines)
                        and config_lines[number - 1].strip() == text.strip()
                    ]
                    if len(matching_lines) != 1:
                        continue
                    location = matching_lines[0]
                if location is not None and location not in referenced_paths[referenced]:
                    continue
                if not re.search(r"(?<![\w/.-])(?:\./)?" + re.escape(referenced)
                                 + r"(?![\w/.-])", non_comment):
                    continue
                canonical = _case_mismatch(referenced, current_index)
                source_url = config.source_url if config else None
                evidence_line = location if config else line
                if canonical:
                    add("change.ci_path_case_mismatch", path, referenced, text, evidence_line,
                        source_url, canonical)
                elif referenced not in current and referenced not in current_index.get(
                    referenced.casefold(), set()
                ) and (known or referenced in deleted):
                    add("change.ci_path_unverified", path, referenced, text,
                        evidence_line, source_url)
    return findings