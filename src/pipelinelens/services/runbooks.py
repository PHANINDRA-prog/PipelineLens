"""Original, source-controlled documentation hints, not downloaded documentation.

Only generic public references and concise editorial summaries live here. Import
and lookup perform no I/O, environment access, model calls or automatic updates.
Inputs select constants; they are never retained or interpolated into text/URLs.

These hints belong under remediation, not diagnostic evidence. A caller must
preserve its finding's category and confidence, including an unknown cause.
``reviewed_on`` records editorial review, not a runtime freshness check.
"""

from dataclasses import dataclass

__all__ = ("Runbook", "runbook_for")

_REVIEWED_ON = "2026-09-13"
_MAX_IDENTIFIER_CHARS = 128
_JOB_LOGS = "https://docs.gitlab.com/ci/jobs/job_logs/#view-job-logs"
_SF_VALIDATE = (
    "https://developer.salesforce.com/docs/platform/salesforce-cli-reference/guide/"
    "cli_reference_project_deploy_validate.html#description-for-project-deploy-validate"
)


@dataclass(frozen=True, slots=True)
class Runbook:
    """Bounded editorial guidance; applicability is a caveat, not a diagnosis."""

    key: str
    title: str
    summary: str
    checks: tuple[str, ...]
    urls: tuple[str, ...]
    reviewed_on: str
    applicability: str


_UNKNOWN = Runbook(
    key="unknown",
    title="Inspect the job before choosing a remedy",
    summary="No curated condition matches this rule. Treat the cause as unknown; documentation "
    "can guide inspection but cannot establish a diagnosis.",
    checks=(
        "Read the complete job trace for the selected commit in the authorized CI interface, "
        "including collapsed sections.",
        "Locate the earliest actionable diagnostic and its command; a nonzero exit or upload "
        "footer alone is not a cause.",
        "Keep private logs, code and credentials local. Ask the job owner to validate a cause "
        "before any retry or change.",
    ),
    urls=(_JOB_LOGS,),
    reviewed_on=_REVIEWED_ON,
    applicability="Generic manual inspection, including successful jobs or incomplete evidence. "
    "The GitLab link illustrates log navigation; other CI providers differ. Not a verified fix.",
)

# References were reviewed as public documentation, not ingested as a corpus.
# Deep links name the relevant topic/heading; upstream pages may later change.
_RUNBOOKS = (
    Runbook(
        key="rlp.datasync_transport",
        title="Review an interrupted DataSync deployment safely",
        summary="A reset during a configuration request can leave the final target state "
        "uncertain. Compare the deployment window with target-side diagnostics before retrying.",
        checks=(
            "Identify the earliest target-side request failure and distinguish it from "
            "compatibility skips reported by the deployment summary.",
            "Check whether the target service accepted any partial configuration before "
            "retrying the same deployment.",
            "Use the existing approved deployment/retry path; do not bypass validation "
            "or force concurrent data movement.",
        ),
        urls=("https://docs.gitlab.com/ci/jobs/job_artifacts/#job-artifacts",),
        reviewed_on=_REVIEWED_ON,
        applicability="For PipelineLens DataSync artifact evidence only. A connection reset "
        "does not identify the failed host, root network cause, or target-side outcome.",
    ),
    Runbook(
        key="runner.job_timeout",
        title="Review the job's effective time budget",
        summary="A job deadline can terminate healthy or stalled work. Compare job and runner "
        "limits with the last active step before considering a larger budget.",
        checks=(
            "Check the job/project timeout and any lower runner maximum, plus script and "
            "cleanup time budgets.",
            "Establish whether a remote operation continues after CI stopped before retrying it.",
            "Validate workload or wait behavior; request CI-owner review for any timeout change.",
        ),
        urls=(
            "https://docs.gitlab.com/ci/runners/configure_runners/#set-the-maximum-job-timeout",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="For an explicit GitLab job execution timeout, not every network or CLI "
        "timeout. Runner version and configured limits matter; this is not a verified fix.",
    ),
    Runbook(
        key="runner.infrastructure",
        title="Inspect runner preparation and image acquisition",
        summary="Locate the runner phase that stopped before attributing the problem to "
        "application code. Preparation and image acquisition need the executor's own diagnostics.",
        checks=(
            "Match the job timestamp to existing runner service logs; retain the underlying "
            "error instead of enabling secret-bearing debug output.",
            "For image-pull failures only, check the image tag/digest and whether the reported "
            "problem concerns transport, availability or access.",
            "Have the runner owner verify the affected executor or route; keep TLS, registry "
            "access controls and isolation intact.",
        ),
        urls=(
            "https://docs.gitlab.com/runner/faq/#view-the-logs",
            "https://docs.gitlab.com/runner/executors/docker/#image-pull-error-messages",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="Runner preparation/system failures only. The image reference applies "
        "only when image pulling failed; neither reference proves a specific infrastructure fault.",
    ),
    Runbook(
        key="compiler.cs0161",
        title="Check C# return paths for CS0161",
        summary="CS0161 points to a value-returning member that can reach its end without "
        "supplying a result. The correct return value depends on the member's contract.",
        checks=(
            "Inspect the reported member at the failing revision and trace its reachable "
            "branches, including exception handlers.",
            "Choose contract-correct returns or intentional exception paths; do not add a "
            "placeholder result just to satisfy compilation.",
            "Rebuild with the matching toolchain and test the affected paths.",
        ),
        urls=(
            "https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/"
            "compiler-messages/jump-statement-errors#return-statement-values",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="Only an explicit C# CS0161 diagnostic qualifies. Other compiler codes "
        "or a generic build failure do not establish a return-path defect.",
    ),
    Runbook(
        key="apt.release_expired",
        title="Check APT repository freshness and time",
        summary="APT rejects Release metadata beyond its accepted validity window. The "
        "repository metadata or host clock needs investigation, rather than a credential change.",
        checks=(
            "Compare the host's UTC time and synchronization with the repository's Date and "
            "Valid-Until metadata.",
            "Check approved mirror/proxy freshness and distribution support; review use of "
            "a maintained signed source and compatible base image.",
            "Keep signature, Check-Date and Check-Valid-Until verification enabled; validate "
            "refreshed indexes without bypassing those checks.",
        ),
        urls=(
            "https://manpages.debian.org/trixie/apt/apt.conf.5.en.html#THE_ACQUIRE_GROUP",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="For an explicit expired Release/InRelease diagnostic in an APT-based "
        "environment. This does not cover every package resolver failure.",
    ),
    Runbook(
        key="salesforce.metadata_dependency",
        title="Review metadata references before removal",
        summary="A referenced component can block a metadata removal; a missing dependency can "
        "block an addition. Decide which operation was intended before changing the package.",
        checks=(
            "Read the named component and dependent references; distinguish an accidental "
            "omission from an approved deletion.",
            "Retain a component still needed by a page, tab or class. For intentional removal, "
            "review reference updates and deletion ordering together.",
            "Use target-appropriate validation with required tests before deployment; keep "
            "rollback and review protections.",
        ),
        urls=(
            "https://developer.salesforce.com/docs/atlas.en-us.api_meta.meta/api_meta/"
            "meta_deploy_deleting_files.htm#meta_deploy_deleting_files",
            _SF_VALIDATE,
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="Salesforce metadata dependency errors only. Supported deletion types, "
        "API version and sandbox versus production validation differ; deletion is not a default "
        "remedy.",
    ),
    Runbook(
        key="salesforce.metadata_validation",
        title="Read detailed metadata validation results",
        summary="A component failure or request wrapper starts an investigation, not a specific "
        "fix. Detailed deployment results separate parse, compile and test problems.",
        checks=(
            "Inspect nested errors and component rows for the original deployment ID and "
            "target, rather than submitting a new deployment to obtain details.",
            "Match reported names, locations, duplicate definitions or Apex signatures to "
            "the intended API version and component set.",
            "Validate only reviewed corrections with target-appropriate dry-run/validation "
            "and required tests; leave unknown causes unresolved until evidence supports them.",
        ),
        urls=(
            "https://developer.salesforce.com/docs/platform/salesforce-cli-reference/guide/"
            "cli_reference_project_deploy_report.html#description-for-project-deploy-report",
            _SF_VALIDATE,
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="For Salesforce metadata/Apex validation only. A count or generic API "
        "wrapper leaves the cause unknown; these checks are not a verified fix.",
    ),
    Runbook(
        key="salesforce.csv_as_sobject",
        title="Separate the object selector from CSV input",
        summary="A bulk-data object selector expects an API object name, not a CSV filename. "
        "Review argument placement without assuming the filename stem is the intended object.",
        checks=(
            "Compare the object selector and input-file argument in the installed command's "
            "help with the actual invocation.",
            "Verify the intended object API name, CSV headers and any external-ID field in "
            "the authorized target context.",
            "Review a synthetic fixture before an approved data operation; changing an "
            "object name is not permission to write records.",
        ),
        urls=(
            "https://developer.salesforce.com/docs/platform/salesforce-cli-reference/guide/"
            "cli_reference_data_upsert_bulk.html#flags",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="Only when a Salesforce data command used a CSV name as an object. "
        "The cited modern command uses --file; legacy commands can use different flags.",
    ),
    Runbook(
        key="salesforce.org_not_authenticated",
        title="Check the CLI's local authorization context",
        summary="Salesforce CLI authorization is tied to its execution context. A missing "
        "authenticated alias can reflect a different user or home directory, not revoked access.",
        checks=(
            "Check the selected target and CLI user/home context; inspect connection status "
            "locally without printing tokens or authorization URLs.",
            "Confirm the approved CI authentication setup and expected account; distinguish "
            "missing local authorization from a rejected remote credential.",
            "If reauthentication is necessary, have the credential owner use the approved "
            "workflow; retain least-privilege access and secret masking.",
        ),
        urls=(
            "https://developer.salesforce.com/docs/platform/salesforce-cli-reference/guide/"
            "cli_reference_org_list.html#flags",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="For an explicit Salesforce CLI org-not-authenticated error. An org "
        "listing does not establish deployment permission or prove credentials expired.",
    ),
    Runbook(
        key="script.invalid_json",
        title="Validate the input passed to jq",
        summary="A jq input parse error says the supplied bytes are not valid JSON for that "
        "invocation. Inspect the producer and shell quoting before changing downstream logic.",
        checks=(
            "Validate a small redacted or synthetic input locally and separate producer "
            "output from diagnostics.",
            "Use a JSON serializer or jq string arguments for text; supply --argjson only "
            "with already valid JSON.",
            "Check parse success and expected data shape separately. With -e, false or null "
            "can produce a failure status despite valid JSON.",
        ),
        urls=("https://jqlang.org/manual/#invoking-jq",),
        reviewed_on=_REVIEWED_ON,
        applicability="Only a jq parse diagnostic qualifies. Different shells quote arguments "
        "differently; successful parsing does not validate an application's schema.",
    ),
    Runbook(
        key="git.merge_conflict",
        title="Reconcile conflicting changes through review",
        summary="Conflicting edits need deliberate reconciliation of source and target content. "
        "A conflict report does not decide which side expresses the intended behavior.",
        checks=(
            "Inspect conflict blocks against the intended source and target revisions with "
            "the affected owners.",
            "Review the combined result, then rerun relevant validation for that revision; "
            "preserve branch and merge protections.",
            "Keep approval blockers separate from code conflicts; an unresolved readiness "
            "check alone proves neither.",
        ),
        urls=(
            "https://docs.gitlab.com/user/project/merge_requests/conflicts/"
            "#understand-conflict-blocks",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="Use only for an explicit merge conflict. The GitLab reference covers "
        "its interface; branch strategy and review policy remain project-specific.",
    ),
    Runbook(
        key="git.merge_approval_required",
        title="Verify required review for the current revision",
        summary="Required review can block merging even when changes combine cleanly. Check "
        "approval eligibility and the current revision, not an assumed authentication defect.",
        checks=(
            "Read the current approval status, eligible reviewers and any approvals "
            "invalidated by newer commits.",
            "Ask the required reviewers to review the intended revision through the existing "
            "workflow.",
            "Retain approval requirements and examine any remaining merge checks separately.",
        ),
        urls=(
            "https://docs.gitlab.com/user/project/merge_requests/approvals/#view-approval-status",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="For an explicit required-approval blocker. GitLab tier and project "
        "policies vary; a pending generic merge status is not proof that approval is missing.",
    ),
    Runbook(
        key="script.exec_format",
        title="Compare the executable with its runtime platform",
        summary="The operating system could not load the executable format. Architecture, file "
        "integrity or a script's interpreter header are candidates to inspect, not established "
        "causes.",
        checks=(
            "Compare the file format and CPU/OS target with the runner image and host.",
            "For scripts, inspect the first-line interpreter header and line endings; verify "
            "the intended interpreter is present.",
            "Check trusted build provenance before choosing a compatible executable; "
            "permission elevation does not repair a format mismatch.",
        ),
        urls=(
            "https://manpages.debian.org/trixie/manpages-dev/execve.2.en.html#ERRORS",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="For an explicit exec format error on a Linux/POSIX-style execution "
        "path. The referenced Linux behavior is not a universal Windows loader diagnosis.",
    ),
    Runbook(
        key="script.not_callable",
        title="Inspect the value used as a JavaScript function",
        summary="A call expression received a value that is not callable. Inspect the runtime "
        "value and API contract; the message alone does not identify a faulty package version.",
        checks=(
            "Locate the first relevant stack frame and inspect the receiver, property and "
            "imported value without logging secrets.",
            "Compare the call with the installed runtime/library API and lockfile; check "
            "for shadowed values or incompatible imports.",
            "Reproduce with a synthetic case before reviewing a caller or dependency change; "
            "a blind downgrade is not a diagnosis.",
        ),
        urls=(
            "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Errors/"
            "Not_a_function#what_went_wrong",
        ),
        reviewed_on=_REVIEWED_ON,
        applicability="Only the JavaScript not-a-function TypeError family. Other script "
        "errors and arbitrary dependency failures need separate evidence.",
    ),
    _UNKNOWN,
)

# A prefix is an entire rule ID, with optional dot-separated refinements. Broad
# vendor/category matches would mislabel unrelated failures, so are not allowed.
_RULE_PREFIXES = (
    ("rlp.datasync_field_mapping_connection_reset", "rlp.datasync_transport"),
    ("rlp.datasync_field_mapping_artifact_failure", "rlp.datasync_transport"),
    ("runner.job_timeout", "runner.job_timeout"),
    ("runner.preparation_failed", "runner.infrastructure"),
    ("runner.ssh_executor_unavailable", "runner.infrastructure"),
    ("runner.image_pull_failed", "runner.infrastructure"),
    ("runner.reported_system_failure", "runner.infrastructure"),
    ("compiler.cs0161", "compiler.cs0161"),
    ("dependency.apt_release_expired", "apt.release_expired"),
    ("apt.release_expired", "apt.release_expired"),
    ("salesforce.metadata_dependency", "salesforce.metadata_dependency"),
    ("salesforce.apex_compile", "salesforce.metadata_validation"),
    ("salesforce.metadata_parse", "salesforce.metadata_validation"),
    ("salesforce.metadata_duplicate", "salesforce.metadata_validation"),
    ("salesforce.metadata_error", "salesforce.metadata_validation"),
    ("salesforce.component_failure", "salesforce.metadata_validation"),
    ("salesforce.validation_failed", "salesforce.metadata_validation"),
    ("salesforce.metadata_request_failed", "salesforce.metadata_validation"),
    ("salesforce.csv_as_sobject", "salesforce.csv_as_sobject"),
    ("salesforce.org_not_authenticated", "salesforce.org_not_authenticated"),
    ("script.invalid_json", "script.invalid_json"),
    ("git.merge_conflict", "git.merge_conflict"),
    ("git.merge_approval_required", "git.merge_approval_required"),
    ("script.exec_format", "script.exec_format"),
    ("script.not_callable", "script.not_callable"),
)


def _identifier(value: str) -> str:
    # Reject oversized or unstructured input rather than truncating it into a
    # known rule. In particular, URLs, log text and non-ASCII lookalikes cannot match.
    if not isinstance(value, str) or len(value) > _MAX_IDENTIFIER_CHARS or not value.isascii():
        return ""
    normalized = value.strip().lower()
    return normalized if all(part.isidentifier() for part in normalized.split(".")) else ""


def runbook_for(rule_id: str, category: str = "unknown") -> Runbook:
    """Select an immutable hint by bounded, case-insensitive rule ID/prefix.

    Unknown IDs always return manual inspection, even with a familiar category.
    Categories cannot establish a vendor or cause; ``no_failure_observed`` also
    suppresses condition-specific hints. This function never inspects a trace,
    fetches a URL, changes confidence or constructs a project-specific remedy.
    """

    rule = _identifier(rule_id)
    if not rule or _identifier(category) == "no_failure_observed":
        return _UNKNOWN
    for prefix, key in _RULE_PREFIXES:
        if rule == prefix or rule.startswith(prefix + "."):
            return next(book for book in _RUNBOOKS if book.key == key)
    return _UNKNOWN