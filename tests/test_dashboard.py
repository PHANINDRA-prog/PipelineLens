"""Dashboard/client regressions: mocked API, synthetic credentials, no network or vault I/O."""

from __future__ import annotations

import ast
import json
import re
import socket
from copy import deepcopy
from pathlib import Path
from typing import Any

import httpx
import pytest
from dotenv import main as dotenv_main
from streamlit.testing.v1 import AppTest

# Importing application types must not read the user's .env, even during collection.
with pytest.MonkeyPatch.context() as import_guard:
    import_guard.setattr(dotenv_main.DotEnv, "dict", lambda self: {})
    from pipelinelens.dashboard import app as dashboard
    from pipelinelens.dashboard import client as client_module
    from pipelinelens.dashboard.client import ApiClientError, PipelineLensApiClient
    from pipelinelens.services.inspection import InspectionResult

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "src/pipelinelens/dashboard/app.py"
LOCAL = "/api/v1/local"
HOST = "https://gitlab.test"
PROJECT = f"{HOST}/group/sample"
PIPELINE = f"{PROJECT}/-/pipelines/123"
SHA = "a" * 40
TOKEN = "synthetic-request-secret-never-real"
CREDENTIAL_ID = "11111111-1111-4111-8111-111111111111"
QUOTE = "ERROR: Preparation failed: dial tcp executor.invalid:22: i/o timeout"
TITLE = "Runner cannot reach its SSH/docker executor"
FIXES = [
    "Check the runner route and firewall access to TCP 22.",
    "Check runner health with the infrastructure owner.",
    "Retry manually only after connectivity is restored.",
    "Additional diagnostic step belongs in collapsed details.",
]
SOURCE_PATH = "src/request.json"
SOURCE_URL = f"{PROJECT}/-/blob/{SHA}/{SOURCE_PATH}"
SOURCE_TEXT = '{\n  "sobject": "accounts.csv",\n  "records": [{"Name": "Sample"}]\n}\n'
SOURCE_DIFF = (
    f"--- a/{SOURCE_PATH}\n"
    f"+++ b/{SOURCE_PATH}\n"
    "@@ -1,4 +1,4 @@\n"
    " {\n"
    '-  "sobject": "accounts.csv",\n'
    '+  "sobject": "Account",\n'
    '   "records": [{"Name": "Sample"}]\n'
    " }\n"
)
VERIFY = [
    "Validate the JSON and confirm Account is the intended object API name.",
    "Run the existing request fixture test against this commit.",
]
CONDITION = "Only if these records are intended for the Account object."
DOC_URL = "https://docs.gitlab.com/runner/faq/#check-the-runner"
SUMMARY_PATH = "datasync/deploy-summary.json"
SUMMARY_URL = f"{PROJECT}/-/jobs/7/artifacts/file/{SUMMARY_PATH}"
SUMMARY_COUNTERS = (
    "DataSync deploy summary counters: DataSync deploy: count=3, failedCount=0; "
    "field mappings: deployed=12, failed=1, skipped=897; "
    "object mappings: updated=3; value transformations: failed=0. "
)


def remediation_fixture(rule_id="runner.ssh_executor_unavailable", job_id="7") -> dict:
    return {
        "job_id": job_id, "rule_id": rule_id,
        "summary": "Runner preparation could not reach its SSH executor.",
        "cause_confidence": 91, "fix_confidence": 28, "score_label": dashboard.SCORE_LABEL,
        "confidence_basis": [
            "The runner diagnostic identifies a TCP timeout before the script ran.",
            "Runner network settings and a restored route were not verified.",
        ],
        "proposals": [], "source_blocks": [],
        "actions": ["Inspect the diagnostic."],
        "missing_information": ["Runner network route and executor health."],
        "documentation": [DOC_URL],
    }


def use_source_proposal(api: FakeApi, *, fix_confidence=82) -> dict:
    finding = api.result["findings"][1]
    finding.update(
        rule_id="salesforce.csv_as_sobject", category="request_validation",
        title="CSV filename was passed as a Salesforce object",
        explanation=(
            "The sobject field contains a CSV path instead of a Salesforce object API name."
        ),
        fix=["Confirm the intended object API name, not the CSV input filename."],
        evidence=[{
            "text": "Unknown sObject: accounts.csv", "path": SOURCE_PATH, "line": 2,
            "source_url": SOURCE_URL + "#L2",
        }],
    )
    remediation = remediation_fixture(finding["rule_id"], finding["job_id"])
    remediation.update(
        summary=finding["explanation"], fix_confidence=fix_confidence,
        confidence_basis=[
            "Exact JSON input and quoted sObject diagnostic compared at the run commit.",
        ],
        proposals=[{
            "kind": "source_diff", "title": "Use the Account object API name",
            "path": SOURCE_PATH, "ref": SHA, "source_url": SOURCE_URL,
            "diff": SOURCE_DIFF, "condition": CONDITION,
            "rationale": (
                "Preserve all record values and change only the object name if Account is intended."
            ),
            "verification": VERIFY,
        }],
        source_blocks=[{
            "path": SOURCE_PATH, "ref": SHA, "source_url": SOURCE_URL,
            "line_start": 1, "line_end": 4, "content": SOURCE_TEXT, "language": "json",
        }],
        documentation=["https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/overview#security-information"],
    )
    api.result["remediations"] = [remediation]
    return remediation


def use_deployment_summary(api: FakeApi, *, rule="connection_reset") -> dict:
    reset = rule == "connection_reset"
    finding = api.result["findings"][1]
    finding.update(
        rule_id=f"rlp.datasync_field_mapping_{rule}", severity="error",
        category="deployment_transport_failure" if reset else "deployment_failure",
        title="DataSync field mapping deployment " + (
            "encountered a connection reset" if reset else "recorded a failure"
        ),
        explanation=(
            "The deployment summary records a field-mapping failure. "
            "The underlying network cause is not established." if reset else
            "The deployment summary records a field-mapping failure without a specific cause."
        ),
        fix=[
            "Review target-platform service diagnostics for this deployment.",
            "Confirm partial target state before a controlled retry.",
        ],
        evidence=[
            {"text": "Process exited with code 1.", "source_url": f"{PROJECT}/-/jobs/7"},
            {
                "path": SUMMARY_PATH, "source_url": SUMMARY_URL,
                "text": SUMMARY_COUNTERS + (
                    "A bounded actual field-mapping failure reports a connection reset."
                    if reset else "A bounded actual field-mapping failure has no recognized "
                    "safe error classification."
                ),
            },
        ],
        confidence="observed" if reset else "unknown", owner="DataSync / target platform",
    )
    api.result["status"] = "failed"
    api.result["pipeline"]["status"] = "failed"
    api.result["jobs"][0].update(name="deploy-datasync", allow_failure=False)
    api.result["analyses"][0]["job"] = deepcopy(api.result["jobs"][0])
    api.result["analyses"][0]["redacted_log"] = "Starting deployment\nProcess exited with code 1."
    remediation = remediation_fixture(finding["rule_id"], finding["job_id"])
    config = api.result["config_bundle"][0]
    remediation.update(
        summary=finding["explanation"], cause_confidence=94 if reset else 30,
        fix_confidence=15 if reset else 10,
        confidence_basis=["Deployment artifact records the failure, not a verified fix."],
        missing_information=["Target diagnostics and partial-state verification."],
        source_blocks=[{**config, "line_start": 1, "line_end": 2, "language": "yaml"}],
    )
    api.result["remediations"] = [remediation]
    return remediation


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Dashboard tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)
    monkeypatch.setattr(dotenv_main.DotEnv, "dict", lambda self: {})


def response_fixture() -> dict[str, Any]:
    repository = {
        "provider": "gitlab", "external_id": "42", "owner": "group", "name": "sample",
        "web_url": PROJECT, "default_branch": "main",
    }
    pipeline = {
        "external_id": "123", "name": "Pipeline fixture", "status": "success",
        "commit_sha": SHA, "ref_name": "main", "web_url": PIPELINE,
    }
    jobs = [
        {
            "external_id": "7", "name": "sonarqube-check", "status": "failed",
            "stage": "quality", "allow_failure": True,
            "failure_reason": "runner_system_failure", "web_url": f"{PROJECT}/-/jobs/7",
        },
        {
            "external_id": "8", "name": "deploy", "status": "success",
            "stage": "deploy", "allow_failure": False, "web_url": f"{PROJECT}/-/jobs/8",
        },
        {
            "external_id": "9", "name": "validate", "status": "success",
            "stage": "validate", "allow_failure": False, "web_url": f"{PROJECT}/-/jobs/9",
        },
    ]
    config = {
        "path": ".gitlab-ci.yml", "ref": SHA, "content": "build:\n  script: dotnet build\n",
        "source_url": f"{PROJECT}/-/blob/{SHA}/.gitlab-ci.yml",
    }
    source = {
        "path": config["path"], "line_start": 1, "line_end": 2, "job_key": "build",
        "source_url": config["source_url"], "match_confidence": 1.0,
    }
    findings = [
        {
            "rule_id": "ci.visibility", "severity": "warning", "category": "ci_configuration",
            "title": "CI visibility is partial", "explanation": "A mutable include was read.",
            "fix": ["Review source access."], "evidence": [], "confidence": "unknown",
        },
        {
            "rule_id": "runner.ssh_executor_unavailable", "severity": "warning",
            "category": "runner_infrastructure_failure", "title": TITLE,
            "explanation": "Runner preparation failed before scanner execution. "
            "allow_failure=true means this warning need not fail the successful pipeline.",
            "fix": FIXES,
            "evidence": [
                {"text": QUOTE, "line": 2, "source_url": f"{PROJECT}/-/jobs/7#L2"},
                {
                    "text": "Runner job definition", "path": ".gitlab-ci.yml", "line": 1,
                    "source_url": config["source_url"] + "#L1",
                },
            ],
            "confidence": "observed", "owner": "Runner / infrastructure team", "job_id": "7",
            "documentation": ["https://docs.gitlab.com/runner/faq/"],
        },
        {
            "rule_id": "job.no_failure_observed", "severity": "info",
            "category": "no_failure_observed", "title": "No failure observed in sampled job",
            "explanation": "The selected evidence reports success; no deployment is inferred.",
            "fix": ["Compare the intended package with its deployment receipt."],
            "evidence": [{"text": "Job succeeded", "source_url": jobs[1]["web_url"]}],
            "confidence": "observed", "owner": "Deployment owner", "job_id": "8",
        },
    ]
    analyses = []
    for job in jobs[:2]:
        analyses.append({
            "analysis_id": f"analysis-{job['external_id']}", "repository": repository,
            "run": pipeline, "job": job, "progress": {"job_log": "fetched"},
            "config": config, "config_bundle": [config], "job_source": source,
            "graph": {"provider": "gitlab", "config_files": [config["path"]], "nodes": []},
            "redacted_log": "Preparing runner\n" + QUOTE if job["status"] == "failed"
            else "Job succeeded",
            "chunks": [],
            "fingerprint": {"digest": SHA, "category": "unknown", "normalized_message": QUOTE},
            "diagnosis": {
                "failure_category": "unknown", "confidence": 0.96, "summary": "Legacy unused",
                "likely_root_cause": "Legacy prose must not override findings",
            },
        })
    # Validate the stub against the real service contract without running a provider or API.
    result = InspectionResult(
        repository=repository, pipeline=pipeline, resolved_url=PIPELINE,
        reference_kind="pipeline", project_key=PROJECT, findings=findings, jobs=jobs,
        analyses=analyses, config_bundle=[config],
        ci_config_access={
            "complete": False,
            "entries": [
                {
                    "path": config["path"], "ref": SHA, "state": "readable",
                    "relationship": "root", "detail": "Root source at the pipeline SHA.",
                    "source_url": config["source_url"],
                },
                {
                    "path": "team/includes/ci.yml", "ref": "release", "state": "readable",
                    "relationship": "project_include",
                    "detail": "Mutable ref pinned during inspection, not verified run history.",
                },
            ],
            "notes": ["Current branch resolution is not proof of historical include content."],
        },
        project_structure=[
            {"path": f"folder/file-{index:03}.txt", "entry_type": "file"}
            for index in range(300)
        ],
        merge_requests=[{
            "iid": 4, "title": "Fix request handling", "status": "opened",
            "source": "feature", "target": "main", "head_sha": "b" * 40,
            "source_type": "pipeline_commit", "web_url": f"{PROJECT}/-/merge_requests/4",
        }],
        changes=[{
            "old_path": "src/Controller.cs", "new_path": "src/Controller.cs",
            "new_file": False, "renamed_file": False, "deleted_file": False,
            "collapsed": False, "too_large": False,
        }],
        downstream=[{
            "id": 17, "name": "trigger-child", "status": "failed", "allow_failure": True,
            "access": "partial", "analyzed_job_id": None,
            "downstream_pipeline": {
                "id": 456, "status": "failed", "web_url": f"{PROJECT}/-/pipelines/456",
            },
        }],
        notes=["Inspection is a bounded sample, not an exhaustive audit."],
        analyzed_job_count=2, skipped_job_count=1, status="warning",
    ).model_dump(mode="json")
    return {
        **result, "submitted_url": PIPELINE, "inspected_at": "2026-09-13T10:00:00+00:00",
        "cached": False, "cache_age_seconds": 0, "elapsed_ms": 1400,
        "connection_used": "Local connection", "credential_saved": False,
        "knowledge_saved": True,
        "knowledge_summary": {"projects": 1, "observations": 2, "confirmed_resolutions": 0},
        "confirmed_resolutions": [], "mode": "local_rules",
        "remediations": [remediation_fixture()],
        "corpus_matches": {
            "runner.ssh_executor_unavailable": {"seen_failed_pipelines": 3, "failed_jobs": 4},
        },
    }


class FakeApi:
    def __init__(self) -> None:
        self.status = {
            "mode": "local_rules", "external_model_calls": False, "vault_available": True,
            "configured_connection": True, "configured_host": HOST, "saved_connections": [],
            "knowledge": {"projects": 1, "observations": 2, "confirmed_resolutions": 0},
            "notes": [],
        }
        self.result = response_fixture()
        self.calls: list[tuple[str, str, dict | None]] = []
        self.errors: dict[str, ApiClientError] = {}
        self.export: Any = {
            "schema_version": 1, "notice": dashboard.EXPORT_NOTICE,
            "projects": {}, "observations": [], "resolutions": [],
        }

    def get(self, path: str) -> dict:
        self.calls.append(("GET", path, None))
        if path in self.errors:
            raise self.errors[path]
        if path == f"{LOCAL}/status":
            return deepcopy(self.status)
        if path == f"{LOCAL}/knowledge/export":
            return deepcopy(self.export)
        raise AssertionError(f"Unexpected route: {path}")

    def post(self, path: str, payload: dict | None = None) -> Any:
        payload = deepcopy(payload or {})
        self.calls.append(("POST", path, payload))
        if path in self.errors:
            raise self.errors[path]
        if path == f"{LOCAL}/inspect":
            result = deepcopy(self.result)
            result["knowledge_saved"] = bool(payload.get("remember_analysis", True))
            if payload.get("remember_token"):
                self.status["saved_connections"] = [{
                    "id": CREDENTIAL_ID, "host": HOST, "projects": ["group/sample"],
                }]
                result["credential_saved"] = True
            if not payload.get("token") and self.status["saved_connections"]:
                result["connection_used"] = "Saved Windows connection"
                result["credential_saved"] = True
            return result
        if path == f"{LOCAL}/connections/forget":
            self.status["saved_connections"] = []
            return {"removed": True}
        if path == f"{LOCAL}/knowledge/confirm":
            self.status["knowledge"]["confirmed_resolutions"] += 1
            return {"saved": True, "human_confirmed": True}
        raise AssertionError(f"Unexpected route: {path}")

    def posted(self, suffix: str = "/inspect") -> list[dict]:
        return [payload for method, path, payload in self.calls
                if method == "POST" and path == LOCAL + suffix]


@pytest.fixture
def ui(monkeypatch):
    monkeypatch.setenv("PIPELINELENS_SELF_HOST_API", "never")
    api = FakeApi()
    monkeypatch.setattr(client_module, "PipelineLensApiClient", lambda base_url: api)
    at = AppTest.from_file(str(APP), default_timeout=15).run()
    assert not at.exception
    return at, api


def button(at: AppTest, label: str):
    return next(item for item in at.button if item.label == label)


def checkbox(at: AppTest, prefix: str):
    return next(item for item in at.checkbox if item.label.startswith(prefix))


def submit(at: AppTest, url: str = PIPELINE, token: str | None = None, *, enter=False):
    at.text_input(key="inspection_url").input(url)
    if token is not None:
        at.text_input(key="read_only_token").input(token)
    analyze = button(at, "Analyze")
    if enter:
        # AppTest has no keyboard driver. Enter in an enter_to_submit form emits
        # the first submit button's trigger; exercise that identical wire event.
        form = next(item for item in at.get("form") if item.proto.form.form_id == "inspect-link")
        assert form.proto.form.enter_to_submit
        states = at._tree.get_widget_states()
        next(item for item in states.widgets if item.id == analyze.id).trigger_value = True
        at._run(widget_state=states)
    else:
        analyze.click().run()
    assert not at.exception
    return at


def rendered_text(at: AppTest) -> str:
    kinds = ("markdown", "caption", "info", "warning", "error", "success", "subheader", "code")
    return "\n".join(str(item.value) for kind in kinds for item in at.get(kind))


def answer_elements(at: AppTest) -> list:
    flat = list(at.main)
    start = next(index for index, item in enumerate(flat) if item.type == "subheader")
    end = next(index for index, item in enumerate(flat)
               if item.type == "expander" and item.label == "Evidence & details")
    return flat[start:end]


def answer_text(at: AppTest) -> str:
    kinds = {"markdown", "caption", "subheader", "code", "warning"}
    return literal("\n".join(str(item.value) for item in answer_elements(at)
                            if item.type in kinds))


def outer_expanders(at: AppTest) -> list[str]:
    return [item.label for item in at.main.children.values() if item.type == "expander"]


def literal(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def test_initial_ui_is_local_only_no_eager_memory_or_model_calls(ui):
    at, api = ui
    assert api.calls == [("GET", f"{LOCAL}/status", None)]
    assert any(
        "optional cloud assist stays off unless you turn it on" in item.value
        for item in at.caption
    )
    assert not at.info and not at.tabs
    assert not at.sidebar.radio
    assert at.radio(key="connection_mode").value == "auto"
    assert at.radio(key="connection_mode").proto.form_id == "inspect-link"
    assert at.text_input(key="read_only_token").proto.form_id == "inspect-link"
    options = next(item for item in at.expander if item.label == "Connection & options")
    assert options.text_input[0].key == "read_only_token"
    assert at.text_input(key="inspection_url").label == "GitLab link"
    assert not at.checkbox(key="remember_token").value
    assert at.checkbox(key="remember_analysis").value
    assert at.checkbox(key="remember_analysis").label == "Save diagnostic notes locally"
    assert at.checkbox(key="remember_analysis").proto.form_id == "inspect-link"
    assert options.checkbox(key="remember_analysis").value
    assert dashboard.LOCAL_NOTES_NOTICE in rendered_text(at)
    assert outer_expanders(at) == ["Settings"]
    assert not at.metric
    assert not at.get("download_button")
    assert all(not item.proto.expanded for item in at.expander)


def test_missing_connection_keeps_minimal_options_collapsed(ui):
    at, api = ui
    api.status.update(configured_connection=False, saved_connections=[])
    at.run()
    assert not at.exception
    assert all(not item.proto.expanded for item in at.expander)
    assert not at.tabs and not api.posted()


@pytest.mark.parametrize("enter", [False, True], ids=["Analyze", "Enter-trigger"])
def test_submission_retains_url_clears_only_password_and_keeps_settings(ui, enter):
    at, api = ui
    at.radio(key="connection_mode").set_value("request").run()
    at.checkbox(key="remember_token").check()
    at.checkbox(key="force_refresh").check()
    submit(at, PIPELINE, TOKEN, enter=enter)
    assert api.posted() == [{
        "url": PIPELINE, "token": TOKEN, "connection": "request",
        "remember_token": True, "remember_analysis": True, "refresh": True, "max_jobs": 5,
        "ask_cloud_ai": False,
    }]
    assert at.text_input(key="inspection_url").value == PIPELINE
    assert at.text_input(key="read_only_token").value == ""
    assert at.radio(key="connection_mode").value == "request"
    assert at.checkbox(key="remember_token").value
    assert at.checkbox(key="force_refresh").value
    assert at.checkbox(key="remember_analysis").value
    assert not at.get("form")[0].proto.form.clear_on_submit
    assert TOKEN not in json.dumps(at.session_state.filtered_state)
    assert TOKEN not in rendered_text(at)
    at.run()
    assert len(api.posted()) == 1
    assert at.text_input(key="inspection_url").value == PIPELINE


@pytest.mark.parametrize("suffix", [
    "/-/pipelines/123", "/-/jobs/8", "/-/tree/feature/review",
    "/-/blob/feature/review/.gitlab-ci.yml", "",
])
def test_supported_url_kinds_use_new_inspection_endpoint(ui, suffix):
    at, api = ui
    url = PROJECT + suffix
    submit(at, url)
    assert api.posted()[0] == {
        "url": url, "connection": "auto", "remember_token": False,
        "remember_analysis": True, "refresh": False, "max_jobs": 5, "ask_cloud_ai": False,
    }
    assert at.text_input(key="inspection_url").value == url
    assert at.session_state.inspection_result["submitted_url"] == url
    assert all(path.startswith(LOCAL + "/") for _, path, _ in api.calls)


def test_save_is_opt_in_and_automatic_reuses_saved_connection_without_token(ui):
    at, api = ui
    submit(at, PIPELINE, TOKEN)
    assert api.posted()[0]["remember_token"] is False
    assert api.status["saved_connections"] == []
    at.checkbox(key="remember_token").check()
    submit(at, PIPELINE, TOKEN)
    assert api.posted()[1]["remember_token"] is True
    assert api.status["saved_connections"][0]["host"] == HOST
    submit(at)
    assert at.radio(key="connection_mode").value == "auto"
    assert "token" not in api.posted()[2]
    assert api.posted()[2]["remember_token"] is False
    assert "Saved Windows connection" in rendered_text(at)
    assert TOKEN not in json.dumps(at.session_state.filtered_state)


def test_unavailable_windows_vault_disables_save_and_never_sends_consent(ui):
    at, api = ui
    api.status["vault_available"] = False
    at.session_state["remember_token"] = True
    at.run()
    assert at.checkbox(key="remember_token").disabled
    submit(at, PIPELINE, TOKEN)
    assert api.posted()[0]["remember_token"] is False
    assert "New tokens will not be saved" in rendered_text(at)


def test_configured_selection_ignores_token_and_clears_it_after_submission(ui):
    at, api = ui
    at.text_input(key="inspection_url").input(PIPELINE).run()
    at.text_input(key="read_only_token").input(TOKEN).run()
    at.radio(key="connection_mode").set_value("configured").run()
    # Form widgets are batched; no stale disabled state relies on an unseen rerun.
    assert not at.text_input(key="read_only_token").disabled
    assert at.text_input(key="read_only_token").value == TOKEN
    assert at.text_input(key="inspection_url").value == PIPELINE
    assert not api.posted()
    submit(at)
    assert "token" not in api.posted()[0]
    assert not api.posted()[0]["remember_token"]
    assert api.posted()[0]["connection"] == "configured"
    assert at.text_input(key="read_only_token").value == ""
    assert TOKEN not in json.dumps(at.session_state.filtered_state)
    at.radio(key="connection_mode").set_value("request").run()
    assert not at.text_input(key="read_only_token").disabled
    assert not at.checkbox(key="remember_token").disabled
    assert at.text_input(key="inspection_url").value == PIPELINE


def test_configured_mode_cannot_retain_a_token_pasted_into_the_url(ui):
    at, api = ui
    at.radio(key="connection_mode").set_value("configured").run()
    submit(at, f"{PROJECT}/-/blob/{TOKEN}/.gitlab-ci.yml", TOKEN)
    assert at.session_state.submission_failed
    assert not api.posted()
    assert at.text_input(key="inspection_url").value == ""
    assert at.text_input(key="read_only_token").value == ""
    assert TOKEN not in json.dumps(at.session_state.filtered_state)
    assert TOKEN not in rendered_text(at)


@pytest.mark.parametrize("url", [
    "", "not a link", f"{PROJECT}/-/jobs/not-an-id", f"{PROJECT}/-/merge_requests/1",
    f"{PIPELINE}?private_token={TOKEN}",
    f"{PROJECT}/-/blob/{TOKEN}/.gitlab-ci.yml",
    f"https://user:{TOKEN}@gitlab.test/group/sample/-/pipelines/123",
])
def test_invalid_selection_clears_stale_result_but_not_url(ui, url):
    at, api = ui
    submit(at)
    assert at.session_state.inspection_result
    submit(at, url, TOKEN)
    assert at.session_state.submission_failed is True
    assert at.session_state.inspection_result is None
    assert at.text_input(key="inspection_url").value == dashboard._url_to_keep(url, TOKEN)
    assert at.text_input(key="read_only_token").value == ""
    assert len(api.posted()) == 1
    assert not at.subheader
    assert "Previous results were cleared" in rendered_text(at)
    assert TOKEN not in rendered_text(at)
    assert TOKEN not in json.dumps(at.session_state.filtered_state)


@pytest.mark.parametrize("selection", ["missing-token", "different-host", "unconfigured"])
def test_connection_selection_errors_are_safe_and_do_not_send_request(ui, selection):
    at, api = ui
    if selection == "missing-token":
        at.radio(key="connection_mode").set_value("request").run()
        url = PIPELINE
    else:
        at.radio(key="connection_mode").set_value("configured").run()
        url = PIPELINE.replace("gitlab.test", "other.test")
        if selection == "unconfigured":
            api.status["configured_connection"] = False
    submit(at, url)
    assert at.session_state.submission_failed
    assert not api.posted()
    assert at.text_input(key="inspection_url").value == url


def test_failed_api_attempt_has_no_stale_result_or_echoed_secret(ui):
    at, api = ui
    submit(at)
    api.errors[f"{LOCAL}/inspect"] = ApiClientError("Access rejected " + TOKEN)
    submit(at, PIPELINE, TOKEN)
    assert at.session_state.submission_failed
    assert at.session_state.inspection_result is None
    assert at.text_input(key="read_only_token").value == ""
    assert TOKEN not in rendered_text(at)
    assert TOKEN not in json.dumps(at.session_state.filtered_state)
    del api.errors[f"{LOCAL}/inspect"]
    submit(at)
    assert not at.session_state.submission_failed
    assert at.session_state.inspection_result


def test_incomplete_response_flags_failure_and_clears_password(ui):
    at, api = ui
    api.result = {"detail": TOKEN}
    submit(at, PIPELINE, TOKEN)
    assert at.session_state.submission_failed
    assert at.session_state.inspection_result is None
    assert at.text_input(key="read_only_token").value == ""
    assert TOKEN not in rendered_text(at)


def test_unavailable_status_does_not_echo_error_or_prevent_request_token(ui):
    at, api = ui
    api.errors[f"{LOCAL}/status"] = ApiClientError(TOKEN)
    at.run()
    assert TOKEN not in rendered_text(at)
    assert at.checkbox(key="remember_token").disabled
    submit(at, PIPELINE, TOKEN)
    assert at.session_state.inspection_result


def test_causal_answer_is_concise_with_one_numbered_list_and_one_details_section(ui):
    at, _ = ui
    submit(at)
    assert at.subheader[0].value == TITLE
    text = answer_text(at)
    numbered = [literal(item.value) for item in answer_elements(at)
                if item.type == "markdown" and item.value.startswith("1. ")]
    assert numbered == ["\n".join(f"{index}. {fix}" for index, fix in enumerate(FIXES[:3], 1))]
    assert FIXES[3] not in text
    assert "No verified source patch" in text
    assert QUOTE not in text and "CI definition" not in text
    assert QUOTE in rendered_text(at)  # Available only in collapsed evidence/logs.
    assert not at.tabs
    assert outer_expanders(at) == ["Evidence & details"]
    assert [item.label for item in at.metric] == ["Cause confidence", "Fix confidence"]
    assert [item.value for item in at.metric] == ["91/100", "28/100"]
    assert all(dashboard.SCORE_LABEL in item.proto.help for item in at.metric)
    assert all("No target verification" in item.proto.help for item in at.metric)
    assert DOC_URL in text
    assert "https://docs.gitlab.com/runner/faq/" in text
    assert "Legacy prose" not in rendered_text(at)
    assert "96%" not in rendered_text(at)
    assert all(not item.proto.expanded for item in at.expander)
    details = next(item for item in at.expander if item.label == "Evidence & details")
    detail_labels = [item.label for item in details.expander]
    assert "Raw redacted logs (bounded view)" in detail_labels
    assert "Merge requests & changed files (static checks)" in detail_labels
    assert "CI source files (bounded view)" in detail_labels
    assert "Local settings & history" in detail_labels
    assert "Local history: 3 failed pipelines" in rendered_text(at)
    assert "Local history:" not in text
    assert not any(item.key.startswith("issue-") for item in at.selectbox)


def test_concrete_static_path_risk_precedes_visibility_and_success_context(ui):
    at, api = ui
    api.result["findings"] = [api.result["findings"][0], api.result["findings"][2], {
        "rule_id": "change.ci_path_case_mismatch", "category": "repository_path_risk",
        "severity": "warning", "title": "Repository path case mismatch",
        "explanation": "Static case mismatch; this does not prove a failed deployment.",
        "fix": ["Compare the intended package path and its case at the run commit."],
        "evidence": [], "confidence": "observed", "owner": "CI / package owner",
    }]
    submit(at)
    assert at.subheader[0].value == "Repository path case mismatch"
    assert "Static case mismatch" in literal(rendered_text(at))


def test_failed_job_without_known_cause_precedes_successful_sibling_warning(ui):
    at, api = ui
    api.result["findings"] = [api.result["findings"][1], {
        "rule_id": "log.explicit_error", "category": "unknown", "severity": "error",
        "title": "Failed job needs diagnostic review", "explanation": "Exit cause unknown.",
        "fix": ["Read the failed command diagnostic."], "evidence": [],
        "job_id": "9", "confidence": "unknown", "owner": "Job owner",
    }]
    api.result["status"] = "failed"
    api.result["pipeline"]["status"] = "failed"
    submit(at)
    assert at.subheader[0].value == "Failed job needs diagnostic review"


def test_successful_job_with_partial_sources_does_not_lead_with_access_noise(ui):
    at, api = ui
    api.result["findings"] = [api.result["findings"][0], api.result["findings"][2]]
    api.result["jobs"] = api.result["jobs"][1:]
    submit(at)
    assert "No failure observed" in at.subheader[0].value
    assert "Pipeline passed · inspection warning" in answer_text(at)
    assert any("CI visibility is partial" in literal(item.label) for item in at.expander)


def test_causal_quote_is_not_repeated_in_the_short_explanation(ui):
    at, api = ui
    api.result["findings"][1]["explanation"] = "Executor preparation timed out. Observed: " + QUOTE
    submit(at)
    short_prose = [literal(item.value) for item in answer_elements(at)
                   if item.type == "markdown"]
    assert "Executor preparation timed out." in short_prose
    assert not any("Observed: " in item for item in short_prose)
    assert QUOTE not in answer_text(at)
    assert QUOTE in [item.value for item in at.code]


def test_specific_causal_job_prioritized_over_pipeline_status_and_visibility(ui):
    at, api = ui
    api.result["findings"].insert(0, {
        "rule_id": "pipeline.failed", "severity": "error", "category": "pipeline_status",
        "title": "Pipeline failed", "explanation": "Metadata only", "fix": [], "evidence": [],
    })
    api.result["pipeline"]["status"] = "failed"
    api.result["status"] = "failed"
    api.result["findings"][2]["severity"] = "error"
    submit(at)
    assert at.subheader[0].value == TITLE
    assert "Pipeline failed" in answer_text(at)
    assert not any(item.key.startswith("issue-") for item in at.selectbox)
    assert not any("Pipeline failed" in literal(item.label) for item in at.expander)


def test_pipeline_success_and_allow_failure_are_compact_not_failure(ui):
    at, _ = ui
    submit(at)
    caption = next(literal(item.value) for item in at.caption if "Pipeline passed" in item.value)
    assert "allowed failure" in caption
    assert "allow_failure=true" in caption
    assert not at.error


def test_selected_successful_job_keeps_parent_pipeline_context(ui):
    at, api = ui
    api.result["selected_job"] = api.result["jobs"][1]
    api.result["reference_kind"] = "job"
    api.result["resolved_url"] = f"{PROJECT}/-/jobs/8"
    submit(at, f"{PROJECT}/-/jobs/8")
    assert "Selected job deploy: success; parent findings are separate" in answer_text(at)
    assert at.subheader[0].value == TITLE
    assert "Resolved parent pipeline" in rendered_text(at)
    assert PIPELINE in rendered_text(at)


def test_passed_sample_uses_passed_message_without_inventing_failure(ui):
    at, api = ui
    api.result["status"] = "passed"
    api.result["jobs"] = api.result["jobs"][1:]
    api.result["findings"] = api.result["findings"][2:]
    api.result["downstream"] = []
    submit(at)
    assert "No failure observed" in at.subheader[0].value
    assert "Pipeline passed · no failure observed in sampled evidence" in answer_text(at)
    assert not at.error


def test_configuration_only_response_is_explicitly_not_runtime(ui):
    at, api = ui
    api.result.update(pipeline=None, status="configuration_only", analyses=[], jobs=[])
    api.result["findings"] = []
    api.result["reference_kind"] = "repository"
    api.result["resolved_url"] = PROJECT
    submit(at, PROJECT)
    assert at.subheader[0].value == "No causal finding established"
    assert "Configuration only" in answer_text(at)
    assert "Static checks are not runtime evidence" in rendered_text(at)
    assert "Resolved parent pipeline" not in rendered_text(at)


def test_summary_keeps_canonical_original_and_discloses_cache_age(ui):
    at, api = ui
    api.result.update(cached=True, cache_age_seconds=37, submitted_url=TOKEN)
    url = f"{HOST.upper()}/group/sample/-/blob/main/.gitlab-ci.yml?ref_type=heads"
    submit(at, url)
    expected = f"{PROJECT}/-/blob/main/.gitlab-ci.yml"
    assert at.text_input(key="inspection_url").value == url
    assert at.session_state.inspection_result["submitted_url"] == expected
    text = literal(rendered_text(at))
    assert "Submitted URL (canonical)" in text and expected in text
    assert "37 seconds old" in text and "access rechecked" in text
    assert "2026-09-13T10:00:00+00:00" in text
    assert "1400 ms" in text
    assert TOKEN not in json.dumps(at.session_state.filtered_state)


def test_context_is_static_and_table_values_are_paginated_without_truncation(ui):
    at, api = ui
    api.result["changes"] *= 25
    submit(at)
    tables = [item.value for item in at.table]
    job_table = next(item for item in tables if "Reported outcome" in item.columns)
    assert job_table["Inspection"].tolist() == ["Sampled", "Sampled", "Metadata only"]
    assert job_table["allow_failure"].tolist() == [True, False, False]
    assert job_table["Source URL"].iloc[0] == dashboard._table_cell(
        "Source URL", f"{PROJECT}/-/jobs/7",
    )
    changes = next(item for item in tables if "New path" in item.columns)
    assert len(changes) == 20
    assert {literal(value) for value in changes["source_type"]} == {"pipeline_commit"}
    assert all("not runtime" in value for value in changes["Scope"])
    page = next(item for item in at.number_input if item.key.startswith("changes-page-"))
    page.set_value(2).run()
    changes = next(item.value for item in at.table if "New path" in item.value.columns)
    assert len(changes) == 5
    assert "not necessarily what a past run used" in rendered_text(at)
    assert "current MR diff is historical evidence only" in rendered_text(at)
    assert not at.dataframe


def test_tree_and_redacted_log_display_are_bounded_folded_and_pageable(ui):
    at, api = ui
    api.result["analyses"][0]["redacted_log"] = "\n".join(
        f"safe trace line {index}" for index in range(6000)
    )
    submit(at)
    tree = next(item for item in at.expander if item.label.startswith("Repository tree"))
    assert not tree.proto.expanded
    assert len(tree.code[0].value.splitlines()) == 280
    assert "file-279" in tree.code[0].value
    assert "file-280" not in tree.code[0].value
    logs = next(item for item in at.expander if item.label.startswith("Raw redacted logs"))
    assert not logs.proto.expanded
    assert len(logs.code[0].value.splitlines()) == dashboard.PAGE_LINES
    assert len(logs.code[0].value) <= dashboard.MAX_DISPLAY_CHARS
    page = next(item for item in at.number_input if item.key.startswith("log-page-"))
    page.set_value(2).run()
    logs = next(item for item in at.expander if item.label.startswith("Raw redacted logs"))
    assert logs.code[0].value.startswith("safe trace line 120")
    assert "original trace-line citation" in rendered_text(at)


def test_forget_requires_click_and_preserves_examined_link(ui):
    at, api = ui
    api.status["saved_connections"] = [{
        "id": CREDENTIAL_ID, "host": HOST, "projects": ["group/sample"],
    }]
    submit(at)
    assert not api.posted("/connections/forget")
    button(at, "Forget saved connection 1").click().run()
    assert not at.exception
    assert api.posted("/connections/forget") == [{"credential_id": CREDENTIAL_ID}]
    assert at.text_input(key="inspection_url").value == PIPELINE
    assert len(api.posted()) == 1
    assert "Saved connection forgotten" in rendered_text(at)


def test_export_requires_preview_and_acknowledgment_and_downloads_exact_snapshot(ui):
    at, api = ui
    assert not any(path.endswith("/export") for _, path, _ in api.calls)
    assert not at.get("download_button")
    button(at, "Preview sanitized export").click().run()
    assert not at.exception
    assert len(at.json) == 1
    assert not at.get("download_button")
    snapshot = at.session_state.export_preview
    assert json.loads(snapshot)["notice"] == dashboard.EXPORT_NOTICE
    api.export["observations"] = [{"kind": "new-unreviewed-snapshot"}]
    checkbox(at, "I reviewed this export").check().run()
    assert len(at.get("download_button")) == 1
    assert at.session_state.export_preview == snapshot
    assert sum(path.endswith("/export") for _, path, _ in api.calls) == 1
    button(at, "Preview sanitized export").click().run()
    assert not at.get("download_button")
    assert not checkbox(at, "I reviewed this export").value
    assert at.session_state.export_preview != snapshot


@pytest.mark.parametrize("export", [[], {"observations": []}, {"notice": ""}])
def test_export_without_review_notice_has_no_download(ui, export):
    at, api = ui
    api.export = export
    button(at, "Preview sanitized export").click().run()
    assert not at.exception
    assert not at.get("download_button")
    assert at.session_state.export_preview is None
    assert "No download is available" in rendered_text(at)


def test_new_inspection_invalidates_export_consent(ui):
    at, _ = ui
    button(at, "Preview sanitized export").click().run()
    checkbox(at, "I reviewed this export").check().run()
    assert at.get("download_button")
    submit(at)
    assert not at.get("download_button")
    assert at.session_state.export_preview is None


def test_confirmation_is_human_only_project_rule_scoped_and_not_auto_replayed(ui):
    at, api = ui
    submit(at)
    assert not api.posted("/knowledge/confirm")
    button(at, "Confirm resolution").click().run()
    assert not api.posted("/knowledge/confirm")
    at.text_area[0].input("Restored runner route and verified the build.")
    checkbox(at, "I tested this resolution").check().run()
    assert not api.posted("/knowledge/confirm")
    button(at, "Confirm resolution").click().run()
    assert not at.exception
    assert api.posted("/knowledge/confirm") == [{
        "project_key": PROJECT, "rule_id": "runner.ssh_executor_unavailable",
        "resolution": "Restored runner route and verified the build.", "confirmed": True,
    }]
    at.run()
    assert len(api.posted("/knowledge/confirm")) == 1
    assert "Human-confirmed resolution saved" in rendered_text(at)


def test_only_human_confirmed_history_is_shown_as_history(ui):
    at, api = ui
    api.result["confirmed_resolutions"] = [
        {"rule_id": "runner.ssh", "resolution": "Unreviewed suggestion", "human_confirmed": False},
        {"rule_id": "runner.ssh", "resolution": "Prior user assertion", "human_confirmed": True},
    ]
    submit(at)
    assert "Unreviewed suggestion" not in rendered_text(at)
    assert "Prior user assertion" in rendered_text(at)
    assert "not fixes revalidated for this run" in rendered_text(at)
    assert not api.posted("/knowledge/confirm")


def test_retention_disclosure_is_visible_outside_collapsed_options(ui):
    at, _ = ui
    notices = [item for item in at.main.children.values()
               if item.type == "caption" and item.value == dashboard.LOCAL_NOTES_NOTICE]
    assert len(notices) == 1
    retention = at.checkbox(key="remember_analysis")
    assert retention.value is True
    assert "No telemetry or uploads" in retention.proto.help
    assert "existing notes are not deleted" in retention.proto.help
    assert not at.get("file_uploader")


def test_retention_opt_out_is_sent_preserved_and_separate_from_token_consent(ui):
    at, api = ui
    at.checkbox(key="remember_analysis").uncheck()
    at.checkbox(key="remember_token").check()
    submit(at, token=TOKEN)
    assert api.posted()[0]["remember_analysis"] is False
    assert api.posted()[0]["remember_token"] is True
    assert at.checkbox(key="remember_analysis").value is False
    assert "No diagnostic notes saved for this analysis" in answer_text(at)
    assert "Redacted observation saved locally" not in rendered_text(at)
    assert "existing notes stay on this device" in rendered_text(at)
    assert TOKEN not in json.dumps(at.session_state.filtered_state)
    submit(at)
    assert api.posted()[1]["remember_analysis"] is False
    at.checkbox(key="remember_analysis").check()
    submit(at)
    assert api.posted()[2]["remember_analysis"] is True
    assert len(api.posted()) == 3
    assert not api.posted("/knowledge/confirm")
    assert not any(path.endswith("/export") for _, path, _ in api.calls)


@pytest.mark.parametrize("reported", [True, None], ids=["ignored-opt-out", "unconfirmed-retention"])
def test_retention_opt_out_cannot_be_silently_ignored_by_an_older_api(ui, monkeypatch, reported):
    at, api = ui
    post = api.post

    def response(path, payload=None):
        result = post(path, payload)
        if path == f"{LOCAL}/inspect":
            if reported is None:
                result.pop("knowledge_saved", None)
            else:
                result["knowledge_saved"] = reported
        return result

    monkeypatch.setattr(api, "post", response)
    at.checkbox(key="remember_analysis").uncheck()
    submit(at)
    text = answer_text(at)
    expected = (
        "saved despite opting out" if reported else "did not confirm whether notes were retained"
    )
    assert expected in text
    assert "No diagnostic notes saved" not in text


@pytest.mark.parametrize(("rule", "scores"), [
    ("connection_reset", ["94/100", "15/100"]),
    ("artifact_failure", ["30/100", "10/100"]),
])
def test_deployment_summary_evidence_is_on_main_before_collapsed_details(ui, rule, scores):
    at, api = ui
    remediation = use_deployment_summary(api, rule=rule)
    evidence = api.result["findings"][1]["evidence"][1]
    submit(at, token=TOKEN)
    main = answer_elements(at)
    codes = [item for item in main if item.type == "code"]
    assert len(codes) == 1
    assert codes[0].proto.language == "text"
    assert "field mappings: deployed=12, failed=1, skipped=897" in codes[0].value.splitlines()
    assert "object mappings: updated=3" in codes[0].value.splitlines()
    assert any(item.type == "caption" and "Deployment summary" in item.value for item in main)
    assert f"[Deployment summary source](<{SUMMARY_URL}>)" in answer_text(at)
    assert "No verified source patch" in answer_text(at)
    assert ".gitlab-ci.yml" not in answer_text(at)
    assert not any(item.proto.language == "diff" for item in at.code)
    assert [item.value for item in at.metric] == scores
    assert not at.tabs and len(at.subheader) == 1
    assert outer_expanders(at) == ["Evidence & details"]
    assert all(not item.proto.expanded for item in at.expander)
    details = next(item for item in at.expander if item.label == "Evidence & details")
    assert remediation["source_blocks"][0]["content"] in [item.value for item in details.code]
    more = next(item for item in details.expander
                if item.label == "More evidence, safe steps & references")
    assert evidence["text"] in [item.value for item in more.code]
    logs = next(item for item in details.expander
                if item.label == "Raw redacted logs (bounded view)")
    assert "Process exited with code 1." in logs.code[0].value
    assert at.text_input(key="inspection_url").value == PIPELINE
    assert at.text_input(key="read_only_token").value == ""
    assert dashboard.LOCAL_NOTES_NOTICE in rendered_text(at)
    assert len(api.posted()) == 1


def test_deployment_summary_source_keeps_canonical_artifact_path_not_query_or_redirect(ui):
    at, api = ui
    use_deployment_summary(api)
    evidence = api.result["findings"][1]["evidence"][1]
    evidence["source_url"] = (
        SUMMARY_URL.replace(HOST, "https://GITLAB.TEST:443")
        + f"?private_token={TOKEN}&redirect=https://external.invalid/#untrusted"
    )
    submit(at)
    assert f"[Deployment summary source](<{SUMMARY_URL}>)" in answer_text(at)
    assert "external.invalid" not in answer_text(at)
    assert "untrusted" not in answer_text(at)
    assert TOKEN not in rendered_text(at)


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
    "file:///C:/local/summary.json", "//external.invalid/summary.json",
    f"https://user:{TOKEN}@gitlab.test/group/sample/-/jobs/7/artifacts/file/{SUMMARY_PATH}",
    SUMMARY_URL + "/%0aunsafe",
])
def test_deployment_summary_unsafe_source_is_not_linkable(ui, url):
    at, api = ui
    use_deployment_summary(api)
    api.result["findings"][1]["evidence"][1]["source_url"] = url
    submit(at)
    assert "failed=1, skipped=897" in answer_text(at)
    assert "Deployment summary source" not in answer_text(at)
    assert url not in answer_text(at)
    assert not any(item.type == "markdown" and item.proto.allow_html
                   for item in answer_elements(at))


def test_deployment_summary_is_redacted_literal_text_not_html_or_a_source_diff(ui):
    at, api = ui
    use_deployment_summary(api)
    hostile = '<img src="https://external.invalid/pixel"> ![x](https://external.invalid/pixel)'
    api.result["findings"][1]["evidence"][1]["text"] = (
        f"field mappings: failed=1, skipped=897\ntoken={TOKEN}\n{hostile}"
    )
    submit(at)
    codes = [item for item in answer_elements(at) if item.type == "code"]
    assert len(codes) == 1 and codes[0].proto.language == "text"
    assert "[REDACTED]" in codes[0].value and TOKEN not in answer_text(at)
    assert hostile in codes[0].value
    assert not any(item.proto.language == "diff" for item in at.code)
    assert not any(hostile in item.value for item in at.markdown if item.proto.allow_html)
    assert not at.get("imgs") and not at.get("iframe")


@pytest.mark.parametrize("bound", ["characters", "lines"])
def test_deployment_summary_excerpt_is_bounded_after_redaction(ui, bound):
    at, api = ui
    use_deployment_summary(api)
    text = "field mappings: failed=1, skipped=897\n"
    if bound == "characters":
        text += "x" * (dashboard.MAX_SUMMARY_CHARS - len(text) - len("\ntoken=") - 8)
        text += f"\ntoken={TOKEN}\nOmitted end of evidence."
    else:
        text += "safe summary line\n" * dashboard.MAX_SUMMARY_LINES
        text += "Omitted end of evidence."
    api.result["findings"][1]["evidence"][1]["text"] = text
    submit(at)
    code = next(item for item in answer_elements(at) if item.type == "code")
    assert len(code.value) <= dashboard.MAX_SUMMARY_CHARS
    assert len(code.value.splitlines()) <= dashboard.MAX_SUMMARY_LINES
    assert TOKEN[:8] not in code.value
    assert "Omitted end of evidence" not in answer_text(at)
    assert "Summary excerpt" in answer_text(at)
    assert SUMMARY_URL in answer_text(at)
    assert "Omitted end of evidence" in rendered_text(at)


@pytest.mark.parametrize("mismatch", ["rule", "path", "empty", "missing"])
def test_deployment_summary_requires_recognized_rule_path_and_text(ui, mismatch):
    at, api = ui
    remediation = use_deployment_summary(api)
    finding = api.result["findings"][1]
    evidence = finding["evidence"][1]
    if mismatch == "rule":
        finding["rule_id"] += ".unrecognized"
        remediation["rule_id"] = finding["rule_id"]
    elif mismatch == "path":
        evidence["path"] = "datasync/other-summary.json"
    elif mismatch == "empty":
        evidence["text"] = " \n "
    else:
        finding["evidence"] = finding["evidence"][:1]
    submit(at)
    codes = [item for item in answer_elements(at) if item.type == "code"]
    assert [item.value for item in codes] == [remediation["source_blocks"][0]["content"]]
    assert "Deployment summary source" not in answer_text(at)
    assert SUMMARY_URL not in answer_text(at)


def test_deployment_summary_does_not_replace_an_existing_diff_or_low_confidence_source(ui):
    at, api = ui
    use_deployment_summary(api)
    artifact = deepcopy(api.result["findings"][1]["evidence"][1])
    rule = api.result["findings"][1]["rule_id"]
    remediation = use_source_proposal(api, fix_confidence=20)
    remediation["rule_id"] = api.result["findings"][1]["rule_id"] = rule
    api.result["findings"][1]["evidence"].append(artifact)
    submit(at)
    codes = [item for item in answer_elements(at) if item.type == "code"]
    assert [item.value for item in codes] == [SOURCE_DIFF, SOURCE_TEXT]
    assert [item.proto.language for item in codes] == ["diff", "json"]
    assert "Deployment summary source" not in answer_text(at)
    assert "No verified source patch" not in answer_text(at)
    assert at.metric[1].value == "20/100"


def test_exact_source_diff_confidence_condition_and_verification_are_in_main_answer(ui):
    at, api = ui
    remediation = use_source_proposal(api)
    submit(at)
    assert at.subheader[0].value == "CSV filename was passed as a Salesforce object"
    codes = [item for item in answer_elements(at) if item.type == "code"]
    assert len(codes) == 1
    assert codes[0].value == SOURCE_DIFF
    assert codes[0].proto.language == "diff"
    assert [item.value for item in at.metric] == ["91/100", "82/100"]
    text = answer_text(at)
    assert f"{SOURCE_PATH} · line 2" in text
    assert SOURCE_URL + "#L2" in text
    assert CONDITION in text
    assert "\n".join(f"{index}. {step}" for index, step in enumerate(VERIFY, 1)) in text
    assert "CI definition" not in text and ".gitlab-ci.yml" not in text
    assert "No verified source patch" not in text
    assert "Review only · not applied or target-verified" in text
    assert remediation["proposals"][0]["rationale"] not in text
    assert not any(item.type == "button" for item in answer_elements(at))
    assert not any(re.search(r"apply|commit|retry|deploy|create.*(?:mr|merge)", item.label, re.I)
                   for item in at.button)
    assert not at.tabs and outer_expanders(at) == ["Evidence & details"]
    assert len(api.posted()) == 1


def test_multiple_source_proposals_are_bounded_and_not_truncated(ui):
    at, api = ui
    remediation = use_source_proposal(api)
    remediation["proposals"] *= 5
    submit(at)
    codes = [item for item in answer_elements(at) if item.type == "code"]
    assert len(codes) == dashboard.MAX_PROPOSALS
    assert all(item.value == SOURCE_DIFF and item.proto.language == "diff" for item in codes)
    assert "Showing 3 of 5 source proposals" in answer_text(at)


@pytest.mark.parametrize("ending", ["lf", "crlf", "no-final-newline"])
def test_exact_diff_and_source_preserve_line_endings_and_boundary_whitespace(ui, ending):
    at, api = ui
    remediation = use_source_proposal(api, fix_confidence=20)
    proposal = remediation["proposals"][0]
    block = remediation["source_blocks"][0]
    if ending == "crlf":
        proposal["diff"] = proposal["diff"].replace("\n", "\r\n")
        block["content"] = block["content"].replace("\n", "\r\n")
    elif ending == "no-final-newline":
        proposal["diff"] = proposal["diff"].removesuffix("\n")
        block["content"] = block["content"].removesuffix("\n")
    block["content"] = "\n  " + block["content"] + "  \n"
    submit(at)
    codes = [item for item in answer_elements(at) if item.type == "code"]
    assert [item.value for item in codes] == [proposal["diff"], block["content"]]


@pytest.mark.parametrize("kind", ["absent", "malformed", "non-source", "oversized"])
def test_no_fabricated_or_partial_diff_when_a_source_patch_cannot_be_displayed(ui, kind):
    at, api = ui
    remediation = use_source_proposal(api)
    if kind == "absent":
        remediation["proposals"] = []
    elif kind == "malformed":
        remediation["proposals"][0]["diff"] = "Just replace the field."
    elif kind == "non-source":
        remediation["proposals"][0]["kind"] = "action"
    else:
        remediation["proposals"][0]["diff"] += " " + "x" * dashboard.MAX_DIFF_CHARS
    submit(at)
    assert "No verified source patch" in answer_text(at)
    assert not any(item.proto.language == "diff" for item in at.code)
    assert SOURCE_TEXT in [item.value for item in at.code]
    if kind == "oversized":
        assert "No truncated or reconstructed diff" in answer_text(at)


def test_source_block_exact_prefix_is_bounded_to_8k_without_new_content(ui):
    at, api = ui
    remediation = use_source_proposal(api)
    remediation["proposals"] = []
    source = remediation["source_blocks"][0]
    source["content"] = ("safe source line " + "a" * 150 + "\r\n") * 160
    source["line_start"], source["line_end"] = 20, 179
    source["language"] = '<img src="https://external.invalid/">'
    submit(at)
    code = next(item for item in answer_elements(at) if item.type == "code")
    expected = "".join(source["content"].splitlines(keepends=True)[:80])[:8000]
    assert code.value == expected
    assert len(code.value) <= dashboard.MAX_SOURCE_CHARS
    assert code.proto.language == "text"
    assert "Exact source prefix shown" in answer_text(at)
    assert SOURCE_URL + "#L20-179" in answer_text(at)


def test_low_fix_confidence_keeps_trusted_docs_anchor_and_exact_source_on_main(ui):
    at, api = ui
    remediation = use_source_proposal(api, fix_confidence=35)
    remediation["documentation"] = [
        "https://learn.microsoft.com/en-us/dotnet/csharp/language-reference/compiler-messages/cs0161?token=discard#example",
        "https://docs.sonarsource.com/sonarqube-server/analyzing-source-code/ci-integration/gitlab-integration/#configuring-your-gitlab-ci-yml-file",
        "https://docs.gitlab.com.evil.test/collect#secret",
        "https://external.invalid/collect",
        "http://docs.gitlab.com/runner/faq/#unsafe",
    ]
    api.result["findings"][1]["documentation"] = []
    submit(at)
    text = answer_text(at)
    assert "cs0161#example" in text
    assert "#configuring-your-gitlab-ci-yml-file" in text
    assert "discard" not in text and "external.invalid" not in text and "evil.test" not in text
    assert "#unsafe" not in text
    codes = [item for item in answer_elements(at) if item.type == "code"]
    assert [item.value for item in codes] == [SOURCE_DIFF, SOURCE_TEXT]
    assert at.metric[1].value == "35/100"
    assert all(path.startswith(LOCAL + "/") for _, path, _ in api.calls)


@pytest.mark.parametrize(
    "remediations", [None, [], "invalid", [{"rule_id": "wrong", "job_id": "7"}]],
    ids=["missing", "empty", "invalid", "wrong-rule"],
)
def test_backward_api_without_matching_remediation_has_unknown_scores(ui, remediations):
    at, api = ui
    if remediations is None:
        api.result.pop("remediations")
    else:
        api.result["remediations"] = remediations
    submit(at)
    assert [item.value for item in at.metric] == ["Unknown", "Unknown"]
    assert "No verified source patch" in answer_text(at)
    assert "94" not in answer_text(at) and "96%" not in rendered_text(at)
    assert FIXES[0] in answer_text(at)


@pytest.mark.parametrize("score", [None, -1, 101, True, "94", float("nan"), float("inf")],
                         ids=["missing", "negative", "too-large", "bool", "string", "nan", "inf"])
def test_invalid_scores_never_become_numeric_confidence(ui, score):
    at, api = ui
    api.result["remediations"][0].update(cause_confidence=score, fix_confidence=score)
    submit(at)
    assert [item.value for item in at.metric] == ["Unknown", "Unknown"]


@pytest.mark.parametrize("score", [0, 100, 62.5])
def test_valid_scores_include_zero_and_are_not_percent_probabilities(ui, score):
    at, api = ui
    api.result["remediations"][0].update(cause_confidence=score, fix_confidence=score)
    submit(at)
    assert [item.value for item in at.metric] == [f"{score:g}/100", f"{score:g}/100"]
    assert not any("%" in item.value for item in at.metric)


def test_unrecognized_score_semantics_are_not_labeled_as_supported_heuristics(ui):
    at, api = ui
    api.result["remediations"][0]["score_label"] = "Guaranteed probability of a fix"
    submit(at)
    assert [item.value for item in at.metric] == ["Unknown", "Unknown"]
    assert "Guaranteed probability" not in rendered_text(at)


def test_multiple_genuine_issues_switch_exact_job_remediation_without_new_inspection(ui):
    at, api = ui
    second = deepcopy(api.result["findings"][1])
    second.update(job_id="9", title="Runner cannot reach a second executor")
    api.result["findings"].append(second)
    other = remediation_fixture(job_id="9")
    other.update(cause_confidence=45, fix_confidence=12)
    api.result["remediations"].insert(0, other)
    api.result["findings"].insert(0, {
        "rule_id": "pipeline.failed", "category": "pipeline_status", "severity": "error",
        "title": "Pipeline failed", "fix": [], "evidence": [],
    })
    submit(at)
    assert at.subheader[0].value == TITLE
    assert at.metric[0].value == "91/100"
    selector = next(item for item in at.selectbox if item.key.startswith("issue-"))
    assert len(selector.options) == 2
    assert all("CI visibility" not in option and "Pipeline failed" not in option
               for option in selector.options)
    # AppTest.select_index supplies the display label, not the underlying int.
    selector.set_value(1).run()
    assert not at.exception
    assert at.subheader[0].value == second["title"]
    assert [item.value for item in at.metric] == ["45/100", "12/100"]
    assert len(api.posted()) == 1


def test_specific_finding_fix_wins_over_generic_remediation_and_number_prefixes_do_not_nest(ui):
    at, api = ui
    api.result["findings"][1]["fix"] = ["1. " + FIXES[0], "2) " + FIXES[1]]
    api.result["remediations"][0]["actions"] = ["Read the logs."]
    submit(at)
    text = answer_text(at)
    assert "1. " + FIXES[0] + "\n2. " + FIXES[1] in text
    assert "1. 1." not in text and "Read the logs" not in text


def test_specific_remediation_actions_replace_a_generic_finding_fix(ui):
    at, api = ui
    api.result["findings"][1]["fix"] = ["Review the logs."]
    api.result["remediations"][0]["actions"] = [
        "Confirm TCP 22 reaches executor.invalid from the runner host.",
    ]
    submit(at)
    assert "Confirm TCP 22" in answer_text(at)
    assert "Review the logs" not in answer_text(at)


def test_source_file_link_never_points_to_a_different_ci_file(ui):
    at, api = ui
    remediation = use_source_proposal(api)
    remediation["proposals"][0]["source_url"] = f"{PROJECT}/-/blob/{SHA}/.gitlab-ci.yml#L1"
    submit(at)
    assert SOURCE_PATH in answer_text(at)
    assert ".gitlab-ci.yml" not in answer_text(at)
    assert SOURCE_DIFF in [item.value for item in at.code]


@pytest.mark.parametrize(("value", "expected"), [
    (PIPELINE + "?token=do-not-display#secret", PIPELINE),
    (PIPELINE + "#L2", PIPELINE + "#L2"),
    (PIPELINE + "#L2-4", PIPELINE + "#L2-4"),
    (PIPELINE + "#L2-L4", PIPELINE + "#L2-L4"),
    (DOC_URL + "?untrusted", "https://docs.gitlab.com/runner/faq/"),
    (DOC_URL, DOC_URL),
    ("https://docs.gitlab.com/runner/faq/?token=discard#check-the-runner", DOC_URL),
    ("https://other.test/docs#check-the-runner", "https://other.test/docs"),
    ("https://docs.gitlab.com.evil.test/faq/#check-the-runner", "https://docs.gitlab.com.evil.test/faq/"),
    ("javascript:alert(1)", None),
    (f"https://user:{TOKEN}@gitlab.test/group/sample", None),
    (f"{PROJECT}/-/blob/main/%0aevil", None),
    (f"{PROJECT}/glpat-12345678901234567890", None),
    ("https://gitlab.test:bad/group/sample", None),
    ("https://host><img.test/path", None),
    ("https://bad%25host.test/path", None),
    ("http://[::1]:8000/group/repo", "http://[::1]:8000/group/repo"),
])
def test_display_links_drop_query_secrets_and_reject_unsafe_urls(value, expected):
    assert dashboard._safe_url(value) == expected


@pytest.mark.parametrize("host", [
    "docs.gitlab.com", "learn.microsoft.com", "developer.salesforce.com", "docs.sonarsource.com",
])
def test_public_documentation_allowlist_keeps_simple_anchors_and_no_queries(host):
    value = f"https://{host}/reference?token=discard#exact-section"
    assert dashboard._documentation_url(value) == f"https://{host}/reference#exact-section"


@pytest.mark.parametrize("url", [
    "https://external.invalid/docs#section", "https://docs.gitlab.com.evil.test/docs#section",
    "http://docs.gitlab.com/docs#section", "https://docs.gitlab.com:444/docs#section",
    "https://user:secret@docs.gitlab.com/docs#section", "javascript:alert(1)",
])
def test_docs_links_reject_arbitrary_hosts_ports_credentials_and_non_https(url):
    assert dashboard._documentation_url(url) is None


def test_table_source_url_uses_explicit_clean_target_not_escaped_autolink():
    url = f"{PROJECT}/-/jobs/7"
    cell = dashboard._table_cell("Source URL", url + "?token=secret")
    assert cell == f"[{dashboard._md(url)}](<{url}>)"
    assert cell.split("](<", 1)[1] == url + ">)"
    assert "secret" not in cell


def test_untrusted_markdown_cannot_become_active_html_images_or_inline_assets(ui):
    at, api = ui
    hostile = '<img src="https://external.invalid/pixel"> ![x](https://external.invalid/pixel)'
    api.result["findings"][1]["explanation"] = hostile
    submit(at)
    assert dashboard._md(hostile) in [item.value for item in at.markdown]
    html = [item.value for item in at.markdown if item.proto.allow_html]
    assert len(html) == 1 and "<style>" in html[0]
    assert hostile not in html[0]
    assert "@media (max-width: 640px)" in html[0]
    assert "overflow-wrap: anywhere" in html[0]
    assert "https://" not in html[0] and "@import" not in html[0]


def test_remediation_content_is_literal_and_cannot_add_active_assets_or_actions(ui):
    at, api = ui
    remediation = use_source_proposal(api, fix_confidence=20)
    hostile = '<img src="https://external.invalid/pixel"> ![x](https://external.invalid/pixel)'
    proposal = remediation["proposals"][0]
    proposal.update(title=hostile, condition=hostile, rationale=hostile, verification=[hostile])
    proposal["diff"] = SOURCE_DIFF.replace("Sample", hostile)
    remediation["source_blocks"][0]["content"] = hostile
    remediation["confidence_basis"] = [hostile]
    remediation["missing_information"] = [hostile]
    remediation["documentation"] = [{"title": hostile, "url": DOC_URL + "?invalid-fragment"}]
    submit(at)
    assert proposal["diff"] in [item.value for item in at.code]
    assert hostile in [item.value for item in at.code]
    assert "**" + dashboard._md(hostile) + "**" in [item.value for item in at.markdown]
    html = [item.value for item in at.markdown if item.proto.allow_html]
    assert len(html) == 1 and "<style>" in html[0] and hostile not in html[0]
    assert not at.get("imgs") and not at.get("iframe")
    assert not any(item.type == "button" for item in answer_elements(at))
    assert all(path.startswith(LOCAL + "/") for _, path, _ in api.calls)


def test_each_static_source_finding_can_select_its_own_remediation():
    from pipelinelens.services.findings import finding_identity

    first = {"rule_id": "change.ci_path_case_mismatch", "job_id": None,
             "category": "repository_path_risk", "severity": "warning",
             "evidence": [{"path": "ci/first.yml", "line": 2, "text": "bad-case"}]}
    second = deepcopy(first)
    second["evidence"][0]["path"] = "ci/second.yml"
    plans = [{"rule_id": first["rule_id"], "job_id": None,
              "finding_key": finding_identity(item)} for item in (first, second)]
    assert len(dashboard._genuine_findings([first, second])) == 2
    assert dashboard._remediation_for({"remediations": plans}, second) == plans[1]


def test_every_curated_runbook_link_is_allowed_by_the_documentation_ui():
    from pipelinelens.services.runbooks import _RUNBOOKS

    for book in _RUNBOOKS:
        for url in book.urls:
            assert dashboard._documentation_url(url) == url


def test_child_finding_is_not_attributed_to_root_history_or_confirmation():
    parent = {"jobs": [{"external_id": "11"}]}
    assert dashboard._root_finding(parent, {"job_id": "11"})
    assert dashboard._root_finding(parent, {"job_id": None})
    assert not dashboard._root_finding(parent, {"job_id": "99"})


def test_no_legacy_network_path_or_cached_client_or_token_remains(monkeypatch):
    source = APP.read_text(encoding="utf-8")
    assert "/system/status" not in source
    assert "/pipeline-url/analyze" not in source
    assert "st.tabs(" not in source
    assert "cache_data" not in source  # Request/response data must never be cached.
    tree = ast.parse(source)
    decorated = {
        node.name: [ast.dump(decorator) for decorator in node.decorator_list]
        for node in tree.body if isinstance(node, ast.FunctionDef) and node.decorator_list
    }
    # Only the plain, credential-free resolved API URL string may ever be cached
    # across reruns; the client factory itself must stay undecorated and uncached.
    assert set(decorated) == {"_resolved_api_url"}
    assert all("cache_resource" in dump for dump in decorated["_resolved_api_url"])
    monkeypatch.setattr(dashboard, "_resolved_api_url", lambda: dashboard.API_URL)
    first, second = dashboard._api(), dashboard._api()
    assert first is not second
    assert vars(first) == {"base_url": dashboard.API_URL.rstrip("/")}


def test_self_host_never_mode_skips_every_probe_and_never_self_hosts(monkeypatch):
    monkeypatch.setattr(dashboard, "SELF_HOST_MODE", "never")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("must not probe or self-host when explicitly disabled")

    monkeypatch.setattr(dashboard, "_api_url_reachable", forbidden)
    monkeypatch.setattr(dashboard, "_start_self_hosted_api", forbidden)

    assert dashboard._resolve_api_url_once() == dashboard.API_URL


def test_self_host_auto_mode_uses_the_reachable_external_api_unchanged(monkeypatch):
    monkeypatch.setattr(dashboard, "SELF_HOST_MODE", "auto")
    monkeypatch.setattr(dashboard, "_api_url_reachable", lambda url: True)

    def forbidden():
        raise AssertionError("must not self-host when the configured API is reachable")

    monkeypatch.setattr(dashboard, "_start_self_hosted_api", forbidden)

    assert dashboard._resolve_api_url_once() == dashboard.API_URL


def test_self_host_auto_mode_falls_back_when_the_external_api_is_unreachable(monkeypatch):
    monkeypatch.setattr(dashboard, "SELF_HOST_MODE", "auto")
    monkeypatch.setattr(dashboard, "_api_url_reachable", lambda url: False)
    monkeypatch.setattr(dashboard, "_SELF_HOST_PROBE_INTERVAL_SECONDS", 0.0)
    monkeypatch.setattr(dashboard, "_start_self_hosted_api", lambda: "http://127.0.0.1:59999")

    assert dashboard._resolve_api_url_once() == "http://127.0.0.1:59999"


def test_self_host_disabled_synonyms_all_skip_self_hosting(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("must not probe or self-host when disabled")

    monkeypatch.setattr(dashboard, "_api_url_reachable", forbidden)
    monkeypatch.setattr(dashboard, "_start_self_hosted_api", forbidden)
    for mode in ("never", "0", "false", "off", "disabled", "NEVER", " Off "):
        monkeypatch.setattr(dashboard, "SELF_HOST_MODE", mode.strip().lower())
        assert dashboard._resolve_api_url_once() == dashboard.API_URL


def test_api_url_reachable_true_when_the_probe_connects(monkeypatch):
    calls = []

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *_exc_info):
            return False

    def fake_create_connection(address, timeout=None):
        calls.append((address, timeout))
        return FakeConnection()

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    assert dashboard._api_url_reachable("http://localhost:8000") is True
    assert calls == [(("localhost", 8000), dashboard._SELF_HOST_PROBE_TIMEOUT_SECONDS)]


def test_api_url_reachable_false_when_the_probe_is_refused(monkeypatch):
    def fake_create_connection(address, timeout=None):
        raise OSError("refused")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)
    assert dashboard._api_url_reachable("http://localhost:8000") is False


def test_api_url_reachable_false_for_an_unparseable_port(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("must not attempt a connection for a malformed URL")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert dashboard._api_url_reachable("http://localhost:not-a-port") is False


def mock_http(monkeypatch, handler):
    real_client = httpx.Client
    options = []

    def factory(**kwargs):
        options.append(kwargs)
        return real_client(**kwargs, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(client_module.httpx, "Client", factory)
    return options


@pytest.mark.parametrize(("method", "route"), [
    ("GET", "/status"), ("POST", "/inspect"), ("POST", "/connections/forget"),
    ("GET", "/knowledge/export"), ("POST", "/knowledge/confirm"),
])
def test_all_local_requests_have_header_bounded_timeout_and_no_environment_proxy(
    monkeypatch, method, route,
):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(200, json={"ok": True})

    options = mock_http(monkeypatch, handle)
    client = PipelineLensApiClient("http://127.0.0.1:8000/")
    result = client.get(LOCAL + route) if method == "GET" else client.post(
        LOCAL + route, {"token": TOKEN},
    )
    assert result == {"ok": True}
    assert requests[0].headers["X-PipelineLens-Local"] == "1"
    assert requests[0].method == method
    assert requests[0].extensions["timeout"] == {
        "connect": 5.0, "read": 180.0, "write": 15.0, "pool": 5.0,
    }
    assert options[0]["trust_env"] is False
    assert options[0]["follow_redirects"] is False
    assert vars(client) == {"base_url": "http://127.0.0.1:8000"}


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422, 429, 500, 504, 302])
@pytest.mark.parametrize("body", [
    {"detail": [{"loc": ["body", "token"], "input": TOKEN, "msg": "Rejected " + TOKEN}]},
    {"detail": TOKEN}, [TOKEN],
])
def test_client_never_echoes_json_error_validation_body_or_redirect(monkeypatch, status, body):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(status, json=body, headers={"Location": f"https://bad.test/{TOKEN}"})

    mock_http(monkeypatch, handle)
    with pytest.raises(ApiClientError) as caught:
        PipelineLensApiClient("http://localhost:8000").post(LOCAL + "/inspect", {"token": TOKEN})
    assert TOKEN not in str(caught.value)
    assert "input" not in str(caught.value)
    assert len(requests) == 1
    assert caught.value.__cause__ is None
    if status == 422:
        assert "connection selection" in str(caught.value)
    if status == 302:
        assert "not followed" in str(caught.value)


@pytest.mark.parametrize("status", [200, 422, 500])
def test_client_non_json_responses_have_generic_errors(monkeypatch, status):
    mock_http(monkeypatch, lambda request: httpx.Response(status, text="<html>" + TOKEN))
    with pytest.raises(ApiClientError) as caught:
        PipelineLensApiClient("http://localhost:8000").get(LOCAL + "/status")
    assert TOKEN not in str(caught.value)
    if status == 200:
        assert "unreadable JSON" in str(caught.value)


@pytest.mark.parametrize(("exception", "message"), [
    (httpx.ReadTimeout(TOKEN), "timed out"), (httpx.ConnectError(TOKEN), "unreachable"),
])
def test_client_transport_errors_do_not_expose_request_or_exception(
    monkeypatch, exception, message,
):
    def handle(request):
        raise exception

    mock_http(monkeypatch, handle)
    with pytest.raises(ApiClientError) as caught:
        PipelineLensApiClient("http://localhost:8000").post(LOCAL + "/inspect", {"token": TOKEN})
    assert message in str(caught.value)
    assert TOKEN not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("status", [200, 204])
def test_empty_success_response_is_none(monkeypatch, status):
    mock_http(monkeypatch, lambda request: httpx.Response(status))
    assert PipelineLensApiClient("http://localhost:8000").get(LOCAL + "/status") is None


@pytest.mark.parametrize("base", [
    "https://external.invalid", "http://localhost.evil.test", "http://user:secret@localhost",
    "http://localhost:8000?token=secret", "http://localhost:8000/path", "http://127.0.0.1:bad",
])
def test_client_rejects_nonlocal_or_credential_bearing_api_base_before_io(base):
    with pytest.raises(ApiClientError, match="loopback") as caught:
        PipelineLensApiClient(base)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("path", [
    "//external.invalid/steal", "https://external.invalid/steal", "/../status",
    "/api/v1/local/status?token=secret", "/api\\v1/local/status",
])
def test_client_rejects_unsafe_routes_before_io(path):
    with pytest.raises(ApiClientError, match="route is invalid"):
        PipelineLensApiClient("http://localhost:8000").get(path)