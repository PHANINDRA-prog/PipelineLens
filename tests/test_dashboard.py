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
from streamlit.testing.v1 import AppTest

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


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Dashboard tests must not open network connections")

    monkeypatch.setattr(socket, "create_connection", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)


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


def literal(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


def test_initial_ui_is_local_only_no_eager_memory_or_model_calls(ui):
    at, api = ui
    assert api.calls == [("GET", f"{LOCAL}/status", None)]
    assert any(item.value == "Local rules • no external AI calls" for item in at.info)
    assert [tab.label for tab in at.tabs] == [
        "Diagnosis", "Pipeline context", "CI sources & files", "Local memory",
    ]
    assert not at.sidebar.radio
    assert at.radio(key="connection_mode").value == "auto"
    assert not at.radio(key="connection_mode").proto.form_id
    assert at.text_input(key="read_only_token").proto.form_id == "inspect-link"
    assert not at.checkbox(key="remember_token").value
    assert not at.get("download_button")
    assert all(not item.proto.expanded for item in at.expander)


@pytest.mark.parametrize("enter", [False, True], ids=["Analyze", "Enter-trigger"])
def test_submission_retains_url_clears_only_password_and_keeps_settings(ui, enter):
    at, api = ui
    at.radio(key="connection_mode").set_value("request").run()
    at.checkbox(key="remember_token").check()
    at.checkbox(key="force_refresh").check()
    submit(at, PIPELINE, TOKEN, enter=enter)
    assert api.posted() == [{
        "url": PIPELINE, "token": TOKEN, "connection": "request",
        "remember_token": True, "refresh": True, "max_jobs": 5,
    }]
    assert at.text_input(key="inspection_url").value == PIPELINE
    assert at.text_input(key="read_only_token").value == ""
    assert at.radio(key="connection_mode").value == "request"
    assert at.checkbox(key="remember_token").value
    assert at.checkbox(key="force_refresh").value
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
        "refresh": False, "max_jobs": 5,
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


def test_connection_radio_updates_disabled_fields_without_submission(ui):
    at, api = ui
    at.text_input(key="inspection_url").input(PIPELINE).run()
    at.text_input(key="read_only_token").input(TOKEN).run()
    at.radio(key="connection_mode").set_value("configured").run()
    assert at.text_input(key="read_only_token").disabled
    assert at.text_input(key="read_only_token").value == ""
    assert at.checkbox(key="remember_token").disabled
    assert at.text_input(key="inspection_url").value == PIPELINE
    assert not api.posted()
    submit(at)
    assert "token" not in api.posted()[0]
    assert api.posted()[0]["connection"] == "configured"
    at.radio(key="connection_mode").set_value("request").run()
    assert not at.text_input(key="read_only_token").disabled
    assert not at.checkbox(key="remember_token").disabled
    assert at.text_input(key="inspection_url").value == PIPELINE


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
    assert at.text_input(key="inspection_url").value == url
    assert at.text_input(key="read_only_token").value == ""
    assert len(api.posted()) == 1
    assert not at.subheader
    assert "Previous results were cleared" in rendered_text(at)
    assert TOKEN not in rendered_text(at)


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


def test_causal_job_answer_fixes_and_exact_quote_precede_all_collapsed_details(ui):
    at, _ = ui
    submit(at)
    assert at.subheader[0].value == "Warning · " + TITLE
    flat = list(at.main)
    first_detail = next(index for index, item in enumerate(flat) if item.type == "expander")
    before_details = flat[:first_detail]
    text = "\n".join(str(item.value) for item in before_details
                     if item.type in {"markdown", "code", "subheader", "caption"})
    assert "**Why**" in text
    assert "Probable correct fix" in text
    for index, fix in enumerate(FIXES[:3], 1):
        assert f"{index}. {fix}" in literal(text)
    assert FIXES[3] not in literal(text)
    assert QUOTE in text
    assert f"{PROJECT}/-/jobs/7#L2" in text
    assert "Observed evidence" in text and "Owner: Runner / infrastructure team" in text
    assert "Legacy prose" not in rendered_text(at)
    assert "96%" not in rendered_text(at)
    assert all(not item.proto.expanded for item in at.expander)
    assert "Other findings (2)" in [item.label for item in at.expander]


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
    assert at.subheader[0].value == "Error · " + TITLE
    assert any("GitLab reported pipeline failed" in item.value for item in at.error)


def test_pipeline_success_and_allow_failure_are_prominent_warnings_not_failure(ui):
    at, _ = ui
    submit(at)
    warning = next(item.value for item in at.warning if "pipeline success" in item.value)
    assert "inspection warning" in warning
    assert "allow_failure=true" in warning
    assert not at.error


def test_selected_successful_job_keeps_parent_pipeline_context(ui):
    at, api = ui
    api.result["selected_job"] = api.result["jobs"][1]
    api.result["reference_kind"] = "job"
    api.result["resolved_url"] = f"{PROJECT}/-/jobs/8"
    submit(at, f"{PROJECT}/-/jobs/8")
    assert any("reported success" in item.value and "not declared failed" in item.value
               for item in at.info)
    assert at.subheader[0].value == "Warning · " + TITLE
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
    assert any("pipeline success" in item.value and "sampled evidence" in item.value
               for item in at.success)
    assert not at.error


def test_configuration_only_response_is_explicitly_not_runtime(ui):
    at, api = ui
    api.result.update(pipeline=None, status="configuration_only", analyses=[], jobs=[])
    api.result["findings"] = []
    api.result["reference_kind"] = "repository"
    api.result["resolved_url"] = PROJECT
    submit(at, PROJECT)
    assert at.subheader[0].value == "No causal finding established"
    assert any("Configuration-only inspection" in item.value for item in at.info)
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


@pytest.mark.parametrize(("value", "expected"), [
    (PIPELINE + "?token=do-not-display#secret", PIPELINE),
    (PIPELINE + "#L2", PIPELINE + "#L2"),
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


def test_no_legacy_network_path_or_cached_token_client_remains():
    source = APP.read_text(encoding="utf-8")
    assert "/system/status" not in source
    assert "/pipeline-url/analyze" not in source
    assert "cache_resource" not in source and "cache_data" not in source
    tree = ast.parse(source)
    assert all(not node.decorator_list for node in tree.body if isinstance(node, ast.FunctionDef))
    first, second = dashboard._api(), dashboard._api()
    assert first is not second
    assert vars(first) == {"base_url": dashboard.API_URL.rstrip("/")}


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