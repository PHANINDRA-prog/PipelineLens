"""Local, evidence-first inspection dashboard; no model, token cache or provider I/O.

Only the password widget temporarily holds a submitted credential. After every
attempt a deferred flag clears that widget before it is rendered on the next
rerun; the URL, connection choice and other settings deliberately remain intact.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import streamlit as st

from pipelinelens.dashboard.client import ApiClientError, PipelineLensApiClient
from pipelinelens.services.gitlab_includes import display_include_path
from pipelinelens.services.pipeline_url import PipelineUrlError, parse_gitlab_url
from pipelinelens.services.redaction import redact_text

API_URL = os.getenv("PIPELINELENS_API_URL", "http://localhost:8000")
LOCAL = "/api/v1/local"
MAX_TREE_ROWS = 280
PAGE_LINES = 120
MAX_DISPLAY_CHARS = 16_000
MAX_VIEW_CHARS = 200_000
MAX_EXPORT_BYTES = 8 * 1024 * 1024
CONNECTIONS = {
    "auto": "Automatic · saved same-host or configured",
    "request": "Request-only connection · enter a token",
    "configured": "Configured connection only",
}
EXPORT_NOTICE = (
    "Redaction is not a guarantee that business-sensitive data is absent. "
    "Review this portable, unencrypted JSON before downloading, copying or sharing it. "
    "Observations and suggested fixes are not verified resolutions; human-confirmed "
    "resolutions are user assertions. Nothing is uploaded automatically."
)
_SUCCESS = {"success", "succeeded", "passed"}
_FAILED = {"failed", "failure", "timed_out"}
_CONTEXT_CATEGORIES = {
    "pipeline_status", "job_status", "ci_configuration", "ci_visibility",
    "no_failure_observed", "unknown", "downstream_pipeline",
}


def _render_styles() -> None:
    # Only static CSS uses HTML. API/user text is escaped or rendered as literal code.
    st.markdown(
        """
        <style>
        .stApp { background: #f5f8f7; color: #152d32; }
        [data-testid="stHeader"] { background: transparent; }
        .block-container { max-width: 1240px; padding: 2rem 2.5rem 4rem; }
        h1, h2, h3, p, label { font-family: "Segoe UI", system-ui, sans-serif; }
        h1, h2, h3 { color: #123c42; letter-spacing: -0.025em; }
        h1 { margin-bottom: 0; }
        [data-testid="stForm"], [data-testid="stExpander"] {
          background: #fff; border: 1px solid #cbdcda; border-radius: 12px;
        }
        [data-testid="stAlert"] { border-radius: 10px; }
        [data-testid="stMarkdownContainer"], [data-testid="stMetricValue"],
        [data-testid="stExpander"] summary, button p {
          overflow-wrap: anywhere; white-space: normal; text-overflow: clip;
        }
        [data-testid="stTextInput"] input { min-width: 0; font-size: 1rem; }
        [data-testid="stBaseButton-primaryFormSubmit"] {
          background: #006d70; border-color: #006d70; color: white;
        }
        [data-testid="stCode"] pre { white-space: pre-wrap; overflow-wrap: anywhere; }
                [data-testid="stTable"] { max-width: 100%; overflow-x: auto; }
                [data-testid="stTable"] table { min-width: 680px; width: 100%; table-layout: fixed; }
                [data-testid="stTable"] td, [data-testid="stTable"] th {
                    white-space: normal; overflow-wrap: anywhere; text-overflow: clip;
                }
        [data-baseweb="tab-list"] { gap: 0.75rem; overflow-x: auto; }
        [data-baseweb="tab"] { height: auto; min-height: 3rem; white-space: normal; }
        [data-testid="stRadio"] [role="radiogroup"] { flex-wrap: wrap; gap: 0.5rem 1rem; }
        @media (max-width: 640px) {
          .block-container { padding: 1rem 0.8rem 2rem; }
          h1 { font-size: 1.9rem !important; }
          h2, h3 { font-size: 1.3rem !important; }
          [data-testid="stHorizontalBlock"] { flex-wrap: wrap; }
          [data-testid="stColumn"] { min-width: 100% !important; }
          [data-testid="stFormSubmitButton"] button { width: 100%; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _api() -> PipelineLensApiClient:
    # Do not cache a client, request, response containing credentials, or token argument.
    return PipelineLensApiClient(API_URL)


def _md(value: object) -> str:
    """Literal Markdown text, not user-supplied links, images or HTML."""
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~<\-])", r"\\\1", str(value))


def _objects(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _safe_url(value: object) -> str | None:
    """Display-only canonical link: no credentials, query secrets or arbitrary fragments."""
    if not isinstance(value, str) or not value or len(value) > 8192:
        return None
    try:
        parts = urlsplit(value)
        if (
            parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or any(char.isspace() for char in value) or "\\" in value
        ):
            return None
        host = parts.hostname.encode("idna").decode("ascii").lower().removesuffix(".")
        if ":" in host:
            ip_address(host)
        elif not host or len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
            return None
        authority = f"[{host}]" if ":" in host else host
        port = parts.port
        if port == 0:
            return None
        if port is not None and port != (443 if parts.scheme == "https" else 80):
            authority += f":{port}"
        decoded = unquote(parts.path, errors="strict")
        if (
            re.search(r"[\x00-\x20\x7f]", decoded) or "\\" in decoded or "%" in decoded
            or any(part in {".", ".."} for part in decoded.split("/"))
            or redact_text(authority + decoded) != authority + decoded
        ):
            return None
        path = quote(decoded, safe="/:@-._~!$&'()*+,;=")
        fragment = parts.fragment if re.fullmatch(r"L[1-9]\d*(?:-[1-9]\d*)?", parts.fragment) else ""
        return urlunsplit((parts.scheme, authority, path, "", fragment))
    except (ValueError, UnicodeError):
        return None


def _link(label: str, value: object) -> None:
    url = _safe_url(value)
    if url:
        st.markdown(f"**{_md(label)}:** [{_md(url)}](<{url}>)")


def _initialize_state() -> None:
    defaults: dict[str, Any] = {
        "inspection_result": None, "submission_failed": False, "submission_error": None,
        "inspection_url": "", "connection_mode": "auto", "remember_token": False,
        "force_refresh": False, "_clear_password": False, "export_preview": None,
        "export_reviewed": False, "local_notice": None,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)
    # Never mutate the password widget after instantiating it in this script run.
    if st.session_state.pop("_clear_password", False):
        st.session_state["read_only_token"] = ""


def _invalidate_export() -> None:
    st.session_state.export_preview = None
    st.session_state.export_reviewed = False


def _begin_submission() -> None:
    """Form callback: remove stale evidence before validating the next selection."""
    st.session_state.inspection_result = None
    st.session_state.submission_failed = False
    st.session_state.submission_error = None
    st.session_state.local_notice = None
    _invalidate_export()


def _connection_changed() -> None:
    if st.session_state.connection_mode == "configured":
        st.session_state._clear_password = True


def _local_status() -> dict[str, Any]:
    try:
        status = _api().get(f"{LOCAL}/status")
        if not isinstance(status, dict) or status.get("mode") != "local_rules" or status.get("external_model_calls") is not False:
            raise ApiClientError("Local status is unavailable.")
        return status
    except ApiClientError:
        st.warning("Local connection status is unavailable. Check that the local API is running; you can still try an inspection with a request-only token.")
        return {}


def _validate_result(result: object) -> dict[str, Any]:
    if (
        not isinstance(result, dict) or result.get("mode") != "local_rules"
        or result.get("status") not in {"failed", "warning", "passed", "in_progress", "configuration_only"}
        or not isinstance(result.get("repository"), dict)
        or not isinstance(result.get("findings"), list)
        or not isinstance(result.get("ci_config_access"), dict)
        or result.get("pipeline") is not None and not isinstance(result["pipeline"], dict)
    ):
        raise ApiClientError("The local API returned an incomplete inspection. Restart or update the local API and try again.")
    return result


def _inspect_submission(status: dict[str, Any], url: str, token: str) -> None:
    payload: dict[str, Any] = {}
    try:
        if not url.strip():
            raise PipelineUrlError("Paste a GitLab pipeline, job, branch, file or repository URL.")
        mode = st.session_state.connection_mode
        expected = None
        if mode == "configured":
            if not status.get("configured_connection"):
                raise PipelineUrlError("No configured connection is available. Choose Automatic or enter a request-only token.")
            expected = status.get("configured_host")
        parse_gitlab_url(url.strip(), expected_base_url=expected)
        canonical = _safe_url(url.strip())
        if canonical is None:
            raise PipelineUrlError("Remove secrets from the URL; enter credentials only in the password field.")
        token = "" if mode == "configured" else token.strip()
        if token and token in unquote(canonical):
            raise PipelineUrlError("Remove credentials from the URL; enter them only in the password field.")
        if mode == "request" and not token:
            raise PipelineUrlError("Enter a read-only GitLab token, or choose Automatic to reuse a saved same-host connection.")
        if len(token) > 8192 or any(not 33 <= ord(char) <= 126 for char in token):
            raise PipelineUrlError("Enter a valid read-only token without whitespace.")
        payload = {
            "url": url.strip(), "connection": mode,
            "remember_token": bool(token and st.session_state.remember_token and status.get("vault_available")),
            "refresh": bool(st.session_state.force_refresh), "max_jobs": 5,
        }
        if token:
            payload["token"] = token
        with st.spinner("Verifying GitLab access; reading pipeline/job metadata, up to five job traces, CI include sources, MR/commit changes and bounded downstream context…"):
            result = _validate_result(_api().post(f"{LOCAL}/inspect", payload))
        # The API owns redaction of evidence. Never persist its raw submitted-URL echo.
        result["submitted_url"] = canonical
        st.session_state.inspection_result = result
    except (PipelineUrlError, ApiClientError) as error:
        message = str(error)
        if token:
            message = message.replace(token, "[REDACTED]")
        st.session_state.inspection_result = None
        st.session_state.submission_failed = True
        st.session_state.submission_error = redact_text(message)
    finally:
        payload.pop("token", None)
        st.session_state._clear_password = True
    # A new run consumes the deferred clear before rendering widgets, including on failure.
    st.rerun()


def _render_input(status: dict[str, Any]) -> None:
    st.radio(
        "GitLab connection", list(CONNECTIONS), format_func=CONNECTIONS.__getitem__,
        key="connection_mode", horizontal=True, on_change=_connection_changed,
    )
    configured = st.session_state.connection_mode == "configured"
    st.caption("Automatic reuses verified saved connections only on the same GitLab host, then a matching configured connection. An entered token takes precedence.")
    with st.form("inspect-link", clear_on_submit=False, enter_to_submit=True):
        url = st.text_input(
            "GitLab pipeline, job, branch, file or repository URL", key="inspection_url",
            placeholder="https://gitlab.example/group/project/-/pipelines/123", max_chars=2048,
        )
        token = st.text_input(
            "Read-only GitLab token", type="password", key="read_only_token", disabled=configured,
            help="Optional for Automatic. Use read_api/read_repository access. The password field is cleared after each attempt; the URL and settings stay visible.",
        )
        st.checkbox(
            "Save token encrypted on this Windows account", key="remember_token",
            disabled=configured or not status.get("vault_available", False),
            help="Explicit consent to Windows DPAPI storage outside project data after access verification. No plaintext fallback. Unchecked new tokens are request-only; existing saved connections can still be reused.",
        )
        if not status.get("vault_available"):
            st.caption("Windows encrypted storage is unavailable. New tokens will not be saved.")
        st.checkbox(
            "Force refresh", key="force_refresh",
            help="Bypass the short-lived result snapshot. Access is rechecked even when a snapshot is reused.",
        )
        submitted = st.form_submit_button("Analyze", type="primary", on_click=_begin_submission)
    if submitted:
        _inspect_submission(status, url, token)
    if st.session_state.submission_failed:
        st.error("Inspection not completed. " + _md(st.session_state.submission_error or "Check the URL and connection.") + " Previous results were cleared.")


def _outcome(item: dict[str, Any]) -> str:
    status = str(item.get("status", "unknown")).lower()
    return str(item.get("conclusion") or status).lower() if status == "completed" else status


def _ordered_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    def priority(finding: dict[str, Any]) -> tuple[int, int]:
        causal = (
            finding.get("job_id") and finding.get("category") not in _CONTEXT_CATEGORIES
            and not str(finding.get("rule_id", "")).startswith(("pipeline.", "ci.visibility"))
            and finding.get("severity") in {"error", "warning"}
        )
        return (
            0 if causal else 1,
            {"error": 0, "warning": 1, "info": 2}.get(finding.get("severity", "info"), 2),
        )

    # Stable within priority groups; keep the API's evidence ordering as the tie-breaker.
    return sorted(_objects(result.get("findings")), key=priority)


def _render_outcome(result: dict[str, Any]) -> None:
    pipeline = result.get("pipeline") or {}
    outcome = _outcome(pipeline)
    status = result["status"]
    if status == "configuration_only":
        st.info("Configuration-only inspection · no pipeline run was available. Static checks are not runtime evidence.")
    elif outcome in _SUCCESS and status == "passed":
        st.success("GitLab reported pipeline success · no failure observed in the sampled evidence.")
    elif outcome in _SUCCESS:
        message = "GitLab reported pipeline success · inspection warning. "
        allowed = [job for job in _objects(result.get("jobs")) if _outcome(job) in _FAILED and job.get("allow_failure")]
        if allowed:
            message += f"{len(allowed)} failed job(s) have allow_failure=true, so they need not fail the pipeline. "
        message += "Warnings do not override GitLab's reported pipeline outcome; CI execution policy is unchanged."
        st.warning(message)
    elif outcome in _FAILED:
        st.error("GitLab reported pipeline " + _md(outcome) + " · the job evidence below explains the cause when established.")
    elif status == "in_progress":
        st.info("GitLab pipeline is " + _md(outcome) + " · no final outcome is available yet.")
    else:
        st.warning("Inspection warning · GitLab pipeline status: " + _md(outcome) + ". Status alone does not establish a cause.")
    selected = result.get("selected_job")
    if isinstance(selected, dict):
        text = f"Selected job {selected.get('name', '')} (#{selected.get('external_id', '')}) reported {_outcome(selected)}. "
        text += (
            "It is not declared failed; warnings or other job findings are separate context."
            if _outcome(selected) in _SUCCESS else "Its outcome is separate from the overall pipeline outcome."
        )
        st.info(_md(text))


def _job_label(result: dict[str, Any], job_id: object) -> str:
    jobs = _objects(result.get("jobs")) + [item.get("job", {}) for item in _objects(result.get("analyses"))]
    job = next((item for item in jobs if str(item.get("external_id")) == str(job_id)), {})
    return f"{job.get('name', 'Job')} (#{job_id})"


def _evidence(evidence: dict[str, Any], *, short: bool = True) -> None:
    text = str(evidence.get("text") or "No quoted diagnostic was supplied.")
    excerpt = "".join(text.splitlines(keepends=True)[:4])[:1200] if short else text[:MAX_DISPLAY_CHARS]
    location = evidence.get("path") or "Job trace / metadata"
    if evidence.get("line") is not None:
        location += f" · line {evidence['line']}"
    st.caption(_md(location))
    st.code(excerpt, language="text", wrap_lines=True)
    if len(excerpt) < len(text):
        st.caption("Exact prefix shown; the remaining evidence is available in the details or cited source.")
    _link("Evidence source", evidence.get("source_url"))


def _finding_body(finding: dict[str, Any], result: dict[str, Any]) -> None:
    confidence = {"observed": "Observed evidence", "likely": "Likely interpretation", "unknown": "Cause not established"}.get(finding.get("confidence", "unknown"), "Cause not established")
    owner = finding.get("owner") or "Unknown"
    context = f"{confidence} · Owner: {owner}"
    if finding.get("job_id"):
        context += " · " + _job_label(result, finding["job_id"])
    else:
        context += " · Pipeline metadata / static context; not a proven runtime cause"
    st.caption(_md(context))
    st.markdown("**Why**")
    st.markdown(_md(finding.get("explanation") or "No cause was established from the available evidence."))
    st.markdown("**Probable correct fix — review before making changes**")
    fixes = finding.get("fix") or []
    if not fixes:
        st.write("Obtain the missing diagnostic before choosing a fix; do not change CI execution policy from status alone.")
    for index, step in enumerate(fixes[:3], 1):
        st.markdown(f"{index}. {_md(step)}")
    evidence = _objects(finding.get("evidence"))
    if evidence:
        st.markdown("**Quoted evidence**")
        _evidence(evidence[0])
        # Keep the short quote singular, but surface the authoritative source-file link too.
        for item in evidence[1:3]:
            if item.get("path"):
                _link(str(item["path"]) + (f" · line {item['line']}" if item.get("line") else ""), item.get("source_url"))


def _finding_details(finding: dict[str, Any]) -> None:
    with st.expander("More evidence, safe steps & references", expanded=False):
        st.caption(_md(f"Rule: {finding.get('rule_id', 'unknown')} · Category: {finding.get('category', 'unknown')}"))
        for index, step in enumerate((finding.get("fix") or [])[3:], 4):
            st.markdown(f"{index}. {_md(step)}")
        for item in _objects(finding.get("evidence")):
            _evidence(item, short=False)
        for url in (finding.get("documentation") or [])[:5]:
            _link("Documentation", url)


def _render_summary(result: dict[str, Any]) -> None:
    repository = result["repository"]
    pipeline = result.get("pipeline") or {}
    with st.container(border=True):
        st.markdown("**Examined link & scope**")
        st.caption(_md(f"{repository.get('owner', '')}/{repository.get('name', '')} · Reference: {result.get('reference_kind', 'unknown')}"))
        _link("Submitted URL (canonical)", result.get("submitted_url"))
        if pipeline:
            _link("Resolved parent pipeline", pipeline.get("web_url"))
        if result.get("resolved_url") not in {result.get("submitted_url"), pipeline.get("web_url")}:
            _link("Resolved reference", result.get("resolved_url"))
        if pipeline.get("commit_sha"):
            st.caption(_md(f"Ref: {pipeline.get('ref_name') or 'unknown'} · Pipeline commit: {pipeline['commit_sha']}"))
        freshness = (
            f"Cached snapshot · {result.get('cache_age_seconds', 0)} seconds old; access rechecked. Use Force refresh for fresh trace/include reads."
            if result.get("cached") else "Fresh inspection snapshot."
        )
        st.caption(_md(f"{freshness} Evidence inspected at {result.get('inspected_at', 'unknown')} · Elapsed: {result.get('elapsed_ms', 0)} ms · Connection: {result.get('connection_used', 'unknown')}"))
        st.caption(_md(f"Bounded sample: {result.get('analyzed_job_count', 0)} jobs inspected; {result.get('skipped_job_count', 0)} enumerated jobs not trace-analyzed. Up to five jobs, including selected/failed jobs and samples of successful jobs. Not a complete pipeline audit or proof of an intended deployment receipt."))
        if result.get("credential_saved"):
            st.caption("A verified Windows-encrypted connection was saved or reused for this inspection. Automatic can reuse it on the same host; no need to re-enter the token.")
        elif st.session_state.remember_token:
            st.caption("No saved credential was reported for this inspection. Check connection settings and inspection notes.")


def _paged_text(text: str, key: str, *, language: str = "text") -> None:
    bounded = text[:MAX_VIEW_CHARS]
    lines = bounded.splitlines()[:5000]
    if not lines:
        st.info("No readable content was returned. Missing evidence does not establish a cause.")
        return
    pages = max(1, (len(lines) + PAGE_LINES - 1) // PAGE_LINES)
    page = int(st.number_input("Display page", min_value=1, max_value=pages, value=1, step=1, key=key)) if pages > 1 else 1
    start = (page - 1) * PAGE_LINES
    raw = "\n".join(lines[start:start + PAGE_LINES])
    st.caption(f"Display lines {start + 1}–{min(start + PAGE_LINES, len(lines))} · page {page}/{pages}. Sanitized display numbering is not an original trace-line citation after omissions.")
    st.code(raw[:MAX_DISPLAY_CHARS], language=language, wrap_lines=True, height=360)
    if len(text) > len(bounded) or len(bounded.splitlines()) > 5000 or len(raw) > MAX_DISPLAY_CHARS:
        st.caption("Display is bounded to the first 200,000 characters / 5,000 lines and 16,000 characters per page. Open the cited GitLab source for omitted content.")


def _result_key(result: dict[str, Any]) -> str:
    return hashlib.sha256(f"{result.get('project_key')}|{result.get('resolved_url')}|{result.get('inspected_at')}".encode()).hexdigest()[:16]


def _render_diagnosis_details(result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    if findings:
        _finding_details(findings[0])
    with st.expander(f"Other findings ({max(0, len(findings) - 1)})", expanded=False):
        if len(findings) < 2:
            st.caption("No additional findings were returned in this bounded inspection.")
        for finding in findings[1:]:
            with st.expander(_md(f"{str(finding.get('severity', 'info')).title()} · {finding.get('title', 'Finding')}"), expanded=False):
                _finding_body(finding, result)
                _finding_details(finding)
    with st.expander("Inspection scope & limitations", expanded=False):
        for note in (result.get("notes") or [])[:100]:
            st.markdown("- " + _md(note))
    with st.expander("Raw redacted logs (bounded view)", expanded=False):
        analyses = _objects(result.get("analyses"))
        if not analyses:
            st.info("No job traces were analyzed for this reference.")
        else:
            selected = st.selectbox(
                "Trace to view", range(len(analyses)), key=f"trace-{_result_key(result)}",
                format_func=lambda index: f"{analyses[index].get('job', {}).get('name', 'Job')} · #{analyses[index].get('job', {}).get('external_id', '')} · pipeline {analyses[index].get('run', {}).get('external_id', '')}",
            )
            snapshot = analyses[selected]
            _link("Job trace", snapshot.get("job", {}).get("web_url"))
            _paged_text(str(snapshot.get("redacted_log") or ""), f"log-page-{_result_key(result)}-{selected}")


def _table_cell(name: str, value: Any) -> Any:
    if name == "Source URL" and (url := _safe_url(value)):
        # Explicit targets prevent Markdown autolinking escaped URL punctuation.
        return f"[{_md(url)}](<{url}>)"
    return _md(value) if isinstance(value, str) else value


def _table(rows: list[dict[str, Any]], key: str) -> None:
    if rows:
        pages = (len(rows) + 19) // 20
        page = int(st.number_input("Table page", min_value=1, max_value=pages, value=1, step=1, key=key)) if pages > 1 else 1
        start = (page - 1) * 20
        st.caption(f"Rows {start + 1}–{min(start + 20, len(rows))} of {len(rows)}. Scroll horizontally on narrow screens; values wrap without truncation.")
        # Static table cells wrap; the interactive grid truncates long values.
        # Tables accept Markdown, so neutralize images/links from provider strings.
        st.table([{name: _table_cell(name, value) for name, value in row.items()} for row in rows[start:start + 20]])
    else:
        st.caption("No entries were available in this bounded inspection.")


def _render_pipeline_context(result: dict[str, Any]) -> None:
    with st.expander("Job status & sampling", expanded=False):
        sampled = {str(item.get("job", {}).get("external_id")) for item in _objects(result.get("analyses"))}
        st.caption("Root pipeline jobs only. An inspected job may have metadata only if its trace was unavailable; child evidence is listed separately. Successful jobs are sampled, not exhaustively checked.")
        _table([
            {
                "Job": job.get("name"), "ID": job.get("external_id"), "Stage": job.get("stage"),
                "Reported outcome": _outcome(job), "allow_failure": bool(job.get("allow_failure")),
                "Inspection": "Sampled" if str(job.get("external_id")) in sampled else "Metadata only",
                "Failure reason": job.get("failure_reason"), "Source URL": _safe_url(job.get("web_url")),
            }
            for job in _objects(result.get("jobs"))[:301]
        ], f"jobs-page-{_result_key(result)}")
    with st.expander("Merge requests & changed files (static checks)", expanded=False):
        st.info("MR/commit changes are static context, not proof that a changed line executed or caused the failure. A current MR diff is historical evidence only when its head matches the pipeline SHA; otherwise the API uses the exact pipeline commit diff when readable.")
        requests = _objects(result.get("merge_requests"))
        _table([
            {
                "MR": f"!{item.get('iid')}", "Title": item.get("title"), "Status": item.get("status"),
                "Source branch": item.get("source"), "Target branch": item.get("target"),
                "source_type": item.get("source_type", "unknown"), "MR head SHA": item.get("head_sha"),
                "Source URL": _safe_url(item.get("web_url")),
            } for item in requests
        ], f"mr-page-{_result_key(result)}")
        source_type = "merge_request" if requests and all(item.get("source_type") == "merge_request" for item in requests) else "pipeline_commit"
        _table([
            {
                "Old path": item.get("old_path"), "New path": item.get("new_path"),
                "Change": "Deleted" if item.get("deleted_file") else "Renamed" if item.get("renamed_file") else "Added" if item.get("new_file") else "Modified",
                "source_type": source_type, "Scope": "Static path check; not runtime evidence",
                "Diff limited": bool(item.get("collapsed") or item.get("too_large")),
            } for item in _objects(result.get("changes"))[:100]
        ], f"changes-page-{_result_key(result)}")
    with st.expander("Downstream pipeline evidence", expanded=False):
        st.caption("One level only: at most two failed/warning child pipelines and one child job analysis within the overall five-job budget. Trigger execution policy is unchanged.")
        _table([
            {
                "Trigger": item.get("name"), "Trigger status": item.get("status"),
                "allow_failure": bool(item.get("allow_failure")), "Access": item.get("access"),
                "Child pipeline": item.get("downstream_pipeline", {}).get("id"),
                "Child status": item.get("downstream_pipeline", {}).get("status"),
                "Analyzed child job": item.get("analyzed_job_id"),
                "Source URL": _safe_url(item.get("downstream_pipeline", {}).get("web_url")),
            } for item in _objects(result.get("downstream"))[:2]
        ], f"downstream-page-{_result_key(result)}")


def _render_sources(result: dict[str, Any]) -> None:
    report = result.get("ci_config_access") or {}
    with st.expander("CI include chain & visibility", expanded=False):
        st.info("Readable is not the same as historically verified. Root sources use the pipeline SHA when available. A mutable branch/tag include pinned during this inspection records what was read today, not necessarily what a past run used.")
        st.caption("Reported source visibility: " + ("Complete within the reported scope" if report.get("complete") else "Partial / unresolved"))
        _table([
            {
                "Relationship": entry.get("relationship"), "CI source": display_include_path(str(entry.get("path", ""))),
                "Ref read": entry.get("ref"), "Read access": entry.get("state"), "Detail": entry.get("detail"),
                "Source URL": _safe_url(entry.get("source_url")),
            } for entry in _objects(report.get("entries"))
        ], f"chain-page-{_result_key(result)}")
        for note in report.get("notes") or []:
            st.markdown("- " + _md(note))
        st.markdown("**Job-to-CI source mapping**")
        rows = []
        for analysis in _objects(result.get("analyses")):
            source = analysis.get("job_source") or {}
            if source:
                rows.append({
                    "Job": analysis.get("job", {}).get("name"), "CI job key": source.get("job_key"),
                    "Source": display_include_path(str(source.get("path", ""))),
                    "Lines": f"{source.get('line_start')}–{source.get('line_end')}",
                    "Inherited from": source.get("inherited_from"),
                    "Mapping": "Observed exact match" if source.get("match_confidence") == 1 else "Likely mapping; verify",
                    "Source URL": _safe_url(source.get("source_url")),
                })
        _table(rows, f"mapping-page-{_result_key(result)}")
    with st.expander("CI source files (bounded view)", expanded=False):
        configs = _objects(result.get("config_bundle"))
        if configs:
            index = st.selectbox(
                "CI source to view", range(len(configs)), key=f"config-{_result_key(result)}",
                format_func=lambda value: display_include_path(str(configs[value].get("path", "Unknown source"))),
            )
            config = configs[index]
            st.caption(_md(f"Ref read: {config.get('ref') or 'unknown'}"))
            _link("CI source", config.get("source_url"))
            _paged_text(str(config.get("content") or ""), f"config-page-{_result_key(result)}-{index}", language="yaml")
        else:
            st.info("No readable CI sources were returned; no historical file was guessed.")
    with st.expander("Repository tree (up to 280 rows)", expanded=False):
        entries = _objects(result.get("project_structure"))
        if entries:
            tree = "\n".join(str(entry.get("path", "")) + ("/" if entry.get("entry_type") == "directory" else "") for entry in entries[:MAX_TREE_ROWS])
            st.code(tree, language="text", wrap_lines=True, height=360)
        st.caption(f"Showing {min(len(entries), MAX_TREE_ROWS)} of {len(entries)} returned entries. Inventory and depth are bounded; absence is not proof that a package or input is missing.")


def _render_connections(status: dict[str, Any]) -> None:
    with st.expander("Connection settings · disconnect / forget", expanded=False):
        st.caption("Only Windows DPAPI-encrypted saved tokens can be forgotten here. Forgetting clears the API result cache; it does not revoke the GitLab token. Automatic may still use a same-host configured connection.")
        _link("Configured host", status.get("configured_host"))
        st.caption("Configured connection: " + ("Available" if status.get("configured_connection") else "Unavailable"))
        saved = _objects(status.get("saved_connections"))
        if not saved:
            st.caption("No saved Windows connections are reported.")
        for index, item in enumerate(saved, 1):
            _link(f"Saved connection {index}", item.get("host"))
            st.caption(_md("Verified projects: " + ", ".join(str(project) for project in item.get("projects", []))))
            if st.button(f"Forget saved connection {index}", key=f"forget-{item.get('id')}"):
                try:
                    response = _api().post(f"{LOCAL}/connections/forget", {"credential_id": item["id"]})
                    if not isinstance(response, dict) or not isinstance(response.get("removed"), bool):
                        raise ApiClientError("Invalid forget response.")
                except ApiClientError:
                    st.error("The saved connection could not be forgotten. Check the local API and retry.")
                else:
                    st.session_state.local_notice = "Saved connection forgotten." if response["removed"] else "The connection was already absent."
                    st.session_state._clear_password = True
                    st.rerun()
        for note in status.get("notes") or []:
            st.caption(_md(redact_text(str(note))))


def _render_confirmation(result: dict[str, Any], findings: list[dict[str, Any]]) -> None:
    with st.expander("Previously human-confirmed resolutions", expanded=False):
        confirmed = [item for item in _objects(result.get("confirmed_resolutions")) if item.get("human_confirmed") is True]
        st.caption("These are prior user assertions for the project/rule, not fixes revalidated for this run.")
        for item in confirmed[:6]:
            st.markdown("**" + _md(item.get("rule_id", "Unknown rule")) + "**")
            st.markdown(_md(item.get("resolution", "")))
        if not confirmed:
            st.caption("No matching human-confirmed resolutions were returned.")
    rules = {item["rule_id"]: item for item in findings if item.get("rule_id")}
    if not rules:
        return
    with st.expander("Confirm a tested resolution", expanded=False):
        st.caption("Nothing is auto-confirmed. Record only a change you actually tested for this project and finding; do not paste credentials.")
        key = _result_key(result)
        with st.form(f"confirm-{key}", clear_on_submit=False):
            rule = st.selectbox("Finding to confirm", list(rules), format_func=lambda value: f"{value} · {rules[value].get('title', '')}", key=f"resolution-rule-{key}")
            resolution = st.text_area("What change was tested and resolved the issue?", max_chars=4000, key=f"resolution-text-{key}")
            confirmed = st.checkbox("I tested this resolution for this project and finding.", key=f"resolution-tested-{key}")
            clicked = st.form_submit_button("Confirm resolution")
        if clicked:
            if not confirmed or not resolution.strip():
                st.warning("Describe the tested resolution and explicitly confirm it before saving.")
            else:
                try:
                    response = _api().post(f"{LOCAL}/knowledge/confirm", {
                        "project_key": result["project_key"], "rule_id": rule,
                        "resolution": resolution.strip(), "confirmed": True,
                    })
                    if not isinstance(response, dict) or response.get("human_confirmed") is not True or response.get("saved") is not True:
                        raise ApiClientError("Invalid confirmation response.")
                except ApiClientError:
                    st.error("The resolution could not be saved. Check the local API and retry.")
                else:
                    _invalidate_export()
                    st.session_state.local_notice = "Human-confirmed resolution saved for this project and rule. It is a user assertion, not an automatic diagnosis."
                    st.rerun()


def _render_export() -> None:
    with st.expander("Review & export local knowledge", expanded=False):
        st.warning(EXPORT_NOTICE)
        if st.button("Preview sanitized export", on_click=_invalidate_export):
            try:
                data = _api().get(f"{LOCAL}/knowledge/export")
                if not isinstance(data, dict) or not isinstance(data.get("notice"), str) or not data["notice"].strip():
                    raise ApiClientError("Export review notice is missing.")
                encoded = json.dumps(data, indent=2, ensure_ascii=False, allow_nan=False)
                if len(encoded.encode("utf-8")) > MAX_EXPORT_BYTES:
                    raise ApiClientError("Export exceeds the local preview limit.")
                st.session_state.export_preview = encoded
            except (ApiClientError, TypeError, ValueError):
                st.error("The sanitized export could not be prepared with its review notice. No download is available; check the local API and retry.")
        preview = st.session_state.export_preview
        if preview is not None:
            st.markdown("**Sanitized export preview — review all sections before downloading**")
            st.json(preview, expanded=1)
            if st.checkbox("I reviewed this export for business-sensitive information and approve downloading it.", key="export_reviewed"):
                # Download exactly the reviewed snapshot; never refetch after consent.
                st.download_button("Download reviewed JSON", preview, file_name="pipelinelens-knowledge.json", mime="application/json", on_click="ignore")


def _render_memory(status: dict[str, Any], result: dict[str, Any] | None, findings: list[dict[str, Any]]) -> None:
    summary = status.get("knowledge") or (result or {}).get("knowledge_summary") or {}
    st.caption(_md(f"Retained local notes: {summary.get('projects', 0)} projects · {summary.get('observations', 0)} observations · {summary.get('confirmed_resolutions', 0)} human-confirmed resolutions. Observations are not verified fixes."))
    if result is not None:
        st.caption("Redacted observation saved locally." if result.get("knowledge_saved") else "No new local observation was saved; the inspection can still be used.")
    if st.session_state.local_notice:
        st.success(st.session_state.local_notice)
    _render_connections(status)
    if result is not None:
        _render_confirmation(result, findings)
    _render_export()


def run() -> None:
    st.set_page_config(page_title="PipelineLens", page_icon="PL", layout="wide", initial_sidebar_state="collapsed")
    _initialize_state()
    _render_styles()
    st.title("PipelineLens")
    st.info("Local rules • no external AI calls")
    st.caption("Understand the cause. Review the safe fix. Expand evidence only when needed.")
    status = _local_status()
    _render_input(status)
    result = st.session_state.inspection_result
    findings = _ordered_findings(result) if result else []
    if result is not None:
        if findings:
            primary = findings[0]
            st.subheader(_md(f"{str(primary.get('severity', 'info')).title()} · {primary.get('title', 'Inspection finding')}"))
        else:
            st.subheader("No causal finding established")
        _render_outcome(result)
        if findings:
            _finding_body(findings[0], result)
        else:
            st.write("The available evidence did not establish a cause or a specific correction. Review the inspection scope before choosing a fix.")
        _render_summary(result)
    diagnosis, context, sources, memory = st.tabs(["Diagnosis", "Pipeline context", "CI sources & files", "Local memory"])
    with diagnosis:
        if result is not None:
            _render_diagnosis_details(result, findings)
        elif not st.session_state.submission_failed:
            st.info("Paste a supported GitLab link and press Enter or Analyze. A branch, file or repository link resolves to its branch's latest pipeline, or a configuration-only inspection if no pipeline exists.")
    with context:
        if result is not None:
            _render_pipeline_context(result)
        else:
            st.caption("Pipeline and job context will appear after a successful inspection.")
    with sources:
        if result is not None:
            _render_sources(result)
        else:
            st.caption("CI source visibility and the bounded file inventory will appear here.")
    with memory:
        _render_memory(status, result, findings)


if __name__ == "__main__":
    run()
