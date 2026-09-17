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
import socket
import time
from ipaddress import ip_address
from typing import Any
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import streamlit as st

from pipelinelens.dashboard.client import ApiClientError, PipelineLensApiClient
from pipelinelens.services.findings import finding_identity
from pipelinelens.services.gitlab_includes import display_include_path
from pipelinelens.services.pipeline_url import PipelineUrlError, parse_gitlab_url
from pipelinelens.services.redaction import redact_text

API_URL = os.getenv("PIPELINELENS_API_URL", "http://localhost:8000")
# "auto" (default): use API_URL if reachable, else self-host the API in this same
# process so one `streamlit run` command works standalone (e.g. Streamlit Community
# Cloud, or a dev machine that forgot to start the API separately). "never" keeps
# today's two-process-only behavior; tests force this so no probe/thread ever runs.
SELF_HOST_MODE = os.getenv("PIPELINELENS_SELF_HOST_API", "auto").strip().lower()
_SELF_HOST_DISABLED = {"never", "0", "false", "off", "disabled"}
_SELF_HOST_PROBE_ATTEMPTS = 8
_SELF_HOST_PROBE_INTERVAL_SECONDS = 0.25
_SELF_HOST_PROBE_TIMEOUT_SECONDS = 0.3
_SELF_HOST_STARTUP_TIMEOUT_SECONDS = 15
LOCAL = "/api/v1/local"
MAX_TREE_ROWS = 280
PAGE_LINES = 120
MAX_DISPLAY_CHARS = 16_000
MAX_VIEW_CHARS = 200_000
MAX_EXPORT_BYTES = 8 * 1024 * 1024
MAX_SOURCE_CHARS = 8_000
MAX_SOURCE_LINES = 80
MAX_DIFF_CHARS = 16_000
MAX_DIFF_LINES = 240
MAX_PROPOSALS = 3
MAX_SUMMARY_CHARS = 1_600
MAX_SUMMARY_LINES = 8
LOW_FIX_CONFIDENCE = 60
SCORE_LABEL = "Rule-based heuristic; not a calibrated probability"
LOCAL_NOTES_NOTICE = "Redacted diagnostic notes stay on this device"
_DOC_HOSTS = {
    "docs.gitlab.com": "GitLab documentation",
    "learn.microsoft.com": "Microsoft Learn",
    "developer.salesforce.com": "Salesforce documentation",
    "docs.sonarsource.com": "SonarSource documentation",
    "docs.docker.com": "Docker documentation",
    "docs.python.org": "Python documentation",
    "docs.npmjs.com": "npm documentation",
    "docs.github.com": "GitHub documentation",
    "documentation.conga.com": "Conga documentation",
    "docs.conga.com": "Conga documentation",
    "manpages.debian.org": "Debian documentation",
    "jqlang.org": "jq manual",
    "developer.mozilla.org": "MDN Web Docs",
}
_SOURCE_LANGUAGES = {
    "text", "bash", "shell", "python", "csharp", "java", "javascript",
    "typescript", "json", "yaml", "xml", "sql", "apex", "powershell",
}
CONNECTIONS = {
    "auto": "Automatic",
    "request": "New token",
    "configured": "Configured connection",
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
        .stApp { background: #fff; color: #1f2937; }
        [data-testid="stHeader"] { background: transparent; }
        .block-container { max-width: 1000px; padding: 1.5rem 2rem 3rem; }
        h1, h2, h3, p, label { font-family: "Segoe UI", system-ui, sans-serif; }
        h1, h2, h3 { color: #111827; letter-spacing: -0.02em; }
        h1 { margin-bottom: 0; font-size: 1.8rem !important; }
        h3 { font-size: 1.3rem !important; }
        [data-testid="stForm"], [data-testid="stExpander"] {
          background: #fff; border: 1px solid #e5e7eb; border-radius: 8px;
        }
        [data-testid="stAlert"] { border-radius: 6px; }
        [data-testid="stCaptionContainer"] { color: #64748b; }
        [data-testid="stMarkdownContainer"], [data-testid="stMetricValue"],
        [data-testid="stExpander"] summary, button p {
          overflow-wrap: anywhere; white-space: normal; text-overflow: clip;
        }
        [data-testid="stMetricValue"] { font-size: 1.5rem; }
        [data-testid="stTextInput"] input {
          min-width: 0; font-size: 1rem; background: #fff; color: #111827;
        }
        [data-testid="stBaseButton-primaryFormSubmit"] {
          background: #252b35; border-color: #252b35; color: white;
          min-height: 2.5rem;
        }
        [data-testid="stCode"] pre { overflow-x: auto; }
        [data-testid="stTable"] { max-width: 100%; overflow-x: auto; }
        [data-testid="stTable"] table { min-width: 680px; width: 100%; table-layout: fixed; }
        [data-testid="stTable"] td, [data-testid="stTable"] th {
          white-space: normal; overflow-wrap: anywhere; text-overflow: clip;
        }
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
    return PipelineLensApiClient(_resolved_api_url())


def _api_url_reachable(url: str) -> bool:
    """A bare TCP-connect probe: fast, no HTTP request, no route assumptions."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if parts.scheme == "https" else 80)
        with socket.create_connection((host, port), timeout=_SELF_HOST_PROBE_TIMEOUT_SECONDS):
            return True
    except (OSError, ValueError):
        return False


def _start_self_hosted_api() -> str:
    """Run the local API in a background thread of this same process, loopback-only.

    Only reached when no external API answered ``API_URL``. The local-only request
    guard in ``api/inspection.py`` is unchanged: it still requires a loopback client
    and the ``X-PipelineLens-Local`` header, which this dashboard already sends.
    """
    import threading

    import uvicorn

    from pipelinelens.api.main import create_app

    probe_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe_socket.bind(("127.0.0.1", 0))
    port = probe_socket.getsockname()[1]
    probe_socket.close()

    config = uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run, name="pipelinelens-self-hosted-api", daemon=True,
    )
    thread.start()

    url = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + _SELF_HOST_STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        if _api_url_reachable(url):
            break
        time.sleep(_SELF_HOST_PROBE_INTERVAL_SECONDS)
    return url


def _resolve_api_url_once() -> str:
    """Plain (uncached) resolution so tests can exercise it without a Streamlit context."""
    if SELF_HOST_MODE in _SELF_HOST_DISABLED:
        return API_URL
    for attempt in range(_SELF_HOST_PROBE_ATTEMPTS):
        if _api_url_reachable(API_URL):
            return API_URL
        if attempt < _SELF_HOST_PROBE_ATTEMPTS - 1:
            time.sleep(_SELF_HOST_PROBE_INTERVAL_SECONDS)
    return _start_self_hosted_api()


@st.cache_resource(show_spinner="Starting the local PipelineLens API...")
def _resolved_api_url() -> str:
    """Resolve once per running process; every rerun and session reuses the result."""
    return _resolve_api_url_once()


def _md(value: object) -> str:
    """Literal Markdown text, not user-supplied links, images or HTML."""
    return re.sub(r"([\\`*_{}\[\]()#+.!|>~<\-])", r"\\\1", str(value))


def _objects(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _text_items(value: object) -> list[str]:
    items = [value] if isinstance(value, str) else value if isinstance(value, list) else []
    return [item.strip() for item in items if isinstance(item, str) and item.strip()]


def _brief(value: object, limit: int = 480) -> str:
    text = " ".join(value.split()) if isinstance(value, str) else ""
    return text if len(text) <= limit else text[:limit - 1].rsplit(" ", 1)[0] + "…"


def _numbered_steps(steps: object, *, start: int = 1, limit: int = 3) -> None:
    # A single Markdown block keeps the browser's ordered list from restarting at 1.
    items = _text_items(steps)[:limit]
    if items:
        items = [_brief(re.sub(r"^\d+[.)]\s+", "", step), 700) for step in items]
        st.markdown("\n".join(
            f"{index}. {_md(step)}"
            for index, step in enumerate(items, start)
        ))


def _exact_code(text: str, *, language: str) -> None:
    # st.code removes one leading and one trailing LF. Guard both boundaries so
    # the displayed/copied payload is exactly the API's text, including CRLF.
    st.code("\n" + text + "\n", language=language, wrap_lines=False)


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
        fragment = parts.fragment if re.fullmatch(r"L[1-9]\d*(?:-L?[1-9]\d*)?", parts.fragment) else ""
        if (
            parts.scheme == "https" and host in _DOC_HOSTS and port in {None, 443}
            and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,199}", parts.fragment)
            and redact_text(parts.fragment) == parts.fragment
        ):
            fragment = parts.fragment
        return urlunsplit((parts.scheme, authority, path, "", fragment))
    except (ValueError, UnicodeError):
        return None


def _link(label: str, value: object) -> None:
    url = _safe_url(value)
    if url:
        st.markdown(f"[{_md(label)}](<{url}>)")


def _documentation_url(value: object) -> str | None:
    url = _safe_url(value)
    if url:
        parts = urlsplit(url)
        if parts.scheme == "https" and parts.hostname in _DOC_HOSTS and parts.port in {None, 443}:
            return url
    return None


def _url_to_keep(url: str, token: str) -> str:
    """Retain ordinary input, but never retain credentials pasted into a URL."""
    try:
        parts = urlsplit(url)
        unsafe = (
            parts.username is not None or parts.password is not None
            or bool(token and token in unquote(url)) or redact_text(url) != url
            or bool(re.search(r"(?:^|[&;])(?:[\w-]*(?:token|secret|password|credential|signature)|api[_-]?key)=", unquote(parts.query), re.I))
        )
    except ValueError:
        return ""
    if not unsafe:
        return url
    canonical = _safe_url(url)
    return canonical if canonical and not (token and token in unquote(canonical)) else ""


def _initialize_state() -> None:
    defaults: dict[str, Any] = {
        "inspection_result": None, "submission_failed": False, "submission_error": None,
        "inspection_url": "", "connection_mode": "auto", "remember_token": False,
        "remember_analysis": True, "ask_cloud_ai": False,
        "force_refresh": False, "_clear_password": False, "export_preview": None,
        "export_reviewed": False, "local_notice": None,
    }
    for key, value in defaults.items():
        st.session_state.setdefault(key, value)
    # Never mutate the password widget after instantiating it in this script run.
    if st.session_state.pop("_clear_password", False):
        st.session_state["read_only_token"] = ""
    if "_safe_inspection_url" in st.session_state:
        st.session_state["inspection_url"] = st.session_state.pop("_safe_inspection_url")


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
    entered_token = token.strip()
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
        if entered_token and entered_token in unquote(url):
            raise PipelineUrlError("Remove credentials from the URL; enter them only in the password field.")
        token = "" if mode == "configured" else token.strip()
        if mode == "request" and not token:
            raise PipelineUrlError("Enter a read-only GitLab token, or choose Automatic to reuse a saved same-host connection.")
        if len(token) > 8192 or any(not 33 <= ord(char) <= 126 for char in token):
            raise PipelineUrlError("Enter a valid read-only token without whitespace.")
        payload = {
            "url": url.strip(), "connection": mode,
            "remember_token": bool(token and st.session_state.remember_token and status.get("vault_available")),
            "remember_analysis": bool(st.session_state.remember_analysis),
            "refresh": bool(st.session_state.force_refresh), "max_jobs": 5,
            "ask_cloud_ai": bool(st.session_state.ask_cloud_ai and status.get("cloud_assist_configured")),
        }
        if token:
            payload["token"] = token
        with st.spinner("Reading GitLab evidence and checking the cause…"):
            result = _validate_result(_api().post(f"{LOCAL}/inspect", payload))
        # The API owns redaction of evidence. Never persist its raw submitted-URL echo.
        result["submitted_url"] = canonical
        result["_remember_analysis_requested"] = bool(st.session_state.remember_analysis)
        st.session_state.inspection_result = result
    except (PipelineUrlError, ApiClientError) as error:
        message = str(error)
        if entered_token:
            message = message.replace(entered_token, "[REDACTED]")
        st.session_state.inspection_result = None
        st.session_state.submission_failed = True
        st.session_state.submission_error = redact_text(message)
    finally:
        payload.pop("token", None)
        st.session_state._clear_password = True
        st.session_state._safe_inspection_url = _url_to_keep(url, entered_token)
    # A new run consumes the deferred clear before rendering widgets, including on failure.
    st.rerun()


def _render_input(status: dict[str, Any]) -> None:
    with st.form("inspect-link", clear_on_submit=False, enter_to_submit=True):
        link_column, action_column = st.columns((5, 1), vertical_alignment="bottom")
        with link_column:
            url = st.text_input(
                "GitLab link", key="inspection_url", max_chars=2048,
                placeholder="Paste a pipeline, job, branch or project URL",
                help="Pipeline and job links inspect that run. Branch, file and project links resolve their latest pipeline or inspect configuration when no run exists.",
            )
        with action_column:
            submitted = st.form_submit_button(
                "Analyze", type="primary", on_click=_begin_submission,
                use_container_width=True,
            )
        with st.expander("Connection & options", expanded=False):
            st.radio(
                "GitLab connection", list(CONNECTIONS), format_func=CONNECTIONS.__getitem__,
                key="connection_mode", horizontal=True,
            )
            st.caption("Automatic reuses a saved or configured same-host connection. A new token is used only for this request unless you choose to save it. Configured connection ignores this field.")
            token = st.text_input(
                "Read-only GitLab token", type="password", key="read_only_token",
                help="Use read_api/read_repository access. Only this field is cleared after an attempt; your link and settings stay visible.",
            )
            st.checkbox(
                "Save token encrypted on this Windows account", key="remember_token",
                disabled=not status.get("vault_available", False),
                help="Opt in to Windows DPAPI storage after access verification. Saved tokens stay on this laptop and are only reused on the same GitLab host.",
            )
            if not status.get("vault_available"):
                st.caption("Windows encrypted storage is unavailable. New tokens will not be saved.")
            st.checkbox(
                "Force refresh", key="force_refresh",
                help="Reread evidence instead of using a short-lived snapshot. GitLab access is always rechecked.",
            )
            st.checkbox(
                "Save diagnostic notes locally", key="remember_analysis",
                help="Save redacted diagnostic notes on this device. No telemetry or uploads. Turn off before Analyze to skip new notes; existing notes are not deleted. This is separate from saving a token.",
            )
            st.checkbox(
                "Ask a cloud assist if the cause is unknown (optional, off by default)",
                key="ask_cloud_ai",
                disabled=not status.get("cloud_assist_configured", False),
                help=(
                    "Sends only the already-redacted rule, category and evidence text of the "
                    "one unresolved finding to the locally configured cloud provider "
                    f"({status.get('cloud_assist_provider') or 'none configured'}). Nothing is "
                    "sent unless this is checked for this analysis and a provider is configured "
                    "locally. Every other analysis stays fully local."
                ),
            )
            if not status.get("cloud_assist_configured"):
                st.caption("Cloud assist is not configured on this local API; analysis stays fully local.")
    # The disclosure stays visible even when the connection options are closed.
    st.caption(LOCAL_NOTES_NOTICE if st.session_state.remember_analysis else "Diagnostic note saving is off for the next analysis; existing notes stay on this device.")
    if submitted:
        _inspect_submission(status, url, token)
    if st.session_state.submission_failed:
        st.error("Inspection not completed. " + _md(st.session_state.submission_error or "Check the URL and connection.") + " Previous results were cleared.")


def _outcome(item: dict[str, Any]) -> str:
    status = str(item.get("status", "unknown")).lower()
    return str(item.get("conclusion") or status).lower() if status == "completed" else status


def _ordered_findings(result: dict[str, Any]) -> list[dict[str, Any]]:
    def priority(finding: dict[str, Any]) -> tuple[int, int]:
        actionable = (
            finding.get("category") not in _CONTEXT_CATEGORIES
            and not str(finding.get("rule_id", "")).startswith(("pipeline.", "ci.visibility"))
            and finding.get("severity") in {"error", "warning"}
        )
        if finding.get("job_id") and finding.get("severity") == "error":
            rank = 0 if actionable else 1
        elif finding.get("severity") == "error" and finding.get("category") in {"pipeline_status", "downstream_pipeline", "job_status"}:
            rank = 2
        elif actionable:
            rank = 3 if finding.get("job_id") else 4
        elif finding.get("severity") in {"error", "warning"} and finding.get("category") in {"job_status", "pipeline_status", "downstream_pipeline", "unknown"}:
            rank = 5
        elif finding.get("category") == "no_failure_observed":
            rank = 6
        else:
            rank = 7
        return (
            rank,
            {"error": 0, "warning": 1, "info": 2}.get(finding.get("severity", "info"), 2),
        )

    # Stable within priority groups; keep the API's evidence ordering as the tie-breaker.
    return sorted(_objects(result.get("findings")), key=priority)


def _genuine_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    context = _CONTEXT_CATEGORIES - {"unknown"}
    seen: set[str] = set()
    issues = []
    for finding in findings:
        key = finding_identity(finding)
        if (
            finding.get("severity") in {"error", "warning"}
            and finding.get("category") not in context
            and not str(finding.get("rule_id") or "").startswith(("pipeline.", "ci.visibility"))
            and key not in seen
        ):
            issues.append(finding)
            seen.add(key)
    return issues


def _select_finding(result: dict[str, Any], findings: list[dict[str, Any]]) -> dict[str, Any]:
    issues = _genuine_findings(findings)
    if len(issues) > 1:
        selected = st.selectbox(
            "Issue", range(len(issues)), key=f"issue-{_result_key(result)}",
            format_func=lambda index: _brief(issues[index].get("title"), 150)
            + (" · " + _job_label(result, issues[index]["job_id"]) if issues[index].get("job_id") else ""),
        )
        return issues[selected]
    return issues[0] if issues else findings[0] if findings else {}


def _remediation_for(result: dict[str, Any], finding: dict[str, Any]) -> dict[str, Any]:
    if not finding.get("rule_id"):
        return {}
    key = finding_identity(finding)
    return next((item for item in _objects(result.get("remediations")) if (
        item.get("rule_id") == finding["rule_id"]
        and str(item.get("job_id") or "") == str(finding.get("job_id") or "")
        and (not item.get("finding_key") or item["finding_key"] == key)
    )), {})


def _root_finding(result: dict[str, Any], finding: dict[str, Any]) -> bool:
    return not finding.get("job_id") or str(finding["job_id"]) in {
        str(job.get("external_id")) for job in _objects(result.get("jobs"))
    }


def _confidence(remediation: dict[str, Any], field: str) -> int | float | None:
    value = remediation.get(field)
    if (
        remediation.get("score_label") == SCORE_LABEL
        and isinstance(value, (int, float)) and not isinstance(value, bool)
        and 0 <= value <= 100
    ):
        return value
    return None


def _render_confidence(remediation: dict[str, Any]) -> None:
    meanings = (
        ("Cause confidence", "cause_confidence", "Evidence supporting the identified cause, not just the pipeline outcome."),
        ("Fix confidence", "fix_confidence", "Evidence supporting the proposed correction, not its chance of succeeding."),
    )
    for column, (label, field, meaning) in zip(st.columns(2), meanings, strict=True):
        value = _confidence(remediation, field)
        with column:
            st.metric(
                label, f"{value:g}/100" if value is not None else "Unknown",
                help=f"{meaning} {SCORE_LABEL}. No target verification. Unknown means no supported numeric score was supplied by the API.",
            )


def _source_proposals(remediation: dict[str, Any]) -> list[dict[str, Any]]:
    # The API verifies source applicability. The UI only checks the display shape;
    # it never synthesizes a patch, reapplies it, or claims target verification.
    proposals = []
    for item in _objects(remediation.get("proposals")):
        diff = item.get("diff")
        if (
            item.get("kind") == "source_diff" and isinstance(diff, str)
            and isinstance(item.get("path"), str) and item["path"].strip()
            and re.search(r"(?m)^--- .+\r?\n\+\+\+ .+\r?$", diff)
            and re.search(r"(?m)^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", diff)
            and re.search(r"(?m)^[+-](?![+-])", diff)
        ):
            proposals.append(item)
    return proposals


def _changed_line(diff: str) -> int | None:
    line = None
    for text in diff.splitlines():
        if match := re.match(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@", text):
            line = int(match[1])
        elif line is not None:
            if text.startswith(("-", "+")):
                return max(1, line)
            if text.startswith(" "):
                line += 1
    return None


def _source_location(source: dict[str, Any], *, proposal: bool = False) -> None:
    path = str(source.get("path") or "Source path unavailable")
    ref = str(source.get("ref") or "")
    url = _safe_url(source.get("source_url"))
    # Do not substitute the CI definition, or label a different file as the source.
    if url and not unquote(urlsplit(url).path).endswith(f"/-/blob/{ref}/{path}"):
        url = None
    line = source.get("line_start")
    line = line if isinstance(line, int) and not isinstance(line, bool) and line > 0 else None
    end = source.get("line_end")
    end = end if isinstance(end, int) and not isinstance(end, bool) and line and end >= line else None
    if proposal:
        fragment = urlsplit(url).fragment if url else ""
        match = re.fullmatch(r"L([1-9]\d*)(?:-L?([1-9]\d*))?", fragment)
        line = int(match[1]) if match else _changed_line(str(source.get("diff") or ""))
        end = int(match[2]) if match and match[2] else None
    label = path
    if line:
        label += f" · lines {line}–{end}" if end and end != line else f" · line {line}"
        if url:
            parts = urlsplit(url)
            url = urlunsplit((parts.scheme, parts.netloc, parts.path, "", f"L{line}" + (f"-{end}" if end and end != line else "")))
    reference = f" · ref {_md(_brief(ref, 48))}" if ref else ""
    if url:
        st.markdown(f"[{_md(label)}](<{url}>){reference}")
    else:
        st.caption(_md(label) + reference)


def _render_source_block(remediation: dict[str, Any]) -> None:
    source = next((item for item in _objects(remediation.get("source_blocks")) if (
        isinstance(item.get("content"), str) and item["content"]
    )), None)
    if source is None:
        st.caption("Source context was not supplied; no file change was guessed.")
        return
    _source_location(source)
    content = source["content"]
    excerpt = "".join(content.splitlines(keepends=True)[:MAX_SOURCE_LINES])[:MAX_SOURCE_CHARS]
    language = source.get("language")
    language = language if isinstance(language, str) and language in _SOURCE_LANGUAGES else "text"
    _exact_code(excerpt, language=language)
    if len(excerpt) < len(content):
        st.caption("Exact source prefix shown: at most 80 lines / 8,000 characters. Open the source for the rest; no omitted code was reconstructed.")


def _deployment_summary_evidence(finding: dict[str, Any], remediation: dict[str, Any]) -> dict[str, Any] | None:
    # Only these artifact-backed rules replace the no-patch source preview.
    if finding.get("rule_id") not in (
        "rlp.datasync_field_mapping_connection_reset",
        "rlp.datasync_field_mapping_artifact_failure",
    ) or any(
        len(item["diff"]) <= MAX_DIFF_CHARS and len(item["diff"].splitlines()) <= MAX_DIFF_LINES
        for item in _source_proposals(remediation)
    ):
        return None
    return next((item for item in _objects(finding.get("evidence")) if (
        item.get("path") == "datasync/deploy-summary.json"
        and isinstance(item.get("text"), str) and item["text"].strip()
    )), None)


def _render_deployment_summary(evidence: dict[str, Any]) -> None:
    # Reflow the supplied counter groups, not artifact JSON or reconstructed code.
    # Redact the entire text before bounding it, including secrets across the cutoff.
    text = redact_text(evidence["text"])
    if text.startswith("DataSync deploy summary counters: "):
        text = text.removeprefix("DataSync deploy summary counters: ")
        text = re.sub(r"; (?=(?:field mappings|object mappings|value transformations): )", "\n", text)
        text = text.replace(". A bounded actual field-mapping failure", ".\nA bounded actual field-mapping failure", 1)
    excerpt = "".join(text.splitlines(keepends=True)[:MAX_SUMMARY_LINES])[:MAX_SUMMARY_CHARS]
    st.caption("Deployment summary · " + _md(evidence["path"]))
    st.code(excerpt, language="text", wrap_lines=True)
    if len(excerpt) < len(text):
        st.caption("Summary excerpt; more evidence is available in Evidence & details or the cited source.")
    _link("Deployment summary source", evidence.get("source_url"))


def _render_documentation(remediation: dict[str, Any], finding: dict[str, Any]) -> None:
    links = []
    seen: set[str] = set()
    for owner in (remediation, finding):
        entries = owner.get("documentation")
        for item in entries if isinstance(entries, list) else []:
            url = _documentation_url(item.get("url") if isinstance(item, dict) else item)
            if not url or url in seen:
                continue
            seen.add(url)
            host = urlsplit(url).hostname
            label = _brief(item.get("title"), 90) if isinstance(item, dict) else ""
            links.append(f"[{_md(label or _DOC_HOSTS.get(host or '', 'Documentation'))}](<{url}>)")
            if len(links) == 3:
                break
        if len(links) == 3:
            break
    if links:
        st.markdown(" · ".join(links))


def _recommended_actions(finding: dict[str, Any], remediation: dict[str, Any]) -> list[str]:
    fixes = _text_items(finding.get("fix"))
    actions = _text_items(remediation.get("actions"))
    generic = re.compile(r"(?:review|inspect|read|check) (?:the )?(?:logs?|evidence|diagnostics?|job logs?|source|source access)[.!]?", re.I)
    for candidates in (fixes, actions):
        specific = [item for item in candidates if not generic.fullmatch(item)]
        if specific:
            return specific
    return fixes or actions


def _render_answer(finding: dict[str, Any], remediation: dict[str, Any]) -> None:
    explanation = finding.get("explanation") or remediation.get("summary") or "The available evidence did not establish a cause or a specific correction."
    summary = re.split(r"\bObserved:\s*", str(explanation), maxsplit=1, flags=re.I)[0].strip()
    st.markdown(_md(_brief(summary or remediation.get("summary") or "A cause has not been established.")))
    _render_confidence(remediation)
    proposals = _source_proposals(remediation)
    bounded = [item for item in proposals if len(item["diff"]) <= MAX_DIFF_CHARS and len(item["diff"].splitlines()) <= MAX_DIFF_LINES]
    summary_evidence = _deployment_summary_evidence(finding, remediation)
    if summary_evidence:
        _render_deployment_summary(summary_evidence)
    for proposal in bounded[:MAX_PROPOSALS]:
        title = _brief(proposal.get("title"), 160)
        if title:
            st.markdown("**" + _md(title) + "**")
        _source_location(proposal, proposal=True)
        condition = _brief(proposal.get("condition"), 320)
        st.caption(_md(condition or "Conditional suggestion; confirm the intended behavior before changing source."))
        _exact_code(proposal["diff"], language="diff")
        verification = _text_items(proposal.get("verification"))
        if verification:
            st.markdown("**Verify**")
            _numbered_steps(verification)
        else:
            st.caption("No proposal-specific verification steps were supplied.")
    if bounded:
        st.caption("Review only · not applied or target-verified.")
    else:
        st.markdown("**No verified source patch**" if not proposals else "**No verified source patch shown**")
        actions = _recommended_actions(finding, remediation)
        if actions:
            _numbered_steps(actions)
        else:
            st.caption("Obtain the missing diagnostic before choosing a correction.")
    if len(bounded) > MAX_PROPOSALS:
        st.caption(f"Showing {MAX_PROPOSALS} of {len(bounded)} source proposals.")
    if len(proposals) > len(bounded):
        st.caption("An oversized source patch was not shown: the limit is 16,000 characters / 240 lines. No truncated or reconstructed diff is presented.")
    fix_confidence = _confidence(remediation, "fix_confidence")
    if not bounded or fix_confidence is None or fix_confidence < LOW_FIX_CONFIDENCE:
        _render_documentation(remediation, finding)
        if not summary_evidence:
            _render_source_block(remediation)


def _render_remediation_details(remediation: dict[str, Any], finding: dict[str, Any], result: dict[str, Any]) -> None:
    st.caption(SCORE_LABEL + ". No target verification; source applicability does not prove a resolution.")
    for basis in _text_items(remediation.get("confidence_basis"))[:12]:
        st.markdown("- " + _md(_brief(basis, 800)))
    missing = _text_items(remediation.get("missing_information"))
    if missing:
        st.markdown("**Missing information**")
        for item in missing[:10]:
            st.markdown("- " + _md(_brief(item, 800)))
    matches = result.get("corpus_matches")
    match = (matches.get(finding.get("rule_id")) if isinstance(matches, dict)
             and _root_finding(result, finding) else None)
    if isinstance(match, dict):
        counts = [match.get("seen_failed_pipelines"), match.get("failed_jobs")]
        if all(isinstance(count, int) and not isinstance(count, bool) and count >= 0 for count in counts):
            st.caption(f"Local history: {counts[0]} failed pipelines · {counts[1]} failed jobs with this rule. Occurrence counts, not verified fixes or calibrated confidence.")
    for proposal in _source_proposals(remediation)[:MAX_PROPOSALS]:
        if proposal.get("rationale"):
            st.markdown("**" + _md(_brief(proposal.get("title") or proposal.get("path"), 160)) + "**")
            st.markdown(_md(_brief(proposal["rationale"], 1200)))
        _numbered_steps(_text_items(proposal.get("verification"))[3:], start=4, limit=10)
    _render_documentation(remediation, finding)
    if _deployment_summary_evidence(finding, remediation) and any(
        isinstance(item.get("content"), str) and item["content"]
        for item in _objects(remediation.get("source_blocks"))
    ):
        _render_source_block(remediation)


def _render_outcome(result: dict[str, Any]) -> None:
    pipeline = result.get("pipeline") or {}
    outcome = _outcome(pipeline)
    status = result["status"]
    if status == "configuration_only":
        message = "Configuration only · no pipeline run. Static checks are not runtime evidence."
    elif outcome in _SUCCESS and status == "passed":
        message = "Pipeline passed · no failure observed in sampled evidence."
    elif outcome in _SUCCESS:
        allowed = [job for job in _objects(result.get("jobs")) if _outcome(job) in _FAILED and job.get("allow_failure")]
        message = "Pipeline passed · " + (f"{len(allowed)} allowed failure(s), allow_failure=true." if allowed else "inspection warning.")
    elif outcome in _FAILED:
        message = f"Pipeline {outcome}."
    elif status == "in_progress":
        message = f"Pipeline {outcome} · no final outcome yet."
    else:
        message = f"Pipeline {outcome} · status alone does not establish a cause."
    selected = result.get("selected_job")
    if isinstance(selected, dict):
        message += f" Selected job {selected.get('name', '')}: {_outcome(selected)}; parent findings are separate."
    st.caption(_md(message))


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
    explanation = str(finding.get("explanation") or "No cause was established from the available evidence.")
    # The diagnostic's verbatim quote is shown once below, not repeated in its prose.
    summary = explanation.partition(" Observed: ")[0]
    st.markdown("**What happened**")
    st.markdown(_md(summary))
    st.markdown("**Recommended fix**")
    fixes = finding.get("fix") or []
    if not fixes:
        st.write("Obtain the missing diagnostic before choosing a fix; do not change CI execution policy from status alone.")
    _numbered_steps(fixes)
    evidence = _objects(finding.get("evidence"))
    if evidence:
        st.markdown("**Evidence**")
        _evidence(evidence[0])
        # Keep the short quote singular, but surface the authoritative source-file link too.
        for item in evidence[1:3]:
            if item.get("path"):
                _link(str(item["path"]) + (f" · line {item['line']}" if item.get("line") else ""), item.get("source_url"))
    if finding.get("job_id"):
        analysis = next((item for item in _objects(result.get("analyses")) if str(item.get("job", {}).get("external_id")) == str(finding["job_id"])), {})
        source = analysis.get("job_source") or {}
        if source.get("source_url"):
            label = f"CI definition · {display_include_path(source['path'])} · lines {source.get('line_start')}–{source.get('line_end')}"
            _link(label, source["source_url"])


def _finding_details(finding: dict[str, Any]) -> None:
    with st.expander("More evidence, safe steps & references", expanded=False):
        st.caption(_md(f"Rule: {finding.get('rule_id', 'unknown')} · Category: {finding.get('category', 'unknown')}"))
        st.write(_md(finding.get("explanation") or "No additional explanation supplied."))
        _numbered_steps(_text_items(finding.get("fix"))[3:], start=4, limit=10)
        for item in _objects(finding.get("evidence")):
            _evidence(item, short=False)
        _render_documentation({}, finding)


def _render_summary(result: dict[str, Any]) -> None:
    repository = result["repository"]
    pipeline = result.get("pipeline") or {}
    parts = [f"{repository.get('owner', '')}/{repository.get('name', '')}"]
    if pipeline.get("external_id"):
        parts.append(f"Pipeline #{pipeline['external_id']}")
    if pipeline.get("ref_name"):
        parts.append(pipeline["ref_name"])
    freshness = f"Cached · {result.get('cache_age_seconds', 0)}s old" if result.get("cached") else "Fresh"
    parts.extend([freshness, f"{result.get('elapsed_ms', 0) / 1000:.1f}s"])
    st.caption(_md(" · ".join(parts)))


def _render_scope_details(result: dict[str, Any]) -> None:
    repository = result["repository"]
    pipeline = result.get("pipeline") or {}
    with st.expander("Inspection details", expanded=False):
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
    additional = [finding for finding in findings[1:] if finding.get("rule_id") != "pipeline.failed"]
    with st.expander("Additional evidence & context", expanded=False):
        if not additional:
            st.caption("No additional findings were returned in this bounded inspection.")
        for finding in additional:
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
    # Root-project notes must never claim a correction confirmed for a child repo.
    findings = [finding for finding in findings if _root_finding(result, finding)]
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


def _render_retention(result: dict[str, Any]) -> None:
    requested = result.get("_remember_analysis_requested")
    saved = result.get("knowledge_saved")
    if requested is False:
        if saved is True:
            st.warning("The API reports diagnostic notes were saved despite opting out. Update the local API before analyzing again; the UI cannot undo that retention.")
        elif saved is False:
            st.caption("No diagnostic notes saved for this analysis.")
        else:
            st.warning("Note saving was turned off, but the API did not confirm whether notes were retained.")


def _render_cloud_assist(result: dict[str, Any]) -> None:
    assist = result.get("cloud_assist")
    summary = assist.get("summary") if isinstance(assist, dict) else None
    if not isinstance(summary, str) or not summary.strip():
        return
    provider = assist.get("provider")
    label = _brief(provider, 40).title() if isinstance(provider, str) and provider.strip() else "cloud"
    st.markdown(f"**Cloud assist ({_md(label)}) \u00b7 optional, unverified**")
    notice = assist.get("notice") if isinstance(assist.get("notice"), str) else "Unverified cloud opinion; separate from the local diagnosis. Review independently."
    st.caption(_md(_brief(notice, 260)))
    st.write(_md(_brief(summary, 1200)))


def run() -> None:
    st.set_page_config(page_title="PipelineLens", page_icon="PL", layout="wide", initial_sidebar_state="collapsed")
    _initialize_state()
    _render_styles()
    st.title("PipelineLens")
    st.caption("Find the cause. See the fix. Local rules by default · optional cloud assist stays off unless you turn it on.")
    status = _local_status()
    _render_input(status)
    result = st.session_state.inspection_result
    findings = _ordered_findings(result) if result else []
    if result is not None:
        primary = _select_finding(result, findings)
        remediation = _remediation_for(result, primary)
        st.subheader(_md(_brief(primary.get("title") or "No causal finding established", 200)))
        _render_outcome(result)
        _render_answer(primary, remediation)
        _render_cloud_assist(result)
        _render_retention(result)
        with st.expander("Evidence & details", expanded=False):
            _render_summary(result)
            _render_remediation_details(remediation, primary, result)
            ordered = [primary] + [item for item in findings if item is not primary] if primary else findings
            _render_diagnosis_details(result, ordered)
            _render_scope_details(result)
            _render_pipeline_context(result)
            _render_sources(result)
            with st.expander("Local settings & history", expanded=False):
                _render_memory(status, result, findings)
    else:
        with st.expander("Settings", expanded=False):
            _render_memory(status, None, [])


if __name__ == "__main__":
    run()
