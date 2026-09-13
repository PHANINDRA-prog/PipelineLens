"""Network-free, credential-free parsing of GitLab inspection URLs."""

from __future__ import annotations

import re
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Literal
from urllib.parse import SplitResult, parse_qsl, unquote, urlsplit

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x20\x7f]")
_PROJECT_SEGMENT = re.compile(r"[A-Za-z0-9_.-]+")
_POSITIVE_ID = re.compile(r"[1-9][0-9]*")


class PipelineUrlError(ValueError):
    """Raised when a pasted URL is not a safe, supported GitLab URL."""


@dataclass(frozen=True, slots=True)
class GitLabReference:
    base_url: str
    project_path: str
    kind: Literal["pipeline", "job", "branch", "repository"]
    pipeline_id: str | None = None
    job_id: str | None = None
    ref: str | None = None
    file_path: str | None = None


@dataclass(frozen=True, slots=True)
class GitLabPipelineReference:
    """The original pipeline-only return type, retained for existing callers."""

    base_url: str
    project_path: str
    pipeline_id: str


def _split_url(value: str) -> tuple[SplitResult, str]:
    if not isinstance(value, str) or len(value) > 8192:
        raise PipelineUrlError("Enter a complete GitLab URL beginning with https://.")
    value = value.strip(" ")
    if _CONTROL_CHARACTERS.search(value) or "\\" in value:
        raise PipelineUrlError("GitLab URLs cannot contain whitespace or backslashes.")
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise PipelineUrlError("The GitLab URL has an invalid host or port.") from None
    if parsed.scheme not in {"http", "https"} or not host:
        raise PipelineUrlError("Enter a complete GitLab URL beginning with https://.")
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise PipelineUrlError("GitLab URLs must not contain credentials.")
    if "%" in parsed.netloc or parsed.netloc.endswith(":") or port == 0:
        raise PipelineUrlError("The GitLab URL has an invalid host or port.")
    try:
        host = host.encode("idna").decode("ascii").lower().removesuffix(".")
        address = ip_address(host)
    except ValueError:
        if not host or len(host) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in host.split(".")
        ):
            raise PipelineUrlError("The GitLab URL has an invalid host.") from None
        authority = host
    else:
        host = address.compressed
        authority = f"[{host}]" if address.version == 6 else host
    if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        raise PipelineUrlError("GitLab URLs must use HTTPS (except explicit localhost tests).")
    if port is not None and port != (443 if parsed.scheme == "https" else 80):
        authority = f"{authority}:{port}"
    if parsed.fragment:
        raise PipelineUrlError("Remove fragments and secrets from the GitLab URL.")
    try:
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise PipelineUrlError("The GitLab URL query is not supported.") from None
    # An allowlist is safer than trying to enumerate every possible secret parameter name.
    allowed = {"ref_type": {"heads", "tags"}, "inline": {"true", "false"}}
    if len({key for key, _ in query}) != len(query) or any(
        key not in allowed or item not in allowed[key] for key, item in query
    ):
        raise PipelineUrlError("Remove query tokens or unsupported parameters from the GitLab URL.")
    return parsed, f"{parsed.scheme}://{authority}"


def _origin(value: str) -> str:
    """Normalize a configured origin, also accepting GitLab's API-base suffix."""

    parsed, origin = _split_url(value)
    if parsed.path.rstrip("/") not in {"", "/api/v4"} or parsed.query:
        raise PipelineUrlError("Configure a GitLab server origin, not a project or file URL.")
    return origin


def _decoded_path(path: str) -> str:
    try:
        decoded = unquote(path, errors="strict")
    except UnicodeError:
        raise PipelineUrlError("The GitLab URL path has invalid encoding.") from None
    if (
        not decoded.startswith("/")
        or "%" in decoded
        or "\\" in decoded
        or _CONTROL_CHARACTERS.search(decoded)
        or any(part in {"", ".", ".."} for part in decoded.strip("/").split("/"))
        or "//" in decoded
    ):
        raise PipelineUrlError("The GitLab URL path is invalid or contains traversal.")
    return decoded.rstrip("/")


def parse_gitlab_url(
    value: str,
    expected_base_url: str | None = None,
) -> GitLabReference:
    """Parse a pipeline, job, tree, blob/raw file, or repository URL without I/O.

    Tree URLs preserve the entire ref/directory tail. For blob/raw URLs the last
    component is provisionally the file, so slash refs with a root CI file work
    directly. A ref containing directories is inherently ambiguous in GitLab web
    URLs: the provider's ``resolve_reference`` checks longest existing ref prefixes
    before using such a reference. No branch existence is inferred by this parser.
    """

    parsed, base_url = _split_url(value)
    if expected_base_url and base_url != _origin(expected_base_url):
        raise PipelineUrlError(
            "This URL belongs to a different GitLab server than the configured token."
        )
    path = _decoded_path(parsed.path)
    project, separator, resource = path[1:].partition("/-/")
    if not separator:
        project = project.removesuffix(".git")
    parts = project.split("/")
    if len(parts) < 2 or any(
        part in {"", ".", ".."} or not _PROJECT_SEGMENT.fullmatch(part) for part in parts
    ):
        raise PipelineUrlError("The GitLab project path in the URL is invalid.")
    if not separator:
        if parsed.query:
            raise PipelineUrlError("Repository URLs cannot contain query parameters.")
        return GitLabReference(base_url, project, "repository")
    action, _, tail = resource.partition("/")
    if action in {"pipelines", "jobs"} and _POSITIVE_ID.fullmatch(tail):
        if parsed.query:
            raise PipelineUrlError("Pipeline and job URLs cannot contain query parameters.")
        if action == "pipelines":
            return GitLabReference(base_url, project, "pipeline", pipeline_id=tail)
        return GitLabReference(base_url, project, "job", job_id=tail)
    if action == "tree" and tail:
        return GitLabReference(base_url, project, "branch", ref=tail)
    if action in {"blob", "raw"} and "/" in tail:
        ref, _, file_path = tail.rpartition("/")
        return GitLabReference(base_url, project, "branch", ref=ref, file_path=file_path)
    raise PipelineUrlError("Enter a GitLab pipeline, job, branch, CI file, or repository URL.")


def parse_gitlab_pipeline_url(
    pipeline_url: str,
    *,
    expected_base_url: str | None = None,
) -> GitLabPipelineReference:
    """Backward-compatible pipeline-only wrapper around :func:`parse_gitlab_url`."""

    reference = parse_gitlab_url(pipeline_url, expected_base_url)
    if reference.kind != "pipeline" or reference.pipeline_id is None:
        raise PipelineUrlError(
            "Enter a GitLab pipeline URL in the form "
            "https://gitlab.example/group/project/-/pipelines/123."
        )
    return GitLabPipelineReference(
        base_url=reference.base_url,
        project_path=reference.project_path,
        pipeline_id=reference.pipeline_id,
    )