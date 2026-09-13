"""Bounded, non-evaluating GitLab include discovery and stable logical loader keys."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import parse_qs, quote, unquote, urlsplit

from pipelinelens.services.pipeline_url import (
    GitLabReference,
    PipelineUrlError,
    parse_gitlab_url,
)

_PROJECT_INCLUDE_SCHEME = "pipelinelens-gitlab-project"
_UNSAFE_CHARACTERS = re.compile(r"[\x00-\x1f\x7f\\%]")
_DYNAMIC_CHARACTERS = re.compile(r"[$*?\[]")


@dataclass(frozen=True, slots=True)
class ProjectIncludeReference:
    project_path: str
    file_path: str
    ref: str


@dataclass(frozen=True, slots=True)
class GitLabIncludeReference:
    key: str
    kind: Literal["local", "project", "remote"]
    file_path: str | None = None
    project_path: str | None = None
    ref: str | None = None


def normalize_local_path(value: str) -> str | None:
    """Accept a concrete repository-root path, never a glob, variable, URL or traversal."""

    if (
        not value
        or len(value) > 4096
        or value.startswith("//")
        or ":" in value
        or _UNSAFE_CHARACTERS.search(value)
        or _DYNAMIC_CHARACTERS.search(value)
    ):
        return None
    value = value.removeprefix("/")
    while value.startswith("./"):
        value = value[2:]
    if any(part in {"", ".", ".."} for part in value.split("/")):
        return None
    return value


def is_concrete_ref(value: str) -> bool:
    return bool(
        value
        and len(value) <= 1024
        and not _UNSAFE_CHARACTERS.search(value)
        and not _DYNAMIC_CHARACTERS.search(value)
        and not re.search(r"[\s~^:@]", value)
        and ".." not in value
        and not value.endswith((".", ".lock"))
        and all(part not in {"", ".", ".."} for part in value.split("/"))
    )


def is_project_path(value: str) -> bool:
    parts = value.split("/")
    return len(parts) >= 2 and all(
        part not in {"", ".", ".."} and re.fullmatch(r"[A-Za-z0-9_.-]+", part)
        for part in parts
    )


def project_include_key(project_path: str, file_path: str, ref: str) -> str:
    """Create an unambiguous internal key for a file included from another GitLab project."""

    return (
        f"{_PROJECT_INCLUDE_SCHEME}://{quote(project_path, safe='')}"
        f"?ref={quote(ref, safe='')}&file={quote(file_path, safe='')}"
    )


def parse_project_include_key(value: str) -> ProjectIncludeReference | None:
    try:
        parsed = urlsplit(value)
        if parsed.scheme != _PROJECT_INCLUDE_SCHEME:
            return None
        query = parse_qs(parsed.query, strict_parsing=True, max_num_fields=2)
    except ValueError:
        return None
    if set(query) != {"ref", "file"} or any(len(items) != 1 for items in query.values()):
        return None
    ref = query.get("ref", [""])[0]
    file_path = query.get("file", [""])[0]
    project_path = unquote(parsed.netloc)
    if (
        parsed.path
        or parsed.fragment
        or not is_project_path(project_path)
        or not is_concrete_ref(ref)
        or normalize_local_path(file_path) != file_path
    ):
        return None
    return ProjectIncludeReference(
        project_path=project_path,
        file_path=file_path,
        ref=ref,
    )


def parse_remote_include_key(value: str) -> GitLabReference | None:
    """Recognize a safe GitLab-shaped blob/raw URL; host authorization is provider-only."""

    try:
        reference = parse_gitlab_url(value)
    except PipelineUrlError:
        return None
    if reference.kind != "branch" or not reference.file_path or not reference.ref:
        return None
    if not is_concrete_ref(reference.ref) or not normalize_local_path(reference.file_path):
        return None
    return reference


def display_include_path(value: str) -> str:
    """Convert an internal include key into a path suitable for source captions."""

    reference = parse_project_include_key(value)
    if reference is None:
        return value
    return f"{reference.project_path}/{reference.file_path} @ {reference.ref}"


def resolve_local_include(current_path: str, local_path: str) -> str | None:
    """Local paths are rooted at the *containing repository*, not the including directory."""

    resolved = normalize_local_path(local_path)
    if resolved is None:
        return None
    project_reference = parse_project_include_key(current_path)
    if project_reference:
        return project_include_key(
            project_reference.project_path,
            resolved,
            project_reference.ref,
        )
    remote_reference = parse_remote_include_key(current_path)
    if remote_reference is not None:
        return project_include_key(
            remote_reference.project_path, resolved, remote_reference.ref or "HEAD"
        )
    return resolved


def _file_paths(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            # Invalid entries still consume the caller's scan budget.
            yield item if isinstance(item, str) else ""


def collect_gitlab_includes(
    value: Any, current_path: str, *, max_includes: int = 120
) -> tuple[list[GitLabIncludeReference], list[str]]:
    """Inspect declarations, not effective config: rules/inputs/variables are never evaluated.

    Iterators and a scan budget bound huge lists, nested arrays and recursive YAML aliases
    before any project resolution or network work can be scheduled. Messages intentionally
    do not echo arbitrary YAML values or possibly credential-bearing remote URLs.
    """

    references: list[GitLabIncludeReference] = []
    unresolved: list[str] = []
    limit = max(0, min(max_includes, 400))
    stack = [iter(value if isinstance(value, list) else [value])]
    scanned = 0

    def note(message: str) -> None:
        if message not in unresolved:
            unresolved.append(message)

    while stack:
        item = next(stack[-1], _END)
        if item is _END:
            stack.pop()
            continue
        scanned += 1
        if scanned > limit or len(references) >= limit:
            note("Include declarations truncated at the inspection safety limit.")
            break
        if str(getattr(item, "tag", "")) == "!reference":
            note("An include uses !reference; its declarations cannot be determined statically.")
            continue
        if isinstance(item, list):
            if len(stack) >= 10:
                note("Nested or recursive include arrays truncated at the inspection safety limit.")
            else:
                stack.append(iter(item))
            continue
        if isinstance(item, str):
            item = {"remote": item} if "://" in item or item.startswith("//") else {"local": item}
        if not isinstance(item, Mapping):
            if item is not None:
                note("Unsupported GitLab include declaration.")
            continue
        if "rules" in item:
            note(
                "Rules-bearing includes are potential includes; rule variables were not evaluated."
            )
        if "inputs" in item:
            note("Include inputs were not evaluated; parameterized configuration may differ.")
        if "local" in item:
            paths = _file_paths(item["local"])
            kind: Literal["local", "project", "remote"] = "local"
            project_path, ref = None, None
        elif "project" in item and "file" in item:
            project_path = item["project"]
            ref = item.get("ref") or "HEAD"
            if (
                not isinstance(project_path, str)
                or not is_project_path(project_path)
                or not isinstance(ref, str)
                or not is_concrete_ref(ref)
            ):
                note("Project include path/ref is unsafe or uses unknown variables.")
                continue
            paths, kind = _file_paths(item["file"]), "project"
        elif "remote" in item:
            remote = item["remote"]
            if not isinstance(remote, str) or parse_remote_include_key(remote) is None:
                note("Remote include is external, unsafe or not a supported GitLab raw/blob URL.")
            else:
                references.append(GitLabIncludeReference(key=remote, kind="remote"))
            continue
        elif "template" in item:
            note("Template include is unresolved; GitLab server templates were not fetched.")
            continue
        elif "component" in item:
            note("Component include is unresolved; component inputs were not evaluated.")
            continue
        else:
            note("Unsupported GitLab include declaration.")
            continue
        found = False
        for index, raw_path in enumerate(paths):
            found = True
            if index >= limit or len(references) >= limit:
                note("Include declarations truncated at the inspection safety limit.")
                break
            path = normalize_local_path(raw_path)
            if path is None:
                note("Include file path is unsafe, a glob, or uses unknown variables/inputs.")
                continue
            key = (
                project_include_key(project_path, path, ref)
                if kind == "project" and project_path is not None and ref is not None
                else resolve_local_include(current_path, path)
            )
            if key is not None:
                references.append(GitLabIncludeReference(key, kind, path, project_path, ref))
        if not found:
            note("Include file declaration has no supported concrete paths.")
    return references, unresolved


_END = object()


def gitlab_include_keys(value: Any, current_path: str) -> tuple[list[str], list[str]]:
    """Backward-compatible key-only view, shared by the provider and graph loader."""

    references, unresolved = collect_gitlab_includes(value, current_path)
    return [reference.key for reference in references], unresolved