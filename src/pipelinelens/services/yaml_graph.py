"""Source-aware parsers for GitHub Actions and GitLab CI configuration."""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from ruamel.yaml import YAML, YAMLError

from pipelinelens.domain import (
    CiConfigFile,
    JobSourceLocation,
    PipelineGraph,
    PipelineJob,
    PipelineNode,
    ProviderName,
)
from pipelinelens.services.gitlab_includes import display_include_path, gitlab_include_keys


class CiConfigParseError(ValueError):
    """Raised when PipelineLens cannot parse a selected CI configuration file."""


_GITLAB_RESERVED_KEYS = {
    "default",
    "spec",
    "image",
    "include",
    "services",
    "stages",
    "variables",
    "workflow",
    "cache",
    "before_script",
    "after_script",
}
_MAX_CONFIGS = 100
_MAX_INCLUDE_EDGES = 400
_MAX_YAML_CHARACTERS = 1_000_000


@dataclass(frozen=True, slots=True)
class ParsedConfig:
    path: str
    content: str
    document: Mapping[str, Any]


def _parse_yaml_documents(path: str, content: str) -> list[Mapping[str, Any]]:
    if len(content) > _MAX_YAML_CHARACTERS:
        raise CiConfigParseError(f"Unable to parse {path}: source-size safety limit exceeded.")
    parser = YAML(typ="rt")
    parser.version = (1, 2)
    try:
        documents = []
        for index, document in enumerate(parser.load_all(content)):
            if index >= 20:
                raise CiConfigParseError(f"Unable to parse {path}: document safety limit exceeded.")
            if document is not None:
                documents.append(document)
    except (YAMLError, RecursionError, ValueError, TypeError):
        # Parser diagnostics can contain raw YAML values, so do not expose their payload.
        raise CiConfigParseError(f"Unable to parse {path}: invalid or unsupported YAML.") from None
    if not documents:
        return [{}]
    if not all(isinstance(document, Mapping) for document in documents):
        raise CiConfigParseError(f"Unable to parse {path}: each document root must be a mapping.")
    return documents


def _parse_yaml(path: str, content: str) -> Mapping[str, Any]:
    documents = _parse_yaml_documents(path, content)
    if len(documents) != 1:
        raise CiConfigParseError(
            f"Unable to parse {path}: GitHub workflows must use one YAML document."
        )
    return documents[0]


def _as_strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        candidate = value.get("job") or value.get("pipeline") or value.get("name")
        return [str(candidate)] if isinstance(candidate, (str, int, float)) else []
    if isinstance(value, list):
        output: list[str] = []
        for item in value[:100]:
            if isinstance(item, Mapping):
                candidate = item.get("job") or item.get("pipeline") or item.get("name")
                if isinstance(candidate, (str, int, float)):
                    output.append(str(candidate))
            elif isinstance(item, (str, int, float)):
                output.append(str(item))
        return output
    return [str(value)]


def _rules(value: Any, depth: int = 0, seen: set[int] | None = None) -> list[str]:
    if value is None or depth > 10:
        return []
    if isinstance(value, str):
        return [value]
    seen = set() if seen is None else seen
    if isinstance(value, (list, Mapping)):
        if id(value) in seen or len(seen) >= 100:
            return ["Recursive/oversized rule values omitted."]
        seen.add(id(value))
    if isinstance(value, Mapping):
        return [", ".join(
            f"{key}: {item}" if isinstance(item, (str, int, float, bool))
            else f"{key}: [structured rule]"
            for key, item in value.items()
        )]
    if isinstance(value, list):
        rendered: list[str] = []
        for item in value[:100]:
            rendered.extend(_rules(item, depth + 1, seen))
        return rendered
    return [str(value)]


def _line_for_key(document: Mapping[str, Any], key: str, fallback: int = 1) -> int:
    location = getattr(document, "lc", None)
    if location is None:
        return fallback
    try:
        key_location = location.key(key)
    except (KeyError, TypeError):
        return fallback
    if isinstance(key_location, tuple):
        return int(key_location[0]) + 1
    if isinstance(key_location, int):
        return key_location + 1
    return fallback


def _top_level_ranges(document: Mapping[str, Any], line_count: int) -> dict[str, tuple[int, int]]:
    keyed_lines = sorted((_line_for_key(document, str(key)), str(key)) for key in document)
    ranges: dict[str, tuple[int, int]] = {}
    for index, (start, key) in enumerate(keyed_lines):
        end = keyed_lines[index + 1][0] - 1 if index + 1 < len(keyed_lines) else line_count
        ranges[key] = (start, max(start, end))
    return ranges


def _artifact_paths(value: Any) -> list[str]:
    if not isinstance(value, Mapping):
        return []
    paths = _as_strings(value.get("paths"))
    reports = value.get("reports")
    if isinstance(reports, Mapping):
        paths.extend(f"report:{key}" for key in reports)
    return paths


def _node(
    *,
    path: str,
    key: str,
    job: Mapping[str, Any],
    line_start: int,
    line_end: int,
    provider: ProviderName,
) -> PipelineNode:
    if provider == ProviderName.GITHUB:
        steps = []
        for step in job.get("steps") or []:
            if not isinstance(step, Mapping):
                continue
            label = str(step.get("name") or step.get("uses") or step.get("run") or "unnamed step")
            action = step.get("run") or step.get("uses")
            steps.append(f"{label}: {action}" if action and action != label else label)
        needs = _as_strings(job.get("needs"))
        rules = _rules(job.get("if"))
        artifacts = [step for step in steps if "artifact" in step.lower()]
        stage = "workflow"
        script = [
            str(step.get("run"))
            for step in job.get("steps") or []
            if isinstance(step, Mapping) and step.get("run")
        ]
    else:
        steps = []
        needs = _as_strings(job.get("needs"))
        rules = _rules(job.get("rules"))
        artifacts = _artifact_paths(job.get("artifacts"))
        stage = str(job.get("stage") or "test")
        script = _as_strings(job.get("script"))

    inherited = _as_strings(job.get("extends"))
    source = JobSourceLocation(
        path=path,
        line_start=line_start,
        line_end=line_end,
        job_key=key,
        inherited_from=", ".join(inherited) if inherited else None,
        match_confidence=1.0,
    )
    return PipelineNode(
        key=key,
        display_name=str(job.get("name") or key),
        stage=stage,
        needs=needs,
        dependencies=_as_strings(job.get("dependencies")),
        rules=rules,
        script=script,
        steps=steps,
        artifacts=artifacts,
        source=source,
    )


def _normalize_job_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def match_job_to_graph(job: PipelineJob, graph: PipelineGraph) -> JobSourceLocation | None:
    """Return a high-confidence YAML job location for provider job metadata."""

    candidates = {candidate for candidate in (job.key, job.name) if candidate}
    exact = [node for node in graph.nodes if candidates & {node.key, node.display_name}]
    if len(exact) == 1:
        return exact[0].source.model_copy(update={"match_confidence": 1.0})
    if exact:
        return None

    # GitLab expands numeric parallel jobs as "job 1/3" and matrix jobs as
    # "job: [value, value]". Do not strip arbitrary suffixes or take a fuzzy prefix.
    expanded: set[str] = set()
    for candidate in candidates:
        numbered = re.fullmatch(r"(.+) ([1-9][0-9]{0,8})/([1-9][0-9]{0,8})", candidate)
        if numbered and int(numbered[2]) <= int(numbered[3]):
            expanded.add(numbered[1])
        matrix = re.fullmatch(r"(.+): \[[^\[\]\r\n]+\]", candidate)
        if matrix:
            expanded.add(matrix[1])
    matches = [node for node in graph.nodes if node.key in expanded]
    if graph.provider == ProviderName.GITLAB and len(matches) == 1:
        return matches[0].source.model_copy(update={"match_confidence": 0.9})
    if graph.provider == ProviderName.GITLAB and any(
        re.search(r"[:\[\]/]", candidate) for candidate in candidates
    ):
        # Malformed expansions must not become exact names after removing punctuation.
        return None

    normalized_candidates = {
        _normalize_job_name(candidate) for candidate in candidates
    }
    normalized = [
        node for node in graph.nodes
        if normalized_candidates & {
            _normalize_job_name(node.key), _normalize_job_name(node.display_name)
        }
    ]
    if len(normalized) == 1:
        return normalized[0].source.model_copy(update={"match_confidence": 0.95})
    return None


def _gitlab_include_paths(value: Any, current_path: str) -> tuple[list[str], list[str]]:
    return gitlab_include_keys(value, current_path)


def analyze_gitlab_yaml(
    config: CiConfigFile,
    include_loader: Callable[[str], str | None] | None = None,
) -> PipelineGraph:
    """Build a bounded declared graph, not GitLab's evaluated historical configuration.

    Included files merge before the including file, later includes win, and mappings
    deep-merge while arrays/scalars replace. Job source points to the effective script
    declaration (including hidden templates), not an unrelated shadow declaration.
    """

    parsed_configs: list[ParsedConfig] = []
    unresolved: list[str] = []
    documents_by_path: dict[str, list[Mapping[str, Any]]] = {}
    contents: dict[str, str] = {config.path: config.content}
    config_paths: list[str] = []
    display_order: list[str] = []
    active: set[str] = set()
    unavailable: set[str] = set()
    edge_count = 0

    def note(message: str) -> None:
        if message not in unresolved and len(unresolved) < _MAX_INCLUDE_EDGES:
            unresolved.append(message)

    def visit(path: str, depth: int = 0) -> None:
        nonlocal edge_count
        if path in active:
            note(f"include cycle ignored: {display_include_path(path)}")
            return
        if depth > 20 or len(parsed_configs) >= _MAX_INCLUDE_EDGES:
            note("Include traversal truncated at the graph safety limit.")
            return
        if path not in documents_by_path:
            if len(documents_by_path) >= _MAX_CONFIGS:
                note("CI source parsing truncated at the graph safety limit.")
                return
            try:
                documents_by_path[path] = _parse_yaml_documents(path, contents[path])
            except CiConfigParseError:
                note(f"Invalid YAML; source could not be analyzed: {display_include_path(path)}")
                documents_by_path[path] = []
        if path not in config_paths:
            config_paths.append(path)
        documents = documents_by_path[path]
        active.add(path)
        include_paths: list[str] = []
        for document in documents:
            for key, value in document.items():
                if isinstance(value, Mapping) and str(key) not in display_order:
                    display_order.append(str(key))
            document_paths, unsupported = _gitlab_include_paths(document.get("include"), path)
            include_paths.extend(document_paths)
            for issue in unsupported:
                note(issue)
        for include_path in include_paths:
            edge_count += 1
            if edge_count > _MAX_INCLUDE_EDGES:
                note("Include edges truncated at the graph safety limit.")
                break
            if include_path not in contents and include_path not in unavailable:
                if include_loader is None:
                    unavailable.add(include_path)
                    note(f"include not loaded: {display_include_path(include_path)}")
                else:
                    try:
                        included_content = include_loader(include_path)
                    except (OSError, ValueError, RuntimeError):
                        included_content = None
                    if not isinstance(included_content, str):
                        unavailable.add(include_path)
                        note(f"include unavailable: {display_include_path(include_path)}")
                    else:
                        contents[include_path] = included_content
            if include_path in contents:
                visit(include_path, depth + 1)
        active.remove(path)
        # Repeated, non-cyclic includes participate in order again. Their contents
        # were read/parsed once, but their later precedence must not be discarded.
        parsed_configs.extend(
            ParsedConfig(path=path, content=contents[path], document=document)
            for document in documents
        )

    visit(config.path)
    merged: dict[str, Any] = {}
    origins: dict[str, tuple[str, int, int]] = {}
    field_origins: dict[str, dict[str, tuple[str, int, int]]] = {}
    merge_visits = 0
    script_visits = 0

    def merge(
        base: Mapping[str, Any], override: Mapping[str, Any], depth: int = 0
    ) -> dict[str, Any]:
        nonlocal merge_visits
        merge_visits += 1
        if depth > 20 or merge_visits > 10000:
            note("Recursive YAML mapping/merge truncated at the graph safety limit.")
            return {}
        result = dict(base)
        for key, value in override.items():
            if isinstance(value, Mapping) and isinstance(result.get(key), Mapping):
                result[key] = merge(result[key], value, depth + 1)
            else:
                result[key] = value
        return result

    for parsed in parsed_configs:
        ranges = _top_level_ranges(parsed.document, len(parsed.content.splitlines()))
        for raw_key, raw_value in parsed.document.items():
            key = str(raw_key)
            location = (
                parsed.path, *ranges.get(key, (1, max(1, len(parsed.content.splitlines())))))
            if isinstance(raw_value, Mapping):
                previous = merged.get(key)
                if not isinstance(previous, Mapping):
                    previous = {}
                    field_origins[key] = {}
                merged[key] = merge(previous, raw_value)
                for field in raw_value:
                    field_origins[key][str(field)] = location
            else:
                merged[key] = raw_value
                field_origins[key] = {}
            origins[key] = location

    resolved_jobs: dict[str, tuple[dict[str, Any], dict[str, tuple[str, int, int]], list[str]]] = {}

    def resolve_job(
        key: str, stack: tuple[str, ...] = ()
    ) -> tuple[dict[str, Any], dict[str, tuple[str, int, int]], list[str]]:
        if key in resolved_jobs:
            return resolved_jobs[key]
        if key in stack or len(stack) >= 11:
            note(f"Cyclic or excessive extends inheritance is unresolved for job: {key}")
            return {}, {}, []
        raw = merged.get(key)
        if not isinstance(raw, Mapping):
            note(f"Missing extends template/job: {key}")
            return {}, {}, []
        effective: dict[str, Any] = {}
        sources: dict[str, tuple[str, int, int]] = {}
        inherited: list[str] = []
        parents = _as_strings(raw.get("extends"))
        for parent in parents[:30]:
            parent_job, parent_sources, parent_inherited = resolve_job(parent, (*stack, key))
            effective = merge(effective, parent_job)
            sources.update(parent_sources)
            inherited = list(dict.fromkeys([*inherited, parent, *parent_inherited]))[:100]
        if len(parents) > 30:
            note(f"Extends inheritance truncated at the graph safety limit for job: {key}")
        effective = merge(effective, raw)
        sources.update(field_origins.get(key, {}))
        result = (effective, sources, list(dict.fromkeys(inherited)))
        resolved_jobs[key] = result
        return result

    def scripts(
        value: Any, stack: tuple[tuple[str, str], ...] = (), depth: int = 0
    ) -> tuple[list[str], tuple[str, int, int] | None, list[str]]:
        nonlocal script_visits
        script_visits += 1
        if depth > 20 or script_visits > 1000:
            note("Recursive script/reference expansion truncated at the graph safety limit.")
            return [], None, []
        if str(getattr(value, "tag", "")) == "!reference":
            if not isinstance(value, list) or len(value) != 2:
                note("Complex !reference script is unresolved; no executable script was inferred.")
                return [], None, []
            target, field = str(value[0]), str(value[1])
            if (target, field) in stack:
                note("Cyclic !reference script is unresolved.")
                return [], None, []
            target_job, target_sources, _ = resolve_job(target)
            if field not in target_job:
                note("Missing !reference script target; no executable script was inferred.")
                return [], None, []
            lines, source, inherited = scripts(
                target_job[field], (*stack, (target, field)), depth + 1
            )
            return lines, source or target_sources.get(field), [target, *inherited]
        if isinstance(value, list):
            lines, source, inherited = [], None, []
            for item in value[:100]:
                item_lines, item_source, item_inherited = scripts(item, stack, depth + 1)
                lines.extend(item_lines)
                source = source or item_source
                inherited.extend(item_inherited)
            if len(value) > 100:
                note("Script items truncated at the graph safety limit.")
            return lines, source, inherited
        if isinstance(value, str):
            return [value], None, []
        if value is not None:
            note("Non-string script is unresolved; no executable script was inferred.")
        return [], None, []

    nodes: list[PipelineNode] = []
    for key in display_order:
        if (
            key in _GITLAB_RESERVED_KEYS or key.startswith(".")
            or not isinstance(merged.get(key), Mapping)
        ):
            continue
        job, sources, inherited = resolve_job(key)
        script, referenced_source, referenced_parents = scripts(job.get("script"))
        # Mixed literal/reference scripts have several origins. Keep the containing
        # declaration as primary instead of presenting a single template as causal.
        direct_reference = str(getattr(job.get("script"), "tag", "")) == "!reference"
        source = referenced_source if direct_reference else None
        path, line_start, line_end = source or sources.get("script") or origins[key]
        node = _node(
            path=path, key=key, job=job, line_start=line_start, line_end=line_end,
            provider=ProviderName.GITLAB,
        )
        node.script = script
        inherited = [*inherited, *referenced_parents]
        captions = []
        for parent in dict.fromkeys(inherited):
            location = origins.get(parent)
            captions.append(
                f"{parent} ({display_include_path(location[0])}:{location[1]})"
                if location else parent
            )
        if not inherited and origins[key] != (path, line_start, line_end):
            captions.append(f"{key} script from {display_include_path(path)}:{line_start}")
        node.source.inherited_from = ", ".join(captions) or None
        if captions or referenced_source:
            note(
                "Inherited/merged jobs show script provenance; "
                "one source is not the entire effective job."
            )
        nodes.append(node)
    return PipelineGraph(
        provider=ProviderName.GITLAB,
        config_files=config_paths,
        stages=_as_strings(merged.get("stages")),
        nodes=nodes,
        unresolved_includes=unresolved,
    )


def analyze_github_workflow(config: CiConfigFile) -> PipelineGraph:
    """Parse a GitHub Actions workflow into jobs and dependency edges."""

    document = _parse_yaml(config.path, config.content)
    jobs = document.get("jobs")
    if not isinstance(jobs, Mapping):
        raise CiConfigParseError(f"Unable to parse {config.path}: no jobs mapping was found.")
    ranges = _top_level_ranges(jobs, len(config.content.splitlines()))
    nodes = [
        _node(
            path=config.path,
            key=str(key),
            job=value,
            line_start=ranges.get(str(key), (1, len(config.content.splitlines())))[0],
            line_end=ranges.get(str(key), (1, len(config.content.splitlines())))[1],
            provider=ProviderName.GITHUB,
        )
        for key, value in jobs.items()
        if isinstance(value, Mapping)
    ]
    return PipelineGraph(
        provider=ProviderName.GITHUB,
        config_files=[config.path],
        stages=["workflow"],
        nodes=nodes,
    )


def analyze_ci_config(
    provider: ProviderName,
    config: CiConfigFile,
    include_loader: Callable[[str], str | None] | None = None,
) -> PipelineGraph:
    if provider == ProviderName.GITLAB:
        return analyze_gitlab_yaml(config, include_loader)
    if provider == ProviderName.GITHUB:
        return analyze_github_workflow(config)
    raise ValueError(f"Unsupported CI configuration provider: {provider}")
