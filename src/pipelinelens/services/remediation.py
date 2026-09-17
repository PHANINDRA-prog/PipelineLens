"""Offline, deterministic, review-only remediation proposals from supplied source text.

No files, environment variables, providers, models, or documentation are read here.
The caller must load authentic source text at the stated ref: a matching URL/SHA is
a provenance check, not cryptographic proof of a provider response. Scores describe
rule evidence, never incident frequency or a measured probability of success.
"""

from __future__ import annotations

import difflib
import json
import re
import shlex
from dataclasses import dataclass, field
from typing import Literal, Self
from urllib.parse import parse_qs, unquote, urlsplit
from xml.parsers import expat

from pydantic import BaseModel, ConfigDict, Field, model_validator
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from ruamel.yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

from pipelinelens.domain import AnalysisSnapshot, CiConfigFile
from pipelinelens.services.findings import Finding, finding_identity
from pipelinelens.services.logs import clean_log_line
from pipelinelens.services.redaction import SecretRedactor

__all__ = [
    "ProposedChange", "Remediation", "SourceBlock", "build_remediation", "candidate_source_paths",
]

_SCORE_LABEL = "Rule-based heuristic; not a calibrated probability"
_TRACE_DOC = "https://docs.gitlab.com/ci/jobs/job_logs/"
_SHA = re.compile(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\Z")
_MARKED = re.compile(
    r"\[(?:[A-Z0-9_]+_)?REDACTED\]|"
    r"\[PIPELINELENS[^\]]*(?:OMITTED|TRUNCATED|BOUNDED)[^\]]*\]", re.I,
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u2028-\u202e\u2060-\u206f\ud800-\udfff]")
_SOURCE_CONTROL = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f"
    r"\u200b-\u200f\u2028-\u202e\u2060-\u206f\ud800-\udfff]",
)
_SECRET_PATH = re.compile(
    r"token|credential|password|passwd|passphrase|secret|private.?key|api.?key", re.I,
)
_SECRET_PARTS = {
    ".git", ".ssh", ".aws", ".azure", ".kube", ".netrc", ".npmrc", ".pypirc",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "auth.json",
}
_SCRIPT_SUFFIXES = (".sh", ".bash", ".ps1", ".cmd", ".bat", ".py", ".js", ".ts")
_SHELL_SUFFIXES = (".sh", ".bash", ".ps1", ".cmd", ".bat")
_YAML_SUFFIXES = (".yml", ".yaml")
_OBJECT_KEYS = {"sobject", "object", "objectName", "sobjectName", "sobjecttype"}
_CSV_ERROR = re.compile(
    r"\bInvalidJob\s*:\s*Unable to find object:\s*"
    r"(?P<file>[A-Za-z_][A-Za-z0-9_]*\.csv)(?![\w./-])", re.I,
)
_BUNDLE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_BLOCKED_ROW = re.compile(
    r"^LightningComponentBundle\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+"
    r"The component is referenced by\s+\S.+$",
)
_JSON_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|[{}\[\]:,]|[^\s{}\[\]:,"]+')
_SHELL_TOKEN = re.compile(r'''(?:[^ \t\r\n'"\\`;|&<>#()]+|'[^'\r\n]*'|"[^"\\`\r\n]*")+''')
_PACKAGE_KEY = re.compile(r"(?:package|migration)[_\w]*(?:path|folder|dir)\Z", re.I)
_XML_NS = "http://soap.sforce.com/2006/04/metadata"
_MAX_SOURCE = 250_000
_MAX_NODES = 10_000
_MAX_RESULTS = 8


class SourceBlock(BaseModel):
    """Redacted, whole physical source lines; provenance caveats live in confidence_basis."""

    model_config = ConfigDict(extra="forbid")
    path: str
    ref: str
    source_url: str | None
    line_start: int = Field(ge=1, strict=True)
    line_end: int = Field(ge=1, strict=True)
    content: str
    language: str

    @model_validator(mode="after")
    def _ordered_lines(self) -> Self:
        if self.line_end < self.line_start:
            raise ValueError("line_end must not precede line_start")
        return self


class ProposedChange(BaseModel):
    """An unapplied diff against one exact, unredacted repository source."""

    model_config = ConfigDict(extra="forbid")
    title: str
    path: str
    ref: str
    source_url: str
    diff: str
    rationale: str
    condition: str
    verification: list[str] = Field(default_factory=list)
    kind: Literal["source_diff"] = "source_diff"


class Remediation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    finding_key: str = ""
    project_key: str | None = None
    job_id: str | None
    rule_id: str
    summary: str
    cause_confidence: int = Field(ge=0, le=100, strict=True)
    fix_confidence: int = Field(ge=0, le=100, strict=True)
    confidence_basis: list[str] = Field(default_factory=list)
    score_label: Literal["Rule-based heuristic; not a calibrated probability"] = _SCORE_LABEL
    proposals: list[ProposedChange] = Field(default_factory=list)
    source_blocks: list[SourceBlock] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    documentation: list[str] = Field(default_factory=list)
    auto_apply_allowed: Literal[False] = False


class _UnsafeSource(ValueError):
    """Only static, non-sensitive messages may be raised with this exception."""


def _text(value: str) -> str:
    return _SOURCE_CONTROL.sub("", SecretRedactor().redact(value).content)


def _unchanged(value: str) -> bool:
    result = SecretRedactor().redact(value)
    return result.content == value and not result.replacements and not _MARKED.search(value)


def _safe_path(value: object) -> str | None:
    # Do not turn rejected paths into different, apparently authorized paths.
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,1024}", value):
        return None
    parts = value.split("/")
    if any(part in {"", ".", ".."} or part.endswith(".") for part in parts):
        return None
    if any(part.lower().startswith(".env") or part.lower() in _SECRET_PARTS for part in parts):
        return None
    if _SECRET_PATH.search(value) or value.lower().endswith(
        (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"),
    ):
        return None
    return value if _unchanged(value) else None


def _http_url(value: str | None) -> str | None:
    if not value or len(value) > 4096 or _CONTROL.search(value) or "\\" in value:
        return None
    safe = _text(value)
    try:
        decoded = unquote(safe, errors="strict")
        parts = urlsplit(safe)
        if (
            parts.scheme not in {"http", "https"} or not parts.hostname
            or parts.username is not None or parts.password is not None
            or _CONTROL.search(decoded) or "\\" in decoded or not _unchanged(decoded)
            or any(char.isspace() for char in safe) or "%" in unquote(parts.path)
        ):
            return None
        _ = parts.port
        if any(part in {".", ".."} for part in unquote(parts.path).split("/")):
            return None
    except (ValueError, UnicodeError):
        return None
    return safe


def _origin_path(url: str) -> tuple[str, str, int, str]:
    parts = urlsplit(url)
    return (
        parts.scheme, parts.hostname or "", parts.port or (443 if parts.scheme == "https" else 80),
        unquote(parts.path).rstrip("/"),
    )


def _repository_identity(snapshot: AnalysisSnapshot | None) -> tuple[str, str, int, str] | None:
    if snapshot is None:
        return None
    url = _http_url(snapshot.repository.web_url)
    if not url or url != snapshot.repository.web_url:
        return None
    parts = urlsplit(url)
    if parts.query or parts.fragment or not parts.path.rstrip("/"):
        return None
    return _origin_path(url)


@dataclass(frozen=True)
class _Blob:
    repository: tuple[str, str, int, str]
    path: str
    ref: str
    url: str


def _blob(value: str | None) -> _Blob | None:
    url = _http_url(value)
    if not url:
        return None
    parts = urlsplit(url)
    if parts.query or (parts.fragment and not re.fullmatch(r"L[1-9]\d*(?:-L?[1-9]\d*)?",
                                                        parts.fragment)):
        return None
    path = unquote(parts.path)
    separator = "/-/blob/" if "/-/blob/" in path else "/blob/"
    repository, found, rest = path.partition(separator)
    ref, slash, physical = rest.partition("/")
    if (
        not found or not slash or not repository or not _safe_path(physical)
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", ref) or not _unchanged(ref)
    ):
        return None
    origin = _origin_path(url)
    return _Blob((*origin[:3], repository), physical, ref, url.split("#", 1)[0])


def _changed_paths(changes: list[dict] | None) -> set[str]:
    return {
        path for change in changes or []
        if isinstance(change, dict) and not change.get("deleted_file")
        if (path := _safe_path(change.get("new_path") or change.get("path")))
    }


def _known_paths(known_paths: list[str] | None) -> set[str]:
    return {path for value in known_paths or [] if (path := _safe_path(value))}


def _destructive(path: str) -> bool:
    return bool(re.fullmatch(r"destructiveChanges[^/]*\.xml", path.rsplit("/", 1)[-1], re.I))


def _data_config(path: str) -> bool:
    return bool(re.fullmatch(r"asfdx-project[^/]*\.json", path.rsplit("/", 1)[-1], re.I))


def _same_job(finding: Finding, snapshot: AnalysisSnapshot | None) -> bool:
    return snapshot is None or not finding.job_id or finding.job_id == snapshot.job.external_id


def _cites_line(url: str, line: int) -> bool:
    fragment = urlsplit(url).fragment
    return not fragment or bool(re.fullmatch(rf"L{line}(?:-L?[1-9]\d*)?", fragment))


def _verified_file_paths(
    finding: Finding, snapshot: AnalysisSnapshot | None, known: set[str],
) -> set[str]:
    references = [(item.path, item.line, item.source_url) for item in finding.evidence]
    if snapshot is not None and _same_job(finding, snapshot):
        references.extend(
            (item.path, item.line, item.source_url) for item in snapshot.code_references
        )
    result: set[str] = set()
    repository = _repository_identity(snapshot)
    for value, line, url in references:
        path = _safe_path(value)
        if not path or line is None or line < 1:
            continue
        if url:
            location = _blob(url)
            if (
                location and location.repository == repository and location.path == path
                and snapshot is not None and location.ref == snapshot.run.commit_sha
                and _SHA.fullmatch(location.ref) and url == _http_url(url)
                and _cites_line(url, line)
            ):
                result.add(path)
        elif path in known:
            result.add(path)
    return result


def candidate_source_paths(
    finding: Finding,
    snapshot: AnalysisSnapshot | None,
    changes: list[dict] | None = None,
    known_paths: list[str] | None = None,
) -> list[str]:
    """Return at most eight safe root-repository fetch candidates, without fetching.

    Changes are GitLab-style ``new_path``/``path`` dictionaries. Compiler paths
    need file/line evidence verified by the root inventory or a matching blob URL;
    external/shared evidence is never reinterpreted as a root-repository path.
    """

    changed, known = _changed_paths(changes), _known_paths(known_paths)
    cited = _verified_file_paths(finding, snapshot, known)
    rule = finding.rule_id
    if not _same_job(finding, snapshot):
        return []
    if rule == "salesforce.metadata_dependency":
        return sorted(path for path in changed if _destructive(path))[:_MAX_RESULTS]
    if rule == "compiler.cs0161":
        return sorted(path for path in cited if path.lower().endswith(".cs"))[:_MAX_RESULTS]
    if rule == "change.ci_path_case_mismatch":
        paths = {path for path in changed if path.lower().endswith(_YAML_SUFFIXES)}
        return sorted(paths, key=lambda path: (path not in cited, path))[:_MAX_RESULTS]
    if rule != "salesforce.csv_as_sobject":
        return []
    configs = sorted(path for path in changed if _data_config(path))
    script_paths = {path for path in known | changed | cited
                    if path.lower().endswith((*_SCRIPT_SUFFIXES, *_YAML_SUFFIXES))}
    if snapshot is not None:
        for config in [*snapshot.config_bundle, snapshot.config]:
            path = _safe_path(config.path)
            location = _blob(config.source_url)
            if path and location and location.repository == _repository_identity(snapshot):
                if location.path == path and path.lower().endswith(_YAML_SUFFIXES):
                    script_paths.add(path)
    scripts = sorted(script_paths, key=lambda path: (path not in cited, path not in changed, path))
    return list(dict.fromkeys([*configs, *scripts]))[:_MAX_RESULTS]


@dataclass(frozen=True)
class _Source:
    config: CiConfigFile
    path: str
    url: str | None
    exact: bool
    note: str


def _source(source: CiConfigFile, snapshot: AnalysisSnapshot | None) -> _Source | None:
    path = _safe_path(source.path)
    location = _blob(source.source_url)
    shared_key = False
    if path is None and source.path.startswith("pipelinelens-gitlab-project://"):
        try:
            key = urlsplit(source.path)
            query = parse_qs(key.query, strict_parsing=True, max_num_fields=2)
            project = _safe_path(unquote(key.netloc))
            if set(query) != {"ref", "file"} or any(len(value) != 1 for value in query.values()):
                return None
            path = _safe_path(query["file"][0])
            if (
                key.path or key.fragment or not project or not path or location is None
                or location.path != path or not location.repository[3].endswith("/" + project)
            ):
                return None
            shared_key = True
        except (ValueError, UnicodeError):
            return None
    if path is None:
        return None
    valid_url = bool(location and location.path == path and location.ref == source.ref)
    same_repository = bool(location and location.repository == _repository_identity(snapshot))
    pinned = bool(_SHA.fullmatch(source.ref))
    exact = bool(
        valid_url and same_repository and pinned and snapshot is not None
        and source.ref == snapshot.run.commit_sha and not shared_key
        and source.source_url == _http_url(source.source_url)
        and not source.source_modified
    )
    if source.source_modified:
        note = f"{path}: source was changed by sanitization; snippet only, no exact diff."
    elif exact:
        note = f"{path}: source ref and blob URL match the pipeline repository and exact commit."
    elif not valid_url:
        note = f"{path}: source origin, file path, or ref is unverified; snippet only."
    elif source.source_url != _http_url(source.source_url):
        note = f"{path}: source URL needed redaction; provenance is display-only, not patchable."
    elif not pinned:
        note = f"{path}: current/mutable ref is not historical pipeline evidence; snippet only."
    elif shared_key or not same_repository:
        note = (f"{path}: pinned shared/other-repository source at {source.ref}; "
                "not the pipeline repository, so display only.")
    else:
        note = f"{path}: pinned source is not the pipeline commit; snippet only."
    return _Source(source, path, location.url if location and valid_url else None, exact, note)


@dataclass(frozen=True)
class _Edit:
    start: int
    end: int
    value: str


def _replacement(content: str, edits: list[_Edit]) -> str:
    previous = 0
    parts: list[str] = []
    for edit in sorted(edits, key=lambda item: item.start):
        if not previous <= edit.start < edit.end <= len(content):
            raise _UnsafeSource("Overlapping or invalid source spans; no diff proposed.")
        parts.extend((content[previous:edit.start], edit.value))
        previous = edit.end
    return "".join([*parts, content[previous:]])


def _patchable_content(content: str) -> None:
    if len(content) > _MAX_SOURCE:
        raise _UnsafeSource("Source exceeds the bounded parser limit; no diff proposed.")
    if not _unchanged(content):
        raise _UnsafeSource(
            "Source contains redacted, secret, or omitted content; no diff proposed.",
        )
    if _SOURCE_CONTROL.search(content) or re.search(r"\r(?!\n)", content):
        raise _UnsafeSource(
            "Unsupported source control characters or line endings; no diff proposed.",
        )


def _unified(path: str, before: str, after: str) -> str:
    # Hunk payload retains original LF/CRLF bytes. difflib does not supply Git's
    # missing-final-newline markers, so add those rather than inventing a newline.
    lines = difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{path}", tofile=f"b/{path}", n=3, lineterm="\n",
    )
    payload = []
    for line in lines:
        payload.append(line if line.endswith("\n") else line + "\n\\ No newline at end of file\n")
    if not payload:
        raise _UnsafeSource("No exact source change was established.")
    diff = f"diff --git a/{path} b/{path}\n" + "".join(payload)
    if len(diff) > 60_000 or not _unchanged(diff):
        raise _UnsafeSource("Diff context is oversized or would need redaction; no diff proposed.")
    return diff


@dataclass
class _XmlElement:
    tag: str
    start: int
    end: int = 0
    text: str = ""
    children: list[_XmlElement] = field(default_factory=list)


@dataclass(frozen=True)
class _Manifest:
    data: bytes
    groups: dict[str, tuple[_XmlElement, list[_XmlElement]]]
    version: str


def _manifest(content: str) -> _Manifest:
    # Comments are inert; declarations, entity references (even predefined ones),
    # CDATA, attributes, and unknown/duplicate structure deliberately fail closed.
    uncommented = re.sub(r"<!--[\s\S]*?-->", "", content)
    if "&" in uncommented:
        raise _UnsafeSource("XML entity references are unsupported; no diff proposed.")
    data = content.encode("utf-8")
    parser = expat.ParserCreate(namespace_separator="|")
    stack: list[_XmlElement] = []
    roots: list[_XmlElement] = []
    namespaces: list[str] = []
    count = 0

    def refuse(*_args: object) -> None:
        raise _UnsafeSource("XML DTD, entities, CDATA, or processing instructions are unsupported.")

    def namespace(_prefix: str | None, uri: str | None) -> None:
        if stack or namespaces or uri != _XML_NS:
            raise _UnsafeSource("XML namespace is missing, unknown, or redeclared.")
        namespaces.append(uri)

    def start(name: str, attributes: dict[str, str]) -> None:
        nonlocal count
        count += 1
        if count > _MAX_NODES or len(stack) >= 64 or attributes:
            raise _UnsafeSource("XML attributes or structural limits prevent a safe edit.")
        if not name.startswith(_XML_NS + "|"):
            raise _UnsafeSource("XML metadata namespace could not be verified.")
        node = _XmlElement(name.split("|", 1)[1], parser.CurrentByteIndex)
        (stack[-1].children if stack else roots).append(node)
        stack.append(node)

    def end(_name: str) -> None:
        index = parser.CurrentByteIndex
        stack.pop().end = data.index(b">", index) + 1 if data[index:index + 2] == b"</" else index

    def text(value: str) -> None:
        if stack:
            stack[-1].text += value

    parser.StartDoctypeDeclHandler = refuse
    parser.EntityDeclHandler = refuse
    parser.ExternalEntityRefHandler = refuse
    parser.StartCdataSectionHandler = refuse
    parser.ProcessingInstructionHandler = refuse
    parser.StartNamespaceDeclHandler = namespace
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = text
    try:
        parser.Parse(data, True)
    except (expat.ExpatError, UnicodeError, ValueError) as error:
        if isinstance(error, _UnsafeSource):
            raise
        raise _UnsafeSource("XML is not structurally valid; no diff proposed.") from None
    if len(roots) != 1 or roots[0].tag != "Package" or not namespaces or roots[0].text.strip():
        raise _UnsafeSource("XML must be a namespaced Salesforce Package manifest.")
    groups: dict[str, tuple[_XmlElement, list[_XmlElement]]] = {}
    versions: list[str] = []
    for node in roots[0].children:
        if node.tag == "version" and not node.children:
            versions.append(node.text.strip())
            continue
        if node.tag != "types" or node.text.strip():
            raise _UnsafeSource("XML contains unknown Package declarations.")
        names = [child for child in node.children if child.tag == "name"]
        members = [child for child in node.children if child.tag == "members"]
        if (
            len(names) != 1 or not members or len(node.children) != len(members) + 1
            or any(child.children or not child.text.strip() for child in node.children)
            or not _BUNDLE.fullmatch(names[0].text.strip())
        ):
            raise _UnsafeSource("XML types must contain one name and unambiguous members only.")
        name = names[0].text.strip()
        values = [member.text.strip() for member in members]
        if name in groups or len(set(values)) != len(values):
            raise _UnsafeSource("XML contains duplicate type or member declarations.")
        groups[name] = node, members
    if len(versions) != 1 or not re.fullmatch(r"\d+(?:\.\d+)?", versions[0]):
        raise _UnsafeSource("XML needs exactly one valid metadata API version declaration.")
    return _Manifest(data, groups, versions[0])


def _deletion_span(content: str, manifest: _Manifest, node: _XmlElement) -> _Edit:
    start = len(manifest.data[:node.start].decode("utf-8"))
    end = len(manifest.data[:node.end].decode("utf-8"))
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    line_end = len(content) if line_end < 0 else line_end + 1
    if not content[line_start:start].strip() and not content[end:line_end].strip():
        start, end = line_start, line_end
    return _Edit(start, end, "")


def _manifest_values(manifest: _Manifest) -> dict[str, list[str]]:
    return {name: [member.text.strip() for member in members]
            for name, (_, members) in manifest.groups.items()}


def _xml_edits(content: str, blocked: set[str]) -> list[_Edit]:
    before = _manifest(content)
    group = before.groups.get("LightningComponentBundle")
    if not group or not any(member.text.strip() in blocked for member in group[1]):
        raise _UnsafeSource("No explicitly blocked bundle matches a real XML members element.")
    node, members = group
    if any(member.text.strip() == "*" for member in members):
        raise _UnsafeSource("A wildcard deletion prevents preserving an individual bundle safely.")
    matched = [member for member in members if member.text.strip() in blocked]
    edits = [_deletion_span(content, before, item)
             for item in ([node] if len(matched) == len(members) else matched)]
    after = _manifest(_replacement(content, edits))
    expected = _manifest_values(before)
    remaining = [member.text.strip() for member in members if member not in matched]
    if remaining:
        expected["LightningComponentBundle"] = remaining
    else:
        del expected["LightningComponentBundle"]
    if _manifest_values(after) != expected or before.version != after.version:
        raise _UnsafeSource("XML structural verification did not preserve unrelated declarations.")
    return edits


def _json_document(content: str) -> object:
    def pairs(values: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in values:
            if key in result:
                raise _UnsafeSource("JSON duplicate keys are ambiguous; no diff proposed.")
            result[key] = value
        return result

    def constant(_value: str) -> None:
        raise _UnsafeSource("JSON non-finite constants are unsupported.")

    try:
        return json.loads(content, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError) as error:
        if isinstance(error, _UnsafeSource):
            raise
        raise _UnsafeSource("JSON does not parse strictly; no diff proposed.") from None


def _json_expected(value: object, targets: set[str], depth: int = 0) -> object:
    if depth >= 64:
        raise _UnsafeSource("JSON nesting exceeds the safe structural limit.")
    if isinstance(value, dict):
        return {
            key: child[:-4] if key in _OBJECT_KEYS and isinstance(child, str) and child in targets
            else _json_expected(child, targets, depth + 1)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_json_expected(child, targets, depth + 1) for child in value]
    return value


def _json_edits(content: str, targets: set[str]) -> list[_Edit]:
    before = _json_document(content)
    tokens = list(_JSON_TOKEN.finditer(content))
    edits = []
    # The full document is parsed first; whole JSON string tokens prevent matching
    # embedded JSON-looking prose, file/path values, or partial filenames.
    for key, colon, value in zip(tokens, tokens[1:], tokens[2:], strict=False):
        if not key[0].startswith('"') or colon[0] != ":" or not value[0].startswith('"'):
            continue
        if json.loads(key[0]) in _OBJECT_KEYS and json.loads(value[0]) in targets:
            edits.append(_Edit(value.start(), value.end(), json.dumps(json.loads(value[0])[:-4])))
    if not edits:
        raise _UnsafeSource(
            "No exact CSV-valued sobject/object/objectName/sobjectName JSON key found.",
        )
    if _json_document(_replacement(content, edits)) != _json_expected(before, targets):
        raise _UnsafeSource("JSON semantic verification failed; no diff proposed.")
    return edits


@dataclass(frozen=True)
class _Scalar:
    trail: tuple[str | int, ...]
    value: str
    start: int
    end: int
    line: int
    style: str | None


@dataclass
class _Yaml:
    scalars: list[_Scalar] = field(default_factory=list)
    shape: list[tuple[tuple[str | int, ...], str, object]] = field(default_factory=list)
    mappings: dict[tuple[str | int, ...], set[str]] = field(default_factory=dict)


def _yaml(content: str) -> _Yaml:
    result = _Yaml()
    seen: set[int] = set()

    def visit(node: Node, trail: tuple[str | int, ...], in_reference: bool = False) -> None:
        if len(trail) >= 64 or len(seen) >= _MAX_NODES or id(node) in seen:
            raise _UnsafeSource("YAML aliases or structural limits prevent an unambiguous edit.")
        seen.add(id(node))
        in_reference = in_reference or node.tag == "!reference"
        if node.tag not in {
            *("tag:yaml.org,2002:" + kind for kind in (
                "map", "seq", "str", "bool", "int", "float", "null", "timestamp", "binary",
            )), "!reference",
        }:
            raise _UnsafeSource("YAML contains an unsupported custom tag.")
        if isinstance(node, MappingNode):
            keys: list[str] = []
            for key, _ in node.value:
                if not isinstance(key, ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                    raise _UnsafeSource(
                        "YAML needs literal string keys, without merge declarations.",
                    )
                keys.append(key.value)
            if len(set(keys)) != len(keys):
                raise _UnsafeSource("YAML contains duplicate declarations.")
            result.mappings[trail] = set(keys)
            result.shape.append((trail, node.tag, tuple(keys)))
            for key, child in node.value:
                visit(child, (*trail, key.value), in_reference)
        elif isinstance(node, SequenceNode):
            result.shape.append((trail, node.tag, len(node.value)))
            for index, child in enumerate(node.value):
                visit(child, (*trail, index), in_reference)
        elif isinstance(node, ScalarNode):
            result.shape.append((trail, node.tag, node.value))
            if node.tag == "tag:yaml.org,2002:str" and not in_reference:
                result.scalars.append(_Scalar(
                    trail, node.value, node.start_mark.index, node.end_mark.index,
                    node.start_mark.line + 1, node.style,
                ))
        else:
            raise _UnsafeSource("YAML contains an unsupported node.")

    try:
        root = YAML(typ="safe", pure=True).compose(content)
        if not isinstance(root, MappingNode):
            raise _UnsafeSource("CI YAML must contain one mapping document.")
        visit(root, ())
    except (YAMLError, ValueError, TypeError, RecursionError) as error:
        if isinstance(error, _UnsafeSource):
            raise
        raise _UnsafeSource("YAML does not parse unambiguously; no diff proposed.") from None
    return result


def _script_role(trail: tuple[str | int, ...]) -> bool:
    parts = trail[:-1] if trail and isinstance(trail[-1], int) else trail
    commands = {"script", "before_script", "after_script"}
    if len(parts) == 1:
        return parts[0] in commands
    if len(parts) == 2:
        return parts[0] not in {
            "variables", "include", "workflow", "stages", "spec", "image", "services", "cache",
            "artifacts", "rules", "needs",
        } and parts[1] in commands
    return (
        len(trail) == 5 and trail[0] == "jobs" and trail[2] == "steps"
        and isinstance(trail[3], int) and trail[4] == "run"
    )


def _command_regions(scalar: _Scalar, content: str) -> list[tuple[str, int, int]]:
    """Map literal commands to both raw source and decoded YAML-value offsets."""
    raw = content[scalar.start:scalar.end]
    if scalar.style in {"'", '"'}:
        if raw[1:-1] == scalar.value and "\n" not in raw:
            return [(scalar.value, scalar.start + 1, 0)]
    elif scalar.style is None and raw == scalar.value and "\n" not in raw:
        return [(raw, scalar.start, 0)]
    elif scalar.style == "|":
        lines = raw.splitlines(keepends=True)
        source_offset = scalar.start + len(lines[0])
        value_offset = 0
        regions = []
        for source_line, value_line in zip(lines[1:], scalar.value.splitlines(keepends=True),
                                          strict=False):
            source_body, value_body = source_line.rstrip("\r\n"), value_line.rstrip("\r\n")
            prefix = len(source_body) - len(value_body)
            if prefix < 0 or source_body[prefix:] != value_body or source_body[:prefix].strip():
                return []
            regions.append((value_body, source_offset + prefix, value_offset))
            source_offset += len(source_line)
            value_offset += len(value_line)
        return regions
    return []  # Folded, escaped and multiline quoted scalars require a human.


def _shell_tokens(command: str) -> list[tuple[str, int, int]]:
    tokens = []
    position = 0
    while position < len(command):
        while position < len(command) and command[position] in " \t":
            position += 1
        if position == len(command) or command[position] == "#":
            break
        match = _SHELL_TOKEN.match(command, position)
        if match is None:
            return []
        tokens.append((match[0], match.start(), match.end()))
        position = match.end()
        if position < len(command) and command[position] not in " \t":
            return []  # A '#' joined to an argument is not a separate shell comment.
    return tokens


def _literal(raw: str) -> tuple[str, int] | None:
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "'\"":
        if not re.search(r"[$`\\'\"]", raw[1:-1]):
            return raw[1:-1], 1
    elif re.fullmatch(r"[A-Za-z0-9_./:-]+", raw):
        return raw, 0
    return None


def _sobject_edits(command: str, targets: set[str]) -> list[_Edit]:
    tokens = _shell_tokens(command)
    if not tokens or tokens[0][0] not in {"sf", "sf.exe", "sfdx", "sfdx.exe"}:
        return []
    if len(tokens) < 3 or not (
        tokens[1][0] == "data" or tokens[1][0].startswith("force:data:")
    ):
        return []
    candidates: list[tuple[str, int, int]] = []
    for index, (raw, start, end) in enumerate(tokens):
        if raw == "--":
            return []
        if raw == "--sobject" and index + 1 < len(tokens):
            candidates.append(tokens[index + 1])
        elif raw.startswith("--sobject="):
            candidates.append((raw[len("--sobject="):], start + len("--sobject="), end))
    if len(candidates) != 1:
        return []
    raw, start, end = candidates[0]
    value = _literal(raw)
    if value is None or value[0] not in targets:
        return []
    return [_Edit(start + value[1], end - value[1], value[0][:-4])]


def _script_guard(content: str) -> None:
    """Reject multiline quoting/continuations before considering ANY command line."""
    for body in content.splitlines():
        stripped = body.lstrip()
        if not stripped.startswith(("#", "::")) and not re.match(r"(?i)rem(?:\s|$)", stripped):
            if re.search(r"<<|<#|#>|@['\"]|['\"]@|`|[\\^]\s*$", body):
                raise _UnsafeSource("Multiline or dynamic script syntax needs manual inspection.")
            try:
                shlex.split(body, comments=True)
            except ValueError:
                raise _UnsafeSource(
                    "Multiline or ambiguous script quoting needs manual inspection.",
                ) from None


def _shell_edits(content: str, targets: set[str]) -> list[_Edit]:
    _script_guard(content)
    edits = []
    offset = 0
    for line in content.splitlines(keepends=True):
        edits.extend(_Edit(offset + edit.start, offset + edit.end, edit.value)
                     for edit in _sobject_edits(line.rstrip("\r\n"), targets))
        offset += len(line)
    if not edits:
        raise _UnsafeSource(
            "No unambiguous direct sf/sfdx --sobject literal matches the diagnostic.",
        )
    return edits


def _yaml_verify(
    before: _Yaml, content: str, edits: list[_Edit], expected: dict[tuple[str | int, ...], str],
) -> None:
    after = _yaml(_replacement(content, edits))
    shape = [(trail, tag, expected.get(trail, value)) for trail, tag, value in before.shape]
    if after.shape != shape:
        raise _UnsafeSource("YAML semantic verification failed; no diff proposed.")


def _yaml_csv_edits(content: str, targets: set[str]) -> list[_Edit]:
    document = _yaml(content)
    edits: list[_Edit] = []
    expected = {}
    for scalar in document.scalars:
        if not _script_role(scalar.trail):
            continue
        _script_guard(scalar.value)
        value_edits = []
        for command, offset, value_offset in _command_regions(scalar, content):
            for edit in _sobject_edits(command, targets):
                edits.append(_Edit(offset + edit.start, offset + edit.end, edit.value))
                value_edits.append(_Edit(value_offset + edit.start, value_offset + edit.end,
                                         edit.value))
        if value_edits:
            expected[scalar.trail] = _replacement(scalar.value, value_edits)
    if not edits:
        raise _UnsafeSource("No parsed YAML command has an exact literal --sobject match.")
    _yaml_verify(document, content, edits, expected)
    return edits


def _inventory_index(known: set[str]) -> dict[str, set[str]]:
    index: dict[str, set[str]] = {}
    for path in known:
        parts = path.split("/")
        for length in range(1, len(parts) + 1):
            prefix = "/".join(parts[:length])
            index.setdefault(prefix.casefold(), set()).add(prefix)
    return index


def _canonical(value: str, inventory: dict[str, set[str]]) -> str | None:
    prefix = "./" if value.startswith("./") else ""
    path = _safe_path(value[len(prefix):])
    matches = inventory.get(path.casefold(), set()) if path else set()
    if len(matches) != 1 or path in matches:
        return None
    return prefix + next(iter(matches))


def _path_role(scalar: _Scalar, document: _Yaml) -> bool:
    trail = scalar.trail
    if trail and trail[0] == "include":
        if len(trail) == 1 or (len(trail) == 2 and isinstance(trail[-1], int)):
            return True
        if trail[-1] == "local":
            return not {"project", "remote", "rules"}.intersection(
                document.mappings.get(trail[:-1], set()),
            )
    return (
        len(trail) >= 2 and trail[-2] == "variables" and isinstance(trail[-1], str)
        and bool(_PACKAGE_KEY.fullmatch(trail[-1]))
    ) or _script_role(trail)


def _command_path_edits(command: str, inventory: dict[str, set[str]]) -> list[_Edit]:
    tokens = _shell_tokens(command)
    if not tokens or tokens[0][0].lower() in {"echo", "printf", "write-host", "write-output"}:
        return []
    candidates = tokens[1:2] if tokens[0][0] == "cd" and len(tokens) == 2 else []
    for index, (raw, start, end) in enumerate(tokens):
        if raw in {"--package", "--package-path", "--package-folder"} and index + 1 < len(tokens):
            candidates.append(tokens[index + 1])
        elif (option := raw.partition("="))[0] in {
            "--package", "--package-path", "--package-folder",
        } and option[1]:
            candidates.append((option[2], start + len(option[0]) + 1, end))
    edits = []
    for raw, start, end in candidates:
        literal = _literal(raw)
        if literal is not None and literal[1] and (canonical := _canonical(literal[0], inventory)):
            edits.append(_Edit(start + 1, end - 1, canonical))
    return edits


def _case_edits(
    content: str, source: _Source, finding: Finding, known: set[str], changed: set[str],
) -> list[_Edit]:
    if source.path not in changed:
        raise _UnsafeSource("A changed YAML path is required for this static change finding.")
    document = _yaml(content)
    lines = content.splitlines()
    cited: set[int] = set()
    for evidence in finding.evidence:
        if evidence.path != source.path or evidence.line is None:
            continue
        if evidence.source_url:
            location = _blob(evidence.source_url)
            own_location = _blob(source.url)
            if (
                location != own_location or evidence.source_url != _http_url(evidence.source_url)
                or not _cites_line(evidence.source_url, evidence.line)
            ):
                continue
        if (
            1 <= evidence.line <= len(lines)
            and lines[evidence.line - 1].strip() == evidence.text.strip()
        ):
            cited.add(evidence.line)
    inventory = _inventory_index(known)
    edits: list[_Edit] = []
    expected = {}
    for scalar in document.scalars:
        raw = content[scalar.start:scalar.end]
        if (
            scalar.line in cited and scalar.style in {"'", '"'} and "\n" not in raw
            and raw[1:-1] == scalar.value and _path_role(scalar, document)
            and (canonical := _canonical(scalar.value, inventory))
        ):
            edits.append(_Edit(scalar.start + 1, scalar.end - 1, canonical))
            expected[scalar.trail] = canonical
        elif _script_role(scalar.trail):
            _script_guard(scalar.value)
            value_edits = []
            for command, offset, value_offset in _command_regions(scalar, content):
                if content.count("\n", 0, offset) + 1 not in cited:
                    continue
                for edit in _command_path_edits(command, inventory):
                    edits.append(_Edit(offset + edit.start, offset + edit.end, edit.value))
                    value_edits.append(_Edit(value_offset + edit.start, value_offset + edit.end,
                                             edit.value))
            if value_edits:
                expected[scalar.trail] = _replacement(scalar.value, value_edits)
    if not edits:
        raise _UnsafeSource(
            "Need an exact cited source line, a quoted path, and one unique inventory case match.",
        )
    _yaml_verify(document, content, edits, expected)
    return edits


def _blocked_bundles(finding: Finding, snapshot: AnalysisSnapshot | None) -> set[str]:
    names = set()
    for evidence in finding.evidence:
        if match := _BLOCKED_ROW.fullmatch(clean_log_line(_text(evidence.text))):
            if _safe_path(match["name"]):
                names.add(match["name"])
    if snapshot is not None:
        for failure in snapshot.component_failures:
            if (
                failure.metadata_type == "LightningComponentBundle"
                and _BUNDLE.fullmatch(failure.component_name) and _safe_path(failure.component_name)
                and re.match(r"The component is referenced by\s+\S", _text(failure.problem))
            ):
                names.add(failure.component_name)
    return names


def _language(path: str) -> str:
    extension = path.rsplit(".", 1)[-1].lower()
    return {
        "cs": "csharp", "ps1": "powershell", "sh": "bash", "bash": "bash", "yml": "yaml",
        "yaml": "yaml", "json": "json", "xml": "xml", "py": "python", "js": "javascript",
        "ts": "typescript", "cmd": "batch", "bat": "batch",
    }.get(extension, "text")


def _source_block(source: _Source, anchor: int) -> SourceBlock | None:
    # Redact the WHOLE source before selecting lines, including multiline secrets.
    if len(source.config.content) > _MAX_SOURCE:
        return None
    lines = _text(source.config.content).splitlines(keepends=True)
    if not lines:
        return None
    anchor = anchor if 1 <= anchor <= len(lines) else 1
    start, end = max(0, anchor - 6), min(len(lines), anchor + 7)
    while sum(map(len, lines[start:end])) > 10_000 and end - start > 1:
        if anchor - start > end - anchor:
            start += 1
        else:
            end -= 1
    content = "".join(lines[start:end])
    if len(content) > 10_000:
        return None
    return SourceBlock(
        path=_text(source.path), ref=_text(source.config.ref), source_url=source.url,
        line_start=start + 1, line_end=end, content=content, language=_language(source.path),
    )


def _anchor(source: _Source, finding: Finding, snapshot: AnalysisSnapshot | None) -> int:
    for item in finding.evidence:
        if item.path == source.path and item.line is not None and item.line > 0:
            return item.line
    if snapshot is not None:
        for reference in snapshot.code_references:
            if reference.path == source.path:
                return reference.line
        if snapshot.job_source is not None and snapshot.job_source.path == source.config.path:
            return snapshot.job_source.line_start
    return 1


def _guidance(finding: Finding) -> tuple[list[str], list[str], int]:
    rule = finding.rule_id
    if rule == "rlp.datasync_field_mapping_connection_reset":
        return [
            "Review target-platform and DataSync service diagnostics for the matching "
            "deployment window; a reset does not establish the failing host or root cause.",
            "Confirm whether a partial target state needs review before one controlled retry. "
            "Keep compatibility skips separate from failed mapping requests.",
        ], [
            "Target-platform diagnostics, partial-state verification, and a reviewed retry result.",
        ], 15
    if rule == "rlp.datasync_field_mapping_artifact_failure":
        return [
            "Review the earliest target-platform DataSync diagnostic before retrying an "
            "unclassified field-mapping deployment failure.",
            "Confirm target state and the intended mapping set before a controlled retry.",
        ], [
            "A specific target-side diagnostic and partial-state verification.",
        ], 10
    if rule == "salesforce.metadata_dependency":
        return [
            "Confirm with the metadata owner whether blocked components should remain available.",
            "If preservation is intended, review only the named members in every destructive "
            "manifest; this changes deployment scope, not the automatic deletion policy.",
            "Validate the reviewed package against the intended target with required tests; "
            "do not invent deletion of the referenced tab or assume the whole deployment is fixed.",
        ], ["Intended component retention/removal and target validation results."], 20
    if rule == "salesforce.csv_as_sobject":
        return [
            "Confirm the intended object API name exists in the target org and inspect the loader "
            "argument/configuration that supplied the CSV filename as the object.",
            "Keep the CSV filename on file/path/--file inputs; change only the explicit "
            "object-valued input after review.",
            "Validate the corrected mapping and target before rerunning any data movement.",
        ], ["Target object existence and the executed loader's object-to-file mapping."], 20
    if rule == "change.ci_path_case_mismatch":
        return [
            "Compare the cited literal with the exact-commit repository inventory on a "
            "case-sensitive runner; this is static evidence, not proof of a job failure.",
            "Review the case-only correction and validate CI syntax and the intended package "
            "selection without changing deployment automation.",
        ], ["Confirmation that the uniquely matching inventory path is the intended input."], 20
    if rule == "compiler.cs0161":
        return [
            "Inspect the cited method and every reachable branch against its declared return type.",
            "Ask the developer for the intended result or exception contract for the uncovered "
            "branch; no return value can be inferred from CS0161 alone.",
            "Test those branches and rebuild with the same compiler/toolchain after review.",
        ], ["The intended return/exception behavior and tests for reachable method branches."], 25
    if "timeout" in rule or finding.category == "timeout":
        return [
            "Identify the last running command and check its existing target-side execution "
            "before starting a duplicate run.",
            "For Apex tests, inspect the existing test run, queue, and results; interruption "
            "does not establish a failed assertion or a completed test run.",
            "Measure the blocking wait or workload with the CI owner; retain required tests "
            "and existing timeout policies until an explicit review approves a change.",
        ], ["Command timing, target-side execution status, and the blocking wait's cause."], 15
    if "auth" in rule or finding.category in {
        "authentication_failure", "authorization_failure",
    }:
        return [
            "Verify the rejected operation, intended identity, and required scope with the owner.",
            "Check credential availability/expiry only through approved secret management, "
            "without revealing values; do not widen permissions or weaken access policies.",
        ], ["The denied operation, required scope, and approved identity/credential status."], 10
    return [
        "Inspect the complete sanitized diagnostic and the exact command/source context.",
        "Establish the intended behavior with the job owner before proposing a source or policy "
        "change; reproduce with a safe fixture and the same toolchain.",
    ], ["A specific causal diagnostic, exact source location, and intended behavior."], 10


def build_remediation(
    finding: Finding,
    snapshot: AnalysisSnapshot | None,
    sources: list[CiConfigFile],
    changes: list[dict] | None = None,
    known_paths: list[str] | None = None,
) -> Remediation:
    """Build unapplied, conditional proposals and redacted context, entirely in memory.

    Only three rules emit diffs: namespaced destructive manifests, explicit CSV
    object inputs, and cited quoted YAML path-case literals. Snapshot CI sources
    are also usable in-memory context. Other refs/repositories are display-only.
    Any source redaction blocks its entire diff (even outside the eventual hunk).
    No correct C# return value, timeout, access policy, or deletion policy is inferred.
    """

    actions, missing, fix_score = _guidance(finding)
    basis = [
        f"Finding evidence is classified as {finding.confidence}.",
        "Scores use rule/evidence checks only, not recurrence, similar incidents, or frequency.",
        "No proposal has been applied or target-validated; every change requires human review.",
    ]
    cause = {"observed": 85, "likely": 60, "unknown": 25}[finding.confidence]
    if finding.category == "unknown" or finding.rule_id not in {
        "compiler.cs0161", "salesforce.metadata_dependency", "salesforce.csv_as_sobject",
        "change.ci_path_case_mismatch", "runner.job_timeout",
        "rlp.datasync_field_mapping_connection_reset",
        "rlp.datasync_field_mapping_artifact_failure",
    }:
        cause = min(cause, 40 if finding.category != "unknown" else 25)
    if not _same_job(finding, snapshot):
        missing.append(
            "Snapshot belongs to a different job; its sources and diagnostics are not used.",
        )
        snapshot = None
    if snapshot is None:
        missing.append(
            "A pipeline snapshot with repository identity and commit is needed for diffs.",
        )
    elif not _SHA.fullmatch(snapshot.run.commit_sha or ""):
        missing.append("A full 40- or 64-hex pipeline commit SHA is required for source diffs.")
    blocked = _blocked_bundles(finding, snapshot)
    targets = {match["file"] for item in finding.evidence
               for match in _CSV_ERROR.finditer(_text(item.text))}
    evidence_text = "\n".join(_text(item.text) for item in finding.evidence)
    explicit = (
        (finding.rule_id == "salesforce.metadata_dependency" and bool(blocked))
        or (finding.rule_id == "salesforce.csv_as_sobject" and bool(targets))
        or (finding.rule_id == "compiler.cs0161" and "CS0161" in evidence_text
            and "not all code paths return a value" in evidence_text)
        or ("timeout" in finding.rule_id and bool(re.search(
            r"execution took longer|timed out|time limit", evidence_text, re.I,
        )))
        or (finding.category in {"authentication_failure", "authorization_failure"}
            and bool(re.search(r"\b(?:401|403|unauthorized|forbidden|access denied)\b",
                               evidence_text, re.I))
        or (finding.rule_id == "rlp.datasync_field_mapping_connection_reset"
            and "connection reset" in evidence_text.casefold())
        or (finding.rule_id == "rlp.datasync_field_mapping_artifact_failure"
            and "field-mapping failure" in evidence_text.casefold()))
    )
    if explicit:
        cause = {"observed": 94, "likely": 65, "unknown": 30}[finding.confidence]
        basis.append("A specific diagnostic establishes the reported failure, not a confirmed fix.")
    elif not finding.evidence:
        cause = min(cause, 35)
        basis.append(
            "No cited diagnostic establishes the cause; the rule label alone is insufficient.",
        )
    changed, known = _changed_paths(changes), _known_paths(known_paths)
    verified = _verified_file_paths(finding, snapshot, known)
    available = list(sources)
    if snapshot is not None:
        available.extend([*snapshot.config_bundle, snapshot.config])
    selected: list[_Source] = []
    for config in available:
        source = _source(config, snapshot)
        if source is None:
            continue
        rule = finding.rule_id
        if rule == "compiler.cs0161" and source.path.lower().endswith(".cs"):
            if source.path not in verified:
                continue
        if rule == "salesforce.metadata_dependency":
            relevant = _destructive(source.path)
        elif rule == "salesforce.csv_as_sobject":
            relevant = _data_config(source.path) or source.path.lower().endswith(
                (*_SCRIPT_SUFFIXES, *_YAML_SUFFIXES),
            )
        elif rule == "change.ci_path_case_mismatch":
            relevant = source.path in changed and source.path.lower().endswith(_YAML_SUFFIXES)
        else:
            relevant = source.path in verified or (
                snapshot is not None and (source.config.path == snapshot.config.path or (
                    snapshot.job_source is not None
                    and source.config.path == snapshot.job_source.path
                ))
            )
        if relevant:
            selected.append(source)
    groups: dict[tuple[str, str, tuple[str, str, int, str] | None], list[_Source]] = {}
    for source in selected:
        location = _blob(source.url)
        identity = location.repository if location is not None else None
        groups.setdefault((source.path, source.config.ref, identity), []).append(source)
    for group in groups.values():
        group.sort(key=lambda item: (not item.exact, item.url or "", item.config.path))
    proposals: list[ProposedChange] = []
    blocks: list[SourceBlock] = []
    ordered = sorted(groups.values(), key=lambda group: (
        not group[0].exact, group[0].path not in verified,
        not _data_config(group[0].path), group[0].path, group[0].config.ref, group[0].url or "",
    ))
    for group in ordered[:_MAX_RESULTS]:
        source = group[0]
        content = source.config.content
        basis.append(source.note)
        anchor = _anchor(source, finding, snapshot)
        conflicting = len({item.config.content for item in group}) != 1
        if conflicting:
            missing.append(
                f"{source.path}: conflicting supplied content for the same source identity.",
            )
            continue
        rule = finding.rule_id
        patch_rule = rule in {
            "salesforce.metadata_dependency", "salesforce.csv_as_sobject",
            "change.ci_path_case_mismatch",
        }
        if source.exact and patch_rule:
            try:
                _patchable_content(content)
                if rule == "salesforce.metadata_dependency":
                    if not blocked:
                        raise _UnsafeSource(
                            "An explicit still-referenced LightningComponentBundle row is needed; "
                            "other metadata failures are not deletion proof.",
                        )
                    edits = _xml_edits(content, blocked)
                    title = "Preserve explicitly blocked Lightning component bundles"
                    condition = "If this component must remain available"
                    rationale = (
                        "Remove only members identified by still-referenced failure rows from this "
                        "destructive manifest (or their types block when no members remain). "
                        "This narrows deployment scope; it neither deletes the tab nor establishes "
                        "a confirmed fix for the entire deployment."
                    )
                    verification = [
                        "Review the intended preservation with the metadata owner and inspect "
                        "all other destructive manifests for the same components.",
                        "Revalidate the XML and the complete package against the intended target "
                        "with required deployment tests, before any approved deployment.",
                    ]
                    score = 70
                elif rule == "salesforce.csv_as_sobject":
                    if not targets:
                        raise _UnsafeSource(
                            "An explicit InvalidJob CSV-as-object diagnostic is needed.",
                        )
                    if _data_config(source.path):
                        edits = _json_edits(content, targets)
                    elif source.path.lower().endswith(_YAML_SUFFIXES):
                        edits = _yaml_csv_edits(content, targets)
                    elif source.path in known | changed and source.path.lower().endswith(
                        _SHELL_SUFFIXES,
                    ):
                        edits = _shell_edits(content, targets)
                    else:
                        raise _UnsafeSource("Only known root scripts with direct CLI literals are "
                                            "supported; embedded/generated commands need review.")
                    title = "Use the object API name, not the CSV filename, for the object input"
                    condition = "If this is the intended object API name in the target org"
                    rationale = (
                        "Only exact CSV-valued object settings or literal --sobject arguments "
                        "matching the diagnostic are changed. File/path/--file inputs remain "
                        "unchanged; target object existence has not been checked."
                    )
                    verification = [
                        "Confirm the object API name and CSV-to-object mapping with the owner.",
                        "Validate the configuration and loader arguments using a safe fixture "
                        "before an approved data load into the intended target.",
                    ]
                    score = 82
                else:
                    edits = _case_edits(content, source, finding, known, changed)
                    title = "Match the cited quoted CI path to unique repository inventory case"
                    condition = "If this is the intended repository path at the pipeline commit"
                    rationale = (
                        "Only quoted literals on exact cited lines are changed to unique "
                        "case-insensitive inventory matches. This is a static path correction, "
                        "not proof that this mismatch caused the job failure."
                    )
                    verification = [
                        "Confirm the inventory describes the same pipeline commit and input.",
                        "Validate CI YAML and path resolution on a case-sensitive runner while "
                        "retaining deployment, approval, and automation policies.",
                    ]
                    score = 85
                after = _replacement(content, edits)
                diff = _unified(source.path, content, after)
                proposals.append(ProposedChange(
                    title=title, path=source.path, ref=source.config.ref,
                    source_url=source.url or "",
                    diff=diff, rationale=rationale, condition=condition, verification=verification,
                ))
                anchor = content.count("\n", 0, min(edit.start for edit in edits)) + 1
                fix_score = min(score, {"observed": 100, "likely": 60, "unknown": 30}[
                    finding.confidence
                ])
                basis.append(f"{source.path}: exact replacement spans and parser/argument checks "
                             "support a conditional, unvalidated proposal.")
            except (_UnsafeSource, UnicodeError, RecursionError) as error:
                detail = (
                    str(error) if isinstance(error, _UnsafeSource) else "Unsupported source text."
                )
                missing.append(f"{source.path}: {detail}")
        elif patch_rule:
            missing.append(f"{source.path}: an unmodified source URL and exact root pipeline SHA "
                           "are required for a diff.")
        if anchor > len(content.splitlines()):
            missing.append(f"{source.path}: cited line is outside the supplied content; "
                           "only file-start context can be shown.")
        if block := _source_block(source, anchor):
            blocks.append(block)
    if finding.rule_id == "compiler.cs0161" and not any(
        block.language == "csharp" for block in blocks
    ):
        missing.append("Readable, verified C# source around the diagnostic is missing; "
                       "a CI snippet cannot establish the method's intended behavior.")
    if not selected:
        missing.append("No safe relevant source was supplied; provide the cited file or manifest "
                       "at the exact pipeline commit. No source was fetched.")
    if finding.rule_id in {"salesforce.metadata_dependency", "salesforce.csv_as_sobject",
                           "change.ci_path_case_mismatch"} and not proposals:
        missing.append("No safe exact-source patch could be established from the supplied files.")
    docs = [url for value in finding.documentation if (url := _http_url(value))]
    job_id = finding.job_id or (snapshot.job.external_id if snapshot is not None else None)
    return Remediation(
        finding_key=finding_identity(finding),
        project_key=(snapshot.repository.web_url
                     if snapshot is not None and _repository_identity(snapshot) else None),
        job_id=_text(job_id) if job_id is not None else None, rule_id=_text(finding.rule_id),
        summary=_text(finding.title), cause_confidence=cause, fix_confidence=fix_score,
        confidence_basis=list(dict.fromkeys(_text(value) for value in basis)),
        proposals=proposals, source_blocks=blocks,
        actions=[_text(value) for value in actions],
        missing_information=list(dict.fromkeys(_text(value) for value in missing)),
        documentation=list(dict.fromkeys(docs))[:_MAX_RESULTS] or [_TRACE_DOC],
    )


def build_verified_json_hunk(
    finding: Finding, snapshot: AnalysisSnapshot, original: CiConfigFile,
) -> Remediation | None:
    """Use authentic, ephemeral JSON to verify a small secret-free hunk only.

    Unlike a sanitized snapshot, the caller's fresh source may contain private
    values outside the hunk. No original source text is returned or retained.
    Parsed before/after documents must differ only in exact object-valued CSV
    inputs, and the complete resulting unified diff must require NO redaction.
    Any altered source, ambiguous JSON, or secret in the hunk rejects the proposal.
    """
    if finding.rule_id != "salesforce.csv_as_sobject" or not _same_job(finding, snapshot):
        return None
    source = _source(original, snapshot)
    if not source or not source.exact or not _data_config(source.path):
        return None
    content = original.content
    if (len(content.encode("utf-8", errors="replace")) > 1_000_000
            or _SOURCE_CONTROL.search(content) or re.search(r"\r(?!\n)", content)
            or _MARKED.search(content)):
        return None
    targets = {match["file"] for item in finding.evidence
               for match in _CSV_ERROR.finditer(_text(item.text))}
    if not targets:
        return None
    try:
        edits = _json_edits(content, targets)
        after = _replacement(content, edits)
        diff = _unified(source.path, content, after)
    except (_UnsafeSource, ValueError, RecursionError, UnicodeError):
        return None
    anchor = content.count("\n", 0, min(edit.start for edit in edits)) + 1
    # A safe hunk supplies a bounded, exact context block without copying any
    # unrelated configuration values into the response.
    lines = content.splitlines(keepends=True)
    start, end = max(0, anchor - 4), min(len(lines), anchor + 3)
    excerpt = "".join(lines[start:end])
    if not _unchanged(excerpt) or len(excerpt) > 10_000:
        return None
    plan = build_remediation(finding, snapshot, [])
    plan.proposals = [ProposedChange(
        title="Use the object API name for this data step",
        path=source.path, ref=original.ref, source_url=(source.url or "") + f"#L{anchor}",
        diff=diff,
        rationale="Parsed JSON differs only in exact CSV-valued object selectors. The displayed "
        "hunk is unchanged by redaction and matches the original file; other source values "
        "were neither changed nor returned.",
        condition="If this is the intended object API name in the target org",
        verification=[
            "Confirm the intended object and external-ID field in the target org.",
            "Validate the data-step configuration; leave the input filename and unrelated "
            "steps unchanged before an approved deployment.",
        ],
    )]
    plan.source_blocks = [SourceBlock(
        path=source.path, ref=original.ref, source_url=source.url,
        line_start=start + 1, line_end=end, content=excerpt, language="json",
    )]
    plan.fix_confidence = {"observed": 82, "likely": 60, "unknown": 30}[finding.confidence]
    plan.confidence_basis.append(
        "Fresh exact-commit JSON was verified in memory. Only a secret-free unchanged hunk "
        "is returned; the rest of the source is not included in this proposal.",
    )
    plan.missing_information = [
        "Target object existence, intended data-step scope and target validation results.",
    ]
    return plan