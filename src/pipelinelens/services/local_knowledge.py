"""Local, portable evidence notes, deliberately separate from a credential vault.

Only ``record_resolution`` asserts human confirmation; callers must obtain that
confirmation themselves. No observation, confidence value, or suggested fix can
implicitly become a resolution. The JSON is not encrypted or authenticated.

One latest source map per project is retained, not historical YAML/log/diff
snapshots. Records are deduplicated and bounded, with oldest records/projects
evicted when necessary. Locks cover threads and multiple instances in this
process; this is not a multi-process database. There is no network/model access.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import tempfile
import threading
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import quote, quote_plus, unquote, urlsplit, urlunsplit

from pipelinelens.services.gitlab_includes import display_include_path
from pipelinelens.services.redaction import redact_text

SCHEMA_VERSION = 1
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_ENTRIES = 200  # Observations and confirmed resolutions combined.
MAX_PROJECTS = 50
MAX_SOURCE_ENTRIES = 40
MAX_FINDINGS = 20
MAX_EVIDENCE = 5
MAX_FIXES = 5
MAX_NOTES = 8
MAX_DOCUMENTATION = 5
MAX_TEXT_CHARS = 400
MAX_PATH_CHARS = 400
MAX_URL_CHARS = 2048
MAX_INPUT_CHARS = 16_384
MAX_IDENTITY_CHARS = 4096

EXPORT_NOTICE = (
    "Redaction is not a guarantee that business-sensitive data is absent. "
    "Review this portable, unencrypted JSON before copying or sharing it. "
    "Observations and suggested fixes are not verified resolutions; human-confirmed "
    "resolutions are user assertions. Nothing is uploaded automatically."
)

_DEFAULT_DIRECTORY = Path(__file__).resolve().parents[3] / "data" / "knowledge"
_LOCK = threading.RLock()
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_CONTROLS = re.compile(r"[\x00-\x1f\x7f]")
_URI = re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s<>\"']+", re.IGNORECASE)
_SECRET_ENV = re.compile(
    r"token|secret|password|passwd|credential|authorization|"
    r"(?:api|access|private|signing|encryption|session)[_-]?key|(?:^|_)pat(?:$|_)",
    re.IGNORECASE,
)
_AUTH_HEADER = re.compile(r"\bauthorization\s*:\s*(?:basic|bearer)\s+\S+", re.IGNORECASE)
_ASSIGNMENT = re.compile(
    r'''["']?\b(?:[\w.-]*(?:token|password|passwd|secret|credential|api[_-]?key|'''
    r'''access[_-]?key|private[_-]?key)[\w.-]*|pat)\b["']?\s*[:=]\s*'''
    r'''(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)''',
    re.IGNORECASE,
)
_STATES = {"readable", "unreadable", "unresolved"}
_RELATIONSHIPS = {"root", "local_include", "project_include", "unsupported_include"}
_CONFIDENCES = {"observed", "likely", "unknown"}
_CORRUPT = "Local knowledge cache is corrupt or unsupported; restore or remove its JSON file."


class KnowledgeCacheError(RuntimeError):
    """Controlled cache/input failure whose message never includes supplied data."""


def _fingerprint(value: dict) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _identity(value: str, kind: str, *, allow_empty: bool = False) -> str:
    if (
        type(value) is not str
        or len(value) > MAX_IDENTITY_CHARS
        or (not allow_empty and not value.strip())
        or _CONTROLS.search(value)
    ):
        raise KnowledgeCacheError("Cache identifiers must be nonempty, bounded strings.")
    # Hash exact identities, not redacted/truncated display labels. Never normalize
    # origins away or let two redacted labels match another project's resolution.
    return hashlib.sha256(
        kind.encode("ascii") + b"\0" + value.encode("utf-8", errors="surrogatepass")
    ).hexdigest()


def _items(value: object, limit: int) -> list:
    # Do not stringify mappings, models, generators, or arbitrary nested objects.
    return value[:limit] if type(value) is list else []


def _unique(values: list, *, enabled: bool = True) -> list:
    if not enabled:
        return values
    seen: set[str] = set()
    result = []
    for value in values:
        key = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)
        if key not in seen:
            seen.add(key)
            result.append(value)
    return result


class _Sanitizer:
    def __init__(self, secrets: tuple[str, ...] = ()) -> None:
        if type(secrets) is not tuple or any(type(value) is not str for value in secrets):
            raise KnowledgeCacheError("Explicit secrets must be a tuple of strings.")
        values = {value for value in secrets if value}
        values.update(
            value for name, value in os.environ.copy().items() if value and _SECRET_ENV.search(name)
        )
        # Fail closed rather than silently ignoring excess configured credentials.
        if len(values) > 256 or sum(map(len, values)) > 131_072:
            raise KnowledgeCacheError("The configured secret redaction budget is exceeded.")
        variants = set(values)
        for value in values:
            variants.update((quote(value, safe=""), quote_plus(value, safe="")))
            variants.add(json.dumps(value, ensure_ascii=True)[1:-1])
        variants.update(
            re.sub(r"%[0-9A-F]{2}", lambda match: match[0].lower(), value)
            for value in tuple(variants)
        )
        self._exact = (
            re.compile("|".join(
                re.escape(value) for value in sorted(variants, key=len, reverse=True)
            ))
            if variants else None
        )

    def _redact(self, value: str) -> str:
        if self._exact is not None:
            value = self._exact.sub("[REDACTED]", value)
        value = _AUTH_HEADER.sub("[REDACTED]", value)
        value = _ASSIGNMENT.sub("[REDACTED]", value)
        return redact_text(value)

    def text(self, value: object, limit: int = MAX_TEXT_CHARS) -> str | None:
        if type(value) is not str:
            return None
        # Never truncate *before* redaction: that can retain a partial credential.
        if len(value) > MAX_INPUT_CHARS:
            return "[OMITTED: oversized text]"
        value = self._redact(value)
        value = _URI.sub(lambda match: self.url(match[0]) or "[OMITTED: unsafe URL]", value)
        value = value.encode("utf-8", errors="replace").decode("utf-8")
        value = " ".join(_CONTROLS.sub(" ", value).split())
        return self._redact(value)[:limit]

    def url(self, value: object) -> str | None:
        if (
            type(value) is not str or len(value) > MAX_INPUT_CHARS
            or "\\" in value or any(char.isspace() for char in value)
            or _CONTROLS.search(value)
        ):
            return None
        if self._exact is not None and self._exact.search(value):
            return None
        try:
            parsed = urlsplit(value)
            host, port = parsed.hostname, parsed.port
            if parsed.scheme.lower() not in {"http", "https"} or not host:
                return None
            if self._redact(parsed.netloc) != parsed.netloc:
                return None
            if ":" in host:
                host = f"[{ipaddress.IPv6Address(host)}]"
            elif not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?", host):
                return None
            path = parsed.path
            for _ in range(3):
                path = unquote(path, errors="strict")
            if _CONTROLS.search(path) or "\\" in path or ".." in path.split("/"):
                return None
            path = quote(self._redact(path), safe="/:@-._~!$&'()*+,;=")
            fragment = self._redact(unquote(parsed.fragment, errors="strict"))
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", fragment):
                fragment = ""
            # Userinfo, all query parameters (including signed URLs), and unsafe
            # fragments are deliberately discarded. These links are never fetched.
            authority = host + (f":{port}" if port is not None else "")
            result = urlunsplit((parsed.scheme.lower(), authority, path, "", fragment))
            return result if len(result) <= MAX_URL_CHARS else None
        except (ValueError, UnicodeError):
            return None

    def path(self, value: object) -> str | None:
        if type(value) is not str:
            return None
        if len(value) > MAX_INPUT_CHARS:
            return "[OMITTED: oversized path]"
        if value.startswith(("http://", "https://")):
            safe_url = self.url(value)
            return (
                safe_url if safe_url and len(safe_url) <= MAX_PATH_CHARS
                else "[OMITTED: unsafe path]"
            )
        value = display_include_path(value)
        for _ in range(3):
            value = unquote(value)
        if _CONTROLS.search(value):
            return "[OMITTED: unsafe path]"
        value = self._redact(value)
        value = value.replace("\\", "/")
        while value.startswith("./"):
            value = value[2:]
        if (
            value.startswith(("/", "~")) or ":" in value or "?" in value or "#" in value
            or any(part in {"", ".", ".."} for part in value.split("/"))
        ):
            return "[OMITTED: unsafe path]"
        return self.text(value, MAX_PATH_CHARS)

    def strings(self, value: object, limit: int, *, deduplicate: bool = True) -> list[str]:
        return _unique(
            [text for item in _items(value, limit) if (text := self.text(item))],
            enabled=deduplicate,
        )

    def source_map(self, ref: object, config_access: dict, *, deduplicate: bool = True) -> dict:
        entries = []
        raw_entries = config_access.get("entries")
        for item in _items(raw_entries, MAX_SOURCE_ENTRIES):
            if type(item) is not dict:
                continue
            state = self.text(item.get("state"), 80)
            relationship = self.text(item.get("relationship"), 80)
            entries.append({
                "path": self.path(item.get("path")) or "[OMITTED: unknown path]",
                "ref": self.text(item.get("ref"), 256),
                "state": state if type(state) is str and state in _STATES else "unresolved",
                "relationship": (
                    relationship if type(relationship) is str and relationship in _RELATIONSHIPS
                    else "unsupported_include"
                ),
                "detail": self.text(item.get("detail")) or "",
                "source_url": self.url(item.get("source_url")),
            })
        notes = self.strings(config_access.get("notes"), MAX_NOTES, deduplicate=deduplicate)
        bounded = type(raw_entries) is list and len(raw_entries) == len(entries)
        if not bounded:
            notes = notes[:MAX_NOTES - 1] + ["Source map omitted invalid or excess entries."]
        return {
            "ref": self.text(ref, 256) or "",
            "entries": _unique(entries, enabled=deduplicate),
            "complete": config_access.get("complete") is True and bounded,
            "notes": notes,
        }

    def findings(self, findings: object, *, deduplicate: bool = True) -> list[dict]:
        result = []
        for item in _items(findings, MAX_FINDINGS):
            if type(item) is not dict or type(item.get("rule_id")) is not str:
                continue
            rule_id = self.text(item["rule_id"], 160)
            if not rule_id:
                continue
            evidence = []
            for entry in _items(item.get("evidence"), MAX_EVIDENCE):
                if type(entry) is not dict:
                    continue
                line = entry.get("line")
                evidence.append({
                    "text": self.text(entry.get("text")) or "",
                    "path": self.path(entry.get("path")),
                    "line": line if type(line) is int and 0 < line <= 1_000_000_000 else None,
                    "source_url": self.url(entry.get("source_url")),
                })
            confidence = item.get("confidence")
            if type(confidence) is str:
                confidence = self.text(confidence)
            if type(confidence) is str and confidence in _CONFIDENCES:
                pass
            elif type(confidence) in {int, float} and 0 <= confidence <= 1:
                if not math.isfinite(confidence):
                    confidence = "unknown"
            else:
                confidence = "unknown"
            result.append({
                "rule_id": rule_id,
                "category": self.text(item.get("category"), 80) or "unknown",
                "title": self.text(item.get("title"), 200) or "",
                "explanation": self.text(item.get("explanation")) or "",
                "fix": self.strings(item.get("fix"), MAX_FIXES, deduplicate=deduplicate),
                "evidence": _unique(evidence, enabled=deduplicate),
                "confidence": confidence,
                "documentation": _unique([
                    url for value in _items(item.get("documentation"), MAX_DOCUMENTATION)
                    if (url := self.url(value))
                ], enabled=deduplicate),
            })
        return _unique(result, enabled=deduplicate)


def _shape(raw: object, clean: object, *, field: str = "") -> None:
    """Reject foreign keys, nesting, and excess lists without traversing arbitrary data."""
    if type(clean) is dict:
        if type(raw) is not dict or raw.keys() != clean.keys():
            raise KnowledgeCacheError(_CORRUPT)
        for key in clean:
            _shape(raw[key], clean[key], field=key)
    elif type(clean) is list:
        if field == "documentation":
            # Newly supplied secrets can invalidate previously safe links. Permit
            # their removal while still rejecting nested values or excess input.
            if type(raw) is not list or len(raw) > MAX_DOCUMENTATION or any(
                type(item) is not str or len(item) > MAX_URL_CHARS for item in raw
            ):
                raise KnowledgeCacheError(_CORRUPT)
            return
        if type(raw) is not list or len(raw) != len(clean):
            raise KnowledgeCacheError(_CORRUPT)
        for old, new in zip(raw, clean, strict=True):
            _shape(old, new)
    elif type(raw) not in {str, int, float, bool, type(None)}:
        raise KnowledgeCacheError(_CORRUPT)
    elif type(raw) is str and len(raw) > MAX_INPUT_CHARS:
        raise KnowledgeCacheError(_CORRUPT)


def _json_object(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise KnowledgeCacheError(_CORRUPT)
    return result


def _invalid_constant(_value: str) -> None:
    raise KnowledgeCacheError(_CORRUPT)


class LocalKnowledgeCache:
    """A single bounded JSON file, lazily created in project-root/data/knowledge.

    ``project_key`` is a caller-supplied identity containing both origin and
    project, e.g. ``https://gitlab.example/group/repo``. Matching is exact and
    case-sensitive. Hashed map keys preserve identity even if display labels
    require redaction. Each project has only its latest ``source_map``.
    """

    def __init__(self, directory: Path | None = None) -> None:
        if directory is not None and not isinstance(directory, Path):
            raise KnowledgeCacheError("The cache directory must be a pathlib.Path.")
        self.directory = directory if directory is not None else _DEFAULT_DIRECTORY
        self.path = self.directory / "knowledge.json"

    def remember(
        self,
        project_key: str,
        ref: str,
        config_access: dict,
        findings: list[dict],
        secrets: tuple[str, ...] = (),
    ) -> dict:
        """Return a detached observation; fixes remain unreviewed suggestions.

        Only allowlisted scalar fields and bounded evidence/fix/doc lists are
        accepted. Duplicate sanitized observations refresh recency, not counts.
        Configured credential-like environment values and explicit secrets are
        redacted before truncation, persistence, and returned/exported data.
        """
        project_id = _identity(project_key, "project")
        ref_id = _identity(ref, "ref", allow_empty=True)
        if type(config_access) is not dict or type(findings) is not list:
            raise KnowledgeCacheError("Expected a configuration dictionary and a findings list.")
        sanitizer = _Sanitizer(secrets)
        source_map = sanitizer.source_map(ref, config_access)
        record = {
            "project_id": project_id,
            "project_key": sanitizer.text(project_key, 1024),
            "ref": sanitizer.text(ref, 256),
            "kind": "observation",
            "human_confirmed": False,
            "fix_status": "unreviewed_suggestion",
            "findings": sanitizer.findings(findings),
        }
        record["id"] = _fingerprint({**record, "ref_id": ref_id, "source_map": source_map})
        with _LOCK:
            data = self._load(sanitizer)
            record["recorded_at"] = datetime.now(UTC).isoformat()
            self._touch_project(data, project_id, record["project_key"], source_map)
            data["observations"] = [
                item for item in data["observations"] if item["id"] != record["id"]
            ]
            data["observations"].append(record)
            self._save(data)
        return record

    def record_resolution(
        self,
        project_key: str,
        rule_id: str,
        resolution: str,
        secrets: tuple[str, ...] = (),
    ) -> None:
        """Record an explicit human-confirmed resolution, never inferred learning."""
        project_id, rule_key = _identity(project_key, "project"), _identity(rule_id, "rule")
        if (
            type(resolution) is not str or not resolution.strip()
            or len(resolution) > MAX_INPUT_CHARS
        ):
            raise KnowledgeCacheError("A resolution must be bounded, nonempty text.")
        sanitizer = _Sanitizer(secrets)
        safe_resolution = sanitizer.text(resolution)
        if not safe_resolution:
            raise KnowledgeCacheError("A resolution must contain readable text.")
        record = {
            "project_id": project_id,
            "project_key": sanitizer.text(project_key, 1024),
            "rule_key": rule_key,
            "rule_id": sanitizer.text(rule_id, 160),
            "kind": "confirmed_resolution",
            "human_confirmed": True,
            "resolution": safe_resolution,
        }
        record["id"] = _fingerprint(record)
        with _LOCK:
            data = self._load(sanitizer)
            record["recorded_at"] = datetime.now(UTC).isoformat()
            self._touch_project(data, project_id, record["project_key"])
            data["resolutions"] = [
                item for item in data["resolutions"] if item["id"] != record["id"]
            ]
            data["resolutions"].append(record)
            self._save(data)

    def summary(self) -> dict:
        """Return retained counts, not cumulative totals before eviction."""
        with _LOCK:
            data = self._load(_Sanitizer())
            return {
                "observations": len(data["observations"]),
                "projects": len(data["projects"]),
                "confirmed_resolutions": len(data["resolutions"]),
            }

    def export(self) -> dict:
        """Return a detached, JSON-serializable copy with a mandatory review notice."""
        with _LOCK:
            return self._load(_Sanitizer())

    def lookup(self, project_key: str, rule_id: str) -> list[dict]:
        """Return at most three newest human confirmations for this exact project/rule."""
        project_id, rule_key = _identity(project_key, "project"), _identity(rule_id, "rule")
        with _LOCK:
            data = self._load(_Sanitizer())
            return [
                item for item in reversed(data["resolutions"])
                if item["project_id"] == project_id and item["rule_key"] == rule_key
                and item["human_confirmed"] is True
            ][:3]

    @staticmethod
    def _empty() -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "notice": EXPORT_NOTICE,
            "projects": {},
            "observations": [],
            "resolutions": [],
        }

    def _load(self, sanitizer: _Sanitizer) -> dict:
        try:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise KnowledgeCacheError("The local knowledge cache must be a regular JSON file.")
            if info.st_size > MAX_FILE_BYTES:
                raise KnowledgeCacheError("The local knowledge cache exceeds the 4 MB size limit.")
            with self.path.open("rb") as stream:
                payload = stream.read(MAX_FILE_BYTES + 1)
            if len(payload) > MAX_FILE_BYTES:
                raise KnowledgeCacheError("The local knowledge cache exceeds the 4 MB size limit.")
        except FileNotFoundError:
            return self._empty()
        except OSError:
            raise KnowledgeCacheError("The local knowledge cache could not be read.") from None
        try:
            raw = json.loads(
                payload.decode("utf-8"), object_pairs_hook=_json_object,
                parse_constant=_invalid_constant,
            )
            return self._validate(raw, sanitizer)
        except (ValueError, TypeError, KeyError, RecursionError):
            raise KnowledgeCacheError(_CORRUPT) from None

    def _validate(self, raw: object, sanitizer: _Sanitizer) -> dict:
        if (
            type(raw) is not dict or type(raw.get("schema_version")) is not int
            or raw["schema_version"] != SCHEMA_VERSION
            or type(raw.get("projects")) is not dict or len(raw["projects"]) > MAX_PROJECTS
            or type(raw.get("observations")) is not list
            or type(raw.get("resolutions")) is not list
            or len(raw["observations"]) + len(raw["resolutions"]) > MAX_ENTRIES
        ):
            raise KnowledgeCacheError(_CORRUPT)
        clean = self._empty()
        for project_id, project in raw["projects"].items():
            if not _HASH.fullmatch(project_id) or type(project) is not dict:
                raise KnowledgeCacheError(_CORRUPT)
            label = project.get("project_key")
            if type(label) is not str or not label:
                raise KnowledgeCacheError(_CORRUPT)
            source = project.get("source_map")
            if source is not None and type(source) is not dict:
                raise KnowledgeCacheError(_CORRUPT)
            clean["projects"][project_id] = {
                "project_key": sanitizer.text(label, 1024),
                "source_map": (
                    sanitizer.source_map(source.get("ref"), source, deduplicate=False)
                    if source else None
                ),
            }
        seen: set[str] = set()
        referenced: set[str] = set()
        collections = (("observations", "observation"), ("resolutions", "confirmed_resolution"))
        for collection, kind in collections:
            for item in raw[collection]:
                if type(item) is not dict:
                    raise KnowledgeCacheError(_CORRUPT)
                record_id, project_id = item.get("id"), item.get("project_id")
                if (
                    type(record_id) is not str or not _HASH.fullmatch(record_id)
                    or record_id in seen
                    or type(project_id) is not str or project_id not in clean["projects"]
                    or item.get("kind") != kind
                    or item.get("human_confirmed") is not (collection == "resolutions")
                    or item.get("project_key") != raw["projects"][project_id]["project_key"]
                ):
                    raise KnowledgeCacheError(_CORRUPT)
                stamp = item.get("recorded_at")
                if (
                    type(stamp) is not str or len(stamp) > 40
                    or datetime.fromisoformat(stamp).tzinfo != UTC
                ):
                    raise KnowledgeCacheError(_CORRUPT)
                seen.add(record_id)
                referenced.add(project_id)
                record = {
                    "id": record_id, "project_id": project_id,
                    "project_key": clean["projects"][project_id]["project_key"],
                    "recorded_at": stamp, "kind": kind,
                    "human_confirmed": collection == "resolutions",
                }
                if collection == "observations":
                    if (
                        item.get("fix_status") != "unreviewed_suggestion"
                        or type(item.get("ref")) is not str
                    ):
                        raise KnowledgeCacheError(_CORRUPT)
                    record.update(
                        ref=sanitizer.text(item.get("ref"), 256),
                        fix_status="unreviewed_suggestion",
                        findings=sanitizer.findings(item.get("findings"), deduplicate=False),
                    )
                else:
                    rule_key = item.get("rule_key")
                    if type(rule_key) is not str or not _HASH.fullmatch(rule_key):
                        raise KnowledgeCacheError(_CORRUPT)
                    if (
                        type(item.get("rule_id")) is not str or not item["rule_id"].strip()
                        or type(item.get("resolution")) is not str or not item["resolution"].strip()
                    ):
                        raise KnowledgeCacheError(_CORRUPT)
                    record.update(
                        rule_key=rule_key, rule_id=sanitizer.text(item.get("rule_id"), 160),
                        resolution=sanitizer.text(item.get("resolution")),
                    )
                clean[collection].append(record)
        if referenced != clean["projects"].keys():
            raise KnowledgeCacheError(_CORRUPT)
        _shape(raw, clean)
        return clean

    @staticmethod
    def _touch_project(
        data: dict, project_id: str, label: str, source_map: dict | None = None,
    ) -> None:
        project = data["projects"].pop(project_id, {"source_map": None})
        project["project_key"] = label
        if source_map is not None:
            project["source_map"] = source_map
        data["projects"][project_id] = project
        for collection in ("observations", "resolutions"):
            for item in data[collection]:
                if item["project_id"] == project_id:
                    item["project_key"] = label

    @staticmethod
    def _drop_project(data: dict, project_id: str) -> None:
        data["projects"].pop(project_id)
        for name in ("observations", "resolutions"):
            data[name] = [item for item in data[name] if item["project_id"] != project_id]

    @staticmethod
    def _evict_oldest(data: dict) -> None:
        name = min(
            (name for name in ("observations", "resolutions") if data[name]),
            key=lambda name: data[name][0]["recorded_at"],
        )
        removed = data[name].pop(0)
        if not any(
            item["project_id"] == removed["project_id"]
            for name in ("observations", "resolutions") for item in data[name]
        ):
            data["projects"].pop(removed["project_id"], None)

    def _save(self, data: dict) -> None:
        while len(data["projects"]) > MAX_PROJECTS:
            self._drop_project(data, next(iter(data["projects"])))
        while len(data["observations"]) + len(data["resolutions"]) > MAX_ENTRIES:
            self._evict_oldest(data)
        while True:
            payload = json.dumps(
                data, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
            if len(payload) <= MAX_FILE_BYTES:
                break
            if len(data["observations"]) + len(data["resolutions"]) <= 1:
                raise KnowledgeCacheError("The sanitized entry exceeds the cache size limit.")
            self._evict_oldest(data)
        temporary: Path | None = None
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.directory, prefix=".knowledge-", suffix=".tmp", delete=False,
            ) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            # Windows scanners can briefly hold a just-read file. Retry only
            # sharing/access-denied errors, without an unbounded wait or a
            # non-atomic delete/rename fallback. Permanent errors preserve disk.
            for attempt in range(8):
                try:
                    os.replace(temporary, self.path)
                    break
                except PermissionError as error:
                    if getattr(error, "winerror", None) not in {5, 32, 33} or attempt == 7:
                        raise
        except OSError:
            raise KnowledgeCacheError("Local knowledge could not be saved atomically.") from None
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass