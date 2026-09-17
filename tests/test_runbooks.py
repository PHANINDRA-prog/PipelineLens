"""Offline registry contracts using identifiers and synthetic inputs, never traces."""

import ast
import builtins
import dataclasses
import io
import os
import re
import socket
import sys
from pathlib import Path
from types import ModuleType
from urllib.parse import urlsplit, urlunsplit

import pytest

from pipelinelens.services import runbooks
from pipelinelens.services.runbooks import Runbook, runbook_for

_CASES = (
    (
        "rlp.datasync_field_mapping_connection_reset",
        "deployment_failure",
        "rlp.datasync_transport",
    ),
    ("runner.job_timeout", "timeout", "runner.job_timeout"),
    ("runner.preparation_failed", "runner_infrastructure_failure", "runner.infrastructure"),
    ("runner.ssh_executor_unavailable", "runner_infrastructure_failure", "runner.infrastructure"),
    ("runner.image_pull_failed", "runner_infrastructure_failure", "runner.infrastructure"),
    ("runner.reported_system_failure", "runner_infrastructure_failure", "runner.infrastructure"),
    ("compiler.cs0161", "build_failure", "compiler.cs0161"),
    ("dependency.apt_release_expired", "dependency_failure", "apt.release_expired"),
    ("apt.release_expired", "dependency_failure", "apt.release_expired"),
    ("salesforce.metadata_dependency", "deployment_failure", "salesforce.metadata_dependency"),
    ("salesforce.apex_compile", "deployment_failure", "salesforce.metadata_validation"),
    ("salesforce.metadata_parse", "deployment_failure", "salesforce.metadata_validation"),
    ("salesforce.metadata_duplicate", "deployment_failure", "salesforce.metadata_validation"),
    ("salesforce.metadata_error", "deployment_failure", "salesforce.metadata_validation"),
    ("salesforce.component_failure", "deployment_failure", "salesforce.metadata_validation"),
    ("salesforce.validation_failed", "deployment_failure", "salesforce.metadata_validation"),
    ("salesforce.metadata_request_failed", "deployment_failure", "salesforce.metadata_validation"),
    ("salesforce.csv_as_sobject", "deployment_failure", "salesforce.csv_as_sobject"),
    (
        "salesforce.org_not_authenticated", "authentication_failure",
        "salesforce.org_not_authenticated",
    ),
    ("script.invalid_json", "script_input_failure", "script.invalid_json"),
    ("git.merge_conflict", "merge_conflict", "git.merge_conflict"),
    ("git.merge_approval_required", "merge_blocked", "git.merge_approval_required"),
    ("script.exec_format", "script_execution_failure", "script.exec_format"),
    ("script.not_callable", "script_execution_failure", "script.not_callable"),
)
_ALLOWED_HOSTS = {
    "docs.gitlab.com", "developer.salesforce.com", "manpages.debian.org",
    "learn.microsoft.com", "jqlang.org", "developer.mozilla.org",
}
_UNKNOWN_RULES = (
    "", "unknown", "future.new_condition", "git.merge_status_unresolved",
    "job.insufficient_evidence", "job.no_failure_observed", "script.nonzero_exit",
    "log.explicit_error", "artifact.upload_failed", "artifact.missing", "compiler.error",
    "compiler.build_failed", "dependency.resolution_failed", "operation.timeout",
    "salesforce.test_failure", "salesforce.coverage_failure", "deployment.failed",
    "auth.authentication_rejected", "sonar.scanner_error", "change.path_case_mismatch",
)


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("Runbook tests must not use the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)


@pytest.mark.parametrize(("rule_id", "category", "key"), _CASES)
def test_current_rule_mappings(rule_id: str, category: str, key: str) -> None:
    book = runbook_for(rule_id, category)
    assert isinstance(book, Runbook)
    assert book.key == key
    assert runbook_for(rule_id) is book
    assert runbook_for(rule_id, "unrelated_category") is book


@pytest.mark.parametrize(("rule_id", "category", "key"), _CASES)
def test_prefix_refinements_and_normalization(rule_id: str, category: str, key: str) -> None:
    assert runbook_for(rule_id + ".detail").key == key
    assert runbook_for(" \t" + rule_id.upper() + "\r\n", category.upper()).key == key
    for unsupported in (rule_id + "_different", rule_id + "0", "other." + rule_id):
        assert runbook_for(unsupported).key == "unknown"


@pytest.mark.parametrize("category", (
    "unknown", "build_failure", "deployment_failure", "dependency_failure", "timeout",
    "authentication_failure", "authorization_failure", "runner_infrastructure_failure",
    "test_failure", "quality_gate_failure", "merge_conflict", "merge_blocked",
    "script_input_failure", "script_execution_failure", "external_api_failure",
))
def test_unknown_is_never_promoted_by_a_category(category: str) -> None:
    fallback = runbook_for("unknown")
    for rule_id in _UNKNOWN_RULES:
        assert runbook_for(rule_id, category) is fallback
    assert "unknown" in fallback.summary.lower()
    assert "manual inspection" in fallback.applicability.lower()
    assert "not a verified fix" in fallback.applicability.lower()
    assert fallback.urls == ("https://docs.gitlab.com/ci/jobs/job_logs/#view-job-logs",)
    assert "trace" in " ".join(fallback.checks).lower()


def test_success_category_suppresses_specific_failure_hints() -> None:
    for rule_id, _, _ in _CASES:
        assert runbook_for(rule_id, " NO_FAILURE_OBSERVED ").key == "unknown"


@pytest.mark.parametrize("value", (
    None, 42, [], {}, "compiler.cs0161.", ".compiler.cs0161", "compiler..cs0161",
    "compiler.cs0161/path", "compiler.cs0161?token=synthetic-only",
    "compiler.cs0161#section", "compiler.cs0161\x00", "compiler.cs0161 error details",
    "https://docs.gitlab.com/ci/jobs/", "compiler.c\u04550161", "scr\u0131pt.invalid_json",
    "compiler.cs0161\nmore-text", "git.merge_conflict.<script>",
), ids=(
    "none", "number", "list", "mapping", "trailing-dot", "leading-dot", "empty-segment",
    "slash", "query", "fragment", "nul", "log-like", "url", "cyrillic", "unicode",
    "embedded-newline", "markup",
))
def test_malformed_identifiers_do_not_match(value: str) -> None:
    assert runbook_for(value).key == "unknown"


def test_identifier_length_is_bounded_without_truncation() -> None:
    prefix = "script.invalid_json."
    at_limit = prefix + "x" * (128 - len(prefix))
    assert runbook_for(at_limit).key == "script.invalid_json"
    assert runbook_for(at_limit + "x").key == "unknown"
    assert runbook_for(prefix + "x" * 1_000_000).key == "unknown"
    assert runbook_for("x" * 1_000_000, "build_failure").key == "unknown"
    assert runbook_for("unknown", "x" * 1_000_000).key == "unknown"


def test_lookup_never_echoes_or_retains_caller_values() -> None:
    before = repr(runbooks._RUNBOOKS)
    marker = "synthetic_sensitive_value_not_a_real_credential"
    for rule_id in ("future." + marker, "script.invalid_json." + marker):
        book = runbook_for(rule_id, "token=" + marker)
        assert marker not in repr(dataclasses.asdict(book))
    assert repr(runbooks._RUNBOOKS) == before
    assert marker not in before


@pytest.mark.parametrize("book", runbooks._RUNBOOKS, ids=lambda book: book.key)
def test_frozen_dataclass_and_bounded_content(book: Runbook) -> None:
    assert dataclasses.is_dataclass(book)
    assert [field.name for field in dataclasses.fields(book)] == [
        "key", "title", "summary", "checks", "urls", "reviewed_on", "applicability",
    ]
    assert re.fullmatch(r"[a-z][a-z0-9_.]*", book.key)
    assert 1 <= len(book.key) <= 64
    assert 1 <= len(book.title) <= 80
    assert 1 <= len(book.summary) <= 320
    assert 1 <= len(book.applicability) <= 240
    assert type(book.checks) is tuple and 1 <= len(book.checks) <= 4
    assert all(type(check) is str and 1 <= len(check) <= 240 for check in book.checks)
    assert type(book.urls) is tuple and 1 <= len(book.urls) <= 3
    assert book.reviewed_on == "2026-09-13"
    assert len(set(book.checks)) == len(book.checks)
    for field in dataclasses.fields(book):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(book, field.name, getattr(book, field.name))
    assert len({book, dataclasses.replace(book)}) == 1
    for text in (book.title, book.summary, book.applicability, *book.checks):
        assert text == text.strip() and text.isascii()
        assert "\n" not in text and "\r" not in text and "```" not in text
        assert not re.search(r"(?i)(?:token|password|secret)\s*[:=]\s*\S+", text)
        assert not re.search(r"[\w.+-]+@[\w.-]+\.[a-z]{2,}", text)
        assert "http" not in text.lower()  # Links belong only in the vetted URL field.


@pytest.mark.parametrize("book", runbooks._RUNBOOKS, ids=lambda book: book.key)
def test_links_are_normalized_public_https_topics_without_query_values(book: Runbook) -> None:
    assert len(set(book.urls)) == len(book.urls)
    for url in book.urls:
        parts = urlsplit(url)
        assert 1 <= len(url) <= 240 and url.isascii()
        assert url == url.strip() and not any(character.isspace() for character in url)
        assert parts.scheme == "https"
        assert parts.hostname in _ALLOWED_HOSTS
        assert parts.netloc == parts.hostname  # No userinfo, port or ambiguous authority.
        assert parts.username is None and parts.password is None and parts.port is None
        assert parts.path.startswith("/") and parts.path != "/"
        assert "//" not in parts.path
        assert not {".", ".."}.intersection(parts.path.split("/"))
        assert not parts.query and "?" not in url  # No search/telemetry/request values.
        assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", parts.fragment)
        assert not any(character in url for character in ("\\", "%", "<", ">", "@"))
        assert urlunsplit(parts) == url


def test_registry_is_small_unique_static_and_reachable() -> None:
    books = runbooks._RUNBOOKS
    assert type(books) is tuple and len(books) == 15  # Fourteen topics and a fallback.
    assert len({book.key for book in books}) == len(books)
    assert len({prefix for prefix, _ in runbooks._RULE_PREFIXES}) == len(runbooks._RULE_PREFIXES)
    assert {key for _, key in runbooks._RULE_PREFIXES} | {"unknown"} == {
        book.key for book in books
    }
    assert {runbook_for(rule_id).key for rule_id, _, _ in _CASES} | {"unknown"} == {
        book.key for book in books
    }


def test_safety_caveats_preserve_protections_and_uncertainty() -> None:
    apt = runbook_for("dependency.apt_release_expired")
    assert "Check-Valid-Until verification enabled" in " ".join(apt.checks)
    assert "signed source" in " ".join(apt.checks)
    assert "UTC" in " ".join(apt.checks)
    dependency = runbook_for("salesforce.metadata_dependency")
    assert "Retain a component" in " ".join(dependency.checks)
    assert "intentional removal" in " ".join(dependency.checks)
    assert "sandbox versus production" in dependency.applicability
    for rule_id in ("salesforce.validation_failed", "salesforce.metadata_request_failed"):
        assert "cause unknown" in runbook_for(rule_id).applicability
    assert "CI-owner review" in " ".join(runbook_for("runner.job_timeout").checks)
    assert "Retain approval requirements" in " ".join(
        runbook_for("git.merge_approval_required").checks
    )
    assert "placeholder result" in " ".join(runbook_for("compiler.cs0161").checks)
    assert "despite valid JSON" in " ".join(runbook_for("script.invalid_json").checks)
    assert "Only an explicit C# CS0161" in runbook_for("compiler.cs0161").applicability
    assert runbook_for("git.merge_conflict").urls != runbook_for(
        "git.merge_approval_required"
    ).urls


def test_module_imports_only_dataclass_and_has_no_dynamic_loading() -> None:
    tree = ast.parse(Path(runbooks.__file__).read_text(encoding="utf-8"))
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert len(imports) == 1
    node = imports[0]
    assert isinstance(node, ast.ImportFrom)
    assert node.level == 0 and node.module == "dataclasses"
    assert [(item.name, item.asname) for item in node.names] == [("dataclass", None)]
    forbidden = {"__import__", "eval", "exec", "compile", "open", "input", "globals", "locals"}
    assert not any(
        isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id in forbidden
        for item in ast.walk(tree)
    )
    assert not any(isinstance(item, ast.JoinedStr) for item in ast.walk(tree))


def test_fresh_module_execution_and_lookups_need_no_io(monkeypatch: pytest.MonkeyPatch) -> None:
    # Read only this public source before denying all file access. Execute in a
    # fresh namespace so a cached import cannot conceal import-time side effects.
    source = Path(runbooks.__file__).read_text(encoding="utf-8")
    compiled = compile(source, "<isolated-runbooks>", "exec")
    module = ModuleType("_isolated_runbooks")
    monkeypatch.setitem(sys.modules, module.__name__, module)
    imports = []

    def guarded_import(name: str, *args: object, **kwargs: object) -> ModuleType:
        imports.append(name)
        assert name == "dataclasses", "Unexpected runtime dependency"
        return dataclasses

    def forbidden_io(*args: object, **kwargs: object) -> None:
        raise AssertionError("Runbook import/lookup attempted I/O or environment access")

    module.__dict__["__builtins__"] = {
        **vars(builtins), "__import__": guarded_import, "open": forbidden_io,
    }
    with monkeypatch.context() as blocked:
        blocked.setattr(builtins, "open", forbidden_io)
        blocked.setattr(io, "open", forbidden_io)
        blocked.setattr(os, "open", forbidden_io)
        blocked.setattr(os, "getenv", forbidden_io)
        exec(compiled, module.__dict__)
        lookup = module.__dict__["runbook_for"]
        for rule_id, category, key in _CASES:
            assert lookup(rule_id, category).key == key
        assert lookup("future.unknown", "build_failure").key == "unknown"
    assert imports == ["dataclasses"]