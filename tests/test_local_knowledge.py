import json
import socket
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote

import pytest

from pipelinelens.services import local_knowledge
from pipelinelens.services.local_knowledge import KnowledgeCacheError, LocalKnowledgeCache

PROJECT = "https://gitlab.example/group/repository"
RULE = "compiler.cs0161"


@pytest.fixture(autouse=True)
def forbid_network(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("The local knowledge cache must not access the network")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)


def _config(ref="main", **extra):
    return {
        "entries": [{
            "path": ".gitlab-ci.yml", "ref": ref, "state": "readable",
            "relationship": "root", "detail": "Source inspected at this ref.",
            "source_url": "https://gitlab.example/group/repository/-/blob/main/.gitlab-ci.yml",
        }],
        "complete": True, "notes": ["Local includes inspected."], **extra,
    }


def _finding(**extra):
    return {
        "rule_id": RULE, "category": "build_failure", "title": "Missing return",
        "explanation": "The compiler rejected a reachable branch.",
        "fix": ["Review the method and test all branches."],
        "evidence": [{
            "text": "CS0161: not all code paths return a value", "path": "src/Program.cs",
            "line": 12, "source_url": "https://gitlab.example/group/repository/-/blob/main/src/Program.cs#L12",
        }],
        "confidence": "observed",
        "documentation": ["https://learn.microsoft.com/en-us/dotnet/csharp/misc/cs0161"],
        **extra,
    }


def _only_project(cache):
    return next(iter(cache.export()["projects"].values()))


def test_default_is_project_knowledge_directory_and_reads_are_lazy():
    cache = LocalKnowledgeCache()
    assert cache.directory == Path(local_knowledge.__file__).resolve().parents[3] / "data/knowledge"
    assert cache.path.name == "knowledge.json"


def test_empty_cache_has_portable_schema_and_no_files(tmp_path):
    directory = tmp_path / "knowledge"
    cache = LocalKnowledgeCache(directory)
    assert cache.summary() == {"observations": 0, "projects": 0, "confirmed_resolutions": 0}
    assert cache.lookup(PROJECT, RULE) == []
    data = json.loads(json.dumps(cache.export()))
    assert data["schema_version"] == 1
    assert data["projects"] == {}
    assert data["observations"] == data["resolutions"] == []
    assert "business-sensitive" in data["notice"]
    assert "Review" in data["notice"] and "unencrypted" in data["notice"]
    assert not directory.exists()


def test_round_trip_retains_only_latest_map_and_detached_observations(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    config, finding = _config(), _finding()
    observation = cache.remember(PROJECT, "main", config, [finding])
    assert observation["kind"] == "observation"
    assert observation["human_confirmed"] is False
    assert observation["fix_status"] == "unreviewed_suggestion"
    observation["findings"].clear()
    config["entries"].clear()
    finding["title"] = "mutated input"
    cache.remember(PROJECT, "next", _config("next"), [_finding()])
    fresh = LocalKnowledgeCache(tmp_path)
    data = fresh.export()
    assert len(data["observations"]) == 2
    assert data["observations"][0]["findings"][0]["title"] == "Missing return"
    assert _only_project(fresh)["source_map"]["ref"] == "next"
    assert _only_project(fresh)["source_map"]["entries"][0]["ref"] == "next"
    assert all("source_map" not in entry for entry in data["observations"])
    data["projects"].clear()
    assert fresh.summary()["projects"] == 1
    assert [path.name for path in tmp_path.iterdir()] == ["knowledge.json"]


def test_supplied_pattern_and_environment_secrets_are_redacted_everywhere(tmp_path, monkeypatch):
    token = "gl" + "pat-" + "abcdefghijklmnopqrstuv123456"
    unknown = "opaque supplied credential /+=&?"
    environment_secret = "nonstandard-environment-value-90871"
    custom_secret = "arbitrary-provider-secret-value-4271"
    monkeypatch.setenv("PIPELINELENS_GITLAB_TOKEN", environment_secret)
    monkeypatch.setenv("ANOTHER_PROVIDER_CLIENT_SECRET", custom_secret)
    combined = f"{token} {unknown} {environment_secret} {custom_secret}"
    cache = LocalKnowledgeCache(tmp_path)
    config = _config(notes=[combined, {"token": combined}])
    config["entries"][0].update(
        path=f"ci/{token}.yml", ref=combined, state=combined, relationship=combined,
        detail=combined,
        source_url=f"https://user:{unknown}@gitlab.example/source?token={token}",
    )
    finding = _finding(
        rule_id=combined, category=combined, title=combined, explanation=combined,
        confidence=combined, fix=[combined, {"api_key": combined}],
        evidence=[{
            "text": combined, "path": f"src/{token}.cs", "line": combined,
            "source_url": "https://gitlab.example/" + quote(unknown, safe=""),
        }],
    )
    returned = cache.remember(
        PROJECT + "/" + environment_secret, combined, config, [finding], (unknown,),
    )
    cache.record_resolution(PROJECT, RULE, combined, (unknown,))
    rendered = json.dumps([returned, cache.export(), cache.lookup(PROJECT, RULE)])
    raw = cache.path.read_text(encoding="utf-8")
    for secret in (token, unknown, environment_secret, custom_secret, quote(unknown, safe="")):
        assert secret not in rendered
        assert secret not in raw
    entry = next(
        project["source_map"]["entries"][0]
        for project in cache.export()["projects"].values() if project["source_map"]
    )
    assert entry["state"] == "unresolved"
    assert entry["relationship"] == "unsupported_include"
    assert returned["findings"][0]["confidence"] == "unknown"
    assert "REDACTED" in raw


def test_quoted_assignments_bearer_tokens_and_url_credentials_are_not_saved(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    text = (
        '''{"token": "quoted-credential-one", "api_key": "quoted-credential-two"} '''
        "CI_JOB_TOKEN='quoted-credential-three' "
        "Authorization: Basic basic-credential-four "
        "https://alice:password-five@gitlab.example/docs?private_token=query-six#token=fragment-seven"
    )
    cache.remember(PROJECT, "main", _config(notes=[text]), [_finding(explanation=text)])
    raw = cache.path.read_text(encoding="utf-8")
    for secret in (
        "quoted-credential-one", "quoted-credential-two", "quoted-credential-three",
        "basic-credential-four", "password-five", "query-six", "fragment-seven",
    ):
        assert secret not in raw
    assert "https://gitlab.example/docs" in raw


def test_explicit_secrets_scrub_existing_records_on_the_next_write(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    secret = "unrecognizable-original-value-548921"
    cache.remember(PROJECT, "main", _config(), [_finding(explanation=secret)])
    assert secret in cache.path.read_text(encoding="utf-8")
    cache.record_resolution(PROJECT, RULE, f"Human reviewed {secret}", (secret,))
    assert secret not in cache.path.read_text(encoding="utf-8")
    assert secret not in json.dumps(cache.export())


def test_new_secrets_can_collapse_existing_notes_without_corrupting_the_cache(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    secrets = ("unknown-note-one-29841", "unknown-note-two-90821")
    cache.remember(PROJECT, "main", _config(notes=list(secrets)), [_finding(
        fix=list(secrets), evidence=[{"text": secret} for secret in secrets],
    )])
    cache.record_resolution(PROJECT, RULE, "Reviewed correction", secrets)
    raw = cache.path.read_text(encoding="utf-8")
    assert all(secret not in raw for secret in secrets)
    assert cache.summary() == {"observations": 1, "projects": 1, "confirmed_resolutions": 1}


def test_new_secret_can_remove_an_existing_documentation_link(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    secret_url = "https://private-docs.example/internal-review"
    cache.remember(PROJECT, "main", _config(), [_finding(documentation=[secret_url])])
    cache.record_resolution(PROJECT, RULE, "Reviewed correction", (secret_url,))
    assert cache.export()["observations"][0]["findings"][0]["documentation"] == []
    assert secret_url not in cache.path.read_text(encoding="utf-8")


def test_exact_secrets_are_redacted_before_path_separator_normalization(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    secret = "opaque\\supplied\\credential-976512"
    config = _config()
    config["entries"][0]["path"] = "ci/" + secret + ".yml"
    cache.remember(PROJECT, "main", config, [], (secret,))
    raw = cache.path.read_text(encoding="utf-8")
    assert "opaque" not in raw and "credential-976512" not in raw


def test_redaction_precedes_truncation_and_oversized_text_is_not_partially_retained(tmp_path):
    secret = "unknown-credential-crossing-the-cutoff-197321"
    cache = LocalKnowledgeCache(tmp_path)
    finding = _finding(evidence=[{
        "text": "x" * 390 + secret,
        "path": "src/Program.cs", "line": 1,
    }], explanation="z" * 30_000 + secret)
    record = cache.remember(PROJECT, "main", _config(), [finding], (secret,))
    evidence = record["findings"][0]["evidence"][0]["text"]
    assert len(evidence) <= 400
    assert "unknown-cred" not in evidence
    assert "oversized" in record["findings"][0]["explanation"]
    assert "z" * 400 not in cache.path.read_text(encoding="utf-8")


def test_strict_allowlists_never_stringify_nested_objects_or_keep_snapshots(tmp_path):
    class UnsafeObject:
        def __str__(self):
            raise AssertionError("Nested values must never be stringified")

    nested = {"token": "raw-credential-marker", "logs": "full-log-marker"}
    nested["cycle"] = nested
    config = _config(
        token="top-level-credential-marker", raw=nested, yaml="entire-yaml-marker",
        mr_diff="entire-diff-marker", snapshot=UnsafeObject(),
        notes=[nested, UnsafeObject(), "a short note"],
    )
    config["entries"][0].update(token=nested, content="config-snapshot-marker", detail=nested)
    finding = _finding(
        token=nested, raw=nested, snapshot=nested, owner=nested, job_log="job-log-marker",
        title=UnsafeObject(), explanation=nested, fix=[nested, UnsafeObject(), "Review manually"],
        evidence=[{
            "text": nested, "path": UnsafeObject(), "line": nested,
            "source_url": nested, "token": nested, "content": "evidence-snapshot-marker",
        }],
    )
    cache = LocalKnowledgeCache(tmp_path)
    result = cache.remember(PROJECT, "main", config, [finding, nested, UnsafeObject()])
    raw = cache.path.read_text(encoding="utf-8")
    for marker in (
        "raw-credential-marker", "top-level-credential-marker", "full-log-marker",
        "entire-yaml-marker", "entire-diff-marker", "config-snapshot-marker",
        "job-log-marker", "evidence-snapshot-marker",
    ):
        assert marker not in raw
    assert result["findings"][0]["title"] == ""
    assert result["findings"][0]["fix"] == ["Review manually"]
    assert set(result["findings"][0]) == {
        "rule_id", "category", "title", "explanation", "fix", "evidence", "confidence",
        "documentation",
    }
    assert set(_only_project(cache)["source_map"]["entries"][0]) == {
        "path", "ref", "state", "relationship", "detail", "source_url",
    }


@pytest.mark.parametrize("path", [
    "../../secret-source", "%2e%2e/secret-source", "\\\\server\\secret-source",
    "C:\\credentials\\secret-source", "/etc/secret-source", "file:///secret-source",
    "javascript:secret-source", "ci/\x00secret-source.yml", "ci/name?token=secret-source",
])
def test_unsafe_paths_are_inert_and_do_not_survive(tmp_path, path):
    cache = LocalKnowledgeCache(tmp_path)
    config = _config()
    config["entries"][0]["path"] = path
    record = cache.remember(PROJECT, "main", config, [_finding(evidence=[{"path": path}])])
    assert "secret-source" not in json.dumps(record)
    assert "secret-source" not in cache.path.read_text(encoding="utf-8")
    assert "unsafe path" in _only_project(cache)["source_map"]["entries"][0]["path"]


def test_safe_http_docs_line_links_and_project_include_captions_survive(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    config = _config()
    config["entries"][0]["path"] = (
        "pipelinelens-gitlab-project://shared%2Fci?ref=main&file=templates%2Fbuild.yml"
    )
    record = cache.remember(PROJECT, "main", config, [_finding(documentation=[
        "https://docs.gitlab.com/ci/yaml/#include",
        "http://internal.example/docs?signature=not-for-storage",
        "javascript:alert(1)", "file:///credentials", "//external.example/path",
    ])])
    assert record["findings"][0]["documentation"] == [
        "https://docs.gitlab.com/ci/yaml/#include", "http://internal.example/docs",
    ]
    assert record["findings"][0]["evidence"][0]["source_url"].endswith("#L12")
    assert _only_project(cache)["source_map"]["entries"][0]["path"] == (
        "shared/ci/templates/build.yml @ main"
    )


@pytest.mark.parametrize("url", [
    "javascript:alert(1)", "data:text/plain,credential", "file:///credentials",
    "https://", "https://example.com:bad/path", "https://[invalid]/path",
    "https://example.com\\@evil.example/path", "https://example.com/%0asecret",
    "https://example.com/../private", "https://example.com/" + "x" * 3000,
])
def test_unsafe_source_urls_are_removed(tmp_path, url):
    cache = LocalKnowledgeCache(tmp_path)
    record = cache.remember(PROJECT, "main", _config(), [_finding(evidence=[{"source_url": url}])])
    assert record["findings"][0]["evidence"][0]["source_url"] is None


def test_only_explicit_confirmation_is_eligible_and_lookup_is_exact_and_limited(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    forged = _finding(
        human_confirmed=True, verified=True, resolution="not reviewed",
        confirmed_resolution="also not reviewed", kind="confirmed_resolution", confidence=1.0,
    )
    cache.remember(PROJECT, "main", _config(), [forged])
    assert cache.lookup(PROJECT, RULE) == []
    assert cache.summary()["confirmed_resolutions"] == 0
    for index in range(5):
        assert cache.record_resolution(PROJECT, RULE, f"Human-reviewed correction {index}") is None
    assert [item["resolution"] for item in cache.lookup(PROJECT, RULE)] == [
        "Human-reviewed correction 4", "Human-reviewed correction 3", "Human-reviewed correction 2",
    ]
    assert all(item["human_confirmed"] for item in cache.lookup(PROJECT, RULE))
    assert cache.lookup(PROJECT.replace("gitlab.example", "other-origin.example"), RULE) == []
    assert cache.lookup(PROJECT + "-other", RULE) == []
    assert cache.lookup(PROJECT, RULE.upper()) == []
    assert cache.lookup(PROJECT, "compiler.other") == []
    assert cache.summary() == {"observations": 1, "projects": 1, "confirmed_resolutions": 5}
    assert cache.export()["observations"][0]["human_confirmed"] is False
    result = cache.lookup(PROJECT, RULE)
    result[0]["resolution"] = "external mutation"
    assert cache.lookup(PROJECT, RULE)[0]["resolution"] == "Human-reviewed correction 4"


def test_redacted_identity_collisions_never_cross_project_or_rule_boundaries(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    secrets = ("private-identity-one", "private-identity-two")
    first, second = (PROJECT + "/" + value for value in secrets)
    first_rule, second_rule = secrets
    cache.record_resolution(first, first_rule, "First reviewed fix", secrets)
    cache.record_resolution(second, second_rule, "Second reviewed fix", secrets)
    assert len(cache.export()["projects"]) == 2
    assert cache.lookup(first, first_rule)[0]["resolution"] == "First reviewed fix"
    assert cache.lookup(second, second_rule)[0]["resolution"] == "Second reviewed fix"
    assert cache.lookup(first, second_rule) == cache.lookup(second, first_rule) == []
    assert all(value not in cache.path.read_text(encoding="utf-8") for value in secrets)


def test_duplicate_observations_and_confirmations_do_not_grow_the_cache(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    config = _config()
    config["entries"] *= 3
    first = cache.remember(PROJECT, "main", config, [_finding(), _finding()])
    second = cache.remember(PROJECT, "main", config, [_finding(), _finding()])
    assert first["id"] == second["id"]
    assert len(second["findings"]) == 1
    assert len(_only_project(cache)["source_map"]["entries"]) == 1
    for _ in range(3):
        cache.record_resolution(PROJECT, RULE, "Same reviewed fix")
    assert cache.summary() == {"observations": 1, "projects": 1, "confirmed_resolutions": 1}


def test_portable_export_can_be_copied_to_a_different_directory(tmp_path):
    first = LocalKnowledgeCache(tmp_path / "original")
    first.remember(PROJECT, "main", _config(), [_finding(title="Méthode échouée")])
    first.record_resolution(PROJECT, RULE, "Human checked all reachable branches.")
    exported = first.export()
    destination = tmp_path / "copied"
    destination.mkdir()
    (destination / "knowledge.json").write_text(json.dumps(exported), encoding="utf-8")
    copied = LocalKnowledgeCache(destination)
    assert copied.export() == exported
    assert copied.lookup(PROJECT, RULE) == first.lookup(PROJECT, RULE)
    assert copied.summary() == first.summary()
    assert str(tmp_path) not in json.dumps(exported)


def test_field_and_collection_caps_remove_excess_snapshots(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    config = _config(notes=[f"note {i}: " + "x" * 900 for i in range(50)])
    config["entries"] = [{**config["entries"][0], "path": f"ci/{i}.yml"} for i in range(100)]
    findings = [_finding(
        rule_id=f"rule.{i}", explanation="e" * 1000,
        fix=[f"fix {j}: " + "x" * 1000 for j in range(50)],
        evidence=[{"text": f"evidence {j}: " + "e" * 1000} for j in range(50)],
    ) for i in range(50)]
    record = cache.remember(PROJECT, "main", config, findings)
    source = _only_project(cache)["source_map"]
    assert len(source["entries"]) == local_knowledge.MAX_SOURCE_ENTRIES
    assert source["complete"] is False
    assert len(source["notes"]) <= local_knowledge.MAX_NOTES
    assert len(record["findings"]) == local_knowledge.MAX_FINDINGS
    for finding in record["findings"]:
        assert len(finding["fix"]) <= local_knowledge.MAX_FIXES
        assert len(finding["evidence"]) <= local_knowledge.MAX_EVIDENCE
        assert len(finding["explanation"]) <= 400
        assert all(len(item["text"]) <= 400 for item in finding["evidence"])
    assert cache.path.stat().st_size < local_knowledge.MAX_FILE_BYTES


def test_total_record_limit_is_200_and_keeps_latest_map(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    for index in range(202):
        cache.remember(PROJECT, f"ref-{index}", _config(f"ref-{index}"), [])
    cache.record_resolution(PROJECT, RULE, "Recent human confirmation")
    summary = cache.summary()
    assert summary["observations"] + summary["confirmed_resolutions"] == 200
    assert cache.export()["observations"][0]["ref"] == "ref-3"
    assert _only_project(cache)["source_map"]["ref"] == "ref-201"
    assert cache.lookup(PROJECT, RULE)[0]["human_confirmed"] is True


def test_project_limit_evicts_oldest_project_and_its_records(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    for index in range(local_knowledge.MAX_PROJECTS + 1):
        cache.record_resolution(f"{PROJECT}/{index}", RULE, f"Reviewed fix {index}")
    assert cache.summary()["projects"] == local_knowledge.MAX_PROJECTS
    assert cache.lookup(PROJECT + "/0", RULE) == []
    assert cache.lookup(f"{PROJECT}/{local_knowledge.MAX_PROJECTS}", RULE)


def test_byte_budget_eviction_and_failed_oversize_write_are_safe(tmp_path, monkeypatch):
    cache = LocalKnowledgeCache(tmp_path)
    cache.remember(PROJECT, "first", _config(), [_finding()])
    one_record_size = cache.path.stat().st_size
    monkeypatch.setattr(local_knowledge, "MAX_FILE_BYTES", one_record_size + 20)
    cache.remember(PROJECT, "other", _config(), [_finding()])
    assert cache.summary()["observations"] == 1
    assert cache.export()["observations"][0]["ref"] == "other"
    assert cache.path.stat().st_size <= one_record_size + 20
    before = cache.path.read_bytes()
    with pytest.raises(KnowledgeCacheError, match="size limit"):
        cache.remember(PROJECT, "third", _config(), [_finding(explanation="x" * 400)] * 20)
    assert cache.path.read_bytes() == before


def test_4mb_limit_is_checked_before_parsing_or_overwriting(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    cache.path.write_bytes(b" " * (4 * 1024 * 1024 + 1))
    assert local_knowledge.MAX_FILE_BYTES == 4 * 1024 * 1024
    for action in (cache.export, cache.summary, lambda: cache.remember(PROJECT, "main", {}, [])):
        with pytest.raises(KnowledgeCacheError, match="4 MB"):
            action()
    assert cache.path.stat().st_size == 4 * 1024 * 1024 + 1


@pytest.mark.parametrize("payload", [
    b"not-json-private-payload", b"\xff", b"[]", b'{"schema_version":99}',
    b'{"schema_version":1,"schema_version":1}', b'{"value":NaN}',
    b"[" * 2000 + b"]" * 2000,
])
def test_corrupt_cache_raises_controlled_errors_without_losing_original(tmp_path, payload):
    cache = LocalKnowledgeCache(tmp_path)
    cache.path.write_bytes(payload)
    with pytest.raises(KnowledgeCacheError) as caught:
        cache.remember(PROJECT, "main", _config(), [_finding()])
    assert "private-payload" not in str(caught.value)
    assert cache.path.read_bytes() == payload


@pytest.mark.parametrize("mutation", [
    lambda data: data.update(credentials={"token": "do-not-export"}),
    lambda data: data["observations"][0].update(human_confirmed=True),
    lambda data: data["observations"][0]["findings"][0].update(token="do-not-export"),
    lambda data: data["observations"].append(data["observations"][0]),
    lambda data: data["observations"][0].update(project_id="a" * 64),
    lambda data: data["resolutions"][0].update(human_confirmed=False),
    lambda data: data["observations"][0].update(recorded_at="not-a-date"),
])
def test_foreign_fields_and_inconsistent_portable_records_are_rejected(tmp_path, mutation):
    cache = LocalKnowledgeCache(tmp_path)
    cache.remember(PROJECT, "main", _config(), [_finding()])
    cache.record_resolution(PROJECT, RULE, "Reviewed fix")
    data = cache.export()
    mutation(data)
    cache.path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(KnowledgeCacheError):
        cache.export()


def test_atomic_replace_failure_keeps_original_and_cleans_temporary_file(tmp_path, monkeypatch):
    cache = LocalKnowledgeCache(tmp_path)
    cache.remember(PROJECT, "first", _config(), [])
    before = cache.path.read_bytes()

    def fail_replace(source, destination):
        assert Path(source).parent == tmp_path
        assert Path(destination) == cache.path
        assert json.loads(Path(source).read_text(encoding="utf-8"))["schema_version"] == 1
        raise OSError("simulated-private-error-detail")

    monkeypatch.setattr(local_knowledge.os, "replace", fail_replace)
    with pytest.raises(KnowledgeCacheError) as caught:
        cache.record_resolution(PROJECT, RULE, "Reviewed correction")
    assert "private-error-detail" not in str(caught.value)
    assert cache.path.read_bytes() == before
    assert list(tmp_path.iterdir()) == [cache.path]


def test_transient_windows_replace_errors_are_retried_atomically(tmp_path, monkeypatch):
    cache = LocalKnowledgeCache(tmp_path)
    cache.remember(PROJECT, "first", _config(), [])
    original_replace = local_knowledge.os.replace
    calls = []

    def transient_replace(source, destination):
        calls.append(source)
        if len(calls) <= 2:
            error = PermissionError("simulated Windows sharing conflict")
            error.winerror = 5
            raise error
        return original_replace(source, destination)

    monkeypatch.setattr(local_knowledge.os, "replace", transient_replace)
    cache.record_resolution(PROJECT, RULE, "Reviewed correction")
    assert 3 <= len(calls) <= 8
    assert cache.summary()["confirmed_resolutions"] == 1
    assert list(tmp_path.iterdir()) == [cache.path]


def test_permanent_windows_replace_error_has_a_bounded_retry_count(tmp_path, monkeypatch):
    cache = LocalKnowledgeCache(tmp_path)
    cache.remember(PROJECT, "first", _config(), [])
    original = cache.path.read_bytes()
    calls = []

    def denied_replace(source, destination):
        calls.append(source)
        error = PermissionError("simulated private Windows error")
        error.winerror = 5
        raise error

    monkeypatch.setattr(local_knowledge.os, "replace", denied_replace)
    with pytest.raises(KnowledgeCacheError):
        cache.record_resolution(PROJECT, RULE, "Reviewed correction")
    assert len(calls) == 8
    assert cache.path.read_bytes() == original
    assert list(tmp_path.iterdir()) == [cache.path]


def test_multiple_instances_share_a_thread_lock_and_do_not_lose_updates(tmp_path):
    def write(index):
        cache = LocalKnowledgeCache(tmp_path)
        if index % 2:
            cache.record_resolution(PROJECT, RULE, f"Confirmed correction {index}")
        else:
            cache.remember(PROJECT, f"ref-{index}", _config(), [_finding()])

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(executor.map(write, range(40)))
    cache = LocalKnowledgeCache(tmp_path)
    assert cache.summary() == {"observations": 20, "projects": 1, "confirmed_resolutions": 20}
    assert len(cache.lookup(PROJECT, RULE)) == 3
    assert list(tmp_path.iterdir()) == [cache.path]


@pytest.mark.parametrize("confidence", [True, float("nan"), float("inf"), 2.0, {"token": "secret"}])
def test_invalid_confidence_and_line_types_do_not_leak_into_json(tmp_path, confidence):
    cache = LocalKnowledgeCache(tmp_path)
    record = cache.remember(PROJECT, "main", _config(), [_finding(
        confidence=confidence, evidence=[{"line": True}, {"line": -1}, {"line": 10**50}],
    )])
    assert record["findings"][0]["confidence"] == "unknown"
    assert all(item["line"] is None for item in record["findings"][0]["evidence"])
    json.dumps(cache.export(), allow_nan=False)


def test_invalid_inputs_and_io_paths_fail_with_controlled_errors(tmp_path):
    cache = LocalKnowledgeCache(tmp_path)
    for action in (
        lambda: cache.remember("", "main", {}, []),
        lambda: cache.remember("\x00", "main", {}, []),
        lambda: cache.remember("x" * 5000, "main", {}, []),
        lambda: cache.remember(PROJECT, "main", [], []),
        lambda: cache.remember(PROJECT, "main", {}, {}),
        lambda: cache.remember(PROJECT, "main", {}, [], ["not-a-tuple"]),
        lambda: cache.record_resolution(PROJECT, RULE, ""),
        lambda: cache.record_resolution(PROJECT, RULE, "\x00\x00"),
        lambda: cache.record_resolution(PROJECT, RULE, {"token": "secret"}),
        lambda: cache.record_resolution(PROJECT, RULE, "x" * 20_000),
        lambda: cache.lookup(PROJECT, ""),
        lambda: LocalKnowledgeCache(str(tmp_path)),
    ):
        with pytest.raises(KnowledgeCacheError):
            action()
    cache.path.mkdir()
    with pytest.raises(KnowledgeCacheError, match="regular JSON file"):
        cache.summary()