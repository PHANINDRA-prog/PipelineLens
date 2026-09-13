"""Offline vault tests. All tokens are synthetic and all storage uses tmp_path.

FakeProtector is intentionally insecure, authenticated XOR for test portability,
not an alternative production cipher. The Windows-only smoke test uses real
current-user DPAPI, but never opens the user's actual credential directory.
"""

import ctypes
import hmac
import json
import os
import socket
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, fields
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest

from pipelinelens.services import credentials
from pipelinelens.services.credentials import CredentialVault, CredentialVaultError, SavedCredential

_HOST = "https://gitlab.example.test"
_PROJECT = "group/project"
_TOKEN = "synthetic-dummy-token-only-for-tests"
_LIMIT = 1024 * 1024


class FakeProtector:
    """Reversible test-only transformation with tamper detection, not encryption."""

    _prefix = b"PL-TEST-ONLY\x00"
    _key = b"synthetic-test-only-key"

    def __init__(self) -> None:
        self.protect_calls = 0
        self.unprotect_calls = 0

    def protect(self, data: bytes) -> bytes:
        self.protect_calls += 1
        body = bytes(value ^ 0xA5 for value in data)
        return self._prefix + hmac.digest(self._key, body, "sha256") + body

    def unprotect(self, data: bytes) -> bytes:
        self.unprotect_calls += 1
        offset = len(self._prefix)
        tag, body = data[offset:offset + 32], data[offset + 32:]
        if not data.startswith(self._prefix) or not hmac.compare_digest(
            tag, hmac.digest(self._key, body, "sha256"),
        ):
            # Deliberately unsafe backend diagnostics must never reach callers.
            raise ValueError(f"{_TOKEN}: synthetic unprotect diagnostic")
        return bytes(value ^ 0xA5 for value in body)


@pytest.fixture(autouse=True)
def offline_and_isolated(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "isolated-local-app-data"))

    def forbidden(*args, **kwargs):
        pytest.fail("Credential vault tests must not perform network calls")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        monkeypatch.setattr(socket, name, forbidden)
    for name in ("connect", "connect_ex", "sendto"):
        monkeypatch.setattr(socket.socket, name, forbidden)


@pytest.fixture
def protector() -> FakeProtector:
    return FakeProtector()


@pytest.fixture
def vault(tmp_path: Path, protector: FakeProtector) -> CredentialVault:
    return CredentialVault(tmp_path / "vault", protector=protector)


def _path(tmp_path: Path) -> Path:
    return tmp_path / "vault" / "vault.dpapi"


def _record(**changes) -> dict:
    return {
        "id": str(uuid4()), "host": _HOST, "token": _TOKEN, "projects": [_PROJECT], **changes,
    }


def _seed(tmp_path: Path, protector: FakeProtector, plaintext: bytes) -> bytes:
    ciphertext = protector.protect(plaintext)
    path = _path(tmp_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(ciphertext)
    return ciphertext


def _invoke(vault: CredentialVault, operation: str, credential_id: str):
    if operation == "save":
        return vault.save(_HOST, "group/fresh", "synthetic-dummy-new-token")
    if operation == "candidates":
        return vault.candidates(_HOST, _PROJECT)
    if operation == "zero_candidates":
        return vault.candidates(_HOST, _PROJECT, limit=0)
    if operation == "metadata":
        return vault.metadata()
    if operation == "mark_verified":
        return vault.mark_verified(credential_id, _HOST, "group/fresh")
    if operation == "forget":
        return vault.forget(credential_id)
    raise AssertionError("Unknown test operation")


def _assert_safe(error: CredentialVaultError, *sensitive: str) -> None:
    rendered = "".join(traceback.format_exception(error))
    for value in (_TOKEN, *sensitive):
        assert value not in str(error)
        assert value not in repr(error)
        assert value not in rendered
    assert error.__cause__ is None


def test_no_implicit_save_or_directory_creation(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
) -> None:
    assert vault.available is True
    assert vault.metadata() == []
    assert vault.candidates(_HOST, _PROJECT) == []
    assert vault.forget(str(uuid4())) is False
    with pytest.raises(CredentialVaultError):
        vault.mark_verified(str(uuid4()), _HOST, _PROJECT)
    assert protector.protect_calls == protector.unprotect_calls == 0
    assert not _path(tmp_path).parent.exists()


def test_default_location_is_outside_portable_project_data(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, protector: FakeProtector,
) -> None:
    local_app_data, portable = tmp_path / "profile-cache", tmp_path / "portable-project"
    portable.mkdir()
    monkeypatch.chdir(portable)
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    vault = CredentialVault(protector=protector)
    assert not local_app_data.exists()
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    expected = local_app_data / "PipelineLens" / "credentials" / "vault.dpapi"
    assert expected.is_file()
    assert list(portable.iterdir()) == []
    reopened = CredentialVault(protector=FakeProtector())
    assert reopened.candidates(_HOST, _PROJECT)[0].credential_id == credential_id


@pytest.mark.parametrize("environment_value", [None, "relative-profile-cache", ""])
def test_missing_or_relative_default_location_never_falls_back(
    environment_value, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    monkeypatch.chdir(tmp_path)
    if environment_value is None:
        monkeypatch.delenv("LOCALAPPDATA", raising=False)
    else:
        monkeypatch.setenv("LOCALAPPDATA", environment_value)
    vault = CredentialVault(protector=FakeProtector())
    assert vault.available is False
    with pytest.raises(CredentialVaultError, match="unavailable"):
        vault.save(_HOST, _PROJECT, _TOKEN)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("platform_name", ["nt", "posix"])
def test_production_availability_is_windows_only(
    platform_name: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    # Replace this module's OS view, not global os.name (which would break Path).
    platform = SimpleNamespace(**vars(os))
    platform.name = platform_name
    monkeypatch.setattr(credentials, "os", platform)
    backend = Mock(side_effect=AssertionError("No eager DPAPI initialization"))
    monkeypatch.setattr(credentials, "_DPAPIProtector", backend)
    vault = CredentialVault(tmp_path / "vault")
    assert vault.available is (platform_name == "nt")
    if platform_name != "nt":
        for operation in ("save", "candidates", "metadata", "mark_verified", "forget"):
            with pytest.raises(CredentialVaultError, match="unavailable"):
                _invoke(vault, operation, str(uuid4()))
    backend.assert_not_called()
    assert not _path(tmp_path).exists()


def test_documented_test_injection_works_without_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path,
) -> None:
    platform = SimpleNamespace(**vars(os))
    platform.name = "posix"
    monkeypatch.setattr(credentials, "os", platform)
    monkeypatch.setattr(credentials, "_DPAPIProtector", Mock(side_effect=AssertionError))
    vault = CredentialVault(tmp_path / "vault", protector=FakeProtector())
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    assert vault.available
    assert vault.candidates(_HOST, _PROJECT)[0].credential_id == credential_id


def test_round_trip_encrypts_entire_document_with_no_plaintext_index(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
) -> None:
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    assert str(UUID(credential_id)) == credential_id
    assert UUID(credential_id).version == 4
    path = _path(tmp_path)
    assert list(path.parent.iterdir()) == [path]
    ciphertext = path.read_bytes()
    for value in (credential_id, _TOKEN, _HOST, _PROJECT, '"version"', '"credentials"'):
        assert value.encode() not in ciphertext
    assert json.loads(protector.unprotect(ciphertext)) == {
        "version": 1,
        "credentials": [
            {"id": credential_id, "host": _HOST, "token": _TOKEN, "projects": [_PROJECT]},
        ],
    }
    reopened = CredentialVault(path.parent, protector=FakeProtector())
    assert reopened.candidates(_HOST, _PROJECT) == [
        SavedCredential(credential_id, _TOKEN, (_PROJECT,)),
    ]
    assert reopened.metadata() == [{"id": credential_id, "host": _HOST, "projects": [_PROJECT]}]


def test_candidate_is_frozen_and_neither_id_nor_token_leaks_through_repr() -> None:
    credential_id = str(uuid4())
    candidate = SavedCredential(credential_id, _TOKEN, (_PROJECT,))
    assert isinstance(candidate.project_paths, tuple)
    for rendered in (repr(candidate), str(candidate), f"{candidate}", repr([candidate]),
                     repr({"candidate": candidate})):
        assert credential_id not in rendered
        assert _TOKEN not in rendered
    assert {item.name for item in fields(candidate) if not item.repr} == {"credential_id", "token"}
    for name in ("credential_id", "token", "project_paths"):
        with pytest.raises(FrozenInstanceError):
            setattr(candidate, name, None)


def test_candidates_prioritize_exact_project_repeatably_without_writes(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
) -> None:
    exact_old = vault.save(_HOST, _PROJECT, _TOKEN)
    fallback_old = vault.save(_HOST, "group/other", "synthetic-dummy-fallback-old")
    exact_new = vault.save(_HOST, _PROJECT, "synthetic-dummy-exact-new")
    fallback_new = vault.save(_HOST, "group/other", "synthetic-dummy-fallback-new")
    vault.save("https://other.example.test", _PROJECT, "synthetic-dummy-other-host")
    before, writes = _path(tmp_path).read_bytes(), protector.protect_calls
    for _ in range(3):
        assert [item.credential_id for item in vault.candidates(_HOST, _PROJECT)] == [
            exact_new, exact_old, fallback_new, fallback_old,
        ]
        assert len(vault.candidates(_HOST, "group/not-yet-verified")) == 4
    assert all("group/not-yet-verified" not in item["projects"] for item in vault.metadata())
    assert _path(tmp_path).read_bytes() == before
    assert protector.protect_calls == writes


@pytest.mark.parametrize("limit", [0, 1, 5, 20, 1000])
def test_candidate_limits(vault: CredentialVault, limit: int) -> None:
    for index in range(7):
        vault.save(_HOST, _PROJECT, f"synthetic-dummy-token-{index}")
    assert len(vault.candidates(_HOST, _PROJECT)) == 5
    assert len(vault.candidates(_HOST, _PROJECT, limit)) == min(limit, 7)


@pytest.mark.parametrize("limit", [-1, True, 1.5, "5", None])
def test_invalid_candidate_limits_are_safe(vault: CredentialVault, limit) -> None:
    with pytest.raises(CredentialVaultError) as error:
        vault.candidates(_HOST, _PROJECT, limit)
    _assert_safe(error.value)


@pytest.mark.parametrize(("supplied", "normalized"), [
    ("HTTPS://GITLAB.EXAMPLE.TEST.:443/api/v4/", _HOST),
    ("https://BÜCHER.example:443/", "https://xn--bcher-kva.example"),
    ("https://[0:0:0:0:0:0:0:1]:443/api/v4", "https://[::1]"),
    ("http://LOCALHOST:80/api/v4/", "http://localhost"),
])
def test_origins_use_existing_normalization(
    vault: CredentialVault, supplied: str, normalized: str,
) -> None:
    credential_id = vault.save(supplied, _PROJECT, _TOKEN)
    assert vault.candidates(normalized, _PROJECT)[0].credential_id == credential_id
    vault.mark_verified(credential_id, supplied, "group/fresh")
    assert vault.metadata() == [
        {"id": credential_id, "host": normalized, "projects": [_PROJECT, "group/fresh"]},
    ]


@pytest.mark.parametrize(("saved_origin", "other_origin"), [
    (_HOST, "https://other.example.test"),
    (_HOST, "https://gitlab.example.test.evil.test"),
    (_HOST, "https://gitlab.example.test:8443"),
    ("https://localhost", "http://localhost"),
    ("http://localhost:8000", "http://localhost:8001"),
    ("https://[::1]", "https://[::1]:8443"),
])
def test_origin_isolation_includes_scheme_port_and_verified_associations(
    vault: CredentialVault, saved_origin: str, other_origin: str,
) -> None:
    first_id = vault.save(saved_origin, _PROJECT, _TOKEN)
    assert vault.candidates(other_origin, _PROJECT) == []
    with pytest.raises(CredentialVaultError):
        vault.mark_verified(first_id, other_origin, "group/fresh")
    assert vault.metadata()[0]["projects"] == [_PROJECT]
    # Equal token strings explicitly saved for different origins must not merge.
    other_id = vault.save(other_origin, _PROJECT, _TOKEN)
    assert other_id != first_id
    assert [item.credential_id for item in vault.candidates(saved_origin, _PROJECT)] == [first_id]
    assert [item.credential_id for item in vault.candidates(other_origin, _PROJECT)] == [other_id]


def test_token_equality_deduplicates_only_explicitly_saved_or_verified_projects(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
) -> None:
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    before, writes = _path(tmp_path).read_bytes(), protector.protect_calls
    assert vault.save(_HOST + ":443/api/v4/", _PROJECT, _TOKEN) == credential_id
    assert _path(tmp_path).read_bytes() == before
    assert protector.protect_calls == writes
    assert vault.save(_HOST, "group/second", _TOKEN) == credential_id
    vault.mark_verified(credential_id, _HOST, "group/third")
    vault.mark_verified(credential_id, _HOST, "group/third")
    assert vault.metadata() == [{
        "id": credential_id, "host": _HOST, "projects": [_PROJECT, "group/second", "group/third"],
    }]
    assert vault.candidates(_HOST, "group/not-verified")[0].project_paths == (
        _PROJECT, "group/second", "group/third",
    )
    # Tokens are compared literally, not case-folded or keyed by a fingerprint.
    assert vault.save(_HOST, _PROJECT, _TOKEN.upper()) != credential_id


def test_mark_verified_updates_only_the_selected_credential(
    vault: CredentialVault, tmp_path: Path,
) -> None:
    first_id = vault.save(_HOST, _PROJECT, _TOKEN)
    second_id = vault.save(_HOST, _PROJECT, "synthetic-dummy-second-token")
    assert vault.candidates(_HOST, "group/fresh")[0].credential_id == second_id
    vault.mark_verified(first_id, _HOST, "group/fresh")
    assert vault.candidates(_HOST, "group/fresh")[0].credential_id == first_id
    assert vault.metadata()[1]["projects"] == [_PROJECT]
    before = _path(tmp_path).read_bytes()
    with pytest.raises(CredentialVaultError):
        vault.mark_verified(str(uuid4()), _HOST, "group/fresh")
    assert _path(tmp_path).read_bytes() == before


def test_metadata_is_a_detached_allowlist_without_tokens_or_fingerprints(
    vault: CredentialVault,
) -> None:
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    metadata = vault.metadata()
    assert metadata == [{"id": credential_id, "host": _HOST, "projects": [_PROJECT]}]
    assert set(metadata[0]) == {"id", "host", "projects"}
    assert _TOKEN not in json.dumps(metadata)
    metadata[0]["projects"].append("group/unverified")
    metadata[0]["host"] = "https://other.example.test"
    metadata.clear()
    assert vault.metadata() == [{"id": credential_id, "host": _HOST, "projects": [_PROJECT]}]


def test_forget_is_persistent_idempotent_and_does_not_remove_other_origins(
    vault: CredentialVault, tmp_path: Path, protector: FakeProtector,
) -> None:
    first_id = vault.save(_HOST, _PROJECT, _TOKEN)
    other_host = "https://other.example.test"
    second_id = vault.save(other_host, _PROJECT, _TOKEN)
    assert vault.forget(first_id) is True
    assert vault.forget(first_id) is False
    reopened = CredentialVault(_path(tmp_path).parent, protector=FakeProtector())
    assert reopened.candidates(_HOST, _PROJECT) == []
    assert reopened.candidates(other_host, _PROJECT)[0].credential_id == second_id
    assert reopened.forget(second_id) is True
    assert vault.metadata() == []
    path = _path(tmp_path)
    assert json.loads(protector.unprotect(path.read_bytes())) == {"version": 1, "credentials": []}
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize("base_url", [
    "not-a-url", "http://gitlab.example.test", "https://gitlab.example.test:99999",
    f"https://dummy:{_TOKEN}@gitlab.example.test",
    f"https://gitlab.example.test?token={_TOKEN}",
    f"https://gitlab.example.test#{_TOKEN}",
    "https://gitlab.example.test/group/project", None,
])
def test_invalid_origins_do_not_echo_inputs_or_persist(
    vault: CredentialVault, tmp_path: Path, base_url,
) -> None:
    for operation in (
        lambda: vault.save(base_url, _PROJECT, _TOKEN),
        lambda: vault.candidates(base_url, _PROJECT),
        lambda: vault.mark_verified(str(uuid4()), base_url, _PROJECT),
    ):
        with pytest.raises(CredentialVaultError) as error:
            operation()
        _assert_safe(error.value)
    assert not _path(tmp_path).parent.exists()


@pytest.mark.parametrize("project_path", [
    "single", "group/../project", "group//project", "group/%2e/project", "group\\project",
    "group/project?token=synthetic-dummy", "group/project\n", "group/" + "x" * 4097, None,
])
def test_invalid_projects_are_rejected_by_all_association_surfaces(
    vault: CredentialVault, tmp_path: Path, project_path,
) -> None:
    for operation in (
        lambda: vault.save(_HOST, project_path, _TOKEN),
        lambda: vault.candidates(_HOST, project_path),
        lambda: vault.mark_verified(str(uuid4()), _HOST, project_path),
    ):
        with pytest.raises(CredentialVaultError) as error:
            operation()
        _assert_safe(error.value)
    assert not _path(tmp_path).exists()


@pytest.mark.parametrize("token", [
    "", " ", " synthetic-dummy", "synthetic-dummy\r\nheader", "synthetic-dummy\x00",
    "synthetic-dummy\x7f", "synthetic-dummy-\u00e9", "x" * 8193, None,
])
def test_invalid_tokens_fail_without_creating_storage(
    vault: CredentialVault, tmp_path: Path, token,
) -> None:
    with pytest.raises(CredentialVaultError) as error:
        vault.save(_HOST, _PROJECT, token)
    _assert_safe(error.value)
    assert not _path(tmp_path).parent.exists()


@pytest.mark.parametrize("credential_id", [
    "synthetic-dummy-invalid-id", "../vault.dpapi", "", None,
])
def test_invalid_ids_are_not_file_paths(vault: CredentialVault, credential_id) -> None:
    with pytest.raises(CredentialVaultError):
        vault.forget(credential_id)
    with pytest.raises(CredentialVaultError):
        vault.mark_verified(credential_id, _HOST, _PROJECT)


@pytest.mark.parametrize("operation", [
    "save", "candidates", "zero_candidates", "metadata", "mark_verified", "forget",
])
def test_corrupt_cipher_is_safe_and_never_silently_overwritten(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
    caplog: pytest.LogCaptureFixture, operation: str,
) -> None:
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    path = _path(tmp_path)
    original = path.read_bytes()
    corrupted = original[:-1] + bytes([original[-1] ^ 1])
    path.write_bytes(corrupted)
    writes = protector.protect_calls
    with pytest.raises(CredentialVaultError) as error:
        _invoke(vault, operation, credential_id)
    _assert_safe(error.value, credential_id)
    assert error.value.__suppress_context__
    assert path.read_bytes() == corrupted
    assert protector.protect_calls == writes
    assert list(path.parent.iterdir()) == [path]
    assert caplog.records == []


@pytest.mark.parametrize("plaintext", [
    b"", b"\xff", b"not JSON", b"[]", b"{}", b'{"version":1}',
    b'{"version":1,"version":1,"credentials":[]}',
    b'{"version":NaN,"credentials":[]}',
    b'{"version":Infinity,"credentials":[]}',
    b"[" * 2000 + b"]" * 2000,
], ids=["empty", "utf8", "json", "array", "missing", "missing-entries", "duplicate-key",
        "nan", "infinity", "deeply-nested"])
def test_invalid_json_never_becomes_an_empty_vault(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path, plaintext: bytes,
) -> None:
    before = _seed(tmp_path, protector, plaintext)
    for operation in ("metadata", "save"):
        with pytest.raises(CredentialVaultError) as error:
            _invoke(vault, operation, str(uuid4()))
        _assert_safe(error.value)
        assert _path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("changes", [
    {"version": 0}, {"version": 2}, {"version": True}, {"version": "1"}, {"version": 1.0},
    {"extra": "synthetic-dummy"}, {"credentials": None}, {"credentials": {}},
    {"credentials": [None]},
])
def test_document_schema_and_version_are_strict(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path, changes: dict,
) -> None:
    document = {"version": 1, "credentials": [_record()], **changes}
    before = _seed(tmp_path, protector, json.dumps(document).encode())
    with pytest.raises(CredentialVaultError):
        vault.save(_HOST, _PROJECT, _TOKEN)
    assert _path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("changes", [
    {"id": "synthetic-dummy-not-uuid"}, {"id": None}, {"extra": "synthetic-dummy"},
    {"host": "https://GITLAB.EXAMPLE.TEST:443"}, {"host": "not-an-origin"},
    {"token": ""}, {"token": None}, {"token": "synthetic-dummy\n"}, {"token": "x" * 8193},
    {"projects": _PROJECT}, {"projects": []}, {"projects": [None]},
    {"projects": ["group/../project"]}, {"projects": [_PROJECT, _PROJECT]},
    {"projects": ["group/" + "x" * 4097]},
    {"projects": [f"group/project-{index}" for index in range(101)]},
])
def test_each_decrypted_record_is_validated_before_any_write(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path, changes: dict,
) -> None:
    document = {"version": 1, "credentials": [_record(**changes)]}
    before = _seed(tmp_path, protector, json.dumps(document).encode())
    with pytest.raises(CredentialVaultError) as error:
        vault.save(_HOST, _PROJECT, _TOKEN)
    _assert_safe(error.value)
    assert _path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("problem", ["duplicate-id", "duplicate-token", "too-many", "missing-key"])
def test_invalid_entry_collections_are_rejected_without_repair(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path, problem: str,
) -> None:
    first = _record()
    if problem == "duplicate-id":
        records = [first, _record(id=first["id"], token="synthetic-dummy-other")]
    elif problem == "duplicate-token":
        records = [first, _record()]
    elif problem == "too-many":
        records = [_record(token=f"synthetic-dummy-{index}") for index in range(21)]
    else:
        first.pop("token")
        records = [first]
    before = _seed(tmp_path, protector, json.dumps({"version": 1, "credentials": records}).encode())
    with pytest.raises(CredentialVaultError):
        vault.save(_HOST, _PROJECT, _TOKEN)
    assert _path(tmp_path).read_bytes() == before


def test_twenty_entry_capacity_does_not_evict_and_forget_frees_a_slot(
    vault: CredentialVault, tmp_path: Path,
) -> None:
    ids = [vault.save(_HOST, _PROJECT, f"synthetic-dummy-{index}") for index in range(20)]
    assert len(vault.candidates(_HOST, _PROJECT, limit=1000)) == 20
    before = _path(tmp_path).read_bytes()
    with pytest.raises(CredentialVaultError, match="capacity"):
        vault.save(_HOST, _PROJECT, "synthetic-dummy-overflow")
    assert _path(tmp_path).read_bytes() == before
    assert vault.save(_HOST, "group/fresh", "synthetic-dummy-0") == ids[0]
    assert vault.forget(ids[0])
    assert vault.save(_HOST, _PROJECT, "synthetic-dummy-overflow") not in ids
    assert len(vault.metadata()) == 20


def test_one_hundred_project_capacity_never_evicts_existing_associations(
    vault: CredentialVault, tmp_path: Path,
) -> None:
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    for index in range(99):
        vault.mark_verified(credential_id, _HOST, f"group/project-{index}")
    assert len(vault.metadata()[0]["projects"]) == 100
    before = _path(tmp_path).read_bytes()
    for operation in (
        lambda: vault.save(_HOST, "group/overflow", _TOKEN),
        lambda: vault.mark_verified(credential_id, _HOST, "group/overflow"),
    ):
        with pytest.raises(CredentialVaultError, match="capacity"):
            operation()
    assert vault.save(_HOST, _PROJECT, _TOKEN) == credential_id
    vault.mark_verified(credential_id, _HOST, _PROJECT)
    assert _path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("stale_stat", [False, True])
def test_oversized_file_is_bounded_before_decryption_even_if_it_grows(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, stale_stat: bool,
) -> None:
    path = _path(tmp_path)
    path.parent.mkdir()
    oversized = b"x" * (_LIMIT + 1)
    path.write_bytes(oversized)
    if stale_stat:
        monkeypatch.setattr(credentials.os, "fstat", lambda fd: SimpleNamespace(st_size=1))
    with pytest.raises(CredentialVaultError):
        vault.save(_HOST, _PROJECT, _TOKEN)
    assert protector.unprotect_calls == protector.protect_calls == 0
    assert path.read_bytes() == oversized


@pytest.mark.parametrize("output_kind", ["oversized", "empty", "not-bytes"])
def test_unprotected_document_size_and_type_are_checked(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, output_kind: str,
) -> None:
    vault.save(_HOST, _PROJECT, _TOKEN)
    before = _path(tmp_path).read_bytes()
    output = {"oversized": b"x" * (_LIMIT + 1), "empty": b"", "not-bytes": _TOKEN}[output_kind]
    monkeypatch.setattr(protector, "unprotect", Mock(return_value=output))
    with pytest.raises(CredentialVaultError) as error:
        vault.save(_HOST, _PROJECT, "synthetic-dummy-new-token")
    _assert_safe(error.value)
    assert _path(tmp_path).read_bytes() == before


def test_plaintext_write_limit_is_checked_before_protection_or_replacement(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
) -> None:
    # A valid document just under 1 MiB, within the entry/project/string bounds.
    records = [
        _record(token=f"synthetic-dummy-{index}", projects=[
            f"group/project-{number}-".ljust(3500, "x") for number in range(count)
        ])
        for index, count in enumerate((100, 100, 99))
    ]
    before = _seed(
        tmp_path, protector,
        json.dumps({"version": 1, "credentials": records}, separators=(",", ":")).encode(),
    )
    assert len(before) <= _LIMIT
    writes = protector.protect_calls
    with pytest.raises(CredentialVaultError):
        vault.save(_HOST, _PROJECT, "synthetic-dummy-".ljust(8192, "x"))
    assert protector.protect_calls == writes
    assert _path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("output_kind", ["raises", "oversized", "empty", "not-bytes"])
def test_protection_failure_has_no_plaintext_fallback_or_directory_creation(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, output_kind: str,
) -> None:
    if output_kind == "raises":
        protect = Mock(side_effect=RuntimeError(_TOKEN))
    else:
        output = {"oversized": b"x" * (_LIMIT + 1), "empty": b"", "not-bytes": _TOKEN}[output_kind]
        protect = Mock(return_value=output)
    monkeypatch.setattr(protector, "protect", protect)
    with pytest.raises(CredentialVaultError) as error:
        vault.save(_HOST, _PROJECT, _TOKEN)
    _assert_safe(error.value)
    assert not _path(tmp_path).parent.exists()
    assert caplog.records == []


def test_atomic_replace_uses_only_encrypted_bytes_in_the_same_directory(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault.save(_HOST, _PROJECT, _TOKEN)
    path = _path(tmp_path)
    before = path.read_bytes()
    original_replace = os.replace
    fsync = Mock(wraps=os.fsync)
    monkeypatch.setattr(credentials.os, "fsync", fsync)

    def replace(source: Path, destination: Path) -> None:
        assert source.parent == destination.parent == path.parent
        assert destination == path
        assert destination.read_bytes() == before
        raw = source.read_bytes()
        for value in (_TOKEN, _HOST, _PROJECT, "synthetic-dummy-new-token"):
            assert value.encode() not in raw
        assert len(json.loads(protector.unprotect(raw))["credentials"]) == 2
        original_replace(source, destination)

    replacement = Mock(side_effect=replace)
    monkeypatch.setattr(credentials.os, "replace", replacement)
    vault.save(_HOST, _PROJECT, "synthetic-dummy-new-token")
    replacement.assert_called_once()
    fsync.assert_called_once()
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize("operation", ["save", "mark_verified", "forget"])
@pytest.mark.parametrize("failure_point", ["replace", "fsync", "protect"])
def test_failed_updates_preserve_original_ciphertext_and_clean_temporary_files(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch, operation: str, failure_point: str,
) -> None:
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    path = _path(tmp_path)
    before = path.read_bytes()
    target = protector if failure_point == "protect" else credentials.os
    monkeypatch.setattr(target, failure_point, Mock(side_effect=OSError(_TOKEN)))
    with pytest.raises(CredentialVaultError) as error:
        _invoke(vault, operation, credential_id)
    _assert_safe(error.value, credential_id)
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]
    assert vault.candidates(_HOST, _PROJECT)[0].credential_id == credential_id


def test_read_io_failure_is_safe_and_does_not_trigger_a_write(
    vault: CredentialVault, protector: FakeProtector, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault.save(_HOST, _PROJECT, _TOKEN)
    before, writes = _path(tmp_path).read_bytes(), protector.protect_calls
    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", Mock(side_effect=PermissionError(_TOKEN)))
        with pytest.raises(CredentialVaultError) as error:
            vault.save(_HOST, _PROJECT, "synthetic-dummy-new-token")
        _assert_safe(error.value)
    assert protector.protect_calls == writes
    assert _path(tmp_path).read_bytes() == before


@pytest.mark.parametrize("winerror", [5, 32, 33])
def test_transient_windows_replacement_errors_retry_only_the_encrypted_file(
    vault: CredentialVault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int,
) -> None:
    vault.save(_HOST, _PROJECT, _TOKEN)
    path = _path(tmp_path)
    before = path.read_bytes()
    platform = SimpleNamespace(**vars(os))
    platform.name = "nt"
    original_replace = os.replace
    attempts = 0

    def replace(source: Path, destination: Path) -> None:
        nonlocal attempts
        attempts += 1
        assert source.parent == destination.parent == path.parent
        assert destination.read_bytes() == before
        assert _TOKEN.encode() not in source.read_bytes()
        if attempts < 3:
            error = OSError(_TOKEN)
            error.winerror = winerror
            raise error
        original_replace(source, destination)

    platform.replace = replace
    monkeypatch.setattr(credentials, "os", platform)
    delay = Mock()
    monkeypatch.setattr(credentials.time, "sleep", delay)
    vault.save(_HOST, _PROJECT, "synthetic-dummy-new-token")
    assert attempts == 3
    assert [call.args[0] for call in delay.call_args_list] == [0.05, 0.1]
    assert len(vault.metadata()) == 2
    assert list(path.parent.iterdir()) == [path]


@pytest.mark.parametrize(("platform_name", "winerror", "expected_attempts"), [
    ("nt", 5, 5), ("nt", 32, 5), ("nt", 33, 5), ("nt", 112, 1), ("posix", 5, 1),
])
def test_replacement_retry_is_bounded_and_never_discards_original_ciphertext(
    vault: CredentialVault, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    platform_name: str, winerror: int, expected_attempts: int,
) -> None:
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    path = _path(tmp_path)
    before = path.read_bytes()
    platform = SimpleNamespace(**vars(os))
    platform.name = platform_name
    error = OSError(_TOKEN)
    error.winerror = winerror
    replacement = Mock(side_effect=error)
    platform.replace = replacement
    monkeypatch.setattr(credentials, "os", platform)
    delay = Mock()
    monkeypatch.setattr(credentials.time, "sleep", delay)
    with pytest.raises(CredentialVaultError) as caught:
        vault.forget(credential_id)
    _assert_safe(caught.value, credential_id)
    assert replacement.call_count == expected_attempts
    assert delay.call_count == expected_attempts - 1
    assert path.read_bytes() == before
    assert list(path.parent.iterdir()) == [path]


def test_threads_and_independent_instances_do_not_lose_verified_associations(
    tmp_path: Path,
) -> None:
    def save_and_verify(index: int) -> str:
        vault = CredentialVault(tmp_path / "vault", protector=FakeProtector())
        credential_id = vault.save(_HOST, f"group/project-{index}", _TOKEN)
        vault.mark_verified(credential_id, _HOST, f"group/verified-{index}")
        return credential_id

    with ThreadPoolExecutor(max_workers=8) as executor:
        ids = list(executor.map(save_and_verify, range(16)))
    assert len(set(ids)) == 1
    vault = CredentialVault(tmp_path / "vault", protector=FakeProtector())
    assert len(vault.metadata()) == 1
    assert set(vault.metadata()[0]["projects"]) == {
        f"group/{kind}-{index}" for index in range(16) for kind in ("project", "verified")
    }
    assert list(_path(tmp_path).parent.iterdir()) == [_path(tmp_path)]


@pytest.mark.parametrize("operation", ["protect", "unprotect"])
@pytest.mark.parametrize("outcome", ["success", "failure", "oversized"])
def test_win32_calls_forbid_ui_use_user_scope_and_always_local_free(
    operation: str, outcome: str,
) -> None:
    # A native-call double exercises flags and ownership even on non-Windows CI.
    backend = credentials._DPAPIProtector.__new__(credentials._DPAPIProtector)
    source_bytes = b"synthetic-dummy-input"
    output_bytes = b"synthetic-dummy-output"
    buffer = ctypes.create_string_buffer(output_bytes)

    def native(source, description, entropy, reserved, prompt, flags, output):
        incoming = ctypes.cast(source, ctypes.POINTER(credentials._DataBlob)).contents
        assert ctypes.string_at(incoming.pbData, incoming.cbData) == source_bytes
        assert description is entropy is reserved is prompt is None
        assert flags == 0x1  # CRYPTPROTECT_UI_FORBIDDEN, NOT LOCAL_MACHINE (0x4).
        result = ctypes.cast(output, ctypes.POINTER(credentials._DataBlob)).contents
        result.cbData = _LIMIT + 1 if outcome == "oversized" else len(output_bytes)
        result.pbData = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))
        return outcome != "failure"

    native_call = Mock(side_effect=native)
    other_call = Mock(side_effect=AssertionError)
    setattr(backend, "_" + operation, native_call)
    setattr(backend, "_" + ("unprotect" if operation == "protect" else "protect"), other_call)
    free = Mock()
    backend._local_free = free
    if outcome == "success":
        assert getattr(backend, operation)(source_bytes) == output_bytes
    else:
        with pytest.raises(CredentialVaultError):
            getattr(backend, operation)(source_bytes)
    native_call.assert_called_once()
    other_call.assert_not_called()
    free.assert_called_once()
    assert ctypes.cast(free.call_args.args[0], ctypes.c_void_p).value == ctypes.addressof(buffer)


@pytest.mark.skipif(os.name != "nt", reason="Real current-user DPAPI requires Windows")
def test_real_dpapi_round_trip_uses_only_temporary_synthetic_credentials(tmp_path: Path) -> None:
    directory = tmp_path / "real-dpapi-smoke-only"
    vault = CredentialVault(directory)
    assert vault.available
    credential_id = vault.save(_HOST, _PROJECT, _TOKEN)
    ciphertext = (directory / "vault.dpapi").read_bytes()
    for value in (_TOKEN, credential_id, _HOST, _PROJECT):
        assert value.encode() not in ciphertext
    reopened = CredentialVault(directory)
    assert reopened.candidates(_HOST, _PROJECT) == [
        SavedCredential(credential_id, _TOKEN, (_PROJECT,)),
    ]
    # Simulate the caller's successful project AND resource checks, without I/O.
    reopened.mark_verified(credential_id, _HOST, "group/verified")
    assert vault.candidates(_HOST, "group/verified")[0].project_paths == (
        _PROJECT, "group/verified",
    )
    assert reopened.forget(credential_id)
    assert vault.metadata() == []