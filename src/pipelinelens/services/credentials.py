"""Opt-in, current-Windows-user GitLab credential storage; no network or logging.

The default location is LOCALAPPDATA/PipelineLens/credentials, never project data.
Missing/relative LOCALAPPDATA disables the default vault instead of falling back.
Only an explicit ``save`` persists a new token. Callers must obtain save consent
and verify both the fresh project and requested resource before saving; candidate
selection is not verification. ``mark_verified`` has the same verification
precondition, but does not grant consent to save a new token.

One DPAPI-encrypted, versioned JSON document contains *all* IDs, origins, tokens
and associations. There is no plaintext index, fingerprint, backup or fallback.
Ciphertext and plaintext are each bounded to 1 MiB, with 20 credentials and 100
projects per credential. Capacity errors never evict existing credentials.
Atomic replacement and a shared RLock serialize read/modify/write across threads
and vault instances in this process; this is not an inter-process write lock.
"""

from __future__ import annotations

import ctypes
import json
import os
import tempfile
import time
from ctypes import wintypes
from dataclasses import dataclass, field, replace
from pathlib import Path
from threading import RLock
from typing import Any, Protocol
from uuid import UUID, uuid4

from pipelinelens.services.gitlab_includes import is_project_path
from pipelinelens.services.pipeline_url import _origin

__all__ = ["CredentialVault", "CredentialVaultError", "Protector", "SavedCredential"]

_VERSION = 1
_FILE_NAME = "vault.dpapi"
_MAX_FILE_BYTES = 1024 * 1024
_MAX_ENTRIES = 20
_MAX_PROJECTS = 100
_MAX_PROJECT_LENGTH = 4096
_MAX_TOKEN_LENGTH = 8192
_CRYPTPROTECT_UI_FORBIDDEN = 0x1
_INVALID_INPUT = "Invalid credential vault input."
_READ_ERROR = "Saved credentials could not be read."
_WRITE_ERROR = "Saved credentials could not be saved."
_CRYPTO_ERROR = "Credential protection failed."
_CAPACITY_ERROR = "Credential vault capacity reached."


class CredentialVaultError(RuntimeError):
    """A safe, constant-message error; underlying exceptions are never displayed."""


class Protector(Protocol):
    """Trusted, keyword-only test injection: protect/unprotect bytes or raise.

    Pass ``protector=...`` together with a temporary directory to test on any OS.
    The implementation must encrypt and authenticate the entire byte string;
    test doubles need not be cryptographically secure. This is not a production
    configuration option. Without injection, only Windows DPAPI is supported.
    """

    def protect(self, data: bytes) -> bytes: ...

    def unprotect(self, data: bytes) -> bytes: ...


@dataclass(frozen=True, slots=True)
class SavedCredential:
    """A candidate, not proof of access. Neither ID nor token appears in repr."""

    credential_id: str = field(repr=False)
    token: str = field(repr=False)
    project_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Entry:
    host: str
    credential: SavedCredential


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


class _DPAPIProtector:
    """CryptProtectData's default scope is the current user, never the machine."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise CredentialVaultError(_CRYPTO_ERROR)
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        blob_pointer = ctypes.POINTER(_DataBlob)
        self._protect = crypt32.CryptProtectData
        self._protect.argtypes = [
            blob_pointer, wintypes.LPCWSTR, blob_pointer, ctypes.c_void_p,
            ctypes.c_void_p, wintypes.DWORD, blob_pointer,
        ]
        self._protect.restype = wintypes.BOOL
        self._unprotect = crypt32.CryptUnprotectData
        self._unprotect.argtypes = [
            blob_pointer, ctypes.POINTER(wintypes.LPWSTR), blob_pointer, ctypes.c_void_p,
            ctypes.c_void_p, wintypes.DWORD, blob_pointer,
        ]
        self._unprotect.restype = wintypes.BOOL
        self._local_free = kernel32.LocalFree
        self._local_free.argtypes = [ctypes.c_void_p]
        self._local_free.restype = ctypes.c_void_p

    def protect(self, data: bytes) -> bytes:
        return self._transform(data, decrypt=False)

    def unprotect(self, data: bytes) -> bytes:
        return self._transform(data, decrypt=True)

    def _transform(self, data: bytes, *, decrypt: bool) -> bytes:
        if not isinstance(data, bytes) or not 0 < len(data) <= _MAX_FILE_BYTES:
            raise CredentialVaultError(_CRYPTO_ERROR)
        buffer = ctypes.create_string_buffer(data)
        source = _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte)))
        output = _DataBlob()
        operation = self._unprotect if decrypt else self._protect
        try:
            # No description, entropy, prompt, or CRYPTPROTECT_LOCAL_MACHINE flag.
            success = operation(
                ctypes.byref(source), None, None, None, None,
                _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output),
            )
            if not success or not output.pbData or not 0 < output.cbData <= _MAX_FILE_BYTES:
                raise CredentialVaultError(_CRYPTO_ERROR)
            return ctypes.string_at(output.pbData, output.cbData)
        finally:
            # Also release a partially allocated output on failure. Passing NULL
            # for the optional description avoids a second LocalFree allocation.
            if output.pbData:
                self._local_free(output.pbData)


def _validated_host(value: str) -> str:
    try:
        return _origin(value)
    except Exception:
        raise CredentialVaultError(_INVALID_INPUT) from None


def _validated_project(value: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_PROJECT_LENGTH
        or not is_project_path(value)
    ):
        raise CredentialVaultError(_INVALID_INPUT)
    return value


def _validated_token(value: str) -> str:
    # GitLab header tokens are opaque: no prefix assumptions or silent trimming.
    if (
        not isinstance(value, str)
        or not 0 < len(value) <= _MAX_TOKEN_LENGTH
        or any(not 0x21 <= ord(character) <= 0x7E for character in value)
    ):
        raise CredentialVaultError(_INVALID_INPUT)
    return value


def _validated_id(value: str) -> str:
    try:
        if not isinstance(value, str) or len(value) != 36 or str(UUID(value)) != value:
            raise ValueError
    except Exception:
        raise CredentialVaultError(_INVALID_INPUT) from None
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError


def _decode_document(data: bytes) -> list[_Entry]:
    document = json.loads(
        data.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant,
    )
    if (
        not isinstance(document, dict)
        or set(document) != {"version", "credentials"}
        or type(document["version"]) is not int
        or document["version"] != _VERSION
    ):
        raise ValueError
    records = document["credentials"]
    if not isinstance(records, list) or len(records) > _MAX_ENTRIES:
        raise ValueError
    entries: list[_Entry] = []
    ids: set[str] = set()
    for record in records:
        if not isinstance(record, dict) or set(record) != {"id", "host", "token", "projects"}:
            raise ValueError
        credential_id = _validated_id(record["id"])
        host = _validated_host(record["host"])
        token = _validated_token(record["token"])
        projects = record["projects"]
        if (
            host != record["host"]
            or credential_id in ids
            or not isinstance(projects, list)
            or not 0 < len(projects) <= _MAX_PROJECTS
        ):
            raise ValueError
        project_paths = tuple(_validated_project(project) for project in projects)
        if len(set(project_paths)) != len(project_paths) or any(
            entry.host == host and entry.credential.token == token for entry in entries
        ):
            raise ValueError
        ids.add(credential_id)
        entries.append(_Entry(host, SavedCredential(credential_id, token, project_paths)))
    return entries


def _associate(entry: _Entry, project: str) -> _Entry:
    candidate = entry.credential
    if project in candidate.project_paths:
        return entry
    if len(candidate.project_paths) >= _MAX_PROJECTS:
        raise CredentialVaultError(_CAPACITY_ERROR)
    return replace(
        entry, credential=replace(candidate, project_paths=(*candidate.project_paths, project)),
    )


def _atomic_replace(source: Path, destination: Path) -> None:
    """Bounded Windows contention retry; never unlink/truncate the destination.

    An external reader/scanner can briefly prevent replacement on Windows, even
    though this process has closed its handles. Access denied (5), sharing (32),
    and lock violations (33) get at most four retries over 750 ms. Other errors
    propagate immediately and the public boundary always removes diagnostics.
    """

    for attempt in range(5):
        try:
            os.replace(source, destination)
            return
        except OSError as error:
            if os.name != "nt" or error.winerror not in {5, 32, 33} or attempt == 4:
                raise
            time.sleep(0.05 * (2 ** attempt))


class CredentialVault:
    """Explicit saves only; read methods never write, create directories or verify.

    ``directory`` overrides the default location (normally only useful in tests).
    ``protector`` is a trusted test-only override described by :class:`Protector`.
    No protector is inferred from environment variables or application config.
    """

    _lock = RLock()

    def __init__(
        self, directory: Path | None = None, *, protector: Protector | None = None,
    ) -> None:
        self._protector = protector
        self._injected = protector is not None
        self._directory: Path | None = None
        try:
            if directory is not None:
                if not isinstance(directory, Path):
                    raise ValueError
                self._directory = directory.absolute()
            else:
                local_app_data = os.environ.get("LOCALAPPDATA")
                if local_app_data and Path(local_app_data).is_absolute():
                    self._directory = Path(local_app_data) / "PipelineLens" / "credentials"
        except Exception:
            raise CredentialVaultError(_INVALID_INPUT) from None

    @property
    def available(self) -> bool:
        """False without Windows (or explicit test injection) and a usable path."""

        return self._directory is not None and (os.name == "nt" or self._injected)

    def save(self, base_url: str, project_path: str, token: str) -> str:
        """Persist only after explicit consent and project/resource verification.

        Equal tokens deduplicate within an origin, preserving the UUID and adding
        the verified project. Different origins/ports always have separate IDs.
        """

        host, project, token = (
            _validated_host(base_url), _validated_project(project_path), _validated_token(token),
        )
        with self._lock:
            entries = self._read()
            for index, entry in enumerate(entries):
                if entry.host == host and entry.credential.token == token:
                    updated = _associate(entry, project)
                    if updated != entry:
                        entries[index] = updated
                        self._write(entries)
                    return entry.credential.credential_id
            if len(entries) >= _MAX_ENTRIES:
                raise CredentialVaultError(_CAPACITY_ERROR)
            credential_id = str(uuid4())
            entries.append(_Entry(host, SavedCredential(credential_id, token, (project,))))
            self._write(entries)
            return credential_id

    def candidates(
        self, base_url: str, project_path: str, limit: int = 5,
    ) -> list[SavedCredential]:
        """Exact projects first, then same-origin tokens; newest entries break ties.

        Results are repeatable, not consumed or implicitly associated. ``limit``
        must be a nonnegative integer and is capped at the vault's 20-entry bound.
        Even an exact association must be freshly verified by the API caller.
        """

        host, project = _validated_host(base_url), _validated_project(project_path)
        if type(limit) is not int or limit < 0:
            raise CredentialVaultError(_INVALID_INPUT)
        with self._lock:
            entries = [entry for entry in reversed(self._read()) if entry.host == host]
            entries.sort(key=lambda entry: project not in entry.credential.project_paths)
            return [entry.credential for entry in entries[:min(limit, _MAX_ENTRIES)]]

    def mark_verified(self, credential_id: str, base_url: str, project_path: str) -> None:
        """Associate ONLY after fresh API success for the project AND resource.

        This method makes no API calls and cannot establish that precondition.
        Unknown IDs and attempts to move a credential to another origin fail.
        """

        credential_id = _validated_id(credential_id)
        host, project = _validated_host(base_url), _validated_project(project_path)
        with self._lock:
            entries = self._read()
            for index, entry in enumerate(entries):
                if entry.credential.credential_id == credential_id and entry.host == host:
                    updated = _associate(entry, project)
                    if updated != entry:
                        entries[index] = updated
                        self._write(entries)
                    return
            raise CredentialVaultError("Saved credential is unavailable for this server.")

    def metadata(self) -> list[dict]:
        """Return new dictionaries containing only id, host and projects (a list)."""

        with self._lock:
            return [
                {"id": entry.credential.credential_id, "host": entry.host,
                 "projects": list(entry.credential.project_paths)}
                for entry in self._read()
            ]

    def forget(self, credential_id: str) -> bool:
        """Remove an ID, returning False if absent; corrupt vaults fail closed."""

        credential_id = _validated_id(credential_id)
        with self._lock:
            entries = self._read()
            remaining = [
                entry for entry in entries if entry.credential.credential_id != credential_id
            ]
            if len(remaining) == len(entries):
                return False
            self._write(remaining)
            return True

    def _path(self) -> Path:
        if not self.available or self._directory is None:
            raise CredentialVaultError("Credential vault is unavailable.")
        return self._directory / _FILE_NAME

    def _backend(self) -> Protector:
        if self._protector is None:
            self._protector = _DPAPIProtector()
        return self._protector

    def _read(self) -> list[_Entry]:
        path = self._path()
        try:
            with path.open("rb") as stream:
                # Bounded reads also protect against a file growing after stat.
                if os.fstat(stream.fileno()).st_size > _MAX_FILE_BYTES:
                    raise ValueError
                ciphertext = stream.read(_MAX_FILE_BYTES + 1)
        except FileNotFoundError:
            return []
        except Exception:
            raise CredentialVaultError(_READ_ERROR) from None
        try:
            if not 0 < len(ciphertext) <= _MAX_FILE_BYTES:
                raise ValueError
            plaintext = self._backend().unprotect(ciphertext)
            if not isinstance(plaintext, bytes) or not 0 < len(plaintext) <= _MAX_FILE_BYTES:
                raise ValueError
            return _decode_document(plaintext)
        except Exception:
            # Never reinterpret an unreadable/unknown-version document as empty.
            raise CredentialVaultError(_READ_ERROR) from None

    def _write(self, entries: list[_Entry]) -> None:
        path = self._path()
        temporary: Path | None = None
        try:
            document = {"version": _VERSION, "credentials": [
                {"id": entry.credential.credential_id, "host": entry.host,
                 "token": entry.credential.token, "projects": list(entry.credential.project_paths)}
                for entry in entries
            ]}
            plaintext = json.dumps(
                document, ensure_ascii=True, separators=(",", ":"),
            ).encode("utf-8")
            if len(plaintext) > _MAX_FILE_BYTES:
                raise ValueError
            ciphertext = self._backend().protect(plaintext)
            if not isinstance(ciphertext, bytes) or not 0 < len(ciphertext) <= _MAX_FILE_BYTES:
                raise ValueError
            # Only protected bytes ever enter a file, including temporary files.
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".vault-", suffix=".tmp", dir=path.parent, delete=False,
            ) as stream:
                temporary = Path(stream.name)
                stream.write(ciphertext)
                stream.flush()
                os.fsync(stream.fileno())
            _atomic_replace(temporary, path)
        except Exception:
            raise CredentialVaultError(_WRITE_ERROR) from None
        finally:
            if temporary is not None:
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    # Best effort: any leftover temporary file is ciphertext only.
                    pass