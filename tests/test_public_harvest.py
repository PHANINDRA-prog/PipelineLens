"""Synthetic, no-network CLI regressions for explicit public corpus operations."""

from __future__ import annotations

import json
import socket
import sqlite3
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

with (
    patch("dotenv.load_dotenv", return_value=False),
    patch("dotenv.main.DotEnv.dict", return_value={}),
):
    from pipelinelens import public_harvest
    from pipelinelens.services.public_corpus import (
        PUBLIC_CORPUS_NOTICE,
        PublicCorpus,
        PublicCorpusError,
        PublicCorpusSummary,
        PublicHarvestReport,
        PublicRepositoryReport,
        preview_public_harvest,
    )


REPOSITORIES = ("actions/checkout", "pallets/flask", "psf/requests")
SENSITIVE_ARGUMENT = "https://user:synthetic-password@example.invalid/?token=synthetic-secret"


@pytest.fixture(autouse=True)
def isolated_io(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("CLI tests must not use real network or load dotenv")

    original_connect = socket.socket.connect
    original_socketpair = socket.socketpair

    def local_socketpair(*args, **kwargs):
        with patch.object(socket.socket, "connect", original_connect):
            return original_socketpair(*args, **kwargs)

    monkeypatch.setattr(socket, "socketpair", local_socketpair)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", forbidden)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", forbidden)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *args, **kwargs: False)
    monkeypatch.setattr("dotenv.main.DotEnv.dict", lambda *args, **kwargs: {})


def test_three_explicit_repositories_preview_without_clients_database_or_writes(
    tmp_path, capsys, monkeypatch,
):
    def forbidden(*args, **kwargs):
        pytest.fail("A harvest preview must not construct storage, make requests, or write")

    argv = ["--directory", str(tmp_path / "absent")]
    for repository in REPOSITORIES:
        argv.extend(["--github-repo", repository])
    with monkeypatch.context() as guard:
        guard.setattr(httpx, "AsyncClient", forbidden)
        guard.setattr(sqlite3, "connect", forbidden)
        guard.setattr(public_harvest, "PublicCorpus", forbidden)
        guard.setattr(public_harvest, "harvest_public_repositories", forbidden)
        guard.setattr(Path, "mkdir", forbidden)
        guard.setattr(Path, "write_bytes", forbidden)
        guard.setattr(Path, "write_text", forbidden)
        assert public_harvest.main(argv) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["mode"] == "public_harvest_preview"
    assert output["remote_requests"] is output["writes"] is False
    assert output["plan"]["repositories"] == list(REPOSITORIES)
    assert output["plan"]["target_run_count"] == 12
    assert output["plan"]["max_jobs_per_run"] == 1
    assert output["plan"]["max_job_listing_pages"] == 2
    assert output["notice"] == PUBLIC_CORPUS_NOTICE
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("option", [
    "--token", "--github-token", "--auth", "--discover", "--export", "--follow-redirects",
    "--exec", "--exe", "--github", "--per", "--summ",
])
def test_sensitive_unsupported_and_abbreviated_options_are_rejected_without_echo(
    capsys, monkeypatch, option,
):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid arguments must not construct storage or execute collection")

    monkeypatch.setattr(public_harvest, "PublicCorpus", forbidden)
    monkeypatch.setattr(public_harvest, "harvest_public_repositories", forbidden)
    with pytest.raises(SystemExit) as error:
        public_harvest.main(["--github-repo", REPOSITORIES[0], option, SENSITIVE_ARGUMENT])
    assert error.value.code == 2
    output = capsys.readouterr()
    assert not output.out
    assert "Invalid arguments" in output.err
    assert SENSITIVE_ARGUMENT not in output.err
    assert "synthetic-password" not in output.err


@pytest.mark.parametrize("argv", [
    [], ["--execute"], ["--summary", "--execute"], ["--summary", "--reevaluate"],
    ["--summary", "--github-repo", REPOSITORIES[0]],
    ["--reevaluate", "--github-repo", REPOSITORIES[0]],
    ["--github-repo"], ["--github-repo", REPOSITORIES[0], "--per-repo", "bad"],
])
def test_invalid_mode_combinations_are_inert(argv, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Invalid CLI modes must not access storage")

    monkeypatch.setattr(public_harvest, "PublicCorpus", forbidden)
    with pytest.raises(SystemExit) as error:
        public_harvest.main(argv)
    assert error.value.code == 2


def test_unsafe_repository_error_does_not_echo_url_or_credentials(capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("An invalid repository must not create a corpus")

    monkeypatch.setattr(public_harvest, "PublicCorpus", forbidden)
    assert public_harvest.main(["--github-repo", SENSITIVE_ARGUMENT]) == 2
    output = capsys.readouterr()
    assert SENSITIVE_ARGUMENT not in output.out + output.err
    assert "error" in json.loads(output.out)


@pytest.mark.parametrize("mode", ["--summary", "--reevaluate"])
def test_summary_and_reevaluation_preview_are_local_read_only(tmp_path, capsys, monkeypatch, mode):
    directory = tmp_path / "never-created"

    def forbidden(*args, **kwargs):
        pytest.fail("Read-only CLI modes must not initialize storage or reclassify")

    monkeypatch.setattr(PublicCorpus, "initialize", forbidden)
    monkeypatch.setattr(public_harvest, "reevaluate_public_corpus", forbidden)
    monkeypatch.setattr(public_harvest, "harvest_public_repositories", forbidden)
    assert public_harvest.main([mode, "--directory", str(directory)]) == 0
    output = json.loads(capsys.readouterr().out)
    summary = output if mode == "--summary" else output["summary"]
    assert summary["run_count"] == summary["no_job_run_count"] == 0
    assert summary["captured_log_job_count"] == summary["captured_config_run_count"] == 0
    if mode == "--reevaluate":
        assert output["writes"] is output["remote_requests"] is False
    assert not directory.exists()


@pytest.mark.parametrize("state,exit_code", [("complete", 0), ("partial", 3), ("rate_limited", 3)])
def test_explicit_execution_prints_distinct_invocation_and_lifetime_counts(
    tmp_path, capsys, monkeypatch, state, exit_code,
):
    calls = []

    async def synthetic_harvest(repositories, *, runs_per_repository, corpus):
        assert repositories == [REPOSITORIES[0]]
        assert runs_per_repository == 2
        assert corpus.directory == tmp_path
        calls.append(corpus)
        return PublicHarvestReport(
            state=state,
            plan=preview_public_harvest(repositories, runs_per_repository=2),
            repositories=(PublicRepositoryReport(
                repository=REPOSITORIES[0], state="collected", selected_run_count=2,
                new_run_count=1, already_retained_run_count=1, retained_run_count=7,
            ),),
            selected_run_count=2, new_run_count=1, already_retained_run_count=1,
            summary=PublicCorpusSummary(
                run_count=7, job_count=5, no_job_run_count=2, captured_log_job_count=3,
                no_log_job_count=2, captured_config_run_count=4, no_config_run_count=3,
            ),
        )

    monkeypatch.setattr(public_harvest, "harvest_public_repositories", synthetic_harvest)
    assert public_harvest.main([
        "--github-repo", REPOSITORIES[0], "--per-repo", "2",
        "--execute", "--directory", str(tmp_path),
    ]) == exit_code
    output = json.loads(capsys.readouterr().out)
    assert len(calls) == 1
    assert output["selected_run_count"] == 2
    assert output["new_run_count"] == output["already_retained_run_count"] == 1
    assert output["summary"]["run_count"] == 7
    assert output["summary"]["captured_log_job_count"] == 3
    assert "log_content" not in output["summary"]
    assert "config_content" not in output["summary"]
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("error,exit_code", [
    (PublicCorpusError(SENSITIVE_ARGUMENT), 2),
    (RuntimeError(SENSITIVE_ARGUMENT), 2),
    (KeyboardInterrupt(), 130),
])
def test_execute_errors_never_print_sensitive_exception_details(
    tmp_path, capsys, monkeypatch, error, exit_code,
):
    async def failing_harvest(*args, **kwargs):
        raise error

    monkeypatch.setattr(public_harvest, "harvest_public_repositories", failing_harvest)
    assert public_harvest.main([
        "--github-repo", REPOSITORIES[0], "--execute", "--directory", str(tmp_path),
    ]) == exit_code
    output = capsys.readouterr()
    assert SENSITIVE_ARGUMENT not in output.out + output.err
    assert "synthetic-password" not in output.out + output.err
    assert list(tmp_path.iterdir()) == []