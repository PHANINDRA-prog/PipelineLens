"""Offline lifecycle fakes and static container contracts; no image build or servers."""

import asyncio
import fnmatch
import signal
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from unittest.mock import AsyncMock, call

import pytest
from ruamel.yaml import YAML

from pipelinelens import container_runtime as runtime

ROOT = Path(__file__).resolve().parents[1]
SECRET = "synthetic-container-secret-not-a-real-credential"


class FakeChild:
    def __init__(self, name: str, events: list[str]) -> None:
        self.name = name
        self.events = events
        self.returncode: int | None = None
        self.ignore_term = False
        self.reaped = False
        self.done = asyncio.Event()
        self.on_wait: Callable[[], None] | None = None

    def finish(self, code: int) -> None:
        self.returncode = code
        self.done.set()

    async def wait(self) -> int:
        if self.on_wait is not None:
            self.on_wait()
        await self.done.wait()
        self.reaped = True
        self.events.append(f"reap:{self.name}")
        assert self.returncode is not None
        return self.returncode

    def terminate(self) -> None:
        self.events.append(f"terminate:{self.name}")
        if not self.ignore_term:
            self.finish(-signal.SIGTERM)

    def kill(self) -> None:
        self.events.append(f"kill:{self.name}")
        self.finish(-9)


def send_signal(signum: int) -> None:
    handler = signal.getsignal(signum)
    assert callable(handler)
    handler(signum, None)


@pytest.fixture
def lifecycle(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    events: list[str] = []
    children = [FakeChild("api", events), FakeChild("dashboard", events)]
    launch = AsyncMock(side_effect=children)
    monkeypatch.setattr(runtime.asyncio, "create_subprocess_exec", launch)
    monkeypatch.setattr(runtime, "_SHUTDOWN_TIMEOUT_SECONDS", 0.01)
    for name in ("PIPELINELENS_GITLAB_TOKEN", "PIPELINELENS_LLM_API_KEY"):
        monkeypatch.setenv(name, SECRET)

    # Exercise the installed callbacks without delivering OS signals to pytest.
    original = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    handlers = original.copy()

    def register(signum, handler):
        previous = handlers[signum]
        handlers[signum] = handler
        return previous

    monkeypatch.setattr(signal, "signal", register)
    monkeypatch.setattr(signal, "getsignal", handlers.__getitem__)
    supervise = runtime._supervise

    async def bounded_supervise() -> int:
        try:
            return await asyncio.wait_for(supervise(), timeout=1.0)
        except TimeoutError:
            pytest.fail("Supervisor did not respond to the synthetic lifecycle event")

    monkeypatch.setattr(runtime, "_supervise", bounded_supervise)
    yield children, launch, events
    assert handlers == original
    captured = capsys.readouterr()
    assert SECRET not in captured.out + captured.err


@pytest.mark.parametrize("index", [0, 1], ids=["api", "dashboard"])
@pytest.mark.parametrize("code, expected", [(7, 7), (0, 1), (-15, 143), (256, 1)])
def test_either_child_exit_stops_and_reaps_its_sibling(lifecycle, index, code, expected):
    children, launch, events = lifecycle
    children[1].on_wait = lambda: children[index].finish(code)

    assert runtime.main() == expected
    assert launch.await_count == 2
    assert all(child.reaped for child in children)
    assert f"terminate:{children[1 - index].name}" in events
    assert f"terminate:{children[index].name}" not in events


def test_commands_use_current_python_and_preserve_loopback_topology(lifecycle, monkeypatch):
    children, launch, _ = lifecycle
    monkeypatch.setattr(sys, "executable", "/synthetic/python")
    children[1].on_wait = lambda: children[0].finish(1)

    assert runtime.main() == 1
    assert launch.await_args_list == [
        call(
            "/synthetic/python", "-m", "uvicorn", "pipelinelens.api.main:app",
            "--host", "127.0.0.1", "--port", "8000", stdin=asyncio.subprocess.DEVNULL,
        ),
        call(
            "/synthetic/python", "-m", "streamlit", "run",
            "src/pipelinelens/dashboard/app.py", "--server.address", "0.0.0.0",
            "--server.port", "8501", "--browser.gatherUsageStats", "false",
            stdin=asyncio.subprocess.DEVNULL,
        ),
    ]


@pytest.mark.parametrize("index", [0, 1], ids=["api", "dashboard"])
@pytest.mark.parametrize("error_type", [OSError, RuntimeError])
def test_startup_failure_is_nonzero_reaps_started_child_and_hides_secrets(
    lifecycle, capsys, index, error_type,
):
    children, launch, _ = lifecycle
    launch.side_effect = [*children[:index], error_type(SECRET)]

    assert runtime.main() == 1
    assert launch.await_count == index + 1
    assert all(child.reaped for child in children[:index])
    assert not any(child.reaped for child in children[index:])
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "PipelineLens container could not start or supervise services.\n"


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
@pytest.mark.parametrize("ignore_term", [False, True])
def test_signals_terminate_both_before_waiting_and_kill_stragglers(
    lifecycle, signum, ignore_term,
):
    children, _, events = lifecycle
    for child in children:
        child.ignore_term = ignore_term
    children[1].on_wait = lambda: send_signal(signum)

    assert runtime.main() == 128 + signum
    assert events[:2] == ["terminate:api", "terminate:dashboard"]
    assert all(child.reaped for child in children)
    for child in children:
        assert (f"kill:{child.name}" in events) is ignore_term


def test_only_unresponsive_child_is_killed(lifecycle):
    children, _, events = lifecycle
    children[0].ignore_term = True
    children[1].on_wait = lambda: send_signal(signal.SIGTERM)

    assert runtime.main() == 143
    assert all(child.reaped for child in children)
    assert "kill:api" in events
    assert "kill:dashboard" not in events


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGINT])
def test_signal_during_startup_reaps_child_without_launching_dashboard(lifecycle, signum):
    children, launch, _ = lifecycle

    async def start(*args, **kwargs):
        send_signal(signum)
        return children[0]

    launch.side_effect = start
    assert runtime.main() == 128 + signum
    assert launch.await_count == 1
    assert children[0].reaped
    assert not children[1].reaped


def test_repeated_signals_do_not_interrupt_cleanup(lifecycle, monkeypatch):
    children, _, _ = lifecycle
    terminate = children[0].terminate

    def terminate_with_more_signals():
        send_signal(signal.SIGINT)
        send_signal(signal.SIGTERM)
        terminate()

    monkeypatch.setattr(children[0], "terminate", terminate_with_more_signals)
    children[1].on_wait = lambda: send_signal(signal.SIGTERM)
    assert runtime.main() == 143
    assert all(child.reaped for child in children)


@pytest.mark.parametrize("operation", ["terminate", "kill"])
def test_exit_racing_shutdown_is_still_reaped(lifecycle, monkeypatch, operation):
    children, _, _ = lifecycle
    children[0].ignore_term = operation == "kill"

    def already_exited():
        children[0].finish(0)
        raise ProcessLookupError(SECRET)

    monkeypatch.setattr(children[0], operation, already_exited)
    children[1].on_wait = lambda: send_signal(signal.SIGTERM)
    assert runtime.main() == 143
    assert all(child.reaped for child in children)


def test_simultaneous_exits_are_both_reaped(lifecycle):
    children, _, events = lifecycle

    def finish_both():
        for child in children:
            child.finish(3)

    children[1].on_wait = finish_both
    assert runtime.main() == 3
    assert all(child.reaped for child in children)
    assert not any(event.startswith(("terminate:", "kill:")) for event in events)


@pytest.fixture
def compose():
    return YAML(typ="safe").load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_compose_publishes_only_loopback_dashboard_and_keeps_init(compose):
    assert set(compose) == {"services", "volumes"}
    assert set(compose["services"]) == {"pipelinelens"}
    service = compose["services"]["pipelinelens"]
    assert service["build"] == "."
    assert service["init"] is True
    assert service["ports"] == ["127.0.0.1:8501:8501"]
    assert service["stop_grace_period"] == "10s"
    assert runtime._SHUTDOWN_TIMEOUT_SECONDS < 10
    # No env_file, host networking, overrides, secrets, or extra port exposure.
    assert set(service) == {
        "build", "init", "stop_grace_period", "environment", "ports", "volumes",
    }


def test_compose_disables_models_and_private_context_without_secret_or_corpus_mounts(compose):
    service = compose["services"]["pipelinelens"]
    assert service["environment"] == {
        "PIPELINELENS_ENV": "development",
        "PIPELINELENS_DATABASE_URL": "sqlite:////app/data/pipelinelens.db",
        "PIPELINELENS_LLM_MODE": "disabled",
        "PIPELINELENS_ALLOW_PRIVATE_CONTEXT": "false",
        "PIPELINELENS_API_URL": "http://127.0.0.1:8000",
    }
    assert service["volumes"] == ["pipelinelens-data:/app/data"]
    assert compose["volumes"] == {"pipelinelens-data": None}


def ignore_rules() -> list[str]:
    return [
        line.strip() for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


@pytest.mark.parametrize("pattern", [
    ".sf/", ".sfdx/", ".ssh/", ".env", ".env.*", "*.env", ".venv/", "venv/", "env/",
    "credentials/", "*.key", "*.pem", "*.p8", "*.p12", "*.pfx", "*.der", "*.jks",
    "*.keystore", "*.ppk", "*.dpapi", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    "gitlab-token.exe", ".pipelinelens/", "data/", "artifacts/", "logs/", "local-corpus/",
    "public-corpus/", "corpora/", "*.db", "*.db-*", "*.sqlite", "*.sqlite-*", "*.sqlite3",
    "*.sqlite3-*", ".streamlit/secrets.toml",
])
def test_dockerignore_excludes_sensitive_paths_at_root_and_nested_depths(pattern):
    rules = ignore_rules()
    # Require Docker's recursive form, not just a root-only exclusion.
    assert f"**/{pattern}" in rules
    assert not any(rule.startswith("!") for rule in rules)


def test_build_copies_required_readme_without_ignoring_it_or_copying_entire_context():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["readme"] == "README.md"
    assert (ROOT / "README.md").is_file()
    assert [line for line in dockerfile.splitlines() if line.startswith("COPY ")] == [
        "COPY pyproject.toml README.md ./",
        "COPY src ./src",
        "COPY skills ./skills",
        "COPY docker-entrypoint.sh /usr/local/bin/pipelinelens-entrypoint",
    ]
    assert not any(line.startswith("ADD ") for line in dockerfile.splitlines())
    for rule in ignore_rules():
        # Root-file glob check only; this is not a replacement for Docker's parser.
        pattern = rule.strip("/")
        while pattern.startswith("**/"):
            pattern = pattern[3:]
        assert not fnmatch.fnmatchcase("README.md", pattern)


def test_image_defaults_to_nonroot_owned_data_and_home_without_os_package_installs():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for required in (
        "USER 10001:10001", "groupadd --gid 10001 pipelinelens",
        "useradd --uid 10001 --gid 10001 --create-home",
        "--home-dir /home/pipelinelens", "HOME=/home/pipelinelens",
        "mkdir -p /app/data", "chown 10001:10001 /app/data", "STOPSIGNAL SIGTERM",
        "PIPELINELENS_ENV=development",
        "PIPELINELENS_DATABASE_URL=sqlite:////app/data/pipelinelens.db",
        "PIPELINELENS_LLM_MODE=disabled", "PIPELINELENS_ALLOW_PRIVATE_CONTEXT=false",
        "PIPELINELENS_API_URL=http://127.0.0.1:8000",
    ):
        assert required in dockerfile
    assert [line for line in dockerfile.splitlines() if line.startswith("EXPOSE ")] == [
        "EXPOSE 8501",
    ]
    assert not any(manager in dockerfile for manager in ("apt-get", "apt install", "apk ", "yum "))


def test_shell_exec_and_line_ending_defenses():
    assert (ROOT / "docker-entrypoint.sh").read_text(encoding="utf-8").splitlines() == [
        "#!/bin/sh", "set -eu", "", "exec python -m pipelinelens.container_runtime",
    ]
    assert "/docker-entrypoint.sh text eol=lf" in (ROOT / ".gitattributes").read_text(
        encoding="utf-8",
    ).splitlines()
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert r"sed -i 's/\r$//' /usr/local/bin/pipelinelens-entrypoint" in dockerfile
    assert "chmod 755 /usr/local/bin/pipelinelens-entrypoint" in dockerfile
    assert 'CMD ["/usr/local/bin/pipelinelens-entrypoint"]' in dockerfile