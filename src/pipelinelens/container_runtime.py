"""Supervise the two container services without exposing the local-only API.

Subprocess waits are event-driven. An unexpected exit (even status zero) stops
the container; shutdown terminates both children before waiting, then kills any
stragglers. Child stdout/stderr are inherited, never buffered or replayed here.
"""

from __future__ import annotations

import asyncio
import signal
import sys
from contextlib import suppress
from types import FrameType

_SHUTDOWN_TIMEOUT_SECONDS = 5.0
_COMMANDS = (
    ("uvicorn", "pipelinelens.api.main:app", "--host", "127.0.0.1", "--port", "8000"),
    (
        "streamlit", "run", "src/pipelinelens/dashboard/app.py",
        "--server.address", "0.0.0.0", "--server.port", "8501",
        "--browser.gatherUsageStats", "false",
    ),
)


async def _stop_children(
    children: list[asyncio.subprocess.Process], waiters: list[asyncio.Task[int]],
) -> None:
    for child in children:
        if child.returncode is None:
            with suppress(ProcessLookupError):
                child.terminate()
    if waiters:
        # One shared deadline, not a separate grace period for each child.
        await asyncio.wait(waiters, timeout=_SHUTDOWN_TIMEOUT_SECONDS)
        for child in children:
            if child.returncode is None:
                with suppress(ProcessLookupError):
                    child.kill()
        await asyncio.gather(*waiters, return_exceptions=True)


async def _supervise() -> int:
    loop = asyncio.get_running_loop()
    stopping = asyncio.Event()
    requested_signal: int | None = None
    children: list[asyncio.subprocess.Process] = []
    waiters: list[asyncio.Task[int]] = []
    stop_waiter: asyncio.Task[bool] | None = None
    previous_handlers = {}

    def request_stop(signum: int, _frame: FrameType | None) -> None:
        nonlocal requested_signal
        if requested_signal is None:
            requested_signal = signum
        loop.call_soon_threadsafe(stopping.set)

    try:
        for signum in (signal.SIGTERM, signal.SIGINT):
            previous_handlers[signum] = signal.signal(signum, request_stop)
        for command in _COMMANDS:
            if requested_signal is not None:
                return 128 + requested_signal
            child = await asyncio.create_subprocess_exec(
                sys.executable, "-m", *command, stdin=asyncio.subprocess.DEVNULL,
            )
            children.append(child)
            waiters.append(asyncio.create_task(child.wait()))

        stop_waiter = asyncio.create_task(stopping.wait())
        done, _ = await asyncio.wait(
            [*waiters, stop_waiter], return_when=asyncio.FIRST_COMPLETED,
        )
        if requested_signal is not None:
            return 128 + requested_signal
        code = next(waiter.result() for waiter in waiters if waiter in done)
        # Zero is not success for a service that must stay alive. Preserve POSIX
        # exit/signal statuses, with a nonzero fallback for out-of-range statuses.
        code = 128 - code if code < 0 else code
        return code if 0 < code < 256 else 1
    finally:
        try:
            await _stop_children(children, waiters)
        finally:
            if stop_waiter is not None:
                stop_waiter.cancel()
                await asyncio.gather(stop_waiter, return_exceptions=True)
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)


def main() -> int:
    try:
        return asyncio.run(_supervise())
    except Exception:
        # Exceptions, command lines and environments can contain credentials.
        # Deliberately report only a fixed diagnostic, with no traceback.
        print("PipelineLens container could not start or supervise services.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())