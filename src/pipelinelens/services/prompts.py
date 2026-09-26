"""Versioned, editable model prompts loaded from the repository ``prompts/`` directory.

Prompts are plain text templates using ``$name`` / ``${name}`` placeholders
(:class:`string.Template`), so JSON braces in a prompt need no escaping. Edit a file under
``prompts/`` (or point ``PIPELINELENS_PROMPTS_DIR`` at your own copy) to change what a model
is told, without touching Python. Every rendered prompt carries a short content hash so a
stored result records exactly which prompt text produced it.

Loading makes no network call. Placeholder values are inserted verbatim; callers must pass
already-redacted text.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from string import Template

_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
MAX_PROMPT_FILE_BYTES = 64_000


class PromptError(ValueError):
    """A prompt file is missing, unreadable, oversized, or has an invalid name."""


@dataclass(frozen=True, slots=True)
class PromptTemplate:
    name: str
    text: str

    @property
    def version(self) -> str:
        """Short content hash identifying this exact prompt text."""
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()[:12]

    def render(self, **values: object) -> str:
        """Substitute known placeholders; unknown ``$words`` are left as written."""
        mapping = {key: str(value) for key, value in values.items()}
        return Template(self.text).safe_substitute(mapping)


def prompts_directory() -> Path:
    configured = os.getenv("PIPELINELENS_PROMPTS_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parents[3] / "prompts"


def load_prompt(name: str, directory: Path | None = None) -> PromptTemplate:
    """Read ``<name>.md`` from the prompts directory. Raises :class:`PromptError`."""
    if not _NAME.fullmatch(name):
        raise PromptError("Prompt names are lowercase letters, digits and underscores.")
    path = (directory or prompts_directory()) / f"{name}.md"
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise PromptError(f"Prompt file {name}.md is not readable.") from error
    if len(raw) > MAX_PROMPT_FILE_BYTES:
        raise PromptError(f"Prompt file {name}.md exceeds {MAX_PROMPT_FILE_BYTES} bytes.")
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n").rstrip("\n")
    if not text.strip():
        raise PromptError(f"Prompt file {name}.md is empty.")
    return PromptTemplate(name=name, text=text)
