"""Redaction helpers that run before logs are persisted, embedded, or sent to an LLM."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RedactionResult:
    content: str
    replacements: int


class SecretRedactor:
    """Apply conservative redaction patterns while retaining diagnostic context."""

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        (
            "bearer_token",
            re.compile(r"(?i)(\bauthorization\s*:\s*bearer\s+|\bbearer\s+)([^\s'\"]+)"),
        ),
        ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
        ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
        ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{10,}\b")),
        (
            "jwt",
            re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        ),
        (
            "private_key",
            re.compile(
                r"-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----", re.DOTALL
            ),
        ),
        (
            "credential_assignment",
            re.compile(
                r"(?i)(\b(?:password|passwd|token|api[_-]?key|client[_-]?secret)\b\s*[:=]\s*)([^\s'\"]+)"
            ),
        ),
    )

    def redact(self, content: str) -> RedactionResult:
        replacements = 0
        redacted = content

        for label, pattern in self._patterns:
            if label in {"bearer_token", "credential_assignment"}:
                redacted, count = pattern.subn(
                    lambda match: f"{match.group(1)}[REDACTED]", redacted
                )
            else:
                redacted, count = pattern.subn(f"[{label.upper()}_REDACTED]", redacted)
            replacements += count

        return RedactionResult(content=redacted, replacements=replacements)


def redact_text(content: str) -> str:
    """Convenience function for one-off sanitization."""

    return SecretRedactor().redact(content).content
