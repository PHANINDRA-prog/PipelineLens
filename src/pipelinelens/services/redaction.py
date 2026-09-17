"""Redaction helpers that run before logs are persisted, embedded, or sent to an LLM."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

_MARKER = "[REDACTED]"
_MAX_STRING_DEPTH = 16
_LINE_ENDINGS = re.compile(r"\r\n?|\n")
_MARKED = re.compile(r"\[(?:[A-Z0-9_]+_)?REDACTED\]", re.IGNORECASE)
_PLACEHOLDER = re.compile(
    r'''\$(?:\{\{\s*[\w.-]+(?:\s*\[\s*(?:[\w.-]+|'[\w.-]+'|"[\w.-]+")'''
    r"\s*\])*\s*\}\}|"
    r"\{[\w.:-]+\}|\([\w.:-]+\)|(?:env:)?[A-Za-z_][\w:]*)|%[\w]+%",
    re.IGNORECASE,
)
_SCHEME = re.compile(r"(?:basic|bearer)[ \t]+", re.IGNORECASE)
_SEPARATOR = re.compile(r"[ \t]*([:=])[ \t]*")
_POWERSHELL_ASSIGNMENT = re.compile(
    r"\$(?:[A-Za-z_][\w.-]*:)?[A-Za-z_][\w.-]*[ \t]*=[ \t]*$",
)
_COMPILER_PREFIX = re.compile(r"\b(?:error|warning)\s+(?:CS\d{4}|TS\d+|MSB\d+)\s*:[ \t]*$", re.I)
_METHOD_SIGNATURE = re.compile(r"[\w.`<>+]+\([^()\r\n]*\)\Z")
_CANCELLATION_TYPE = re.compile(r"\b(?:System\.Threading\.)?CancellationToken[ \t]+$")
_CANCELLATION_DEFAULT = re.compile(
    r"(?:default(?:[ \t]*\([ \t]*(?:System\.Threading\.)?CancellationToken[ \t]*\))?"
    r"|(?:System\.Threading\.)?CancellationToken\.None)(?=[ \t]*[,;)])",
)
_LEXEME = re.compile(
    r"(?P<pem>-----BEGIN [A-Z ]*PRIVATE KEY-----)|"
    r"(?P<url>[A-Za-z][A-Za-z0-9+.-]*:(?:\\?/){2})|"
    r"(?P<quote>[\"'])|(?P<container>[{}\[\]])|"
    r"(?P<query>[?&#])|(?P<word>[A-Za-z_][\w.-]*)",
)
_URL_END = re.compile(r"[\s<>\"']")
_QUERY_PAIR = re.compile(r"([^=&#;\s<>\"']+)=([^&#;\s<>\"']*)")
_QUERY_DELIMITER = re.compile(r"[&;]")
_BLOCK_HEADER = re.compile(r"[|>][+\-1-9]*[ \t]*(?:#[^\r\n]*)?(?=\r\n?|\n)")
_SCHEMA_VALUES = frozenset({
    "string", "str", "int", "integer", "float", "double", "number", "decimal",
    "bool", "boolean", "object", "array", "null", "none", "nil", "true", "false", "~",
})
_SECRET_NAMES = (
    "password", "passwd", "passphrase", "token", "secret", "credential", "authorization",
    "apikey", "accesskey", "privatekey", "signingkey", "encryptionkey", "sessionkey",
)
_TOKEN_METADATA = (
    "tokencount", "tokencounts", "tokenscount", "tokentype", "tokentypes", "tokenusage",
    "tokenlimit", "tokenlength", "tokensize", "maxtokens", "mintokens", "totaltokens",
    "numtokens", "inputtokens", "outputtokens", "prompttokens", "completiontokens",
    "cachedtokens", "reasoningtokens",
)
_SIGNED_QUERY_NAMES = frozenset({
    "sig", "signature", "policy", "keypairid", "googleaccessid", "awsaccesskeyid",
    "xamzsignature", "xgoogsignature", "auth", "key", "code",
})


def _sensitive_name(name: str, *, query: bool = False) -> bool:
    # Normalize the *whole* identifier, not a word-boundary suffix: underscores,
    # vendor prefixes, camel case and escaped JSON keys must not hide a credential.
    canonical = re.sub(r"[^a-z0-9]", "", name.lower())
    if canonical.endswith(_TOKEN_METADATA):
        return False
    if query and canonical in _SIGNED_QUERY_NAMES:
        return True
    if any(part in canonical for part in _SECRET_NAMES):
        return True
    words = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower()
    return bool({"pass", "pwd", "pat"}.intersection(re.split(r"\W|_", words)))


def _unquote_query(value: str) -> str:
    for _ in range(3):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def _benign(value: str) -> bool:
    value = value.strip()
    # Non-JSON YAML/PowerShell bodies retain their quote escapes while scanning.
    # Only unwrap complete literals; a marker/placeholder plus a suffix is unsafe.
    for wrapper in ('\\"', '`"'):
        if len(value) >= 4 and value.startswith(wrapper) and value.endswith(wrapper):
            value = value[2:-2].strip()
            break
    if scheme := _SCHEME.match(value):
        value = value[scheme.end():].strip()
    return (
        not value
        or value.lower().removesuffix("?") in _SCHEMA_VALUES
        or value.lower() in {"basic", "bearer"}
        or _MARKED.fullmatch(value) is not None
        or _PLACEHOLDER.fullmatch(value) is not None
    )


def _mask(value: str, marker: str = _MARKER) -> str:
    # Retain CR, LF and CRLF verbatim, including terminal-control carriage returns.
    return marker + "".join(_LINE_ENDINGS.findall(value))


def _line_start(content: str, position: int) -> int:
    return max(content.rfind("\n", 0, position), content.rfind("\r", 0, position)) + 1


def _powershell(content: str, position: int) -> bool:
    # Inspect the immediately preceding assignment, not every earlier character
    # on a potentially huge single-line JSON document for each quoted scalar.
    index = position - 1
    while index >= 0 and content[index] in " \t":
        index -= 1
    if index < 0 or content[index] != "=":
        return False
    index -= 1
    while index >= 0 and content[index] in " \t":
        index -= 1
    while index >= 0 and (content[index].isalnum() or content[index] in "_.:-"):
        index -= 1
    return index >= 0 and _POWERSHELL_ASSIGNMENT.fullmatch(content[index:position]) is not None


def _quote_end(content: str, start: int, *, powershell: bool = False) -> tuple[int, bool]:
    """Scan without a length cap; an unterminated secret consumes the remainder."""
    quote = content[start]
    index = start + 1
    escape = "`" if powershell else "\\"
    while index < len(content):
        char = content[index]
        if quote == '"' and char == escape:
            index += 2
        elif char == quote:
            if quote == "'" and content[index:index + 2] == "''":
                index += 2  # YAML and PowerShell doubled single quotes.
            else:
                return index + 1, True
        else:
            index += 1
    return len(content), False


def _literal(
    content: str, start: int, end: int, closed: bool, *, powershell: bool = False,
) -> tuple[str, bool]:
    raw = content[start:end]
    if closed and raw.startswith('"') and not powershell:
        try:
            decoded = json.loads(raw)
            if isinstance(decoded, str):
                return decoded, True
        except ValueError:
            pass
    inner = raw[1:-1] if closed else raw[1:]
    return (inner.replace("''", "'") if raw.startswith("'") else inner), False


def _bare_end(
    content: str, start: int, *, spaces: bool, mapping: bool = False,
    flow: bool = False, powershell: bool = False,
) -> int:
    index = start
    delimiters = ",]}" if flow else ("" if mapping else ";&|<>")
    escape = "`" if powershell else "\\"
    while index < len(content):
        # Placeholders and prior markers can contain delimiters or spaces. Only
        # whole scalar matches are considered benign; appended suffixes are not.
        placeholder = _PLACEHOLDER.match(content, index) or _MARKED.match(content, index)
        if placeholder:
            index = placeholder.end()
            continue
        char = content[index]
        if char == escape and not mapping:
            index += 2
            if content[index - 1:index + 1] == "\r\n":
                index += 1
        elif char in "\"'" and not mapping:
            index, _ = _quote_end(content, index, powershell=powershell)
        elif char in "\r\n" or char in delimiters:
            break
        elif char.isspace() and not (spaces and char in " \t"):
            break
        elif char == "#" and (index == start or content[index - 1].isspace()):
            break
        else:
            index += 1
    return min(index, len(content))


def _apply_edits(content: str, edits: list[tuple[int, int, str]]) -> str:
    pieces: list[str] = []
    previous = 0
    for start, end, value in edits:
        pieces.extend((content[previous:start], value))
        previous = end
    pieces.append(content[previous:])
    return "".join(pieces)


@dataclass(frozen=True, slots=True)
class RedactionResult:
    content: str
    replacements: int


class SecretRedactor:
    """Redact credential scalars without reformatting their surrounding document.

    This is a lexical sanitizer, not a shell/YAML interpreter or an entropy-based
    secret detector. Complete scalars win over nested matches, so each occurrence
    is counted once. Encoded JSON strings are decoded recursively, with a bounded,
    fail-closed nesting budget; ordinary JSON objects require no recursion.
    """

    _patterns: tuple[tuple[str, re.Pattern[str]], ...] = (
        ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
        ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
        ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_-]{10,}\b")),
        (
            "jwt",
            re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        ),
    )

    def redact(self, content: str) -> RedactionResult:
        return self._scan(content, 0)

    def _scan(self, content: str, depth: int) -> RedactionResult:
        if depth >= _MAX_STRING_DEPTH:
            return RedactionResult(content, 0) if _benign(content) else RedactionResult(
                _mask(content), 1,
            )

        edits: list[tuple[int, int, str]] = []
        replacements = 0
        containers: list[str] = []
        index = 0
        while match := _LEXEME.search(content, index):
            start, index = match.span()
            if match.lastgroup == "container":
                if match[0] in "[{":
                    containers.append(match[0])
                elif containers:
                    containers.pop()
                continue
            if match.lastgroup == "pem":
                terminator = match[0].replace("BEGIN", "END", 1)
                stop = content.find(terminator, index)
                end = len(content) if stop < 0 else stop + len(terminator)
                edits.append((start, end, _mask(content[start:end], "[PRIVATE_KEY_REDACTED]")))
                replacements += 1
                index = end
                continue

            if match.lastgroup == "url":
                stop_match = _URL_END.search(content, index)
                end = stop_match.start() if stop_match else len(content)
                candidate = content[start:end]
                excess = {right: candidate.count(right) - candidate.count(left)
                          for left, right in (("(", ")"), ("[", "]"), ("{", "}"))}
                while end > index and excess.get(content[end - 1], 0) > 0:
                    excess[content[end - 1]] -= 1
                    end -= 1
                result = self._url(content[start:end], index - start)
                if result.replacements:
                    edits.append((start, end, result.content))
                    replacements += result.replacements
                index = end
                continue

            if match.lastgroup == "query":
                pair = _QUERY_PAIR.match(content, index)
                if pair:
                    replacement = self._query_value(pair[1], pair[2])
                    if replacement is not None:
                        edits.append((*pair.span(2), replacement))
                        replacements += 1
                    index = pair.end()
                continue

            if match.lastgroup == "quote":
                powershell = _powershell(content, start)
                end, closed = _quote_end(content, start, powershell=powershell)
                name, _ = _literal(content, start, end, closed, powershell=powershell)
                separator = _SEPARATOR.match(content, end) if closed else None
                # A compiler's quoted method signature is prose, not a JSON/YAML
                # credential key (for example a CancellationToken parameter).
                if separator and _METHOD_SIGNATURE.fullmatch(name) and _COMPILER_PREFIX.search(
                    content[_line_start(content, start):start],
                ):
                    separator = None
                index = end
                if separator is None:
                    result = self._quoted(content, start, end, closed, depth, powershell=powershell)
                    if result.replacements:
                        edits.append((start, end, result.content))
                        replacements += result.replacements
                    continue
            else:
                name = match[0]
                separator = _SEPARATOR.match(content, index)

            value_start: int | None = None
            mapping = False
            if separator is not None and _sensitive_name(name):
                if (match.lastgroup == "word" and separator[1] == "="
                        and _CANCELLATION_TYPE.search(content[_line_start(content, start):start])
                        and (default := _CANCELLATION_DEFAULT.match(content, separator.end()))):
                    index = default.end()
                    continue
                value_start = separator.end()
                mapping = separator[1] == ":"
            elif match.lastgroup == "word" and name.lower() in {"basic", "bearer"}:
                if scheme := _SCHEME.match(content, start):
                    value_start = scheme.end()
            if value_start is not None:
                scalar = self._scalar(content, value_start, mapping=mapping, flow=bool(containers))
                if scalar is not None:
                    end, value, count = scalar
                    if count:
                        edits.append((value_start, end, value))
                        replacements += count
                    index = end

        redacted = _apply_edits(content, edits)
        # Fingerprints are deliberately last: never count a token twice because
        # it also occupied an assignment, authorization value, or private key.
        for label, pattern in self._patterns:
            redacted, count = pattern.subn(f"[{label.upper()}_REDACTED]", redacted)
            replacements += count
        return RedactionResult(content=redacted, replacements=replacements)

    def _scalar(
        self, content: str, start: int, *, mapping: bool, flow: bool,
    ) -> tuple[int, str, int] | None:
        if start >= len(content) or content[start] in "\r\n,;}#":
            return None
        if mapping and (header := _BLOCK_HEADER.match(content, start)):
            return self._block(content, start, header.end())
        powershell = _powershell(content, start)
        quote = content[start] if content[start] in "\"'" else ""
        if quote:
            end, closed = _quote_end(content, start, powershell=powershell)
            decoded, _ = _literal(content, start, end, closed, powershell=powershell)
            inner = content[start + 1:end - int(closed)]
            if not mapping and closed:
                token_end = _bare_end(content, start, spaces=False, powershell=powershell)
                if token_end > end:
                    end = token_end
                    inner = decoded = content[start:end]
        else:
            # Leave mappings/lists in place and inspect their own keyed scalars.
            if mapping and content[start] in "[{" and not _MARKED.match(content, start):
                return None
            end = _bare_end(
                content, start, spaces=mapping or bool(_SCHEME.match(content, start)),
                mapping=mapping, flow=flow, powershell=powershell,
            )
            while end > start and content[end - 1] in " \t":
                end -= 1
            inner = decoded = content[start:end]
            closed = False
        if end == start or _benign(decoded):
            return end, content[start:end], 0

        scheme = _SCHEME.match(inner)
        prefix = inner[:scheme.end()] if scheme else ""
        masked = prefix + _mask(inner[len(prefix):])
        if quote:
            masked = quote + masked + (quote if closed else "")
        elif mapping:
            # A bare [REDACTED] is a YAML sequence and an invalid JSON scalar.
            # Keep a scalar a scalar, including JSON numeric credential values.
            masked = '"' + masked + '"'
        return end, masked, int(masked != content[start:end])

    def _quoted(
        self, content: str, start: int, end: int, closed: bool, depth: int,
        *, powershell: bool = False,
    ) -> RedactionResult:
        decoded, json_string = _literal(content, start, end, closed, powershell=powershell)
        result = self._scan(decoded, depth + 1)
        if not result.replacements:
            return RedactionResult(content[start:end], 0)
        if json_string:
            value = json.dumps(result.content, ensure_ascii=True)
        else:
            quote = content[start]
            if quote == "'":
                inner = result.content.replace("'", "''")
            else:
                # Invalid-JSON YAML and PowerShell literals retain their original
                # escapes; only newly inserted quotes need another escape layer.
                escape = "`" if powershell else "\\"
                inner = re.sub(
                    re.escape(escape) + r'[\s\S]|"',
                    lambda match: escape + '"' if match[0] == '"' else match[0],
                    result.content,
                )
            value = quote + inner + (quote if closed else "")
        return RedactionResult(value, result.replacements if value != content[start:end] else 0)

    def _block(self, content: str, start: int, header_end: int) -> tuple[int, str, int]:
        prefix = content[_line_start(content, start):start]
        indentation = len(prefix) - len(prefix.lstrip(" \t"))
        end = header_end
        for line in content[header_end:].splitlines(keepends=True):
            indent = len(line) - len(line.lstrip(" \t"))
            if line.strip() and indent <= indentation:
                break
            end += len(line)
        body = content[header_end:end]
        if _benign(body):
            return end, content[start:end], 0
        first = True

        def mask_line(match: re.Match[str]) -> str:
            nonlocal first
            value = match[0]
            indentation = value[:len(value) - len(value.lstrip(" \t"))]
            if first and value.strip():
                first = False
                return indentation + _MARKER
            return indentation

        body = re.sub(r"[^\r\n]+", mask_line, body)
        return end, content[start:header_end] + body, 1

    @staticmethod
    def _query_value(key: str, value: str) -> str | None:
        if _sensitive_name(_unquote_query(key), query=True) and not _benign(_unquote_query(value)):
            return "%5BREDACTED%5D"
        return None

    def _url(self, content: str, authority_start: int) -> RedactionResult:
        edits: list[tuple[int, int, str]] = []
        # Do not search for @ past the authority: paths, file names and fragments
        # commonly contain it. Escaped JSON slashes delimit the authority too.
        boundary = re.search(r"[/\\?#]", content[authority_start:])
        authority_end = authority_start + boundary.start() if boundary else len(content)
        at = content.rfind("@", authority_start, authority_end)
        if at >= 0:
            # Removing userinfo (rather than inserting bracketed marker userinfo)
            # keeps urllib/IPv6 parsing and the local-knowledge URL validator valid.
            edits.append((authority_start, at + 1, ""))
        fragment = content.find("#", authority_end)
        query_end = fragment if fragment >= 0 else len(content)
        question = content.find("?", authority_end, query_end)
        for start, stop in ((question, query_end), (fragment, len(content))):
            if start < 0:
                continue
            index = start + 1
            while index < stop:
                pair = _QUERY_PAIR.match(content, index, stop)
                if pair:
                    replacement = self._query_value(pair[1], pair[2])
                    if replacement is not None:
                        edits.append((*pair.span(2), replacement))
                    index = pair.end()
                delimiter = _QUERY_DELIMITER.search(content, index, stop)
                if delimiter is None:
                    break
                index = delimiter.end()
        return RedactionResult(_apply_edits(content, edits), len(edits))


def redact_text(content: str) -> str:
    """Convenience function for one-off sanitization."""

    return SecretRedactor().redact(content).content
