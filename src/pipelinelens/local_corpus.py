"""Opt-in local ingestion for sanitized, non-public CI knowledge."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path

from pipelinelens.config import Settings, get_settings
from pipelinelens.services.redaction import SecretRedactor
from pipelinelens.storage import IncidentStore

_EXCLUDED_DIRECTORIES = {
    ".git",
    ".sf",
    ".sfdx",
    ".venv",
    "__pycache__",
    "bin",
    "obj",
    "node_modules",
}
_EXCLUDED_FILE_PARTS = {"token", "secret", "credential", "password", ".env"}
_CURATED_FILENAMES = {".gitlab-ci.yml", "gitlab-ci.yml", "pipeline.yml", "pipeline.yaml"}


@dataclass(frozen=True, slots=True)
class CorpusImportReport:
    discovered: int
    imported: int
    skipped: int
    redactions: int
    files: list[str]


def _is_candidate(path: Path, root: Path, include_source: bool) -> bool:
    relative = path.relative_to(root)
    lower_parts = [part.lower() for part in relative.parts]
    if any(part in _EXCLUDED_DIRECTORIES for part in lower_parts[:-1]):
        return False
    name = path.name.lower()
    if path.suffix.lower() == ".exe" or any(part in name for part in _EXCLUDED_FILE_PARTS):
        return False
    if name in _CURATED_FILENAMES:
        return True
    if (
        len(relative.parts) >= 3
        and relative.parts[0] == ".github"
        and relative.parts[1] == "workflows"
    ):
        return path.suffix.lower() in {".yml", ".yaml"}
    if path.suffix.lower() in {".log", ".trace"} or "pipeline" in name or "trace" in name:
        return path.suffix.lower() in {".log", ".txt", ".trace"}
    if name in {"runbook.md", "issues_and_resolutions.md", "ci_failures.md"}:
        return True
    return include_source and path.suffix.lower() in {".py", ".cs"}


class LocalCorpusImporter:
    """Imports only redacted, purpose-built local CI corpus records after explicit opt-in."""

    def __init__(self, store: IncidentStore, settings: Settings | None = None) -> None:
        self.store = store
        self.settings = settings or get_settings()
        self.redactor = SecretRedactor()

    def preview(
        self, root: Path, include_source: bool = False, max_files: int = 100
    ) -> CorpusImportReport:
        candidates = [
            path
            for path in sorted(root.rglob("*"))
            if path.is_file() and _is_candidate(path, root, include_source)
        ][:max_files]
        return CorpusImportReport(
            discovered=len(candidates),
            imported=0,
            skipped=0,
            redactions=0,
            files=[str(path.relative_to(root)) for path in candidates],
        )

    def ingest(
        self,
        root: Path,
        source_label: str,
        *,
        include_source: bool = False,
        max_files: int = 100,
        max_file_bytes: int = 250000,
    ) -> CorpusImportReport:
        if not self.settings.allow_private_context:
            raise PermissionError(
                "Set PIPELINELENS_ALLOW_PRIVATE_CONTEXT=true for local corpus ingestion."
            )
        preview = self.preview(root, include_source=include_source, max_files=max_files)
        imported = 0
        skipped = 0
        redactions = 0
        files: list[str] = []
        for relative_name in preview.files:
            path = root / relative_name
            if path.stat().st_size > max_file_bytes:
                skipped += 1
                continue
            try:
                raw_content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                skipped += 1
                continue
            sanitized = self.redactor.redact(raw_content)
            self.store.upsert_knowledge_document(
                source_label=source_label,
                source_path=relative_name.replace("\\", "/"),
                content=sanitized.content,
                private_scope=True,
            )
            imported += 1
            redactions += sanitized.replacements
            files.append(relative_name.replace("\\", "/"))
        return CorpusImportReport(
            discovered=preview.discovered,
            imported=imported,
            skipped=skipped,
            redactions=redactions,
            files=files,
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Import a local, redacted CI corpus into PipelineLens."
    )
    parser.add_argument("root", type=Path, help="Local repository root to scan.")
    parser.add_argument("--label", required=True, help="Human-readable local source label.")
    parser.add_argument(
        "--include-source",
        action="store_true",
        help="Include Python/C# source files in addition to CI evidence.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Persist the redacted corpus. Defaults to preview only.",
    )
    args = parser.parse_args()

    settings = get_settings()
    store = IncidentStore(settings.database_url)
    store.initialize()
    importer = LocalCorpusImporter(store, settings)
    report = (
        importer.ingest(args.root, args.label, include_source=args.include_source)
        if args.execute
        else importer.preview(args.root, include_source=args.include_source)
    )
    print(
        "discovered="
        f"{report.discovered} imported={report.imported} skipped={report.skipped} "
        f"redactions={report.redactions}"
    )
    for path in report.files:
        print(path)


if __name__ == "__main__":
    main()
