"""Offline import of an already-downloaded, arbitrary CI/CD log dataset (e.g. a local
Kaggle CSV export), so more real-world failure text can be run through the SAME
deterministic rules used for live inspections.

This is explicitly NOT model training and NOT an automatic download:
  - PipelineLens never fetches, logs into, or scrapes a dataset site. You must
    already have the CSV on local disk (respecting that source's own license/terms).
  - Each row's log text is redacted and bounded before classification and before any
    local storage; the ORIGINAL text is never retained, only a sha256 hash (for
    de-duplication) and a short redacted excerpt.
  - Classification reuses the exact same ``PipelineAnalyzer`` + ``diagnose_job`` path
    used for a live inspection. No network access, no model call, ever.
  - A dataset's own status/label column (if any) is stored only as a short, redacted,
    bounded string for your own manual comparison. PipelineLens does not compute or
    claim an accuracy/agreement score against it.

The default store is the ignored ``data/dataset-corpus/dataset-corpus.sqlite3``.
"""

from __future__ import annotations

import csv
import re
import sqlite3
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from pipelinelens.services.redaction import redact_text

DEFAULT_DATASET_CORPUS_DIRECTORY = Path(__file__).resolve().parents[3] / "data" / "dataset-corpus"
DEFAULT_TEXT_COLUMNS = (
    "log", "logs", "log_text", "message", "output", "text", "content", "trace",
)
MAX_ROWS_PER_IMPORT = 5_000
DEFAULT_ROW_LIMIT = 500
MAX_EXCERPT_CHARS = 4_000
MAX_LABEL_CHARS = 80
MAX_SOURCE_LABEL_CHARS = 80
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_STORE_BYTES = 128 * 1024 * 1024
_APPLICATION_ID = 0x504C4453
_SCHEMA_VERSION = 1
_SOURCE_LABEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_NOTICE = (
    "Offline, deterministic reclassification of a local dataset you already downloaded. "
    "Not model training, not an accuracy/agreement score, and no network access."
)

__all__ = (
    "DatasetCorpus",
    "DatasetCorpusError",
    "DatasetImportPlan",
    "DatasetImportReport",
    "DatasetCorpusSummary",
    "preview_dataset_import",
    "import_dataset",
    "reevaluate_dataset_corpus",
)


class DatasetCorpusError(RuntimeError):
    """Controlled, credential-free local dataset-corpus failure."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DatasetImportPlan(_Model):
    """An offline plan; constructing one performs no file writes."""

    csv_path: str
    source_label: str
    text_column: str | None
    label_column: str | None
    row_limit: int = Field(ge=1, le=MAX_ROWS_PER_IMPORT)
    notice: str = _NOTICE


class RuleCount(_Model):
    rule_id: str
    count: int = Field(ge=0)


class DatasetCorpusSummary(_Model):
    source_count: int = Field(default=0, ge=0)
    row_count: int = Field(default=0, ge=0)
    classified_row_count: int = Field(default=0, ge=0)
    unknown_row_count: int = Field(default=0, ge=0)
    analysis_error_row_count: int = Field(default=0, ge=0)
    rows_with_dataset_label: int = Field(default=0, ge=0)
    rule_counts: tuple[RuleCount, ...] = ()
    notice: str = _NOTICE


class DatasetImportReport(_Model):
    source_label: str
    state: Literal["complete", "shortfall", "empty"]
    selected_row_count: int = Field(default=0, ge=0)
    new_row_count: int = Field(default=0, ge=0)
    already_retained_row_count: int = Field(default=0, ge=0)
    missing_text_row_count: int = Field(default=0, ge=0)
    summary: DatasetCorpusSummary
    notice: str = _NOTICE


class DatasetReevaluationReport(_Model):
    reevaluated_row_count: int = Field(ge=0)
    classified_row_count: int = Field(ge=0)
    unknown_row_count: int = Field(ge=0)
    analysis_error_row_count: int = Field(ge=0)
    summary: DatasetCorpusSummary
    notice: str = _NOTICE


def _validated_source_label(value: str) -> str:
    if not isinstance(value, str) or not _SOURCE_LABEL.fullmatch(value):
        raise DatasetCorpusError(
            "--source-label must be 1-80 characters: letters, digits, dot, dash or underscore."
        )
    return value


def _detect_text_column(fieldnames: list[str], requested: str | None) -> str:
    if requested:
        for name in fieldnames:
            if name.strip().lower() == requested.strip().lower():
                return name
        raise DatasetCorpusError(f"Column '{requested}' was not found in the CSV header.")
    lowered = {name.strip().lower(): name for name in fieldnames}
    for candidate in DEFAULT_TEXT_COLUMNS:
        if candidate in lowered:
            return lowered[candidate]
    raise DatasetCorpusError(
        "Could not guess the log-text column. Pass --text-column with the exact CSV header."
    )


def _detect_label_column(fieldnames: list[str], requested: str | None) -> str | None:
    if not requested:
        return None
    for name in fieldnames:
        if name.strip().lower() == requested.strip().lower():
            return name
    raise DatasetCorpusError(f"Column '{requested}' was not found in the CSV header.")


def _read_header(csv_path: Path) -> list[str]:
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader, None)
    except OSError as error:
        raise DatasetCorpusError(f"Could not read the CSV file: {error.strerror}") from error
    except UnicodeDecodeError as error:
        raise DatasetCorpusError("The CSV file is not valid UTF-8 text.") from error
    if not header:
        raise DatasetCorpusError("The CSV file has no header row.")
    return [name.strip() for name in header]


def preview_dataset_import(
    csv_path: str | Path,
    *,
    source_label: str,
    text_column: str | None = None,
    label_column: str | None = None,
    row_limit: int = DEFAULT_ROW_LIMIT,
) -> DatasetImportPlan:
    """Validate the path, header and limits. Performs no writes and no classification."""

    path = Path(csv_path)
    label = _validated_source_label(source_label)
    if not (1 <= row_limit <= MAX_ROWS_PER_IMPORT):
        raise DatasetCorpusError(f"--limit must be between 1 and {MAX_ROWS_PER_IMPORT}.")
    if not path.is_file():
        raise DatasetCorpusError("The CSV path does not exist or is not a file.")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise DatasetCorpusError("The CSV file exceeds the local import size limit.")
    fieldnames = _read_header(path)
    resolved_text = _detect_text_column(fieldnames, text_column)
    resolved_label = _detect_label_column(fieldnames, label_column)
    return DatasetImportPlan(
        csv_path=str(path), source_label=label, text_column=resolved_text,
        label_column=resolved_label, row_limit=row_limit,
    )


def _row_hash(text: str) -> str:
    return sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _classify_text(source_label: str, row_hash: str, text: str) -> tuple[str, str, str]:
    """Classify one row's redacted text through the normal deterministic analyzer."""

    from pipelinelens.domain import PipelineJob, PipelineRun, ProviderName, RepositoryRef
    from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
    from pipelinelens.services.findings import diagnose_job
    from pipelinelens.services.pipeline_corpus import _analysis_settings

    try:
        snapshot = PipelineAnalyzer(_analysis_settings()).analyze_input(AnalysisInput(
            repository=RepositoryRef(
                provider=ProviderName.GITLAB, external_id=source_label,
                owner="dataset", name=source_label, web_url=f"dataset://{source_label}",
            ),
            run=PipelineRun(external_id=row_hash[:16], name="Dataset row", status="failed"),
            job=PipelineJob(external_id=row_hash[:16], name="dataset-row", status="failed"),
            configs=[], raw_log=text,
        ))
        finding = diagnose_job(snapshot)
    except Exception:
        return "analysis_error", "dataset.analysis_error", "unknown"
    rule_id = finding.rule_id if isinstance(finding.rule_id, str) else "job.insufficient_evidence"
    category = finding.category if isinstance(finding.category, str) else "unknown"
    state = "unknown" if finding.confidence == "unknown" or category == "unknown" else "classified"
    return state, rule_id, category


@contextmanager
def _connection(directory: Path) -> Iterator[sqlite3.Connection | None]:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "dataset-corpus.sqlite3"
    if path.exists() and path.stat().st_size > MAX_STORE_BYTES:
        yield None
        return
    connection = sqlite3.connect(path, timeout=30, isolation_level=None)
    try:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        (application_id,) = connection.execute("PRAGMA application_id").fetchone()
        if application_id not in (0, _APPLICATION_ID):
            raise DatasetCorpusError("The dataset-corpus file is not a PipelineLens store.")
        connection.execute(f"PRAGMA application_id={_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS sources ("
            "source_label TEXT PRIMARY KEY, row_count INTEGER NOT NULL DEFAULT 0, "
            "imported_at TEXT NOT NULL)"
        )
        connection.execute(
            "CREATE TABLE IF NOT EXISTS rows ("
            "source_label TEXT NOT NULL, row_hash TEXT NOT NULL, excerpt TEXT NOT NULL, "
            "dataset_label TEXT, rule_id TEXT NOT NULL, category TEXT NOT NULL, "
            "state TEXT NOT NULL, classified_at TEXT NOT NULL, "
            "PRIMARY KEY (source_label, row_hash))"
        )
        yield connection
    except sqlite3.DatabaseError as error:
        raise DatasetCorpusError(
            "Dataset corpus is corrupt, incompatible, locked, or unreadable; "
            "existing data was preserved."
        ) from error
    finally:
        connection.close()


class DatasetCorpus:
    """Bounded, local, offline store of redacted dataset-row classifications."""

    def __init__(self, directory: Path | str | None = None) -> None:
        self.directory = Path(directory) if directory else DEFAULT_DATASET_CORPUS_DIRECTORY

    def initialize(self) -> None:
        with _connection(self.directory):
            pass

    def has_row(self, source_label: str, row_hash: str) -> bool:
        with _connection(self.directory) as connection:
            if connection is None:
                return False
            row = connection.execute(
                "SELECT 1 FROM rows WHERE source_label = ? AND row_hash = ?",
                (source_label, row_hash),
            ).fetchone()
            return row is not None

    def record_row(
        self, source_label: str, row_hash: str, excerpt: str, dataset_label: str | None,
        state: str, rule_id: str, category: str, *, now: str,
    ) -> None:
        with _connection(self.directory) as connection:
            if connection is None:
                raise DatasetCorpusError("Dataset corpus has reached its local size limit.")
            connection.execute(
                "INSERT OR REPLACE INTO rows "
                "(source_label, row_hash, excerpt, dataset_label, rule_id, category, "
                "state, classified_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (source_label, row_hash, excerpt, dataset_label, rule_id, category, state, now),
            )
            connection.execute(
                "INSERT INTO sources (source_label, row_count, imported_at) VALUES (?, 1, ?) "
                "ON CONFLICT(source_label) DO UPDATE SET row_count = row_count + 1",
                (source_label, now),
            )

    def summary(self) -> DatasetCorpusSummary:
        with _connection(self.directory) as connection:
            if connection is None:
                return DatasetCorpusSummary()
            source_count = connection.execute("SELECT COUNT(*) FROM sources").fetchone()[0]
            row_count = connection.execute("SELECT COUNT(*) FROM rows").fetchone()[0]
            classified = connection.execute(
                "SELECT COUNT(*) FROM rows WHERE state = 'classified'"
            ).fetchone()[0]
            unknown = connection.execute(
                "SELECT COUNT(*) FROM rows WHERE state = 'unknown'"
            ).fetchone()[0]
            errors = connection.execute(
                "SELECT COUNT(*) FROM rows WHERE state = 'analysis_error'"
            ).fetchone()[0]
            labeled = connection.execute(
                "SELECT COUNT(*) FROM rows WHERE dataset_label IS NOT NULL"
            ).fetchone()[0]
            counts = Counter()
            for rule_id, count in connection.execute(
                "SELECT rule_id, COUNT(*) FROM rows WHERE state = 'classified' GROUP BY rule_id"
            ):
                counts[rule_id] = count
            rule_counts = tuple(
                RuleCount(rule_id=rule_id, count=count)
                for rule_id, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
            )
            return DatasetCorpusSummary(
                source_count=source_count, row_count=row_count, classified_row_count=classified,
                unknown_row_count=unknown, analysis_error_row_count=errors,
                rows_with_dataset_label=labeled, rule_counts=rule_counts,
            )

    def _rows(self) -> list[sqlite3.Row]:
        with _connection(self.directory) as connection:
            if connection is None:
                return []
            connection.row_factory = sqlite3.Row
            return list(connection.execute("SELECT source_label, row_hash, excerpt FROM rows"))

    def _update_classification(
        self, source_label: str, row_hash: str, state: str, rule_id: str, category: str,
        *, now: str,
    ) -> None:
        with _connection(self.directory) as connection:
            if connection is None:
                return
            connection.execute(
                "UPDATE rows SET state = ?, rule_id = ?, category = ?, classified_at = ? "
                "WHERE source_label = ? AND row_hash = ?",
                (state, rule_id, category, now, source_label, row_hash),
            )


def import_dataset(
    csv_path: str | Path,
    *,
    source_label: str,
    text_column: str | None = None,
    label_column: str | None = None,
    row_limit: int = DEFAULT_ROW_LIMIT,
    corpus: DatasetCorpus | None = None,
) -> DatasetImportReport:
    """Explicitly read, redact, classify and store bounded rows from a local CSV."""

    from datetime import UTC, datetime

    plan = preview_dataset_import(
        csv_path, source_label=source_label, text_column=text_column,
        label_column=label_column, row_limit=row_limit,
    )
    active_corpus = corpus if corpus is not None else DatasetCorpus()
    active_corpus.initialize()
    now = datetime.now(UTC).isoformat()
    path = Path(plan.csv_path)
    selected = new_rows = already_retained = missing_text = 0
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for raw_row in reader:
                if selected >= plan.row_limit:
                    break
                selected += 1
                text = (raw_row.get(plan.text_column) or "").strip()
                if not text:
                    missing_text += 1
                    continue
                row_hash = _row_hash(text)
                if active_corpus.has_row(plan.source_label, row_hash):
                    already_retained += 1
                    continue
                redacted = redact_text(text)
                excerpt = redacted[:MAX_EXCERPT_CHARS]
                dataset_label = None
                if plan.label_column:
                    raw_label = (raw_row.get(plan.label_column) or "").strip()
                    if raw_label:
                        dataset_label = redact_text(raw_label)[:MAX_LABEL_CHARS]
                state, rule_id, category = _classify_text(plan.source_label, row_hash, redacted)
                active_corpus.record_row(
                    plan.source_label, row_hash, excerpt, dataset_label,
                    state, rule_id, category, now=now,
                )
                new_rows += 1
    except OSError as error:
        raise DatasetCorpusError(f"Could not read the CSV file: {error.strerror}") from error
    state: Literal["complete", "shortfall", "empty"] = (
        "empty" if new_rows == 0 and already_retained == 0
        else "shortfall" if missing_text > 0 else "complete"
    )
    return DatasetImportReport(
        source_label=plan.source_label, state=state, selected_row_count=selected,
        new_row_count=new_rows, already_retained_row_count=already_retained,
        missing_text_row_count=missing_text, summary=active_corpus.summary(),
    )


def reevaluate_dataset_corpus(corpus: DatasetCorpus) -> DatasetReevaluationReport:
    """Reclassify retained redacted excerpts locally, without reading the CSV again."""

    from datetime import UTC, datetime

    corpus.initialize()
    now = datetime.now(UTC).isoformat()
    reevaluated = classified = unknown = errors = 0
    for row in corpus._rows():
        state, rule_id, category = _classify_text(
            row["source_label"], row["row_hash"], row["excerpt"],
        )
        corpus._update_classification(
            row["source_label"], row["row_hash"], state, rule_id, category, now=now,
        )
        reevaluated += 1
        classified += state == "classified"
        unknown += state == "unknown"
        errors += state == "analysis_error"
    return DatasetReevaluationReport(
        reevaluated_row_count=reevaluated, classified_row_count=classified,
        unknown_row_count=unknown, analysis_error_row_count=errors, summary=corpus.summary(),
    )
