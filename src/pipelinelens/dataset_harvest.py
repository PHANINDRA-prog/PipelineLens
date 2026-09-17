"""CLI for the opt-in, offline external dataset importer (e.g. a local Kaggle CSV).

Examples:

``python -m pipelinelens.dataset_harvest --csv logs.csv --source-label kaggle-cicd``
    validates the file/header and prints a local-only preview; no writes.

``python -m pipelinelens.dataset_harvest --csv logs.csv --source-label kaggle-cicd --execute``
    reads, redacts, classifies and stores bounded rows locally.

``python -m pipelinelens.dataset_harvest --reevaluate --execute``
    reclassifies retained redacted excerpts without reading the CSV again.

You must already have the CSV on local disk; this command never downloads, logs
into, or scrapes any dataset site. Output is summary metadata only: never the
original log text, dataset label values, or file contents.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from pathlib import Path

from pipelinelens.services.dataset_corpus import (
    DEFAULT_ROW_LIMIT,
    DatasetCorpus,
    DatasetCorpusError,
    import_dataset,
    preview_dataset_import,
    reevaluate_dataset_corpus,
)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message  # Argv can contain a local file path; do not echo it verbatim.
        self.exit(2, "Invalid arguments. Use --help.\n")


def _json_safe(value: object) -> object:
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump(mode="json"))
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _print(value: object) -> None:
    print(json.dumps(_json_safe(value), indent=2, sort_keys=True))


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(description="Offline import of an already-downloaded CI/CD log dataset.")
    parser.add_argument("--csv", type=Path, help="Path to a local CSV file you already downloaded.")
    parser.add_argument("--source-label", help="Short name for this dataset (required with --csv).")
    parser.add_argument("--text-column", help="Exact CSV header containing the log text.")
    parser.add_argument(
        "--label-column", help="Optional CSV header with the dataset's own status/label.",
    )
    parser.add_argument(
        "--limit", type=int, default=DEFAULT_ROW_LIMIT, metavar="N",
        help=f"Maximum rows to read this run (default: {DEFAULT_ROW_LIMIT}).",
    )
    parser.add_argument(
        "--directory", type=Path,
        help="Local corpus directory; default is ignored data/dataset-corpus.",
    )
    parser.add_argument(
        "--execute", action="store_true", help="Explicitly allow local reads and writes.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--summary", action="store_true", help="Read local aggregate coverage only.")
    mode.add_argument(
        "--reevaluate", action="store_true", help="Reclassify retained excerpts locally.",
    )
    args = parser.parse_args(argv)

    if (args.summary or args.reevaluate) and (args.csv or args.source_label):
        parser.error("Modes cannot be combined with --csv/--source-label.")
    if args.summary and args.execute:
        parser.error("Summary is always read-only.")
    if not (args.summary or args.reevaluate) and not (args.csv and args.source_label):
        parser.error("--csv and --source-label are required for an import plan.")

    try:
        if args.summary:
            _print(DatasetCorpus(args.directory).summary())
            return 0
        if args.reevaluate:
            corpus = DatasetCorpus(args.directory)
            if not args.execute:
                _print({
                    "mode": "dataset_reevaluation_preview", "reads": False, "writes": False,
                    "summary": corpus.summary(),
                })
                return 0
            report = reevaluate_dataset_corpus(corpus)
            _print(report)
            return 3 if report.analysis_error_row_count else 0
        if not args.execute:
            plan = preview_dataset_import(
                args.csv, source_label=args.source_label, text_column=args.text_column,
                label_column=args.label_column, row_limit=args.limit,
            )
            _print({
                "mode": "dataset_import_preview", "reads": False, "writes": False, "plan": plan,
            })
            return 0
        report = import_dataset(
            args.csv, source_label=args.source_label, text_column=args.text_column,
            label_column=args.label_column, row_limit=args.limit,
            corpus=DatasetCorpus(args.directory),
        )
        _print(report)
        return 0 if report.state != "empty" else 3
    except DatasetCorpusError as error:
        _print({"error": str(error)})
        return 2
    except KeyboardInterrupt:
        _print({"state": "interrupted"})
        return 130
    except Exception:
        _print({"error": "Unexpected local failure; sensitive details were omitted."})
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
