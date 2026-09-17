"""Offline regression coverage for the local, opt-in external dataset importer.

No network access is used or permitted; everything reads/writes only within a
pytest ``tmp_path``. Classification reuses the real deterministic analyzer, so a
recognizable synthetic log line proves genuine (not stubbed) classification.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from pipelinelens.dataset_harvest import main as cli_main
from pipelinelens.services.dataset_corpus import (
    DatasetCorpus,
    DatasetCorpusError,
    import_dataset,
    preview_dataset_import,
    reevaluate_dataset_corpus,
)

SECRET = "fixture-dataset-secret-not-a-real-credential"
CS0161_LINE = (
    "src/Controller.cs(47,30): error CS0161: Controller.GetItems(string, bool): "
    "not all code paths return a value"
)


def _write_csv(path: Path, rows: list[dict[str, str]], fieldnames: list[str]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_preview_detects_a_conventional_text_column_without_writes(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "logs.csv",
        [{"log": CS0161_LINE, "status": "failure"}],
        ["log", "status"],
    )
    plan = preview_dataset_import(csv_path, source_label="unit-test-ds")
    assert plan.text_column == "log"
    assert plan.label_column is None
    assert plan.row_limit > 0
    corpus = DatasetCorpus(tmp_path / "store")
    assert corpus.summary().row_count == 0  # Preview never writes.


def test_preview_rejects_missing_file_bad_label_and_unknown_column(tmp_path: Path) -> None:
    with pytest.raises(DatasetCorpusError):
        preview_dataset_import(tmp_path / "missing.csv", source_label="ok")
    csv_path = _write_csv(tmp_path / "logs.csv", [{"log": "x"}], ["log"])
    with pytest.raises(DatasetCorpusError):
        preview_dataset_import(csv_path, source_label="../not allowed")
    with pytest.raises(DatasetCorpusError):
        preview_dataset_import(csv_path, source_label="ok", text_column="does_not_exist")


def test_import_classifies_a_real_pattern_and_bounds_redacts_the_label(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "logs.csv",
        [{"log": f"{CS0161_LINE} token={SECRET}", "status": f"failed token={SECRET}"}],
        ["log", "status"],
    )
    corpus = DatasetCorpus(tmp_path / "store")
    report = import_dataset(
        csv_path, source_label="unit-test-ds", label_column="status", corpus=corpus,
    )

    assert report.state == "complete"
    assert report.new_row_count == 1
    assert report.already_retained_row_count == 0
    assert report.summary.row_count == 1
    assert report.summary.rows_with_dataset_label == 1
    rule_ids = {item.rule_id for item in report.summary.rule_counts}
    assert "compiler.cs0161" in rule_ids
    dump = json.loads(report.model_dump_json())
    assert SECRET not in json.dumps(dump)


def test_reimport_deduplicates_by_row_hash_not_position(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "logs.csv", [{"log": CS0161_LINE}], ["log"])
    corpus = DatasetCorpus(tmp_path / "store")
    first = import_dataset(csv_path, source_label="unit-test-ds", corpus=corpus)
    second = import_dataset(csv_path, source_label="unit-test-ds", corpus=corpus)

    assert first.new_row_count == 1
    assert second.new_row_count == 0
    assert second.already_retained_row_count == 1
    assert corpus.summary().row_count == 1


def test_rows_with_blank_text_are_counted_and_skipped(tmp_path: Path) -> None:
    csv_path = _write_csv(
        tmp_path / "logs.csv",
        [{"log": ""}, {"log": "   "}, {"log": CS0161_LINE}],
        ["log"],
    )
    corpus = DatasetCorpus(tmp_path / "store")
    report = import_dataset(csv_path, source_label="unit-test-ds", corpus=corpus)

    assert report.missing_text_row_count == 2
    assert report.new_row_count == 1
    assert report.state == "shortfall"


def test_row_limit_bounds_how_many_rows_are_read(tmp_path: Path) -> None:
    rows = [{"log": CS0161_LINE} for _ in range(10)]
    csv_path = _write_csv(tmp_path / "logs.csv", rows, ["log"])
    corpus = DatasetCorpus(tmp_path / "store")
    report = import_dataset(csv_path, source_label="unit-test-ds", row_limit=3, corpus=corpus)
    assert report.selected_row_count == 3
    assert report.new_row_count == 1  # Identical rows dedupe to one stored hash.


def test_reevaluate_is_offline_and_reclassifies_retained_excerpts(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "logs.csv", [{"log": CS0161_LINE}], ["log"])
    corpus = DatasetCorpus(tmp_path / "store")
    import_dataset(csv_path, source_label="unit-test-ds", corpus=corpus)

    report = reevaluate_dataset_corpus(corpus)

    assert report.reevaluated_row_count == 1
    assert report.classified_row_count == 1
    assert report.analysis_error_row_count == 0
    rule_ids = {item.rule_id for item in report.summary.rule_counts}
    assert "compiler.cs0161" in rule_ids


def test_unrecognized_text_is_unknown_not_an_error(tmp_path: Path) -> None:
    csv_path = _write_csv(tmp_path / "logs.csv", [{"log": "just some ordinary line"}], ["log"])
    corpus = DatasetCorpus(tmp_path / "store")
    report = import_dataset(csv_path, source_label="unit-test-ds", corpus=corpus)
    assert report.summary.unknown_row_count == 1
    assert report.summary.analysis_error_row_count == 0


def test_cli_preview_then_execute_then_summary(tmp_path: Path, capsys, monkeypatch) -> None:
    csv_path = _write_csv(tmp_path / "logs.csv", [{"log": CS0161_LINE}], ["log"])
    directory = tmp_path / "store"
    monkeypatch.chdir(tmp_path)

    exit_code = cli_main([
        "--csv", str(csv_path), "--source-label", "unit-test-ds", "--directory", str(directory),
    ])
    preview = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert preview["reads"] is False and preview["writes"] is False
    assert not (directory / "dataset-corpus.sqlite3").exists()

    exit_code = cli_main([
        "--csv", str(csv_path), "--source-label", "unit-test-ds", "--directory", str(directory),
        "--execute",
    ])
    report = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert report["new_row_count"] == 1

    exit_code = cli_main(["--summary", "--directory", str(directory)])
    summary = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert summary["row_count"] == 1


def test_cli_rejects_combined_modes_and_missing_required_args(capsys) -> None:
    with pytest.raises(SystemExit) as combined:
        cli_main(["--summary", "--csv", "x.csv", "--source-label", "y"])
    assert combined.value.code == 2
    with pytest.raises(SystemExit) as missing:
        cli_main([])
    assert missing.value.code == 2
    captured = capsys.readouterr().out + capsys.readouterr().err
    assert "x.csv" not in captured


def test_cli_never_prints_the_dataset_label_or_log_text(tmp_path: Path, capsys) -> None:
    csv_path = _write_csv(
        tmp_path / "logs.csv",
        [{"log": f"{CS0161_LINE} {SECRET}", "status": SECRET}],
        ["log", "status"],
    )
    directory = tmp_path / "store"
    cli_main([
        "--csv", str(csv_path), "--source-label", "unit-test-ds", "--label-column", "status",
        "--directory", str(directory), "--execute",
    ])
    out = capsys.readouterr().out
    assert SECRET not in out
