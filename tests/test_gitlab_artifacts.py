"""Offline regression coverage for bounded GitLab artifact inspection."""

from __future__ import annotations

import io
import json
import struct
import warnings
import zipfile

import pytest

from pipelinelens.services.gitlab_artifacts import ArtifactInspection, inspect_job_artifact

SUMMARY_PATH = "datasync/deploy-summary.json"
JOB_URL = "https://gitlab.test/group/project/-/jobs/182518438"


def _archive(entries: list[tuple[str, bytes]], *, compression: int = zipfile.ZIP_DEFLATED) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=compression) as zip_archive:
        for path, content in entries:
            zip_archive.writestr(path, content)
    return stream.getvalue()


def _summary_archive(summary: object) -> bytes:
    return _archive([(SUMMARY_PATH, json.dumps(summary).encode("utf-8"))])


def _summary_with_rows(rows: list[object], *, failed: int = 0) -> dict[str, object]:
    return {
        "env": "MERCURY",
        "dryRun": False,
        "count": 227,
        "failedCount": 0,
        "mappings": {"updated": 227},
        "fieldMappings": {
            "deployed": 4727,
            "failed": failed,
            "skipped": 897,
            "failures": rows,
        },
        "valueTransformations": {"failed": 0},
    }


def _central_directory_with_uncompressed_size(archive: bytes, size: int) -> bytes:
    modified = bytearray(archive)
    central_directory = modified.index(b"PK\x01\x02")
    struct.pack_into("<I", modified, central_directory + 24, size)
    return bytes(modified)


def _corrupt_first_member_data(archive: bytes) -> bytes:
    modified = bytearray(archive)
    local_header = modified.index(b"PK\x03\x04")
    file_name_size, extra_size = struct.unpack_from("<HH", modified, local_header + 26)
    data_start = local_header + 30 + file_name_size + extra_size
    modified[data_start] ^= 0x01
    return bytes(modified)


def _deep_json(depth: int) -> bytes:
    content = "null"
    for _ in range(depth):
        content = '{"nested":' + content + "}"
    return content.encode("utf-8")


def test_connection_reset_field_mapping_failure_is_redacted_bounded_and_linked() -> None:
    signed_secret = "fixture-signed-value-not-for-output"
    summary = _summary_with_rows([
        {"status": "updated", "error": "ConnectionResetError: old completed work"},
        {
            "status": "failed",
            "error": (
                "ConnectionResetError: peer reset "
                f"https://download.test/result?sig={signed_secret}"
            ),
            "response": {"opaque": "must not reach output"},
            "mapping": "opaque-id-must-not-reach-output",
        },
    ], failed=1)

    inspection = inspect_job_artifact(_summary_archive(summary), job_web_url=JOB_URL)

    assert isinstance(inspection, ArtifactInspection)
    assert inspection.recognized_paths == (SUMMARY_PATH,)
    assert len(inspection.findings) == 1
    finding = inspection.findings[0]
    assert finding.rule_id == "rlp.datasync_field_mapping_connection_reset"
    assert finding.category == "deployment_transport_failure"
    assert finding.severity == "error"
    assert finding.confidence == "observed"
    assert finding.owner == "RLP DataSync / target platform"
    assert finding.title == "DataSync field mapping deployment encountered a connection reset"
    evidence = finding.evidence[0]
    assert evidence.path == SUMMARY_PATH
    assert evidence.source_url == f"{JOB_URL}/artifacts/file/{SUMMARY_PATH}"
    assert "deployed=4727" in evidence.text
    assert "failed=1" in evidence.text
    assert "skipped=897" in evidence.text
    assert "updated=227" in evidence.text
    output = inspection.model_dump_json()
    assert signed_secret not in output
    assert "opaque-id-must-not-reach-output" not in output
    assert "must not reach output" not in output


def test_updated_success_and_skipped_rows_do_not_create_a_failure() -> None:
    summary = _summary_with_rows([
        {"status": "updated", "error": "ConnectionResetError: completed update"},
        {"status": "success"},
        {"status": "skipped"},
    ])

    inspection = inspect_job_artifact(_summary_archive(summary), job_web_url=JOB_URL)

    assert inspection.findings == []
    assert inspection.recognized_paths == (SUMMARY_PATH,)


def test_explicitly_benign_rows_do_not_become_failures_from_an_inconsistent_counter() -> None:
    summary = _summary_with_rows([
        {"status": "updated"},
        {"status": "success"},
        {"status": "skipped"},
    ], failed=1)

    inspection = inspect_job_artifact(_summary_archive(summary), job_web_url=JOB_URL)

    assert inspection.findings == []


def test_actual_failure_after_benign_rows_is_still_observed_within_the_row_bound() -> None:
    summary = _summary_with_rows(
        [{"status": "updated"} for _ in range(24)]
        + [{"status": "failed", "error": "ConnectionResetError: peer reset"}],
        failed=1,
    )

    inspection = inspect_job_artifact(_summary_archive(summary), job_web_url=JOB_URL)

    assert inspection.findings[0].rule_id == "rlp.datasync_field_mapping_connection_reset"


def test_summary_survives_larger_uninterpreted_receipt_and_hundreds_of_skips() -> None:
    summary = _summary_with_rows(
        [{"status": "skipped", "error": "Compatibility skip"} for _ in range(897)]
        + [{"status": "failed", "error": "ConnectionResetError: peer reset"}],
        failed=1,
    )
    archive = _archive([
        ("datasync/receipt.json", b"x" * (6 * 1024 * 1024)),
        (SUMMARY_PATH, json.dumps(summary).encode("utf-8")),
    ])

    inspection = inspect_job_artifact(archive, job_web_url=JOB_URL)

    assert inspection.recognized_paths == (SUMMARY_PATH,)
    assert inspection.notes == []
    assert len(inspection.findings) == 1
    assert inspection.findings[0].rule_id == "rlp.datasync_field_mapping_connection_reset"
    assert "skipped=897" in inspection.findings[0].evidence[0].text
    assert "receipt.json" not in inspection.model_dump_json()


def test_non_summary_entry_still_has_a_strict_uncompressed_limit() -> None:
    archive = _archive([
        ("datasync/receipt.json", b"x" * (8 * 1024 * 1024 + 1)),
        (SUMMARY_PATH, b"{}"),
    ])

    inspection = inspect_job_artifact(archive)

    assert inspection.findings == []
    assert inspection.recognized_paths == ()
    assert inspection.notes == ["The job artifact archive could not be inspected safely."]


def test_total_uncompressed_limit_applies_to_other_members_too() -> None:
    archive = _archive([
        (f"datasync/receipt-{index}.json", b"x" * (6 * 1024 * 1024))
        for index in range(3)
    ] + [(SUMMARY_PATH, b"{}")])

    inspection = inspect_job_artifact(archive)

    assert inspection.findings == []
    assert inspection.recognized_paths == ()
    assert inspection.notes == ["The job artifact archive could not be inspected safely."]


def test_row_bound_never_infers_a_reset_from_an_unread_row() -> None:
    summary = _summary_with_rows(
        [{"status": "skipped"} for _ in range(10_000)]
        + [{"status": "failed", "error": "ConnectionResetError: peer reset"}],
        failed=1,
    )

    inspection = inspect_job_artifact(_summary_archive(summary))

    assert inspection.findings[0].rule_id == "rlp.datasync_field_mapping_artifact_failure"
    assert inspection.findings[0].confidence == "unknown"
    assert inspection.notes == [
        "DataSync field-mapping failure details were bounded for inspection.",
    ]


def test_multiple_actual_failures_are_reported_once_with_a_bounded_note() -> None:
    summary = _summary_with_rows(
        [{"status": "failed", "error": "unclassified target failure"} for _ in range(21)],
        failed=21,
    )

    inspection = inspect_job_artifact(_summary_archive(summary), job_web_url=JOB_URL)

    assert [finding.rule_id for finding in inspection.findings] == [
        "rlp.datasync_field_mapping_artifact_failure",
    ]
    assert inspection.notes == [
        "DataSync field-mapping failure details were bounded for inspection.",
    ]


def test_unknown_actual_failure_remains_generic_and_does_not_leak_error_text() -> None:
    signed_secret = "fixture-generic-signed-value-not-for-output"
    summary = _summary_with_rows([
        {
            "status": "failed",
            "error": f"unclassified target condition; token={signed_secret}",
            "response": "entire raw response must remain private",
        },
    ], failed=1)

    inspection = inspect_job_artifact(_summary_archive(summary), job_web_url=JOB_URL)

    assert len(inspection.findings) == 1
    finding = inspection.findings[0]
    assert finding.rule_id == "rlp.datasync_field_mapping_artifact_failure"
    assert finding.category == "deployment_failure"
    assert finding.confidence == "unknown"
    assert signed_secret not in inspection.model_dump_json()
    assert "entire raw response" not in inspection.model_dump_json()


def test_source_url_requires_a_query_free_safe_job_url() -> None:
    signed_secret = "fixture-url-signature-not-for-output"
    summary = _summary_with_rows([
        {"status": "failed", "error": "ConnectionResetError: peer reset"},
    ], failed=1)

    inspection = inspect_job_artifact(
        _summary_archive(summary),
        job_web_url=f"{JOB_URL}?sig={signed_secret}",
    )

    assert inspection.findings[0].evidence[0].source_url is None
    assert signed_secret not in inspection.model_dump_json()


@pytest.mark.parametrize("job_web_url", [
    "https://gitlab.test/group/project/artifacts",
    "https://gitlab.test/group/project/-/jobs/not-an-id",
    "https://gitlab.test/group/project/-/jobs/182518438#private",
])
def test_source_url_requires_a_canonical_gitlab_job_path(job_web_url: str) -> None:
    summary = _summary_with_rows([
        {"status": "failed", "error": "ConnectionResetError: peer reset"},
    ], failed=1)

    inspection = inspect_job_artifact(_summary_archive(summary), job_web_url=job_web_url)

    assert inspection.findings[0].evidence[0].source_url is None


@pytest.mark.parametrize("archive", [
    b"",
    _archive([]),
    _archive([("other/result.json", b"{}")]),
])
def test_empty_or_missing_artifacts_produce_no_findings(archive: bytes) -> None:
    inspection = inspect_job_artifact(archive)

    assert inspection.findings == []
    assert inspection.recognized_paths == ()
    assert all("other/result.json" not in note for note in inspection.notes)


def test_path_traversal_is_rejected_without_echoing_the_member_name() -> None:
    unsafe_path = "../datasync/deploy-summary.json"
    inspection = inspect_job_artifact(_archive([(unsafe_path, b"{}")] ))

    assert inspection.findings == []
    assert inspection.recognized_paths == ()
    assert unsafe_path not in inspection.model_dump_json()


def test_non_zip_prefix_is_rejected_without_parsing_a_trailing_zip() -> None:
    archive = b"not-a-zip-prefix" + _summary_archive({})

    inspection = inspect_job_artifact(archive)

    assert inspection.findings == []
    assert inspection.recognized_paths == ()


def test_duplicate_summary_candidates_are_rejected() -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        archive = _archive([(SUMMARY_PATH, b"{}"), (SUMMARY_PATH, b"{}")])

    inspection = inspect_job_artifact(archive)

    assert inspection.findings == []
    assert inspection.recognized_paths == ()


def test_zip_bomb_metadata_is_rejected_before_decompression() -> None:
    archive = _central_directory_with_uncompressed_size(_summary_archive({}), 1_048_577)

    inspection = inspect_job_artifact(archive)

    assert inspection.findings == []
    assert inspection.recognized_paths == ()


def test_corrupt_member_crc_is_rejected_without_exposing_archive_data() -> None:
    secret = b"fixture-crc-content-not-for-output"
    archive = _corrupt_first_member_data(_archive([("private.txt", secret)]))

    inspection = inspect_job_artifact(archive)

    assert inspection.findings == []
    assert inspection.recognized_paths == ()
    assert secret.decode() not in inspection.model_dump_json()


@pytest.mark.parametrize("payload", [
    b'{"fieldMappings":',
    b'{"fieldMappings": {}, "fieldMappings": {}}',
    b'{"fieldMappings": {"failed": NaN}}',
    b'{"fieldMappings": {"failed": 1e999}}',
    _deep_json(65),
])
def test_malformed_duplicate_nonfinite_or_deep_summary_is_rejected(payload: bytes) -> None:
    inspection = inspect_job_artifact(_archive([(SUMMARY_PATH, payload)]))

    assert inspection.findings == []
    assert inspection.recognized_paths == (SUMMARY_PATH,)
    assert inspection.notes == ["The DataSync deploy summary could not be parsed safely."]