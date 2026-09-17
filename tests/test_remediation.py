"""Synthetic offline remediation contracts; every proposed diff is applied exactly in memory."""

from __future__ import annotations

import builtins
import copy
import inspect
import json
import os
import re
import socket
from pathlib import Path
from urllib.parse import quote
from xml.etree import ElementTree

import pytest
from pydantic import ValidationError
from ruamel.yaml import YAML

from pipelinelens.domain import (
    AnalysisProgress,
    AnalysisSnapshot,
    CiConfigFile,
    CodeReference,
    DeploymentComponentFailure,
    DiagnosisResult,
    FailureFingerprint,
    PipelineGraph,
    PipelineJob,
    PipelineRun,
    ProviderName,
    RepositoryRef,
    SimilarIncident,
)
from pipelinelens.services.findings import Finding, FindingEvidence
from pipelinelens.services.remediation import (
    ProposedChange,
    Remediation,
    SourceBlock,
    build_remediation,
    candidate_source_paths,
)

SHA = "a" * 40
OTHER_SHA = "b" * 40
REPO = "https://gitlab.example.test/team/project"
NS = "http://soap.sforce.com/2006/04/metadata"
XML_PATH = "metadata/destructiveChangesPost.xml"
JSON_PATH = "config/asfdx-project.json"
ROW = (
    "LightningComponentBundle  exampleWidget  The component is referenced by "
    "exampleWidget : Custom Tab Definition - exampleWidget."
)
CSV_ERROR = "InvalidJob : Unable to find object: Routing__c.csv"
CS_ERROR = (
    "src/Widget.cs(4,19): error CS0161: 'Widget.Resolve(bool)': "
    "not all code paths return a value"
)
CS_SOURCE = (
    "namespace Example;\npublic class Widget\n{\n    public string Resolve(bool ready)\n"
    '    {\n        if (ready) return "ready";\n    }\n}\n'
)
TRACE_DOC = "https://docs.gitlab.com/ci/jobs/job_logs/"


def _source(
    path: str, content: str, *, ref: str = SHA, repository: str = REPO,
) -> CiConfigFile:
    return CiConfigFile(
        path=path, ref=ref, content=content, content_sha="c" * 40,
        source_url=f"{repository}/-/blob/{ref}/{quote(path, safe='/')}",
    )


def _snapshot(config: CiConfigFile | None = None, *, sha: str | None = SHA) -> AnalysisSnapshot:
    config = config or _source(".gitlab-ci.yml", "build:\n  script: echo verify\n")
    return AnalysisSnapshot(
        analysis_id="synthetic-analysis",
        repository=RepositoryRef(
            provider=ProviderName.GITLAB, external_id="100", owner="team", name="project",
            web_url=REPO,
        ),
        run=PipelineRun(external_id="200", name="test", status="failed", commit_sha=sha),
        job=PipelineJob(external_id="300", name="build", status="failed"),
        progress=AnalysisProgress(), config=config, config_bundle=[config],
        graph=PipelineGraph(provider=ProviderName.GITLAB, config_files=[config.path]),
        redacted_log="", chunks=[],
        fingerprint=FailureFingerprint(
            digest="synthetic", category="unknown", normalized_message="",
        ),
        diagnosis=DiagnosisResult(
            failure_category="unknown", confidence=0.2, summary="test", likely_root_cause="unknown",
        ),
    )


def _finding(
    rule: str = "salesforce.metadata_dependency", text: str = ROW, *,
    evidence: list[FindingEvidence] | None = None, category: str = "deployment_failure",
) -> Finding:
    return Finding(
        rule_id=rule, severity="error", category=category, title="Synthetic failure",
        explanation="Synthetic diagnostic", fix=[],
        evidence=evidence if evidence is not None else [FindingEvidence(text=text, line=11)],
        job_id="300",
    )


def _manifest(
    members: tuple[str, ...] = ("exampleWidget", "otherWidget"), *, newline: str = "\n",
    prefix: str = "", suffix: str = "", terminal_newline: bool = True,
) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>', f'<Package xmlns="{NS}">',
        "  <types>", *(f"    <members>{name}</members>" for name in members),
        "    <name>LightningComponentBundle</name>", "  </types>",
    ]
    if suffix:
        lines.append(suffix)
    lines.extend(["  <version>65.0</version>", "</Package>"])
    return prefix + newline.join(lines) + (newline if terminal_newline else "")


def _apply_exact(before: str, diff: str, path: str) -> str:
    """Small strict unified-diff applier, including CRLF and no-final-newline records."""
    records = diff.splitlines(keepends=True)
    assert records[:3] == [
        f"diff --git a/{path} b/{path}\n", f"--- a/{path}\n", f"+++ b/{path}\n",
    ]
    original = before.splitlines(keepends=True)
    result: list[str] = []
    cursor = 0
    index = 3
    hunks = 0
    while index < len(records):
        header = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@\n", records[index])
        assert header, records[index]
        old_start, old_count, new_start, new_count = (
            int(header[1]), int(header[2] or 1), int(header[3]), int(header[4] or 1),
        )
        target = old_start - 1 if old_count else old_start
        assert cursor <= target <= len(original)
        result.extend(original[cursor:target])
        cursor = target
        assert len(result) == (new_start - 1 if new_count else new_start)
        removed = added = 0
        index += 1
        while index < len(records) and not records[index].startswith("@@ "):
            record = records[index]
            assert record[0] in " +-", record
            operation, payload = record[0], record[1:]
            index += 1
            if index < len(records) and records[index] == "\\ No newline at end of file\n":
                assert payload.endswith("\n")
                payload = payload[:-1]
                index += 1
            if operation in " -":
                assert cursor < len(original) and original[cursor] == payload
                cursor += 1
                removed += 1
            if operation in " +":
                result.append(payload)
                added += 1
        assert (removed, added) == (old_count, new_count)
        hunks += 1
    assert hunks > 0
    return "".join([*result, *original[cursor:]])


def _propose_xml(content: str, *, finding: Finding | None = None) -> Remediation:
    return build_remediation(finding or _finding(), _snapshot(), [_source(XML_PATH, content)],
                             changes=[{"new_path": XML_PATH}])


def _propose_csv(content: str, path: str = JSON_PATH, *, known: bool = True) -> Remediation:
    return build_remediation(
        _finding("salesforce.csv_as_sobject", CSV_ERROR), _snapshot(), [_source(path, content)],
        changes=[{"new_path": path}], known_paths=[path] if known else [],
    )


def _case(
    content: str = "include:\n  - local: 'ci/build.yml'\n", *, line: int = 2,
    known: list[str] | None = None, cited: str | None = None, changed: bool = True,
) -> Remediation:
    source = _source(".gitlab-ci.yml", content)
    evidence = FindingEvidence(
        path=source.path, line=line,
        text=cited if cited is not None else content.splitlines()[line - 1],
        source_url=f"{source.source_url}#L{line}",
    )
    return build_remediation(
        _finding("change.ci_path_case_mismatch", evidence=[evidence],
                 category="repository_path_risk"),
        _snapshot(source), [source], changes=[{"new_path": source.path}] if changed else [],
        known_paths=known if known is not None else ["ci/Build.yml"],
    )


def test_public_models_and_function_signatures_match_the_fixed_contract():
    assert set(Remediation.model_fields) == {
        "finding_key", "project_key",
        "job_id", "rule_id", "summary", "cause_confidence", "fix_confidence", "confidence_basis",
        "score_label", "proposals", "source_blocks", "actions", "missing_information",
        "documentation", "auto_apply_allowed",
    }
    assert set(ProposedChange.model_fields) == {
        "title", "path", "ref", "source_url", "diff", "rationale", "condition", "verification",
        "kind",
    }
    assert set(SourceBlock.model_fields) == {
        "path", "ref", "source_url", "line_start", "line_end", "content", "language",
    }
    for function, names in [
        (build_remediation, ["finding", "snapshot", "sources", "changes", "known_paths"]),
        (candidate_source_paths, ["finding", "snapshot", "changes", "known_paths"]),
    ]:
        signature = inspect.signature(function)
        assert list(signature.parameters) == names
        assert signature.parameters["changes"].default is None
        assert signature.parameters["known_paths"].default is None
    result = build_remediation(_finding(), None, [])
    assert result.auto_apply_allowed is False
    assert result.score_label == "Rule-based heuristic; not a calibrated probability"
    assert result.documentation == [TRACE_DOC]
    assert Remediation.model_validate_json(result.model_dump_json()) == result


def test_datasync_artifact_reset_has_high_cause_but_low_fix_confidence():
    finding = _finding(
        "rlp.datasync_field_mapping_connection_reset",
        "DataSync deploy summary counters: failed=1. A bounded actual field-mapping "
        "failure reports a connection reset.",
        category="deployment_transport_failure",
    )
    result = build_remediation(finding, _snapshot(), [])

    assert result.cause_confidence == 94
    assert result.fix_confidence == 15
    assert not result.proposals
    assert "Target-platform diagnostics" in result.missing_information[0]


@pytest.mark.parametrize("field,value", [
    ("cause_confidence", -1), ("cause_confidence", 101), ("cause_confidence", 3.5),
    ("fix_confidence", -1), ("fix_confidence", 101), ("fix_confidence", True),
    ("auto_apply_allowed", True), ("score_label", "calibrated probability"),
])
def test_model_rejects_scores_and_automatic_application(field, value):
    data = build_remediation(_finding(), None, []).model_dump()
    data[field] = value
    with pytest.raises(ValidationError):
        Remediation.model_validate(data)


def test_model_list_defaults_are_independent_and_source_lines_are_ordered():
    first = build_remediation(_finding(), None, [])
    second = build_remediation(_finding(), None, [])
    first.actions.append("changed only in memory")
    assert "changed only in memory" not in second.actions
    with pytest.raises(ValidationError):
        SourceBlock(path="x.cs", ref=SHA, source_url=None, line_start=3, line_end=2,
                    content="", language="csharp")


@pytest.mark.parametrize("unsafe", [
    ".env", ".env.example", "src/.env.local", "src/token_helper.py", "ci/credentials.yml",
    "ci/secrets.yml", "ci/private-key.yml", "keys/key.pem", "keys/data.pfx", ".git/config",
    ".ssh/id_rsa", "../src/File.cs", "src/../File.cs", "/src/File.cs", "./src/File.cs",
    "C:/src/File.cs", r"src\File.cs", "https://elsewhere.test/File.cs", "//host/File.cs",
    "src/%2e%2e/File.cs", "src/%252e%252e/File.cs", "src\n/File.cs", "src\x00File.cs",
    "src\t/File.cs", "src/File.cs?token=value", "src/File.cs#L1", "src//File.cs",
    "src/Ｆile.cs", "src/File.cs\u202e", "src/auth.json",
])
def test_candidates_reject_unsafe_or_secret_paths(unsafe):
    finding = _finding("compiler.cs0161", evidence=[
        FindingEvidence(text=CS_ERROR, path=unsafe, line=4),
    ])
    assert candidate_source_paths(finding, _snapshot(), known_paths=[unsafe]) == []
    result = build_remediation(
        finding, _snapshot(), [_source(unsafe, CS_SOURCE)], known_paths=[unsafe],
    )
    assert not result.proposals
    assert all(block.language != "csharp" for block in result.source_blocks)


def test_destructive_candidates_use_changes_not_guessed_or_unrelated_xml():
    paths = [f"packages/p{index:02}/destructiveChangesPost.xml" for index in range(12)]
    changes = [{"new_path": path} for path in reversed(paths)] + [
        {"new_path": "package.xml"},
        {"new_path": "destructiveChangesDeleted.xml", "deleted_file": True},
        {"old_path": "destructiveChangesOld.xml", "new_path": "renamed.xml", "renamed_file": True},
    ]
    assert candidate_source_paths(
        _finding(), _snapshot(), changes, ["destructiveChanges.xml"],
    ) == paths[:8]
    assert candidate_source_paths(_finding(), _snapshot(), [], paths) == []


def test_csv_candidates_prioritize_changed_json_then_known_sources_and_exclude_file_data():
    finding = _finding("salesforce.csv_as_sobject", CSV_ERROR)
    paths = ["scripts/load.sh", "src/loader.py", "ci/data.yml", "Routing__c.csv", ".env"]
    candidates = candidate_source_paths(finding, _snapshot(), [
        {"path": "pkg/asfdx-project-prod.json"}, {"new_path": "other.json"},
        {"new_path": "asfdx-project-old.json", "deleted_file": True},
    ], paths)
    assert candidates[0] == "pkg/asfdx-project-prod.json"
    assert {"scripts/load.sh", "src/loader.py", "ci/data.yml", ".gitlab-ci.yml"} <= set(candidates)
    assert not {"Routing__c.csv", ".env", "other.json", "asfdx-project-old.json"} & set(candidates)
    assert len(candidates) <= 8


def test_compiler_candidates_require_file_line_and_inventory_or_exact_root_url():
    finding = _finding("compiler.cs0161", CS_ERROR)
    assert candidate_source_paths(finding, _snapshot(), known_paths=["src/Widget.cs"]) == []
    finding.evidence.append(FindingEvidence(text=CS_ERROR, path="src/Widget.cs", line=4))
    assert candidate_source_paths(finding, _snapshot()) == []
    assert candidate_source_paths(finding, _snapshot(), known_paths=["src/Widget.cs"]) == [
        "src/Widget.cs",
    ]
    finding.evidence[-1].source_url = f"{REPO}/-/blob/{SHA}/src/Widget.cs#L4"
    assert candidate_source_paths(finding, _snapshot()) == ["src/Widget.cs"]


@pytest.mark.parametrize("repository,ref", [
    ("https://gitlab.example.test/team/shared", SHA), ("https://other.test/team/project", SHA),
    (REPO + "-other", SHA), (REPO, "main"), (REPO, OTHER_SHA),
])
def test_compiler_external_evidence_never_becomes_root_candidate(repository, ref):
    finding = _finding("compiler.cs0161", evidence=[FindingEvidence(
        text=CS_ERROR, path="src/Widget.cs", line=4,
        source_url=f"{repository}/-/blob/{ref}/src/Widget.cs#L4",
    )])
    assert candidate_source_paths(finding, _snapshot(), known_paths=["src/Widget.cs"]) == []


def test_compiler_candidates_use_verified_snapshot_code_references():
    snapshot = _snapshot()
    snapshot.code_references = [CodeReference(path="src/Widget.cs", line=4)]
    assert candidate_source_paths(_finding("compiler.cs0161", CS_ERROR), snapshot,
                                  known_paths=["src/Widget.cs"]) == ["src/Widget.cs"]


def test_case_candidates_only_include_changed_yaml_and_no_candidates_for_policy_rules():
    changes = [{"new_path": ".gitlab-ci.yml"}, {"path": "ci/extra.yaml"}, {"path": "src/File.cs"}]
    assert candidate_source_paths(
        _finding("change.ci_path_case_mismatch"), _snapshot(), changes,
    ) == [
        ".gitlab-ci.yml", "ci/extra.yaml",
    ]
    for rule in ["unknown", "runner.job_timeout", "auth.unauthorized"]:
        assert candidate_source_paths(_finding(rule), _snapshot(), changes) == []


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize("terminal_newline", [True, False])
def test_live_shape_xml_only_removes_matching_member_and_diff_applies(newline, terminal_newline):
    before = _manifest(newline=newline, terminal_newline=terminal_newline)
    result = _propose_xml(before)
    assert len(result.proposals) == 1
    proposal = result.proposals[0]
    expected = before.replace(f"    <members>exampleWidget</members>{newline}", "")
    assert _apply_exact(before, proposal.diff, XML_PATH) == expected
    root = ElementTree.fromstring(expected)
    assert [item.text for item in root.findall(f"{{{NS}}}types/{{{NS}}}members")] == ["otherWidget"]
    assert "<name>LightningComponentBundle</name>" in expected
    assert proposal.condition == "If this component must remain available"
    assert "scope" in proposal.rationale and "confirmed fix" in proposal.rationale
    assert proposal.ref == SHA and proposal.kind == "source_diff"
    assert proposal.verification
    assert result.cause_confidence > result.fix_confidence
    assert result.auto_apply_allowed is False
    assert "<members>exampleWidget</members>" in result.source_blocks[0].content


def test_last_xml_member_removes_only_its_types_group_not_other_metadata():
    other_type = (
        "  <types>\n    <members>ExistingClass</members>\n"
        "    <name>ApexClass</name>\n  </types>"
    )
    before = _manifest(("exampleWidget",), suffix=other_type)
    result = _propose_xml(before)
    after = _apply_exact(before, result.proposals[0].diff, XML_PATH)
    assert "LightningComponentBundle" not in after
    assert other_type in after and "<version>65.0</version>" in after
    assert [node.find(f"{{{NS}}}name").text for node in ElementTree.fromstring(after).findall(
        f"{{{NS}}}types",
    )] == ["ApexClass"]


def test_all_last_xml_members_can_be_removed_only_when_each_has_a_failure_row():
    before = _manifest()
    snapshot = _snapshot()
    snapshot.component_failures = [DeploymentComponentFailure(
        metadata_type="LightningComponentBundle", component_name="otherWidget",
        problem="The component is referenced by otherWidget : Custom Tab Definition - otherWidget.",
    ), DeploymentComponentFailure(
        metadata_type="ApexClass", component_name="UnrelatedClass", problem="unrelated problem",
    )]
    result = build_remediation(_finding(), snapshot, [_source(XML_PATH, before)])
    after = _apply_exact(before, result.proposals[0].diff, XML_PATH)
    assert "<types>" not in after
    assert ElementTree.fromstring(after).find(f"{{{NS}}}version").text == "65.0"


def test_multiple_failure_rows_do_not_blanket_remove_unblocked_members():
    before = _manifest(("exampleWidget", "secondWidget", "unblockedWidget"))
    finding = _finding(evidence=[FindingEvidence(text=ROW), FindingEvidence(
        text=ROW.replace("exampleWidget", "secondWidget"),
    )])
    result = _propose_xml(before, finding=finding)
    after = _apply_exact(before, result.proposals[0].diff, XML_PATH)
    assert "<members>unblockedWidget</members>" in after
    assert "<members>exampleWidget</members>" not in after
    assert "<members>secondWidget</members>" not in after


def test_xml_comments_are_inert_and_preserved_outside_removed_elements():
    before = _manifest().replace(
        "  <types>", "  <!-- café: <members>exampleWidget</members> &foo; "
        "<!DOCTYPE ignored> -->\n  <types>",
    )
    result = _propose_xml(before)
    after = _apply_exact(before, result.proposals[0].diff, XML_PATH)
    assert "<!-- café: <members>exampleWidget</members> &foo; <!DOCTYPE ignored> -->" in after
    assert after == before.replace("    <members>exampleWidget</members>\n", "")


def test_xml_comment_only_member_does_not_count_as_a_blocked_component():
    before = _manifest(("otherWidget",)).replace(
        "  <types>", "  <types>\n    <!-- <members>exampleWidget</members> -->",
    )
    result = _propose_xml(before)
    assert not result.proposals
    assert any("No explicitly blocked" in item for item in result.missing_information)


@pytest.mark.parametrize("transform", [
    lambda source: source.replace(f' xmlns="{NS}"', ""),
    lambda source: source.replace(NS, "https://unknown.example.test/metadata"),
    lambda source: source.replace("<types>", '<types xmlns="urn:unknown">'),
    lambda source: source.replace("<types>", f'<types xmlns="{NS}">'),
    lambda source: source.replace("<types>", '<types unknown="value">'),
    lambda source: source.replace("<types>", "<unknown>"),
    lambda source: source.replace("</Package>", "</Package><Package/>"),
    lambda source: source.replace("</Package>", ""),
    lambda source: source.replace("<version>65.0</version>",
                                  "<version>65.0</version><version>66</version>"),
    lambda source: source.replace("<version>65.0</version>", ""),
    lambda source: source.replace("<version>65.0</version>", "<unknown>65.0</unknown>"),
    lambda source: source.replace("<name>LightningComponentBundle</name>",
                                  "<name>LightningComponentBundle</name><name>ApexClass</name>"),
    lambda source: source.replace("<members>otherWidget</members>",
                                  "<members>exampleWidget</members>"),
    lambda source: source.replace("<members>otherWidget</members>", "<members>*</members>"),
    lambda source: source.replace("<members>otherWidget</members>", "<members/>"),
    lambda source: source.replace("<members>exampleWidget</members>",
                                  "<members>example&#87;idget</members>"),
    lambda source: source.replace("<members>exampleWidget</members>",
                                  "<members><![CDATA[exampleWidget]]></members>"),
    lambda source: source.replace("</Package>", "<?unsafe content?></Package>"),
    lambda source: source.replace("  <types>", "  <!DOCTYPE types>\n  <types>"),
    lambda source: source.replace("<Package",
                                  '<!DOCTYPE Package [<!ENTITY x "value">]>\n<Package', 1),
    lambda source: source.replace("<Package",
                                  '<!DOCTYPE Package SYSTEM "file:///not-read">\n<Package', 1),
    lambda source: source.replace("<Package", '<!DOCTYPE Package [<!ENTITY x SYSTEM '
                                  '"https://not-read.test/">]>\n<Package', 1),
])
def test_xml_invalid_unsafe_ambiguous_structure_never_proposes(transform):
    result = _propose_xml(transform(_manifest()))
    assert not result.proposals
    assert result.missing_information


def test_duplicate_xml_types_are_rejected_instead_of_guessing():
    before = _manifest()
    group = re.search(r"  <types>[\s\S]+?</types>", before)[0]
    before = before.replace("  <version>", group + "\n  <version>")
    assert not _propose_xml(before).proposals


def test_inline_prefixed_xml_preserves_exact_surroundings_and_no_final_newline():
    before = (
        f'<m:Package xmlns:m="{NS}"><m:types><m:members>exampleWidget</m:members>'
        "<m:members>otherWidget</m:members><m:name>LightningComponentBundle</m:name>"
        "</m:types><m:version>65.0</m:version></m:Package>"
    )
    proposal = _propose_xml(before).proposals[0]
    assert _apply_exact(before, proposal.diff, XML_PATH) == before.replace(
        "<m:members>exampleWidget</m:members>", "",
    )
    assert "\\ No newline at end of file\n" in proposal.diff


@pytest.mark.parametrize("text", [
    ROW.replace("exampleWidget", "absentWidget"),
    ROW.replace("LightningComponentBundle", "ApexClass"),
    ROW.replace("The component is referenced by", "Missing dependency for"),
    "# " + ROW,
])
def test_unmatched_or_non_deletion_failure_rows_have_guidance_only(text):
    assert not _propose_xml(_manifest(), finding=_finding(text=text)).proposals


@pytest.mark.parametrize("ref", [
    "main", "release-2026", "a" * 39, "a" * 41, "g" * 40, "", "a" * 63,
])
def test_non_full_hex_refs_never_propose_even_when_snapshot_agrees(ref):
    source = _source(XML_PATH, _manifest(), ref=ref)
    result = build_remediation(_finding(), _snapshot(sha=ref), [source])
    assert not result.proposals
    assert any("40- or 64-hex" in item for item in result.missing_information)


@pytest.mark.parametrize("sha", ["a" * 40, "1" * 64])
def test_exact_40_and_64_hex_source_refs_are_supported(sha):
    before = _manifest()
    result = build_remediation(_finding(), _snapshot(sha=sha), [_source(XML_PATH, before, ref=sha)])
    assert _apply_exact(before, result.proposals[0].diff, XML_PATH) == before.replace(
        "    <members>exampleWidget</members>\n", "",
    )


@pytest.mark.parametrize("url", [
    None, "", f"{REPO}/-/blob/main/{XML_PATH}",
    f"https://other.test/team/project/-/blob/{SHA}/{XML_PATH}",
    f"https://gitlab.example.test/team/project-other/-/blob/{SHA}/{XML_PATH}",
    f"{REPO}/-/blob/{SHA}/different.xml", f"{REPO}/-/raw/{SHA}/{XML_PATH}",
    f"{REPO}/-/blob/{SHA}/{XML_PATH}?download=1",
    f"{REPO}/-/blob/{SHA}/{XML_PATH}?token=fixture-only-value",
    f"https://fixture-user:fixture-password@gitlab.example.test/team/project/-/blob/{SHA}/{XML_PATH}",
    f"{REPO}/-/blob/{SHA}/../{XML_PATH}",
    f"{REPO}/-/blob/{SHA}/%2e%2e/{XML_PATH}",
    f"{REPO}/-/blob/{SHA}/%252e%252e/{XML_PATH}",
    f"{REPO}/-/blob/{SHA}/{XML_PATH}#arbitrary", f"{REPO}/-/blob/{SHA}/{XML_PATH}\n",
    f"{REPO}/-/blob/{SHA}/{XML_PATH}%0a", f"{REPO}/-/blob/{SHA}/{XML_PATH}%5c",
    f"file:///repo/{XML_PATH}", f"javascript:/{XML_PATH}",
])
def test_provenance_requires_safe_matching_origin_repo_path_and_blob_ref(url):
    source = _source(XML_PATH, _manifest()).model_copy(update={"source_url": url})
    result = build_remediation(_finding(), _snapshot(), [source])
    assert not result.proposals
    encoded = result.model_dump_json()
    assert "fixture-only-value" not in encoded and "fixture-password" not in encoded


def test_commit_mismatch_and_mutable_sources_are_display_only_with_explicit_notes():
    for ref, phrase in [(OTHER_SHA, "not the pipeline commit"), ("main", "current/mutable")]:
        result = build_remediation(
            _finding(), _snapshot(), [_source(XML_PATH, _manifest(), ref=ref)],
        )
        assert not result.proposals and result.source_blocks
        assert any(phrase in item for item in result.confidence_basis)


def test_shared_pinned_sources_can_be_displayed_but_not_patched_or_fetched_as_root():
    repository = "https://gitlab.example.test/team/shared"
    source = _source(
        "ci/data.yml", "load:\n  script: sf data import bulk --sobject Routing__c.csv\n",
        ref=OTHER_SHA, repository=repository,
    )
    logical = "pipelinelens-gitlab-project://team%2Fshared?ref=main&file=ci%2Fdata.yml"
    source.path = logical
    snapshot = _snapshot(source)
    result = build_remediation(_finding("salesforce.csv_as_sobject", CSV_ERROR), snapshot, [])
    assert not result.proposals and result.source_blocks[0].path == "ci/data.yml"
    assert result.source_blocks[0].ref == OTHER_SHA
    assert any("pinned shared/other-repository" in item for item in result.confidence_basis)
    assert candidate_source_paths(_finding("salesforce.csv_as_sobject", CSV_ERROR), snapshot) == []


def test_missing_snapshot_config_or_repository_proof_yields_useful_guidance():
    result = build_remediation(_finding(), None, [])
    assert not result.proposals and not result.source_blocks
    assert result.actions and result.missing_information
    result = build_remediation(_finding(), None, [_source(XML_PATH, _manifest())])
    assert not result.proposals and result.source_blocks
    assert any("pipeline snapshot" in item for item in result.missing_information)


def test_wrong_job_cannot_supply_component_failures_or_patch_provenance():
    finding = _finding().model_copy(update={"job_id": "unrelated-job"})
    result = build_remediation(finding, _snapshot(), [_source(XML_PATH, _manifest())])
    assert not result.proposals
    assert any("different job" in item for item in result.missing_information)
    assert candidate_source_paths(finding, _snapshot(), [{"path": XML_PATH}]) == []


def test_conflicting_duplicate_source_identity_is_not_resolved_by_input_order():
    source = _source(XML_PATH, _manifest())
    conflicting = source.model_copy(update={"content": _manifest(("exampleWidget",))})
    for sources in [[source, conflicting], [conflicting, source]]:
        result = build_remediation(_finding(), _snapshot(), sources)
        assert not result.proposals and not result.source_blocks
        assert any("conflicting" in item for item in result.missing_information)


def test_identical_snapshot_sources_do_not_create_duplicate_proposals():
    source = _source(XML_PATH, _manifest())
    result = build_remediation(_finding(), _snapshot(source), [source, source])
    assert len(result.proposals) == len(result.source_blocks) == 1


@pytest.mark.parametrize("key", ["sobject", "object", "objectName", "sobjectName"])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_csv_json_only_exact_semantic_object_values_change(key, newline):
    before = newline.join([
        "{", '  "steps": [', '    {', f'      "{key}": "Routing__c.csv",',
        '      "file": "Routing__c.csv",', '      "path": "Routing__c.csv",',
        '      "note": "Routing__c.csv",', '      "other": "Other__c.csv"', "    }", "  ]", "}",
    ])
    result = _propose_csv(before)
    assert len(result.proposals) == 1
    after = _apply_exact(before, result.proposals[0].diff, JSON_PATH)
    assert after == before.replace(f'"{key}": "Routing__c.csv"', f'"{key}": "Routing__c"')
    step = json.loads(after)["steps"][0]
    assert step[key] == "Routing__c"
    assert step["file"] == step["path"] == step["note"] == "Routing__c.csv"
    assert step["other"] == "Other__c.csv"


def test_json_escaped_key_and_value_are_semantically_matched_not_unconstrained_replaced():
    before = r'{"\u0073object": "Routing__c\u002ecsv", "file": "Routing__c.csv"}'
    result = _propose_csv(before)
    after = _apply_exact(before, result.proposals[0].diff, JSON_PATH)
    assert after == r'{"\u0073object": "Routing__c", "file": "Routing__c.csv"}'


@pytest.mark.parametrize("before", [
    '{"file": "Routing__c.csv", "path": "Routing__c.csv"}',
    '{"sobject": "Other__c.csv"}', '{"sobject": "folder/Routing__c.csv"}',
    '{"sobject": "Routing__c.csv.backup"}', '{"sobject": "Routing__c"}',
    '{"sobject": "Routing__c.csv",}', '{"sobject": "Routing__c.csv", "sobject": "Routing__c.csv"}',
    '{"sobject": "Routing__c.csv", "other": NaN}',
    '{"nested": {"key": 1, "key": 2}, "sobject": "Routing__c.csv"}',
    json.dumps({"note": '{"sobject": "Routing__c.csv"}'}),
    '# {"sobject": "Routing__c.csv"}\n{}',
])
def test_csv_json_rejects_file_keys_partial_matches_embedded_text_and_invalid_documents(before):
    result = _propose_csv(before)
    assert not result.proposals and result.missing_information


def test_csv_json_separate_hunks_apply_exactly_to_multiple_explicit_matches():
    before = json.dumps({
        "sobject": "Routing__c.csv", **{f"unchanged{index}": index for index in range(20)},
        "nested": {"objectName": "Routing__c.csv", "file": "Routing__c.csv"},
    }, indent=2) + "\n"
    proposal = _propose_csv(before).proposals[0]
    assert len(re.findall(r"(?m)^@@ ", proposal.diff)) == 2
    after = json.loads(_apply_exact(before, proposal.diff, JSON_PATH))
    assert after["sobject"] == after["nested"]["objectName"] == "Routing__c"
    assert after["nested"]["file"] == "Routing__c.csv"


@pytest.mark.parametrize("option", [
    "--sobject Routing__c.csv", "--sobject 'Routing__c.csv'", '--sobject "Routing__c.csv"',
    "--sobject=Routing__c.csv", "--sobject='Routing__c.csv'", '--sobject="Routing__c.csv"',
])
@pytest.mark.parametrize("path", ["scripts/load.sh", "scripts/load.ps1"])
def test_csv_script_only_direct_literal_sobject_changes_not_file(option, path):
    before = f"# fixture\r\nsf data import bulk {option} --file Routing__c.csv\r\n"
    proposal = _propose_csv(before, path).proposals[0]
    after = _apply_exact(before, proposal.diff, path)
    assert after == before.replace(option, option.replace("Routing__c.csv", "Routing__c"))
    assert "--file Routing__c.csv" in after


@pytest.mark.parametrize("command", [
    "sf data import bulk --file Routing__c.csv",
    "echo sf data import bulk --sobject Routing__c.csv",
    "printf 'sf data import bulk --sobject Routing__c.csv'",
    "# sf data import bulk --sobject Routing__c.csv",
    "sf data import bulk --sobject $OBJECT --file Routing__c.csv",
    "sf data import bulk --sobject 'Routing__c.csv'${SUFFIX}",
    "sf data import bulk --sobject Routing__c.csv#suffix",
    "sf data import bulk --sobject Routing__c.csv.bak",
    "sf data import bulk --sobject Routing__c.csv --sobject Other__c",
    "sf data import bulk -- --sobject Routing__c.csv",
    "echo x; sf data import bulk --sobject Routing__c.csv",
    "sf data import bulk --sobject Routing__c.csv | other-command",
    "cat <<'EOF'\nsf data import bulk --sobject Routing__c.csv\nEOF",
    '$message = @"\nsf data import bulk --sobject Routing__c.csv\n"@',
    'echo "\nsf data import bulk --sobject Routing__c.csv\n"',
    "sf data import bulk \\\n  --sobject Routing__c.csv",
])
def test_csv_script_comments_echo_variables_heredocs_and_dynamic_commands_rejected(command):
    assert not _propose_csv(command + "\n", "scripts/load.sh").proposals


def test_unknown_script_and_embedded_python_command_are_not_patched():
    command = "sf data import bulk --sobject Routing__c.csv\n"
    result = build_remediation(_finding("salesforce.csv_as_sobject", CSV_ERROR), _snapshot(), [
        _source("scripts/load.sh", command),
    ])
    assert not result.proposals and result.source_blocks
    result = _propose_csv('command = "' + command.rstrip() + '"\n', "scripts/load.py")
    assert not result.proposals


@pytest.mark.parametrize("before", [
    "load:\n  script:\n    - sf data import bulk --sobject 'Routing__c.csv' "
    "--file Routing__c.csv\n",
    "load:\n  script: \"sf data import bulk --sobject 'Routing__c.csv' --file Routing__c.csv\"\n",
    "load:\n  script: |\n    sf data import bulk --sobject Routing__c.csv --file Routing__c.csv\n",
    "load:\r\n  script: |-\r\n    sf data import bulk --sobject Routing__c.csv "
    "--file Routing__c.csv\r\n",
    "load:\n  before_script:\n    - sfdx force:data:bulk:upsert --sobject Routing__c.csv "
    "--file Routing__c.csv\n",
])
def test_csv_yaml_parsed_commands_preserve_formatting_and_file_inputs(before):
    proposal = _propose_csv(before, "ci/load.yml").proposals[0]
    after = _apply_exact(before, proposal.diff, "ci/load.yml")
    assert after == before.replace("--sobject Routing__c.csv", "--sobject Routing__c").replace(
        "--sobject 'Routing__c.csv'", "--sobject 'Routing__c'",
    )
    assert "--file Routing__c.csv" in after
    assert YAML(typ="safe").load(after)


@pytest.mark.parametrize("before", [
    "variables:\n  EXAMPLE: 'sf data import bulk --sobject Routing__c.csv'\n",
    "load:\n  script: echo sf data import bulk --sobject Routing__c.csv\n",
    "load:\n  script: >\n    sf data import bulk --sobject Routing__c.csv\n",
    "# sf data import bulk --sobject Routing__c.csv\nload:\n  script: echo okay\n",
    "load:\n  script: [unterminated\n",
    "load:\n  script: sf data import bulk --sobject Routing__c.csv\n  script: echo okay\n",
    "load:\n  script: &cmd sf data import bulk --sobject Routing__c.csv\nother:\n  script: *cmd\n",
])
def test_csv_yaml_does_not_patch_examples_comments_folded_or_invalid_alias_sources(before):
    assert not _propose_csv(before, "ci/load.yml").proposals


@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_cited_quoted_yaml_case_fix_is_exact_and_preserves_comments(newline):
    before = newline.join(["include:", "  - local: 'ci/build.yml' # keep formatting", ""])
    proposal = _case(before).proposals[0]
    after = _apply_exact(before, proposal.diff, ".gitlab-ci.yml")
    assert after == before.replace("'ci/build.yml'", "'ci/Build.yml'")
    assert YAML(typ="safe").load(after)["include"][0]["local"] == "ci/Build.yml"


@pytest.mark.parametrize("known", [
    [], ["ci/Build.yml", "ci/BUILD.yml"], ["ci/build.yml"], ["ci/Other.yml"],
])
def test_yaml_case_requires_unique_actual_inventory_match(known):
    assert not _case(known=known).proposals


@pytest.mark.parametrize("before,line", [
    ("include:\n  - local: ci/build.yml\n", 2),
    ("# include: 'ci/build.yml'\njob:\n  script: echo okay\n", 1),
    ("variables:\n  NOTE: 'ci/build.yml'\n", 2),
    ("include:\n  - project: shared/repo\n    local: 'ci/build.yml'\n", 3),
    ("include:\n  - local: 'ci/build.yml'\n    rules: []\n", 2),
    ("job:\n  script: echo 'ci/build.yml'\n", 2),
    ("include: ['ci/build.yml'\n", 1),
    ("include: 'ci/build.yml'\ninclude: 'ci/build.yml'\n", 1),
    ("include: &path 'ci/build.yml'\nother: *path\n", 1),
])
def test_yaml_case_rejects_unquoted_comment_unknown_role_shared_duplicate_and_invalid(before, line):
    assert not _case(before, line=line).proposals


def test_case_patch_requires_exact_cited_content_and_changed_yaml():
    assert not _case(cited="different evidence").proposals
    assert not _case(line=1).proposals
    assert not _case(changed=False).proposals


def test_yaml_case_supports_quoted_directory_from_unique_known_descendant():
    before = "variables:\n  PACKAGE_PATH: './packages/example'\n"
    proposal = _case(before, known=["Packages/Example/manifest.xml"]).proposals[0]
    assert _apply_exact(before, proposal.diff, ".gitlab-ci.yml") == (
        "variables:\n  PACKAGE_PATH: './Packages/Example'\n"
    )


@pytest.mark.parametrize("before,line", [
    ("job:\n  script:\n    - cd 'ci/build'\n", 3),
    ('job:\n  script: "cd \'ci/build\'"\n', 2),
    ("job:\n  script: |\n    cd 'ci/build'\n", 3),
    ("job:\n  script: deploy --package-path='ci/build'\n", 2),
])
def test_yaml_case_supports_quoted_command_path_literals_on_cited_line(before, line):
    proposal = _case(before, line=line, known=["ci/Build/file.txt"]).proposals[0]
    assert _apply_exact(before, proposal.diff, ".gitlab-ci.yml") == before.replace(
        "'ci/build'", "'ci/Build'",
    )


def test_yaml_case_leaves_uncited_matching_literals_untouched():
    before = "include:\n  - local: 'ci/build.yml'\n  - local: 'ci/build.yml'\n"
    proposal = _case(before).proposals[0]
    assert _apply_exact(before, proposal.diff, ".gitlab-ci.yml") == before.replace(
        "'ci/build.yml'", "'ci/Build.yml'", 1,
    )


def test_compiler_shows_real_method_lines_but_never_fabricates_a_return_value():
    source = _source("src/Widget.cs", CS_SOURCE)
    finding = _finding("compiler.cs0161", evidence=[FindingEvidence(
        text=CS_ERROR, path=source.path, line=4, source_url=f"{source.source_url}#L4",
    )], category="build_failure")
    result = build_remediation(finding, _snapshot(), [source], known_paths=[source.path])
    assert not result.proposals
    block = next(block for block in result.source_blocks if block.path == source.path)
    assert "public string Resolve(bool ready)" in block.content and block.language == "csharp"
    assert block.line_start <= 4 <= block.line_end
    assert block.content == "".join(
        CS_SOURCE.splitlines(keepends=True)[block.line_start - 1:block.line_end],
    )
    assert "return null" not in result.model_dump_json().lower()
    assert result.cause_confidence >= 85 and result.fix_confidence <= 30
    assert any("intended return/exception" in item for item in result.missing_information)


@pytest.mark.parametrize("rule,category,text", [
    ("runner.job_timeout", "timeout", "ERROR: execution took longer than 2h0m0s seconds"),
    ("auth.unauthorized", "authentication_failure", "HTTP 401 Unauthorized"),
    ("auth.forbidden", "authorization_failure", "HTTP 403 access denied"),
    ("log.explicit_error", "unknown", "Error: unspecified operation failed"),
])
def test_timeout_auth_unknown_have_targeted_guidance_and_no_policy_patches(rule, category, text):
    config = _source(".gitlab-ci.yml", "job:\n  timeout: 2h\n  script: sf apex run test\n")
    result = build_remediation(_finding(rule, text, category=category), _snapshot(config), [config])
    assert not result.proposals and result.source_blocks
    assert result.actions and result.missing_information and result.fix_confidence <= 25
    if category != "unknown":
        assert result.cause_confidence >= 85
    else:
        assert result.cause_confidence <= 40 and result.documentation == [TRACE_DOC]


@pytest.mark.parametrize("secret_source", [
    '{"sobject": "Routing__c.csv", "token": "fixture-only-value"}',
    '{"sobject": "Routing__c.csv", "token": "[REDACTED]"}',
    '{"sobject": "Routing__c.csv", "note": "[GITLAB_TOKEN_REDACTED]"}',
    '{"sobject": "Routing__c.csv", "note": "[PIPELINELENS_CONFIG_OMITTED]"}',
    '{"sobject": "Routing__c.csv", "token": "' + "gl" + "pat-" + "z" * 30 + '"}',
])
def test_any_redaction_in_source_blocks_the_diff_instead_of_dropping_hunk_context(secret_source):
    result = _propose_csv(secret_source)
    assert not result.proposals
    assert "fixture-only-value" not in result.model_dump_json()
    assert any("redacted, secret, or omitted" in item for item in result.missing_information)


def test_secret_outside_the_patch_hunk_also_blocks_patch_conservatively():
    before = json.dumps({
        "sobject": "Routing__c.csv", **{f"keep{index}": index for index in range(50)},
        "token": "fixture-only-value",
    }, indent=2)
    assert not _propose_csv(before).proposals


def test_redacts_full_multiline_content_before_taking_source_window():
    before = (
        'const string credential = "fixture-only-start\n'
        + "fixture-only-continuation\n" * 20 + 'fixture-only-end";\n' + CS_SOURCE
    )
    source = _source("src/Widget.cs", before)
    finding = _finding("compiler.cs0161", evidence=[FindingEvidence(
        text=CS_ERROR, path=source.path, line=15, source_url=f"{source.source_url}#L15",
    )])
    result = build_remediation(finding, _snapshot(), [source])
    assert "fixture-only" not in result.model_dump_json()
    assert result.source_blocks


def test_all_serialized_names_content_and_urls_are_redacted_and_docs_do_not_need_requests():
    fake = "gl" + "pat-" + "q" * 30
    finding = _finding("unknown." + fake, "token=fixture-only-value", category="unknown")
    finding.title = f"Request {fake} failed; token=fixture-only-value"
    finding.job_id = fake
    finding.documentation = [
        "https://docs.example.test/help?token=fixture-only-value", "javascript:alert(1)",
        "https://fixture-user:fixture-password@docs.example.test/guide",
        "https://docs.example.test/guide#details",
    ]
    result = build_remediation(finding, None, [])
    serialized = result.model_dump_json()
    assert fake not in serialized and "fixture-only-value" not in serialized
    assert "fixture-password" not in serialized and "javascript:" not in serialized
    assert result.documentation == [
        "https://docs.example.test/guide", "https://docs.example.test/guide#details",
    ]


def test_unknown_preserves_existing_safe_documentation_otherwise_uses_generic_trace_doc():
    finding = _finding("unknown", "unspecified", category="unknown")
    finding.documentation = ["https://docs.example.test/reference"]
    assert build_remediation(finding, None, []).documentation == finding.documentation
    finding.documentation = []
    assert build_remediation(finding, None, []).documentation == [TRACE_DOC]


def test_frequency_and_historical_confirmations_do_not_inflate_scores():
    snapshot = _snapshot()
    source = _source(XML_PATH, _manifest())
    first = build_remediation(_finding(), snapshot, [source])
    snapshot.similar_incidents = [SimilarIncident(
        incident_id=str(index), fingerprint="synthetic", category="deployment_failure",
        summary="same error", confirmed_resolution="previously solved", similarity=1,
    ) for index in range(100)]
    second = build_remediation(_finding(), snapshot, [source])
    assert (first.cause_confidence, first.fix_confidence) == (
        second.cause_confidence, second.fix_confidence,
    )
    assert any("not recurrence" in item for item in second.confidence_basis)


def test_no_io_environment_model_network_or_input_mutation_and_repeatable_results(monkeypatch):
    source = _source(XML_PATH, _manifest())
    finding, snapshot = _finding(), _snapshot()
    sources, changes, known = [source], [{"new_path": XML_PATH}], [XML_PATH]
    original = copy.deepcopy((finding, snapshot, sources, changes, known))

    def forbidden(*_args, **_kwargs):
        pytest.fail("Remediation must not perform I/O, environment reads, or network access")

    with monkeypatch.context() as patch:
        patch.setattr(builtins, "open", forbidden)
        patch.setattr(Path, "read_text", forbidden)
        patch.setattr(Path, "write_text", forbidden)
        patch.setattr(socket, "create_connection", forbidden)
        patch.setattr(socket.socket, "connect", forbidden)
        patch.setattr(os, "getenv", forbidden)
        patch.setattr(type(os.environ), "__getitem__", forbidden)
        patch.setattr(type(os.environ), "__iter__", forbidden)
        first = build_remediation(finding, snapshot, sources, changes, known)
        second = build_remediation(finding, snapshot, sources, changes, known)
        candidates = candidate_source_paths(finding, snapshot, changes, known)
    assert first == second and first.proposals and candidates == [XML_PATH]
    assert (finding, snapshot, sources, changes, known) == original


@pytest.mark.parametrize("content", [
    '{"sobject": "Routing__c.csv"}\r', '{"sobject": "Routing__c.csv"}\x00',
    '{"sobject": "Routing__c.csv", "note": "' + "x" * 250_000 + '"}',
], ids=["bare-cr", "nul", "oversize"])
def test_unsupported_line_endings_controls_and_oversized_sources_fail_closed(content):
    assert not _propose_csv(content).proposals


@pytest.mark.parametrize("script", [
    "cat <<'EOF'\nsf data import bulk --sobject Routing__c.csv\nEOF\n",
    "echo '\nsf data import bulk --sobject Routing__c.csv\n'\n",
    "sf data import bulk ^\n  --sobject Routing__c.csv\n",
    "sf data import bulk --sobject Routing__c.csv#not-a-comment\n",
])
def test_yaml_literal_blocks_cannot_patch_heredoc_or_quoted_example_text(script):
    before = "job:\n  script: |\n" + "".join("    " + line for line in script.splitlines(True))
    assert not _propose_csv(before, "ci/load.yml").proposals


def test_case_literal_inside_heredoc_is_not_a_command_or_patch():
    before = "job:\n  script: |\n    cat <<'EOF'\n    cd 'ci/build'\n    EOF\n"
    assert not _case(before, line=4, known=["ci/Build/file.txt"]).proposals


def test_mismatched_citation_url_line_does_not_authorize_case_patch_or_compiler_candidate():
    source = _source(".gitlab-ci.yml", "include:\n  - local: 'ci/build.yml'\n")
    evidence = FindingEvidence(path=source.path, line=2, text=source.content.splitlines()[1],
                               source_url=f"{source.source_url}#L8")
    result = build_remediation(
        _finding("change.ci_path_case_mismatch", evidence=[evidence]),
        _snapshot(source), [source], [{"path": source.path}], ["ci/Build.yml"],
    )
    assert not result.proposals
    compiler = _finding("compiler.cs0161", evidence=[FindingEvidence(
        path="src/Widget.cs", line=4, text=CS_ERROR,
        source_url=f"{REPO}/-/blob/{SHA}/src/Widget.cs#L8",
    )])
    assert candidate_source_paths(compiler, _snapshot(), known_paths=["src/Widget.cs"]) == []


def test_equivalent_repository_url_spelling_cannot_hide_conflicting_source_contents():
    first = _source(XML_PATH, _manifest())
    second = _source(XML_PATH, _manifest(("exampleWidget",)))
    second.source_url = second.source_url.replace("gitlab.example.test", "GITLAB.EXAMPLE.TEST")
    result = build_remediation(_finding(), _snapshot(), [first, second])
    assert not result.proposals
    assert any("conflicting" in item for item in result.missing_information)


@pytest.mark.parametrize("tag", ["!!python/object", "!unknown"])
def test_yaml_unsupported_tags_fail_closed(tag):
    before = f"include: 'ci/build.yml'\nunknown: {tag} {{}}\n"
    assert not _case(before, line=1).proposals


@pytest.mark.parametrize("before", [
    "variables:\n  script: sf data import bulk --sobject Routing__c.csv\n",
    "variables:\n  run: sf data import bulk --sobject Routing__c.csv\n",
    "job:\n  variables:\n    script: sf data import bulk --sobject Routing__c.csv\n",
    "job:\n  notes:\n    script: sf data import bulk --sobject Routing__c.csv\n",
])
def test_yaml_named_script_variables_and_examples_are_not_executed_command_inputs(before):
    assert not _propose_csv(before, "ci/load.yml").proposals


def test_csharp_unreadable_or_out_of_range_source_explicitly_requests_missing_information():
    finding = _finding("compiler.cs0161", evidence=[FindingEvidence(
        text=CS_ERROR, path="src/Widget.cs", line=400,
        source_url=f"{REPO}/-/blob/{SHA}/src/Widget.cs#L400",
    )])
    missing = build_remediation(finding, _snapshot(), [])
    assert any("C# source" in item for item in missing.missing_information)
    readable = build_remediation(finding, _snapshot(), [_source("src/Widget.cs", CS_SOURCE)])
    assert not readable.proposals
    assert any("outside the supplied content" in item for item in readable.missing_information)


@pytest.mark.parametrize("confidence,ceiling", [("likely", 60), ("unknown", 30)])
def test_uncertain_finding_does_not_get_observed_confidence_from_source_alone(confidence, ceiling):
    finding = _finding().model_copy(update={"confidence": confidence})
    result = _propose_xml(_manifest(), finding=finding)
    assert result.proposals and result.fix_confidence <= ceiling


def test_missing_diagnostic_cannot_get_high_cause_score_from_rule_name_alone():
    result = build_remediation(_finding("compiler.cs0161", evidence=[]), _snapshot(), [])
    assert result.cause_confidence <= 35 and not result.proposals


def test_pure_api_and_parser_dependency_imports_do_not_load_app_settings():
    import ast

    from pipelinelens.services import remediation

    tree = ast.parse(inspect.getsource(remediation))
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            modules.add(node.module)
        elif isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
    assert not modules & {
        "os", "pathlib", "httpx", "requests", "dotenv", "pipelinelens.config",
        "pipelinelens.services.llm", "pipelinelens.providers.gitlab",
    }


def test_gitlab_reference_selectors_are_not_commands_or_ci_path_literals():
    command = "job:\n  script: !reference ['sf data import bulk --sobject Routing__c.csv']\n"
    assert not _propose_csv(command, "ci/load.yml").proposals
    assert not _case("include: !reference ['ci/build.yml']\n", line=1).proposals


def test_unrelated_gitlab_reference_is_preserved_beside_a_real_command_patch():
    before = (
        "job:\n  script: sf data import bulk --sobject Routing__c.csv --file Routing__c.csv\n"
        "other:\n  script: !reference [.base, script]\n"
    )
    result = _propose_csv(before, "ci/load.yml")
    after = _apply_exact(before, result.proposals[0].diff, "ci/load.yml")
    assert after == before.replace("--sobject Routing__c.csv", "--sobject Routing__c")
    assert "!reference [.base, script]" in after
    assert YAML(typ="rt").load(after)