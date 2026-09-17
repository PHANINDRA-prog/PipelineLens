"""Fresh JSON hunk verification with synthetic private values outside the diff."""

import json

import pytest

from pipelinelens.domain import CiConfigFile
from pipelinelens.services.redaction import SecretRedactor
from pipelinelens.services.remediation import build_verified_json_hunk
from test_remediation import CSV_ERROR, JSON_PATH, _apply_exact, _finding, _snapshot, _source


def source_with_private_value():
    return json.dumps({
        "consumerSecret": "fixture-only-private-value",
        "unrelated": [f"context-{index}" for index in range(20)],
        "steps": [{"file": "data/Routing__c.csv", "sobjecttype": "Routing__c.csv"}],
    }, indent=2) + "\n"


def propose(content, **updates):
    original = _source(JSON_PATH, content).model_copy(update=updates)
    return build_verified_json_hunk(
        _finding("salesforce.csv_as_sobject", CSV_ERROR), _snapshot(), original,
    )


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_only_secret_free_hunk_is_returned_and_applies_to_original_exactly(ending):
    content = source_with_private_value().replace("\n", ending)
    plan = propose(content)
    assert plan is not None
    assert plan.cause_confidence == 94 and plan.fix_confidence == 82
    change = plan.proposals[0]
    after = _apply_exact(content, change.diff, JSON_PATH)
    parsed = json.loads(after)
    assert parsed["consumerSecret"] == "fixture-only-private-value"
    assert parsed["steps"][0] == {"file": "data/Routing__c.csv", "sobjecttype": "Routing__c"}
    assert "fixture-only-private-value" not in plan.model_dump_json()
    assert "consumerSecret" not in change.diff
    assert SecretRedactor().redact(change.diff).content == change.diff
    assert plan.auto_apply_allowed is False


@pytest.mark.parametrize("private", [
    '"consumerSecret": "fixture-only-private-value",',
    '"note": "https://user:password@host.invalid/path",',
])
def test_sensitive_context_inside_hunk_prevents_proposal(private):
    content = '{\n  ' + private + '\n  "sobjecttype": "Routing__c.csv"\n}\n'
    assert propose(content) is None


def test_source_already_changed_by_sanitizer_cannot_be_used_as_original():
    assert propose(source_with_private_value(), source_modified=True) is None


def test_large_config_can_propose_bounded_hunk_without_returning_full_source():
    content = json.dumps({
        "description": "x" * 300_000,
        "padding": list(range(20)),
        "steps": [{"file": "data/Routing__c.csv", "sobjecttype": "Routing__c.csv"}],
    }, indent=2)
    plan = propose(content)
    assert plan is not None
    assert len(plan.proposals[0].diff) < 2000
    assert len(plan.model_dump_json()) < 20_000
    _apply_exact(content, plan.proposals[0].diff, JSON_PATH)


@pytest.mark.parametrize("content", [
    '{"sobjecttype": "Routing__c.csv", "sobjecttype": "Other__c"}',
    '{"file": "Routing__c.csv", "sobjecttype": "Other__c"}',
    '{"sobjecttype": "Routing__c.csv", "x": NaN}',
    '{"sobjecttype": "Routing__c.csv", "note": "[REDACTED]"}',
    '{"sobjecttype": "Routing__c.csv", "note": "' + "x" * 1_000_000 + '"}',
], ids=["duplicate", "unmatched", "nonfinite", "redacted", "oversized"])
def test_ambiguous_redacted_oversized_or_unmatched_json_never_proposes(content):
    assert propose(content) is None


def test_hunk_requires_same_project_and_pipeline_sha():
    assert propose(source_with_private_value(), ref="b" * 40) is None
    original = CiConfigFile(
        path=JSON_PATH, ref="a" * 40, content=source_with_private_value(),
        source_url=f"https://other.test/unrelated/repo/-/blob/{'a' * 40}/{JSON_PATH}",
    )
    assert build_verified_json_hunk(
        _finding("salesforce.csv_as_sobject", CSV_ERROR), _snapshot(), original,
    ) is None


@pytest.mark.parametrize("default", [
    "default", "default(CancellationToken)", "CancellationToken.None",
])
def test_csharp_cancellation_parameter_default_is_not_a_credential(default):
    source = f"public void Work(CancellationToken cancellationToken = {default}) {{ }}"
    result = SecretRedactor().redact(source)
    assert result.content == source and result.replacements == 0
    unsafe = 'CancellationToken cancellationToken = "fixture-only-private-value";'
    assert "fixture-only-private-value" not in SecretRedactor().redact(unsafe).content