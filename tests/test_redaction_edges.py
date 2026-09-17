"""Offline edge cases for the lexical redactor; all credentials are test-only."""

import json
from urllib.parse import quote, urlsplit

import pytest
from ruamel.yaml import YAML

from pipelinelens.services.redaction import SecretRedactor


@pytest.mark.parametrize("key", [
    "vendor_password_suffix", "VendorPassphraseSuffix", "vendor.api-key.region",
    "REGION_ACCESS_KEY_ID", "vendorCredentialsSuffix", "ProxyAuthorization", "VENDOR_PASS",
    "vendorPwd", "VENDOR_PAT", "clientSecretSuffix", r"vendor\u005fpassword",
])
def test_sensitive_identifier_variants_keep_json_shape_and_count_once(key):
    source = '{"' + key + '": "fixture-only-opaque-value", "ok": 12}'
    result = SecretRedactor().redact(source)
    parsed = json.loads(result.content)
    assert len(parsed) == 2 and parsed["ok"] == 12
    assert list(parsed.values())[0] == "[REDACTED]"
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("depth", [1, 2, 4, 8])
def test_nested_json_strings_keep_siblings_and_count_once(depth):
    source = json.dumps({"token": "fixture-only-value\\\"suffix", "ok": [1, True]})
    for _ in range(depth):
        source = json.dumps({"payload": source, "keep": "context"})
    result = SecretRedactor().redact(source)
    decoded = result.content
    for _ in range(depth):
        layer = json.loads(decoded)
        assert layer["keep"] == "context"
        decoded = layer["payload"]
    assert json.loads(decoded) == {"token": "[REDACTED]", "ok": [1, True]}
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).content == result.content
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("ending", ["\n", "\r\n", "\r"])
def test_private_key_and_multiline_assignment_preserve_all_line_endings(ending):
    source = ending.join([
        'vendor_secret="fixture-only-first', 'fixture-only-second"',
        "-----BEGIN EC PRIVATE KEY-----", "fixture-only-body", "-----END EC PRIVATE KEY-----",
        "diagnostic context",
    ])
    result = SecretRedactor().redact(source)
    assert "fixture-only" not in result.content
    assert result.content.count("\n") == source.count("\n")
    assert result.content.count("\r") == source.count("\r")
    assert result.content.endswith("diagnostic context")
    assert result.replacements == 2
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("style", ["|", "|-", ">", ">+"])
def test_yaml_block_scalar_preserves_structure_and_line_endings(style):
    source = (
        "variables:\r\n  VENDOR_SECRET: " + style + " # retain\r\n"
        "    fixture-only-first\r\n    fixture-only-second\r\n"
        "  ORDINARY: keep\r\nbuild:\r\n  script: echo useful\r\n"
    )
    result = SecretRedactor().redact(source)
    parsed = YAML(typ="safe").load(result.content)
    assert parsed["variables"]["VENDOR_SECRET"].strip() == "[REDACTED]"
    assert parsed["variables"]["ORDINARY"] == "keep"
    assert parsed["build"]["script"] == "echo useful"
    assert "# retain" in result.content
    assert result.content.count("\r\n") == source.count("\r\n")
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


def test_url_redaction_preserves_ipv6_path_fragment_and_query_encoding():
    source = (
        "ssh://fixture-user:fixture-password@[::1]:22/path/user:docs@file"
        "?download=a%2Fb&%2573ig=" + quote("fixture-only-value /+", safe="")
        + "&page=2#anchor"
    )
    result = SecretRedactor().redact(source)
    parsed = urlsplit(result.content)
    assert parsed.hostname == "::1" and parsed.port == 22
    assert parsed.username is None and parsed.password is None
    assert parsed.path == "/path/user:docs@file"
    assert "download=a%2Fb" in parsed.query and "page=2" in parsed.query
    assert parsed.fragment == "anchor"
    assert "fixture" not in result.content
    assert result.replacements == 2
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("value", [
    "[REDACTED]suffix", "$ENV-suffix", "${ENV}suffix", "%ENV%suffix",
])
def test_marker_or_placeholder_prefix_does_not_exempt_a_real_suffix(value):
    result = SecretRedactor().redact("vendor_token=" + value)
    assert result.content == "vendor_token=[REDACTED]"
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


def test_overlapping_fingerprint_assignment_and_authorization_matches_count_once():
    token = "gl" + "pat-" + "a" * 30
    result = SecretRedactor().redact(
        f'token="{token}"\nAuthorization: Bearer {token}\n{token}',
    )
    assert token not in result.content
    assert result.replacements == 3
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("value", ["fixture-only\\", "fixture-only`", "fixture-only\\`"])
def test_single_quoted_yaml_does_not_use_backslash_or_backtick_escapes(value):
    source = "VENDOR_SECRET: '" + value + "'\nordinary: keep\n"
    result = SecretRedactor().redact(source)
    assert YAML(typ="safe").load(result.content) == {
        "VENDOR_SECRET": "[REDACTED]", "ordinary": "keep",
    }
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


def test_json_backtick_is_literal_and_keeps_sibling_fields():
    source = json.dumps({"vendor_secret": "fixture-only`", "ordinary": "keep"})
    result = SecretRedactor().redact(source)
    assert json.loads(result.content) == {"vendor_secret": "[REDACTED]", "ordinary": "keep"}
    assert result.replacements == 1


def test_invalid_json_yaml_escape_survives_nested_assignment_redaction():
    source = r'script: "echo \e Authorization: fixture-only-value"' + '\nordinary: keep\n'
    result = SecretRedactor().redact(source)
    parsed = YAML(typ="safe").load(result.content)
    assert parsed["ordinary"] == "keep"
    assert "fixture-only" not in parsed["script"]
    assert "\x1b" in parsed["script"]
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


def test_powershell_noncredential_string_masks_nested_authorization_once():
    source = '$message = "echo Authorization: Bearer fixture-only`"suffix"'
    result = SecretRedactor().redact(source)
    assert "fixture-only" not in result.content and "suffix" not in result.content
    assert result.content.startswith('$message = "echo Authorization: ')
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).content == result.content
    assert SecretRedactor().redact(result.content).replacements == 0


def test_escaped_markers_do_not_count_again_beside_a_new_credential():
    marked = r'script: "echo \e Authorization: \"[REDACTED]\""'
    source = marked + '\nTOKEN="fixture-only-value"\n'
    result = SecretRedactor().redact(source)
    assert result.content.startswith(marked)
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("value", [
    '"fixture-only-first"fixture-only-tail',
    "'fixture-only-first'\"fixture-only-tail\"",
    "fixture-only-first,fixture-only-tail", "[fixture-only-value]",
])
def test_shell_scalar_concatenation_and_punctuation_leave_no_suffix(value):
    result = SecretRedactor().redact("TOKEN=" + value + "; ordinary=keep")
    assert "fixture-only" not in result.content
    assert result.content.endswith("; ordinary=keep")
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("value", [
    "fixture-only-first,fixture-only-tail", "fixture-only-first;fixture-only-tail",
    "fixture-only-first&fixture-only-tail", "fixture-only-first}fixture-only-tail",
])
def test_yaml_plain_scalar_punctuation_does_not_leave_a_credential_suffix(value):
    result = SecretRedactor().redact("TOKEN: " + value + " # retain\nordinary: keep\n")
    assert YAML(typ="safe").load(result.content) == {"TOKEN": "[REDACTED]", "ordinary": "keep"}
    assert "# retain" in result.content
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


def test_yaml_flow_mapping_keeps_neighboring_properties():
    source = "{TOKEN: fixture-only-value, ordinary: keep, next: [1, 2]}"
    result = SecretRedactor().redact(source)
    assert YAML(typ="safe").load(result.content) == {
        "TOKEN": "[REDACTED]", "ordinary": "keep", "next": [1, 2],
    }
    assert result.replacements == 1


@pytest.mark.parametrize("value", [
    "${{ secrets['DEPLOY_TOKEN'] }}", '${{ secrets["DEPLOY_TOKEN"] }}',
])
def test_ci_bracket_reference_placeholders_are_unchanged(value):
    source = json.dumps({"vendor_token": value})
    result = SecretRedactor().redact(source)
    assert result.content == source and result.replacements == 0


def test_signed_markdown_link_keeps_delimiters_and_masks_oauth_fragment():
    source = (
        "[docs](https://host.invalid/path_(guide)?page=2&sig=fixture-only-signature"
        "#access_token=fixture-only-token&state=keep)"
    )
    result = SecretRedactor().redact(source)
    assert "fixture-only" not in result.content
    assert result.content.startswith("[docs](https://host.invalid/path_(guide)?page=2&sig=")
    assert result.content.endswith("&state=keep)")
    assert result.replacements == 2
    assert SecretRedactor().redact(result.content).replacements == 0


def test_excess_encoded_string_nesting_fails_closed_and_is_idempotent():
    source = json.dumps({"token": "fixture-only-value"})
    for _ in range(17):
        source = json.dumps({"payload": source})
    result = SecretRedactor().redact(source)
    assert "fixture-only" not in result.content
    json.loads(result.content)
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).content == result.content
    assert SecretRedactor().redact(result.content).replacements == 0