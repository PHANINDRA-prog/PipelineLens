"""Synthetic third-party credentials must not reach inspection consumers or caches."""

from __future__ import annotations

import json
import socket
from dataclasses import replace
from typing import cast
from urllib.parse import quote

import httpx
import pytest
from ruamel.yaml import YAML

from pipelinelens.api.inspection import _ResultCache
from pipelinelens.config import Settings
from pipelinelens.domain import (
    CiConfigAccessEntry,
    CiConfigAccessReport,
    CiConfigFile,
    PipelineJob,
    PipelineRun,
    ProviderName,
    RepositoryRef,
    RepositoryTreeEntry,
)
from pipelinelens.providers.gitlab import ConfigInspection, GitLabProvider
from pipelinelens.services.analysis import AnalysisInput, PipelineAnalyzer
from pipelinelens.services.inspection import _Scrubber, inspect_gitlab
from pipelinelens.services.logs import analyze_log, failure_signals, redact_log
from pipelinelens.services.pipeline_url import parse_gitlab_url
from pipelinelens.services.redaction import SecretRedactor

ORIGIN = "https://gitlab.test"
SHA = "a" * 40
PROJECT = "fixtures/redaction"
OPAQUE = "synthetic-third-party-value-A7q9"
BASIC = "Zml4dHVyZS11c2VyOm5vdC1hLXJlYWwtY3JlZGVudGlhbA=="
USERINFO = "synthetic-url-value-B8r0"
SIGNED = "synthetic-signed-value-C9s1"
ESCAPED = 'synthetic-escaped-value-D0t2"\\tail'
COMPILER_ERROR = "src/App.cs(7,3): error CS0161: not all code paths return a value"


def _settings() -> Settings:
    return Settings(
        environment="test", database_url="sqlite://", redis_url="redis://unused",
        max_log_bytes=500_000, max_context_chars=18_000, llm_mode="disabled",
        llm_base_url="https://unused.invalid", llm_model="unused", llm_api_key=None,
        allow_private_context=False, configured_gitlab_token=None,
        configured_gitlab_base_url=ORIGIN,
    )


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def blocked(*args, **kwargs):
        pytest.fail("Security regressions must not access the network", pytrace=False)

    # Windows asyncio creates an internal loopback socketpair when opening a loop.
    # Block outbound client/DNS entry points, not that interpreter self-pipe.
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(httpx.Client, "send", blocked)
    monkeypatch.setattr(httpx.AsyncClient, "send", blocked)


def _assert_no_secrets(text: str, values: tuple[str, ...]) -> None:
    """Do not let pytest's assertion introspection echo a leaking credential."""
    for value in values:
        variants = (value, quote(value, safe=""), json.dumps(value)[1:-1])
        if any(variant in text for variant in variants):
            pytest.fail("A synthetic credential escaped sanitization", pytrace=False)


@pytest.mark.parametrize("source", [
    pytest.param(f'VENDOR_ACCESS_TOKEN: "{OPAQUE}" # keep this comment', id="yaml-double"),
    pytest.param(f"'vendor.client_secret': '{OPAQUE}'", id="yaml-quoted-key"),
    pytest.param(f'{{"VeNdOr_ApI_KeY":"{OPAQUE}","ok":true}}', id="json-mixed-case"),
    pytest.param(f'{{"vendor\\u005fsecret":"{OPAQUE}"}}', id="json-escaped-key"),
    pytest.param(f'$env:THIRD_PARTY_PASSWORD = "{OPAQUE}"', id="powershell-env"),
    pytest.param(f"$VendorPassphrase = '{OPAQUE}'", id="powershell-variable"),
    pytest.param(f"export THIRD_PARTY_SECRET='{OPAQUE}'", id="shell-export"),
    pytest.param(f"set VENDOR_PASS={OPAQUE}", id="cmd-assignment"),
    pytest.param(f'{{"X-API-Key":"{OPAQUE}"}}', id="header-field"),
    pytest.param(f'Authorization: "{OPAQUE}"', id="opaque-authorization"),
    pytest.param(f'"Proxy-Authorization" = "Basic {BASIC}"', id="quoted-basic"),
    pytest.param(f"Authorization: Basic {BASIC}", id="basic-header"),
    pytest.param(f"basic {BASIC}", id="basic-plain-text"),
    pytest.param(f"Bearer {OPAQUE}", id="bearer-plain-text"),
    pytest.param(f'Authorization: Bearer {OPAQUE}', id="bearer-header"),
    pytest.param(f'{{"vendor_secret":{json.dumps(ESCAPED)}}}', id="json-escaped-value"),
    pytest.param(f"VENDOR_TOKEN: 'prefix''{OPAQUE}'", id="yaml-doubled-single-quote"),
    pytest.param(f'$env:VENDOR_SECRET = "prefix`"{OPAQUE}"', id="powershell-escaped-quote"),
    pytest.param(json.dumps({"payload": json.dumps({"vendor_token": ESCAPED})}),
                 id="json-encoded-json"),
    pytest.param(f"vendor_token=prefix\\ {OPAQUE}", id="shell-escaped-space"),
    pytest.param(f'VENDOR_TOKEN="{OPAQUE}', id="unterminated-quoted-assignment"),
])
def test_unknown_credential_assignments_are_redacted_once(source: str) -> None:
    result = SecretRedactor().redact(source)
    _assert_no_secrets(result.content, (OPAQUE, BASIC, ESCAPED, "synthetic-escaped-value-D0t2"))
    assert result.replacements == 1
    assert "REDACTED" in result.content
    again = SecretRedactor().redact(result.content)
    assert again.content == result.content
    assert again.replacements == 0


@pytest.mark.parametrize("key", [
    "sig", "signature", "X-Amz-Signature", "X-Amz-Credential", "X-Amz-Security-Token",
    "X-Goog-Signature", "X-Goog-Credential", "AWSAccessKeyId", "GoogleAccessId",
    "Key-Pair-Id", "Policy", "api_key", "access_token", "%73ig",
])
def test_signed_query_parameters_in_arbitrary_text_are_redacted(key: str) -> None:
    source = f'fetch "https://download.invalid/file?download=1&{key}={SIGNED}&page=2" now'
    result = SecretRedactor().redact(source)
    _assert_no_secrets(result.content, (SIGNED,))
    assert "download=1" in result.content and "page=2" in result.content
    assert result.content.startswith('fetch "https://download.invalid/file?')
    assert result.content.endswith('" now')
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("source", [
    pytest.param(f"https://fixture-user:{USERINFO}@host.invalid/file", id="https"),
    pytest.param(f"HTTP://fixture-user:{USERINFO}@host.invalid:8080/file", id="http-case"),
    pytest.param(f"ssh://fixture-user:{USERINFO}@[::1]:22/repo", id="ipv6"),
    pytest.param(f"https://fixture-user:{quote(USERINFO + '/?#', safe='')}@host.invalid/f",
                 id="encoded-userinfo"),
    pytest.param(f'{{"url":"https:\\/\\/fixture-user:{USERINFO}@host.invalid/file"}}',
                 id="json-escaped-slashes"),
    pytest.param(f"see https://{USERINFO}@host.invalid/file next", id="username-only"),
])
def test_url_credentials_are_removed_only_from_the_authority(source: str) -> None:
    result = SecretRedactor().redact(source)
    _assert_no_secrets(result.content, (USERINFO, "fixture-user"))
    assert "host.invalid" in result.content or "[::1]:22" in result.content
    assert result.replacements == 1
    assert SecretRedactor().redact(result.content).replacements == 0


@pytest.mark.parametrize("source", [
    pytest.param("https://host.invalid/path/user:docs@file.yml", id="url-path-at"),
    pytest.param("file:///C:/repo/user@file.yml", id="file-url-at"),
    pytest.param("ci/build.yml@group/project:main", id="gitlab-project-ci"),
    pytest.param(r"C:\repo\user@file.yml", id="windows-file"),
    pytest.param("user@example.invalid and @group/ci", id="email-and-scope"),
    pytest.param("Token: string?\nPassword: string\nAuthorization: null", id="schema-types"),
    pytest.param('{"token_count":42,"max_tokens":4096,"TokenType":"string"}',
                 id="metadata-stats"),
    pytest.param('TOKEN="$ENV"\nPASSWORD: \'${PASSWORD}\'\nAPI_KEY=%API_KEY%',
                 id="environment-placeholders"),
    pytest.param('$env:API_KEY = "$env:OTHER_KEY"\nTOKEN: ${CI_TOKEN}', id="powershell-env"),
    pytest.param('TOKEN: "${{ secrets.DEPLOY_TOKEN }}"\nAPI_KEY: $(ApiKey)',
                 id="ci-placeholders"),
    pytest.param('Authorization: Bearer $ACCESS_TOKEN\nAuthorization: "Basic ${AUTH}"',
                 id="authorization-placeholders"),
    pytest.param('VENDOR_TOKEN: ""\nVENDOR_SECRET:\n  description: string', id="empty-and-group"),
])
def test_harmless_paths_placeholders_and_metadata_are_unchanged(source: str) -> None:
    result = SecretRedactor().redact(source)
    assert result.content == source
    assert result.replacements == 0


def test_json_structure_and_quoted_yaml_values_survive_redaction() -> None:
    original = {
        "client_secret": ESCAPED, "PASSWORD": "12345", "api_key": 98765,
        "metadata": {"Token": "string", "token_count": 12},
        "ok": True, "ordinary": "useful context", "next": ["left", "right"],
    }
    result = SecretRedactor().redact(json.dumps(original, indent=2))
    _assert_no_secrets(result.content, (ESCAPED, "12345", "98765"))
    parsed = json.loads(result.content)
    assert set(parsed) == set(original)
    assert parsed["metadata"] == original["metadata"]
    assert parsed["ok"] is True and parsed["ordinary"] == "useful context"
    assert parsed["next"] == ["left", "right"]
    assert all(parsed[name] == "[REDACTED]" for name in ("client_secret", "PASSWORD", "api_key"))

    source = (
        'variables:\n  "VENDOR_TOKEN": "' + OPAQUE + '" # keep\n'
        "  VENDOR_SECRET: '" + OPAQUE + "'\n  VENDOR_PASSWORD: " + OPAQUE + "\n"
        "build:\n  script: echo useful\n"
    )
    redacted = SecretRedactor().redact(source).content
    data = YAML(typ="safe").load(redacted)
    assert set(data["variables"]) == {"VENDOR_TOKEN", "VENDOR_SECRET", "VENDOR_PASSWORD"}
    assert all(value == "[REDACTED]" for value in data["variables"].values())
    assert '"VENDOR_TOKEN": "[REDACTED]" # keep' in redacted
    assert "VENDOR_SECRET: '[REDACTED]'" in redacted
    assert data["build"]["script"] == "echo useful"
    assert redacted.count("\n") == source.count("\n")


def test_encoded_json_remains_decodable_without_an_escaped_secret_suffix() -> None:
    source = json.dumps({"payload": json.dumps({"ToKeN": ESCAPED, "ok": True})})
    redacted = SecretRedactor().redact(source).content
    _assert_no_secrets(redacted, ("synthetic-escaped-value-D0t2", "tail"))
    assert json.loads(json.loads(redacted)["payload"]) == {"ToKeN": "[REDACTED]", "ok": True}


@pytest.mark.parametrize("ending", ["\n", "\r\n"])
def test_multiline_quoted_values_and_private_keys_keep_causal_log_offsets(ending: str) -> None:
    source = ending.join([
        'VENDOR_SECRET="' + OPAQUE, 'private second line"',
        "-----BEGIN PRIVATE KEY-----", USERINFO, "-----END PRIVATE KEY-----",
        COMPILER_ERROR,
    ])
    result = analyze_log(source)
    _assert_no_secrets(result.redaction.content, (OPAQUE, USERINFO, "private second line"))
    assert result.redaction.content.count("\n") == source.count("\n")
    assert result.redaction.content.count("\r") == source.count("\r")
    assert result.redaction.replacements == 2
    assert failure_signals(result.redaction.content)[0].line == 6
    assert result.chunks[0].line_end == 6


@pytest.mark.parametrize("kind", ["", "RSA ", "EC ", "OPENSSH ", "ENCRYPTED "])
def test_truncated_private_keys_fail_closed_without_losing_lines(kind: str) -> None:
    source = "context\n-----BEGIN " + kind + "PRIVATE KEY-----\n" + OPAQUE + "\n" + USERINFO
    for result in (SecretRedactor().redact(source), redact_log(source)):
        _assert_no_secrets(result.content, (OPAQUE, USERINFO))
        assert result.content.startswith("context\n")
        assert result.content.count("\n") == source.count("\n")
        assert result.replacements == 1


def test_long_unterminated_values_are_redacted_in_full_not_just_a_regex_prefix() -> None:
    source = 'VENDOR_TOKEN="' + "x" * 200_000 + OPAQUE
    result = SecretRedactor().redact(source)
    _assert_no_secrets(result.content, (OPAQUE, "x" * 100))
    assert len(result.content) < 100 and result.replacements == 1
    benign = "unrelated_identifier" * 20_000 + ": ordinary\n" + 'TOKEN="$ENV"'
    assert SecretRedactor().redact(benign).content == benign


def _repository(ci_config_path: str | None = None) -> RepositoryRef:
    return RepositoryRef(
        provider=ProviderName.GITLAB, external_id="42", owner="fixtures", name="redaction",
        web_url=f"{ORIGIN}/{PROJECT}", default_branch="main", ci_config_path=ci_config_path,
    )


def _config() -> CiConfigFile:
    return CiConfigFile(
        path=".gitlab-ci.yml", ref=SHA,
        source_url=f"{ORIGIN}/{PROJECT}/-/blob/{SHA}/.gitlab-ci.yml",
        content=(
            f'variables:\n  VENDOR_TOKEN: "{OPAQUE}"\n'
            f"  THIRD_PARTY_PASSWORD: '{OPAQUE}'\n"
            "build:\n  script:\n"
            f"    - 'curl https://fixture-user:{USERINFO}@download.invalid/file?sig={SIGNED}'\n"
            f"    - 'echo Authorization: Basic {BASIC}'\n"
        ),
    )


def _trace() -> str:
    return "\n".join([
        f'$env:VENDOR_SECRET = "{OPAQUE}"',
        json.dumps({"vendor_API_key": ESCAPED}),
        f"Authorization: Basic {BASIC}",
        f"GET https://fixture-user:{USERINFO}@download.invalid/file?sig={SIGNED}",
        COMPILER_ERROR,
    ])


def test_pipeline_analyzer_scrubs_unknown_config_and_log_values_before_graph_and_diagnosis():
    config = _config()
    analyzer = PipelineAnalyzer(_settings())
    snapshot = analyzer.analyze_input(AnalysisInput(
        repository=_repository(),
        run=PipelineRun(external_id="8", name="fixture", status="failed", commit_sha=SHA),
        job=PipelineJob(external_id="9", name="build", status="failed"),
        configs=[config], raw_log=_trace(),
    ))
    _assert_no_secrets(snapshot.model_dump_json(), (OPAQUE, USERINFO, SIGNED, BASIC,
                                                   "synthetic-escaped-value-D0t2"))
    assert snapshot.config_bundle and snapshot.graph.nodes and snapshot.job_source
    assert snapshot.fingerprint.category == "build_failure"
    assert failure_signals(snapshot.redacted_log)[0].line == 5
    assert OPAQUE in config.content  # Never mutate provider inputs.


def test_actual_scrubber_covers_plain_metadata_and_excluded_raw_fields() -> None:
    url = f"https://fixture-user:{USERINFO}@config.invalid/root.yml?sig={SIGNED}"
    scrub = _Scrubber(ORIGIN, "synthetic-request-credential", _settings())
    repository = scrub.model(_repository(url))
    _assert_no_secrets(repository.model_dump_json(), (USERINFO, SIGNED))
    assert repository.ci_config_path and "config.invalid/root.yml" in repository.ci_config_path
    config = _config().model_copy(update={"path": url, "ref": f'TOKEN="{OPAQUE}"'})
    data = scrub.data({"config": config, "notes": [_trace()], "raw": {"keep_out": OPAQUE}})
    _assert_no_secrets(json.dumps(data), (OPAQUE, USERINFO, SIGNED, BASIC,
                                        "synthetic-escaped-value-D0t2"))
    assert "raw" not in data


class _OfflineProvider:
    """A strict duck-typed service fixture; no real provider/client is constructed."""

    web_base_url = ORIGIN

    def __init__(self) -> None:
        self.repository = _repository(
            f"https://fixture-user:{USERINFO}@config.invalid/root.yml?sig={SIGNED}",
        )
        self.config = _config()
        self.run = PipelineRun(
            external_id="8", name=f'pipeline vendor_token="{OPAQUE}"', status="failed",
            commit_sha=SHA, ref_name="main", raw={"private": OPAQUE},
        )
        self.job = PipelineJob(
            external_id="9", name="build", status="failed", raw={"private": OPAQUE},
        )

    async def get_repository_by_path(self, *args):
        return self.repository

    async def get_run(self, *args):
        return self.run

    async def list_pipeline_jobs(self, *args, **kwargs):
        return [self.job]

    async def list_pipeline_bridges(self, *args):
        return []

    async def load_ci_sources(self, *args):
        return ConfigInspection([self.config], CiConfigAccessReport(
            complete=True,
            entries=[CiConfigAccessEntry(
                path=self.repository.ci_config_path or "", ref=SHA, state="readable",
                relationship="root", detail=f'fixture vendor_token="{OPAQUE}"',
            )],
            notes=[f"Signed source https://download.invalid/file?sig={SIGNED}"],
        ))

    async def list_repository_tree(self, *args, **kwargs):
        return [RepositoryTreeEntry(path="src/App.cs", entry_type="file")]

    async def fetch_job_log(self, *args):
        return _trace()

    async def _request(self, token, method, path, **kwargs):
        if method != "GET" or path not in {
            "/projects/42/pipelines/8/merge_requests",
            f"/projects/42/repository/commits/{SHA}/diff",
        }:
            pytest.fail("Unexpected offline service request", pytrace=False)
        return httpx.Response(200, json=[])


async def test_actual_inspection_scrubs_before_analyzer_response_and_model_cache(monkeypatch):
    provider = _OfflineProvider()
    secrets = (OPAQUE, USERINFO, SIGNED, BASIC, "synthetic-escaped-value-D0t2")
    analyzer_inputs = []
    original = PipelineAnalyzer.analyze_input

    def checked(self, analysis_input, *args, **kwargs):
        for item in (analysis_input.repository, analysis_input.run, analysis_input.job,
                     *analysis_input.configs):
            _assert_no_secrets(item.model_dump_json(), secrets)
        _assert_no_secrets(analysis_input.raw_log, secrets)
        assert analysis_input.run.raw == analysis_input.job.raw == {}
        analyzer_inputs.append(analysis_input)
        return original(self, analysis_input, *args, **kwargs)

    monkeypatch.setattr(PipelineAnalyzer, "analyze_input", checked)
    result = await inspect_gitlab(
        cast(GitLabProvider, provider), "synthetic-request-credential", provider.repository,
        parse_gitlab_url(f"{ORIGIN}/{PROJECT}/-/pipelines/8"), _settings(),
    )
    assert len(analyzer_inputs) == 1
    assert result.analyses and result.config_bundle and result.findings
    assert any(finding.rule_id == "compiler.cs0161" for finding in result.findings)
    _assert_no_secrets(result.model_dump_json(), secrets)
    _assert_no_secrets(repr(result), secrets)
    assert result.repository.ci_config_path
    assert "config.invalid/root.yml" in result.repository.ci_config_path
    cache = _ResultCache()
    # An external/unverifiable source must be reread, not authorized by root access.
    assert not cache.put("fixture", result, "2026-09-13T00:00:00+00:00")
    assert cache.get("fixture") is None
    local = result.model_copy(deep=True)
    local.repository.ci_config_path = ".gitlab-ci.yml"
    local.ci_config_access.entries[0].path = local.config_bundle[0].path
    local.ci_config_access.entries[0].source_url = local.config_bundle[0].source_url
    assert cache.put("root-only", local, "2026-09-13T00:00:00+00:00")
    cached = cache.get("root-only")
    assert cached is not None and cached.result is not local
    _assert_no_secrets(cached.result.model_dump_json(), secrets)
    assert OPAQUE in provider.config.content


def test_explicit_multiline_secret_redaction_still_preserves_log_lines() -> None:
    configured = replace(_settings(), llm_api_key="synthetic\nconfigured\nfixture")
    scrub = _Scrubber(ORIGIN, "synthetic-request-credential", configured)
    source = "start\n" + (configured.llm_api_key or "") + "\n" + COMPILER_ERROR
    result = scrub.text(source)
    _assert_no_secrets(result, (configured.llm_api_key or "unused",))
    assert result.count("\n") == source.count("\n")
    assert failure_signals(result)[0].line == 5