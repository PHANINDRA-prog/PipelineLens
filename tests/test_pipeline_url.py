import pytest

from pipelinelens.services.pipeline_url import (
    GitLabPipelineReference,
    GitLabReference,
    PipelineUrlError,
    parse_gitlab_pipeline_url,
    parse_gitlab_url,
)


def test_parses_pasted_nested_gitlab_pipeline_url() -> None:
    reference = parse_gitlab_pipeline_url(
        "https://gitlab.test/platform/services/sample/-/pipelines/12345",
        expected_base_url="https://gitlab.test",
    )

    assert reference.base_url == "https://gitlab.test"
    assert reference.project_path == "platform/services/sample"
    assert reference.pipeline_id == "12345"


def test_rejects_a_pipeline_url_for_a_different_gitlab_host() -> None:
    with pytest.raises(PipelineUrlError, match="different GitLab server"):
        parse_gitlab_pipeline_url(
            "https://gitlab.com/group/project/-/pipelines/42",
            expected_base_url="https://gitlab.test",
        )


@pytest.mark.parametrize(
    "value",
    [
        "https://gitlab.test/group/project/-/jobs/42",
        "https://gitlab.test/group/project/pipelines/42",
        "not-a-url",
    ],
)
def test_rejects_non_pipeline_urls(value: str) -> None:
    with pytest.raises(PipelineUrlError):
        parse_gitlab_pipeline_url(value, expected_base_url="https://gitlab.test")


@pytest.mark.parametrize(
    ("suffix", "kind", "pipeline_id", "job_id", "ref", "file_path"),
    [
        ("/-/pipelines/123", "pipeline", "123", None, None, None),
        ("/-/jobs/456", "job", None, "456", None, None),
        ("/-/tree/validation_release_example", "branch", None, None,
         "validation_release_example", None),
        ("/-/blob/validation_release_example/.gitlab-ci.yml?ref_type=heads", "branch",
         None, None, "validation_release_example", ".gitlab-ci.yml"),
        ("/-/tree/release/1.2", "branch", None, None, "release/1.2", None),
        ("/-/blob/release%2F1.2/.gitlab-ci.yml", "branch", None, None,
         "release/1.2", ".gitlab-ci.yml"),
        ("/-/raw/release/1.2/.gitlab-ci.yml?inline=false", "branch", None, None,
         "release/1.2", ".gitlab-ci.yml"),
        ("", "repository", None, None, None, None),
        ("/", "repository", None, None, None, None),
        (".git", "repository", None, None, None, None),
    ],
)
def test_generic_gitlab_url_contract(
    suffix, kind, pipeline_id, job_id, ref, file_path
) -> None:
    parsed = parse_gitlab_url(
        f"https://GITLAB.TEST:443/sample-org/sample-sfdx{suffix}",
        "https://gitlab.test/",
    )

    assert parsed == GitLabReference(
        "https://gitlab.test", "sample-org/sample-sfdx", kind,
        pipeline_id, job_id, ref, file_path,
    )


def test_pipeline_wrapper_keeps_original_dataclass_contract() -> None:
    assert parse_gitlab_pipeline_url("https://gitlab.test/group/repo/-/pipelines/1") == (
        GitLabPipelineReference("https://gitlab.test", "group/repo", "1")
    )


@pytest.mark.parametrize(
    "value",
    [
        "http://gitlab.test/group/repo",
        "ftp://gitlab.test/group/repo",
        "//gitlab.test/group/repo",
        "https://user:password@gitlab.test/group/repo",
        "https://user@gitlab.test/group/repo",
        "https://gitlab.test@evil.test/group/repo",
        "https://gitlab.test:invalid/group/repo",
        "https://gitlab.test:70000/group/repo",
        "https://gitlab.test:0/group/repo",
        "https://gitlab.test:/group/repo",
        "https://[not-an-ip]/group/repo",
        "https://bad_host/group/repo",
        "https://gitlab.test%2f.evil.test/group/repo",
        "https://gitlab.test/group/../repo/-/pipelines/1",
        "https://gitlab.test/group/%2e%2e/repo/-/pipelines/1",
        "https://gitlab.test/group/%252e%252e/repo/-/pipelines/1",
        "https://gitlab.test/group//repo/-/pipelines/1",
        "https://gitlab.test/group/repo/-/blob/main/../.gitlab-ci.yml",
        "https://gitlab.test/group/repo/-/blob/main/%2e%2e/.gitlab-ci.yml",
        "https://gitlab.test/group/repo/-/pipelines/0",
        "https://gitlab.test/group/repo/-/jobs/-1",
        "https://gitlab.test/group/repo/-/jobs/1/extra",
        "https://gitlab.test/group/repo/-/blob/main",
        "https://gitlab.test/group/repo/-/tree/",
        "https://gitlab.test/group/repo/-/jobs/1?private_token=secret",
        "https://gitlab.test/group/repo/-/jobs/1?access_token=secret",
        "https://gitlab.test/group/repo/-/jobs/1?jwt=secret",
        "https://gitlab.test/group/repo/-/jobs/1?arbitrary_secret=secret",
        "https://gitlab.test/group/repo/-/blob/main/.gitlab-ci.yml?ref_type=secret",
        "https://gitlab.test/group/repo/-/blob/main/.gitlab-ci.yml?ref_type=heads&token=secret",
        "https://gitlab.test/group/repo/-/blob/main/.gitlab-ci.yml?ref_type=heads&ref_type=tags",
        "https://gitlab.test/group/repo#token=secret",
        "https://gitlab.test/group/repo\\evil",
        "https://gitlab.test/group/repo%5Cevil",
        "https://gitlab.test/group/repo%0aevil",
        "https://gitlab.test/\ngroup/repo",
        "https://gitlab.test/group/repo%zz",
    ],
)
def test_url_parser_rejects_unsafe_or_unsupported_inputs_without_echoing_secrets(value) -> None:
    with pytest.raises(PipelineUrlError) as error:
        parse_gitlab_url(value)
    assert "password" not in str(error.value)
    assert "=secret" not in str(error.value)


@pytest.mark.parametrize("origin", ["http://localhost:8000", "http://127.0.0.1:8000", "http://[::1]:8000"])
def test_only_explicit_loopback_http_is_allowed(origin) -> None:
    assert parse_gitlab_url(f"{origin}/group/repo", origin).base_url == origin


@pytest.mark.parametrize("origin", ["http://localhost.evil.test", "http://127.1", "http://10.0.0.1"])
def test_http_lookalikes_and_non_loopback_are_rejected(origin) -> None:
    with pytest.raises(PipelineUrlError):
        parse_gitlab_url(f"{origin}/group/repo")


def test_url_parser_normalizes_hosts_but_keeps_port_boundaries() -> None:
    assert parse_gitlab_url(
        "https://GITLAB.TEST.:443/group/repo", "https://gitlab.test/api/v4"
    ).base_url == "https://gitlab.test"
    with pytest.raises(PipelineUrlError, match="different GitLab server"):
        parse_gitlab_url("https://gitlab.test:8443/group/repo", "https://gitlab.test")


def test_parsing_does_not_contact_network(monkeypatch) -> None:
    def forbidden(*args, **kwargs):
        pytest.fail("URL parsing must not perform DNS or HTTP requests")

    monkeypatch.setattr("socket.getaddrinfo", forbidden)
    assert parse_gitlab_url("https://gitlab.test/group/repo/-/jobs/7").job_id == "7"