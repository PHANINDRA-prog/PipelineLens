from pipelinelens.config import get_settings
from pipelinelens.domain import ProviderName, RepositoryRef


def test_default_settings_are_safe(monkeypatch) -> None:
    monkeypatch.delenv("PIPELINELENS_ALLOW_PRIVATE_CONTEXT", raising=False)
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.llm_mode == "disabled"
    assert settings.allow_private_context is False


def test_repository_display_name() -> None:
    repository = RepositoryRef(
        provider=ProviderName.GITLAB,
        external_id="42",
        owner="acme",
        name="platform",
        web_url="https://gitlab.example/acme/platform",
    )

    assert repository.display_name == "acme/platform"


def test_configured_gitlab_settings_are_loaded_from_environment(monkeypatch) -> None:
    monkeypatch.setenv("PIPELINELENS_GITLAB_TOKEN", "local-development-token")
    monkeypatch.setenv("PIPELINELENS_GITLAB_BASE_URL", "https://gitlab.internal/")
    get_settings.cache_clear()

    settings = get_settings()

    assert settings.configured_gitlab_token == "local-development-token"
    assert settings.configured_gitlab_base_url == "https://gitlab.internal"
    get_settings.cache_clear()
