"""Provider factory used by API routes and background analysis."""

from __future__ import annotations

from pipelinelens.domain import ProviderName
from pipelinelens.providers.base import CiProvider
from pipelinelens.providers.github import GitHubProvider
from pipelinelens.providers.gitlab import GitLabProvider


def get_provider(provider: ProviderName, base_url: str | None = None) -> CiProvider:
    if provider == ProviderName.GITHUB:
        return GitHubProvider(base_url or "https://api.github.com")
    if provider == ProviderName.GITLAB:
        return GitLabProvider(base_url or "https://gitlab.com")
    raise ValueError(f"No live provider adapter exists for {provider}.")
