from pipelinelens.config import Settings
from pipelinelens.local_corpus import LocalCorpusImporter
from pipelinelens.storage import IncidentStore


def _settings() -> Settings:
    return Settings(
        environment="test",
        database_url="sqlite:///:memory:",
        redis_url="redis://localhost:6379/0",
        max_log_bytes=500000,
        max_context_chars=18000,
        llm_mode="disabled",
        llm_base_url="http://localhost:11434",
        llm_model="test-model",
        llm_api_key=None,
        allow_private_context=True,
    )


def _simulated_gitlab_token() -> str:
    return "gl" + "pat-" + "abcdefghijklmnopqrstuvwxyz123456"


def test_local_corpus_excludes_credential_files_and_redacts_candidates(tmp_path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / ".gitlab-ci.yml").write_text("test:\n  script: pytest\n", encoding="utf-8")
    (repository / "pipeline_trace.log").write_text(
        f"Authorization: Bearer {_simulated_gitlab_token()}\nHTTP 401 Unauthorized\n",
        encoding="utf-8",
    )
    (repository / "gitlab-token.exe").write_text("simulated-token-do-not-index", encoding="utf-8")

    store = IncidentStore("sqlite:///:memory:")
    store.initialize()
    report = LocalCorpusImporter(store, _settings()).ingest(repository, "private-test")
    documents = store.find_relevant_knowledge("401 unauthorized", include_private_context=True)

    assert report.discovered == 2
    assert report.imported == 2
    assert report.redactions == 1
    assert all("token" not in path for path in report.files)
    assert "glpat-" not in documents[0].content
