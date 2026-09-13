"""Sanitized, public-safe demo incidents used when no provider token is available."""

from __future__ import annotations

from dataclasses import dataclass

from pipelinelens.domain import CiConfigFile, PipelineJob, PipelineRun, ProviderName, RepositoryRef


@dataclass(frozen=True, slots=True)
class DemoIncident:
    fixture_id: str
    title: str
    description: str
    repository: RepositoryRef
    run: PipelineRun
    job: PipelineJob
    configs: list[CiConfigFile]
    log: str


_GITLAB_REPOSITORY = RepositoryRef(
    provider=ProviderName.GITLAB,
    external_id="demo-gitlab-release",
    owner="sample-org",
    name="release-service",
    web_url="https://gitlab.example/sample-org/release-service",
    default_branch="main",
)

_GITHUB_REPOSITORY = RepositoryRef(
    provider=ProviderName.GITHUB,
    external_id="demo-github-api",
    owner="sample-org",
    name="api-service",
    web_url="https://github.com/sample-org/api-service",
    default_branch="main",
)

_SIMULATED_GITLAB_TOKEN = "gl" + "pat-" + "fixture-token-value-that-is-not-real"


_DEMO_INCIDENTS: tuple[DemoIncident, ...] = (
    DemoIncident(
        fixture_id="gitlab-auth-expired",
        title="GitLab deployment credential expired",
        description="A protected deployment job received an HTTP 401 after validation passed.",
        repository=_GITLAB_REPOSITORY,
        run=PipelineRun(
            external_id="101",
            name="Release pipeline #101",
            status="failed",
            conclusion="failed",
            ref_name="main",
            commit_sha="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12b432",
            web_url="https://gitlab.example/sample-org/release-service/-/pipelines/101",
        ),
        job=PipelineJob(
            external_id="305",
            key="deploy-production",
            name="deploy-production",
            stage="deploy",
            status="failed",
            conclusion="failed",
            web_url="https://gitlab.example/sample-org/release-service/-/jobs/305",
        ),
        configs=[
            CiConfigFile(
                path=".gitlab-ci.yml",
                ref="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12b432",
                content="""stages:\n  - validate\n  - deploy\n  - verify\n\ninclude:\n  - local: ci/deploy.yml\n\nvalidate-release:\n  stage: validate\n  script:\n    - python -m pytest\n  artifacts:\n    paths:\n      - reports/validation.json\n""",
            ),
            CiConfigFile(
                path="ci/deploy.yml",
                ref="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12b432",
                content="""deploy-production:\n  stage: deploy\n  needs:\n    - job: validate-release\n      artifacts: true\n  rules:\n    - if: '$CI_COMMIT_BRANCH == "main"'\n  resource_group: production\n  script:\n    - ./scripts/deploy.sh production\n  environment:\n    name: production\n""",
            ),
        ],
        log=(
            "Running with gitlab-runner 17.8.0\n"
            "$ ./scripts/deploy.sh production\n"
            "Validating deployment credential\n"
            f"Authorization: Bearer {_SIMULATED_GITLAB_TOKEN}\n"
            "HTTP 401 Unauthorized: deployment credential expired\n"
            "ERROR: Job failed: exit code 1\n"
        ),
    ),
    DemoIncident(
        fixture_id="github-test-failure",
        title="GitHub Actions integration test timeout",
        description="A test job failed before the downstream deployment job could consume its coverage artifact.",
        repository=_GITHUB_REPOSITORY,
        run=PipelineRun(
            external_id="202",
            name="CI",
            status="completed",
            conclusion="failure",
            ref_name="feature/timeout-guard",
            commit_sha="3b0e8efac1d8cc43e2c883260709bd2c11caa321",
            web_url="https://github.com/sample-org/api-service/actions/runs/202",
            raw={"workflow_id": 44},
        ),
        job=PipelineJob(
            external_id="410",
            key="test",
            name="test",
            stage="workflow",
            status="completed",
            conclusion="failure",
            web_url="https://github.com/sample-org/api-service/actions/runs/202/job/410",
        ),
        configs=[
            CiConfigFile(
                path=".github/workflows/ci.yml",
                ref="3b0e8efac1d8cc43e2c883260709bd2c11caa321",
                content="""name: CI\non:\n  pull_request:\n  push:\n    branches: [main]\n\njobs:\n  test:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: Run integration tests\n        run: python -m pytest tests/integration\n      - name: Upload coverage\n        uses: actions/upload-artifact@v4\n        with:\n          name: coverage-report\n          path: coverage/\n  deploy-staging:\n    needs: test\n    if: github.ref == 'refs/heads/main'\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/download-artifact@v4\n        with:\n          name: coverage-report\n      - run: ./scripts/deploy.sh staging\n""",
            )
        ],
        log="""Run python -m pytest tests/integration\n============================= test session starts =============================\nFAILED tests/integration/test_checkout.py::test_quote_timeout\nExpected: response within 5000ms\nReceived: response after 10012ms\nAssertionError: checkout service exceeded timeout budget\nError: Process completed with exit code 1.\n""",
    ),
    DemoIncident(
        fixture_id="gitlab-csharp-build-failure",
        title="GitLab C# compilation failure",
        description="A custom-code build reported a missing symbol and exact source location.",
        repository=_GITLAB_REPOSITORY,
        run=PipelineRun(
            external_id="109",
            name="Release pipeline #109",
            status="failed",
            conclusion="failed",
            ref_name="feature/quote-validation",
            commit_sha="9a8724d0cfea9b77e06462d3d2cb1b44e030f005",
            web_url="https://gitlab.example/sample-org/release-service/-/pipelines/109",
        ),
        job=PipelineJob(
            external_id="321",
            key="build-custom-code",
            name="build-custom-code",
            stage="validate",
            status="failed",
            conclusion="failed",
            web_url="https://gitlab.example/sample-org/release-service/-/jobs/321",
        ),
        configs=[
            CiConfigFile(
                path=".gitlab-ci.yml",
                ref="9a8724d0cfea9b77e06462d3d2cb1b44e030f005",
                content="""stages: [validate, deploy]

build-custom-code:
  stage: validate
  image: mcr.microsoft.com/dotnet/sdk:8.0
  script:
    - dotnet build customcodes/Pricing/Pricing.sln --configuration Release
  artifacts:
    reports:
      junit: reports/build.xml

deploy-custom-code:
  stage: deploy
  needs: [build-custom-code]
  script:
    - ./scripts/deploy.sh staging
""",
            )
        ],
        log="""$ dotnet build customcodes/Pricing/Pricing.sln --configuration Release
Determining projects to restore...
customcodes/Pricing/QuoteEngine.cs(42,17): error CS0103: The name 'pricingContext' does not exist in the current context
Build FAILED.
    0 Warning(s)
    1 Error(s)
ERROR: Job failed: exit code 1
""",
    ),
    DemoIncident(
        fixture_id="gitlab-artifact-missing",
        title="GitLab downstream artifact unavailable",
        description="A release job started after a dependency path was changed and could not download its expected artifact.",
        repository=_GITLAB_REPOSITORY,
        run=PipelineRun(
            external_id="116",
            name="Release pipeline #116",
            status="failed",
            conclusion="failed",
            ref_name="release/1.8",
            commit_sha="13579bdf13579bdf13579bdf13579bdf13579bdf",
            web_url="https://gitlab.example/sample-org/release-service/-/pipelines/116",
        ),
        job=PipelineJob(
            external_id="336",
            key="publish-release",
            name="publish-release",
            stage="deploy",
            status="failed",
            conclusion="failed",
            web_url="https://gitlab.example/sample-org/release-service/-/jobs/336",
        ),
        configs=[
            CiConfigFile(
                path=".gitlab-ci.yml",
                ref="13579bdf13579bdf13579bdf13579bdf13579bdf",
                content="""stages: [build, deploy]\n\npackage:\n  stage: build\n  script:\n    - python -m build\n  artifacts:\n    paths:\n      - dist/release.tar.gz\n\npublish-release:\n  stage: deploy\n  needs:\n    - job: package\n      artifacts: true\n  script:\n    - test -f dist/release.tar.gz\n    - ./scripts/publish.sh dist/release.tar.gz\n""",
            )
        ],
        log="""Downloading artifacts for package (job 335)...\nWARNING: Downloading artifacts from coordinator... failed  host=gitlab.example id=335 responseStatus=404 Not Found\nERROR: Job failed: could not download required artifact dist/release.tar.gz\nERROR: Job failed: exit code 1\n""",
    ),
)


def list_demo_incidents() -> list[DemoIncident]:
    return list(_DEMO_INCIDENTS)


def get_demo_incident(fixture_id: str) -> DemoIncident:
    for incident in _DEMO_INCIDENTS:
        if incident.fixture_id == fixture_id:
            return incident
    raise KeyError(f"Unknown demo incident: {fixture_id}")
