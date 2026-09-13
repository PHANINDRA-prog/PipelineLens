import pytest

from pipelinelens.domain import CiConfigFile, PipelineJob
from pipelinelens.services.gitlab_includes import (
    collect_gitlab_includes,
    gitlab_include_keys,
    parse_project_include_key,
    project_include_key,
    resolve_local_include,
)
from pipelinelens.services.yaml_graph import (
    analyze_github_workflow,
    analyze_gitlab_yaml,
    match_job_to_graph,
)


def test_gitlab_graph_resolves_local_include_and_maps_job_source() -> None:
    root = CiConfigFile(
        path=".gitlab-ci.yml",
        ref="abc123",
        content="""stages: [validate, deploy]\ninclude:\n  - local: ci/deploy.yml\nvalidate:\n  stage: validate\n  script:\n    - pytest\n""",
    )
    included = """deploy-production:\n  stage: deploy\n  needs: [validate]\n  script:\n    - ./deploy production\n  artifacts:\n    paths: [deployment.json]\n"""

    graph = analyze_gitlab_yaml(
        root, include_loader=lambda path: included if path == "ci/deploy.yml" else None
    )
    source = match_job_to_graph(
        PipelineJob(external_id="91", name="deploy-production", status="failed"), graph
    )

    assert graph.stages == ["validate", "deploy"]
    assert [node.key for node in graph.nodes] == ["validate", "deploy-production"]
    assert graph.nodes[1].needs == ["validate"]
    assert graph.nodes[1].artifacts == ["deployment.json"]
    assert source is not None
    assert source.path == "ci/deploy.yml"
    assert source.line_start == 1


def test_gitlab_graph_accepts_a_spec_header_before_the_pipeline_document() -> None:
    config = CiConfigFile(
        path=".gitlab-ci.yml",
        ref="abc123",
        content="""spec:
    inputs:
        target:
            default: staging
---
stages: [validate]
validate:
    stage: validate
    script: pytest
""",
    )

    graph = analyze_gitlab_yaml(config)

    assert graph.stages == ["validate"]
    assert [node.key for node in graph.nodes] == ["validate"]
    assert graph.nodes[0].source.line_start == 7


def test_gitlab_graph_resolves_project_include_to_the_external_job_source() -> None:
    root = CiConfigFile(
        path=".gitlab-ci.yml",
        ref="abc123",
        content="""include:
  - project: platform/shared-ci
    file: HandleAll.yml
    ref: release/1.0
""",
    )
    external_key = project_include_key("platform/shared-ci", "HandleAll.yml", "release/1.0")
    external_config = """build-job:
  stage: build
  script:
    - dotnet test
"""

    graph = analyze_gitlab_yaml(
        root,
        include_loader=lambda path: external_config if path == external_key else None,
    )
    source = match_job_to_graph(
        PipelineJob(external_id="4", name="build-job", status="failed"), graph
    )

    assert source is not None
    assert source.path == external_key
    assert graph.unresolved_includes == []


def test_github_graph_captures_needs_and_artifact_steps() -> None:
    config = CiConfigFile(
        path=".github/workflows/release.yml",
        ref="abc123",
        content="""name: Release\non: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: pytest\n      - uses: actions/upload-artifact@v4\n  deploy:\n    needs: build\n    if: github.ref == 'refs/heads/main'\n    runs-on: ubuntu-latest\n    steps:\n      - run: ./deploy.sh\n""",
    )

    graph = analyze_github_workflow(config)

    assert [node.key for node in graph.nodes] == ["build", "deploy"]
    assert graph.nodes[1].needs == ["build"]
    assert graph.nodes[0].artifacts == ["actions/upload-artifact@v4"]
    assert graph.nodes[1].rules == ["github.ref == 'refs/heads/main'"]
    assert graph.nodes[1].source.line_start == 9


@pytest.mark.parametrize("path", [".gitlab/jobs.yml", "/.gitlab/jobs.yml", "./.gitlab/jobs.yml"])
def test_local_includes_are_repository_root_relative_and_preserve_dotfiles(path) -> None:
        assert resolve_local_include("ci/nested/parent.yml", path) == ".gitlab/jobs.yml"
        parent = project_include_key("group/shared", "ci/nested/parent.yml", "release/4.2")
        expected = project_include_key("group/shared", ".gitlab/jobs.yml", "release/4.2")
        assert resolve_local_include(parent, path) == expected
        assert parse_project_include_key(expected).file_path == ".gitlab/jobs.yml"


@pytest.mark.parametrize(
        "path", ["../private.yml", "ci/../private.yml", "//outside/file.yml", "ci/*.yml",
                         "$CI_PATH/file.yml", "ci/%2e%2e/file.yml", "ci\\file.yml", "ci//file.yml"]
)
def test_unsafe_or_dynamic_local_includes_are_unresolved(path) -> None:
        keys, notes = gitlab_include_keys({"local": path}, ".gitlab-ci.yml")
        assert keys == []
        assert notes


def test_include_arrays_and_unsupported_types_have_bounded_safe_notes() -> None:
        includes = [
                [{"local": ["a.yml", ".gitlab/b.yml"]}],
                {"project": "group/ci", "file": ["/c.yml", "ci/d.yml"], "ref": "release/4.2",
                 "rules": [{"if": "$SECRET == 'private-value'"}]},
                {"template": "Jobs/Test.gitlab-ci.yml"},
                {"component": "example.test/group/component@main"},
                {"remote": "https://user:private-value@evil.test/ci.yml"},
                {"local": "$UNKNOWN"},
        ]
        refs, notes = collect_gitlab_includes(includes, ".gitlab-ci.yml")
        assert [ref.file_path for ref in refs] == ["a.yml", ".gitlab/b.yml", "c.yml", "ci/d.yml"]
        assert any("potential" in note.lower() for note in notes)
        assert any("template" in note.lower() for note in notes)
        assert any("component" in note.lower() for note in notes)
        assert "private-value" not in str(notes)

        cyclic = []
        cyclic.append(cyclic)
        _, notes = collect_gitlab_includes(cyclic, ".gitlab-ci.yml", max_includes=5)
        assert any("truncated" in note for note in notes)


def test_graph_merges_includes_before_parent_without_shadow_script_sources() -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="abc123", content="""include: [a.yml, b.yml]
stages: [verify, deploy]
build:
    stage: verify
    artifacts:
        reports:
            junit: result.xml
override:
    script: echo parent
""")
        sources = {
                "a.yml": """stages: [old]
build:
    script: echo first
    needs: [prepare]
    artifacts:
        paths: [build.zip]
override:
    script: echo shadow
""",
                "b.yml": "build:\n  script: echo second\n",
        }
        graph = analyze_gitlab_yaml(root, sources.get)
        nodes = {node.key: node for node in graph.nodes}
        assert len(graph.nodes) == 2
        assert graph.stages == ["verify", "deploy"]
        assert nodes["build"].script == ["echo second"]
        assert nodes["build"].source.path == "b.yml"
        assert nodes["build"].stage == "verify"
        assert nodes["build"].needs == ["prepare"]
        assert nodes["build"].artifacts == ["build.zip", "report:junit"]
        assert nodes["override"].script == ["echo parent"]
        assert nodes["override"].source.path == ".gitlab-ci.yml"


def test_repeated_includes_have_later_precedence_without_duplicate_loader_calls() -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="include: [a.yml, b.yml, a.yml]\n")
        calls = []

        def load(path):
                calls.append(path)
                return f"test:\n  script: echo {path}\n"

        graph = analyze_gitlab_yaml(root, load)
        assert graph.nodes[0].script == ["echo a.yml"]
        assert calls == ["a.yml", "b.yml"]
        assert not any("cycle" in note for note in graph.unresolved_includes)


def test_hidden_template_inheritance_and_reference_report_script_provenance() -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="""include: ci/templates.yml
test:
    extends: [.first, .second]
    stage: verify
reference-job:
    script: !reference [.second, script]
""")
        template = """.first:
    script: echo first
    needs: [build]
.second:
    script:
        - pytest
    artifacts:
        paths: [result.xml]
"""
        graph = analyze_gitlab_yaml(root, lambda _: template)
        nodes = {node.key: node for node in graph.nodes}
        assert set(nodes) == {"test", "reference-job"}
        assert nodes["test"].script == ["pytest"]
        assert nodes["test"].stage == "verify"
        assert nodes["test"].needs == ["build"]
        assert nodes["test"].source.path == "ci/templates.yml"
        assert nodes["test"].source.line_start == 4
        assert ".second" in nodes["test"].source.inherited_from
        assert nodes["reference-job"].script == ["pytest"]
        assert nodes["reference-job"].source.path == "ci/templates.yml"
        assert ".second" in nodes["reference-job"].source.inherited_from


def test_root_script_override_is_not_attributed_to_hidden_template() -> None:
        config = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content=""".template:
    script: echo hidden
test:
    extends: .template
    script: echo explicit
""")
        node = analyze_gitlab_yaml(config).nodes[0]
        assert node.script == ["echo explicit"]
        assert node.source.line_start == 3
        assert ".template" in node.source.inherited_from


@pytest.mark.parametrize("content", ["job: [unterminated", "- not-a-mapping", "job: 1\njob: 2"])
def test_invalid_gitlab_yaml_returns_partial_graph_not_an_exception(content) -> None:
        graph = analyze_gitlab_yaml(CiConfigFile(path=".gitlab-ci.yml", ref="sha", content=content))
        assert graph.nodes == []
        assert any("invalid yaml" in note.lower() for note in graph.unresolved_includes)


def test_bad_or_inaccessible_includes_preserve_readable_parent_jobs() -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="""include: [bad.yml, missing.yml]
valid:
    script: pytest
""")

        def load(path):
                if path == "bad.yml":
                        return "job: [unterminated"
                raise PermissionError("private data must not be echoed")

        graph = analyze_gitlab_yaml(root, load)
        assert [node.key for node in graph.nodes] == ["valid"]
        assert len(graph.unresolved_includes) == 2
        assert "private data" not in str(graph.unresolved_includes)


def test_cycles_missing_extends_and_reference_are_partial_not_crashes() -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="""include: .gitlab-ci.yml
.a:
    extends: .b
.b:
    extends: .a
test:
    extends: [.a, .missing]
    script: !reference [.missing, script]
""")
        graph = analyze_gitlab_yaml(root, lambda _: root.content)
        assert len(graph.nodes) == 1
        assert graph.nodes[0].script == []
        assert any("cycle" in note.lower() for note in graph.unresolved_includes)
        assert any("missing" in note.lower() for note in graph.unresolved_includes)


@pytest.mark.parametrize("name", ["test: [linux, 3.13]", "test 1/3", "test 3/3"])
def test_runtime_parallel_and_matrix_names_match_only_unique_base_job(name) -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="test:\n  script: pytest\n")
        source = match_job_to_graph(PipelineJob(external_id="1", name=name, status="failed"), analyze_gitlab_yaml(root))
        assert source is not None
        assert source.job_key == "test"
        assert source.match_confidence == 0.9


@pytest.mark.parametrize("name", ["test 4/3", "test 0/3", "test suffix", "test: []"])
def test_runtime_names_do_not_get_arbitrary_prefix_matches(name) -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="test:\n  script: pytest\n")
        assert match_job_to_graph(PipelineJob(external_id="1", name=name, status="failed"), analyze_gitlab_yaml(root)) is None


def test_normalized_job_name_collisions_are_not_guessed() -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="""test-job:
    script: echo one
test_job:
    script: echo two
""")
        job = PipelineJob(external_id="1", name="TEST JOB", status="failed")
        assert match_job_to_graph(job, analyze_gitlab_yaml(root)) is None


def test_pages_job_is_not_treated_as_a_reserved_global_setting() -> None:
        root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content="pages:\n  script: publish\n")
        assert [node.key for node in analyze_gitlab_yaml(root).nodes] == ["pages"]


def test_mixed_reference_scripts_keep_containing_job_as_primary_source() -> None:
    content = "include: ci/template.yml\ntest:\n  script:\n    - echo local\n    - !reference [.template, script]\n"
    root = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content=content)
    graph = analyze_gitlab_yaml(root, lambda _: ".template:\n  script: pytest\n")
    assert graph.nodes[0].script == ["echo local", "pytest"]
    assert graph.nodes[0].source.path == ".gitlab-ci.yml"
    assert graph.nodes[0].source.line_start == 2
    assert ".template" in graph.nodes[0].source.inherited_from


def test_yaml_alias_graphs_do_not_expand_recursively_without_a_bound() -> None:
    content = ".a: &a [echo leaf]\n"
    for name, previous in [("b", "a"), ("c", "b"), ("d", "c")]:
        content += f".{name}: &{name} [" + ", ".join([f"*{previous}"] * 10) + "]\n"
    content += "test:\n  script: [*d, *d, *d, *d]\n"
    config = CiConfigFile(path=".gitlab-ci.yml", ref="sha", content=content)
    graph = analyze_gitlab_yaml(config)
    assert len(graph.nodes[0].script) <= 1000
    assert any("truncated" in note for note in graph.unresolved_includes)


def test_large_include_file_array_counts_invalid_entries_toward_scan_limit() -> None:
        refs, notes = collect_gitlab_includes(
            {"project": "group/ci", "file": [None] * 1000 + ["should-not-load.yml"]},
            ".gitlab-ci.yml", max_includes=5,
        )
        assert refs == []
        assert any("truncated" in note for note in notes)
