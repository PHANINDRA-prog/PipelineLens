# Operations and Safety

## Supported v1 sources

| Provider       | Scope required                                           | Data retrieved                                                                                     |
| -------------- | -------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| GitHub Actions | Read-only Contents, Actions, Metadata, and Pull requests | Repositories, failed workflow runs/jobs, job logs, workflow YAML at the failing commit.            |
| GitLab CI/CD   | `read_api` and `read_repository`                         | Projects, failed pipelines/jobs, job traces, `.gitlab-ci.yml`, and same-repository local includes. |

PipelineLens does not invoke provider write endpoints. It cannot rerun a job, modify a pipeline, create a branch, approve a merge request, merge code, update a secret, or deploy a release.

## Token handling

- A PAT is entered into Streamlit's password input and kept in the active session only.
- It is passed to FastAPI for the immediate request and is not added to database rows, embeddings, logs, screenshots, or diagnostic results.
- Deploy the API behind HTTPS before connecting real cloud-hosted providers.
- Configure trusted CA certificates for self-hosted GitLab installations; do not disable TLS verification.

## Local private corpus

The local corpus importer is opt-in and starts in preview mode. It is intended for an approved private environment only.

```powershell
$env:PYTHONPATH = "$PWD/src"
python -m pipelinelens.local_corpus "C:\path\to\repo" --label "private-ci"
```

It excludes token, secret, credential, password, and `.env` files, plus `.git`, `.sf`, `.sfdx`, virtual environments, build folders, and executable files. A user must set `PIPELINELENS_ALLOW_PRIVATE_CONTEXT=true` and include `--execute` before any sanitized document is saved locally.

For private data, use a local model endpoint such as Ollama unless organizational policy explicitly approves a hosted LLM provider. The public repository must contain only synthetic fixtures.

## Cloud deployment checklist

1. Provision HTTPS endpoints for FastAPI and Streamlit.
2. Use managed PostgreSQL with pgvector and managed Redis.
3. Set environment values through the hosting platform's secret manager, never through checked-in `.env` files.
4. Set `PIPELINELENS_API_URL` on the dashboard to the FastAPI HTTPS address.
5. Keep `PIPELINELENS_ALLOW_PRIVATE_CONTEXT=false` in the public cloud environment.
6. Turn on an LLM mode only after confirming that source/log data is approved for the selected model provider.
7. Verify `/health/live` and `/health/ready` before accepting user traffic.

## Current limits

- GitLab v1 recursively resolves local `include:` files only. Remote/project/template/component includes are surfaced as unresolved context.
- GitHub v1 analyzes the selected workflow file; reusable workflow resolution is a later feature.
- The worker accepts only token-free sanitized demo work. Live provider calls intentionally remain request-scoped so PATs never enter Redis.
- The public demo uses synthetic data and deterministic diagnoses by default. Set an approved OpenAI-compatible or local Ollama configuration to enable the optional LLM synthesis stage.
