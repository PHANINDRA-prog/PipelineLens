PYTHON ?= python
PER_PROJECT ?= 75
PER_REPO ?= 2

.PHONY: install test lint run-api run-dashboard compose-up compose-down \
	corpus-preview corpus-ingest pipeline-corpus-preview pipeline-corpus-ingest \
	pipeline-corpus-summary pipeline-corpus-reevaluate public-corpus-preview \
	public-corpus-ingest public-corpus-summary public-corpus-reevaluate \
	dataset-corpus-preview dataset-corpus-ingest dataset-corpus-summary \
	dataset-corpus-reevaluate

install:
	$(PYTHON) -m pip install -e ".[dev]"

test:
	$(PYTHON) -m pytest --override-ini addopts= -q --tb=short -p no:cacheprovider

lint:
	$(PYTHON) -m ruff check src tests

run-api:
	$(PYTHON) -m uvicorn pipelinelens.api.main:app --reload --host 127.0.0.1 --port 8000

run-dashboard:
	$(PYTHON) -m streamlit run src/pipelinelens/dashboard/app.py --server.address 127.0.0.1 --server.port 8501 --browser.gatherUsageStats false

compose-up:
	docker compose up --build

compose-down:
	docker compose down

corpus-preview:
	$(PYTHON) -m pipelinelens.local_corpus "$(REPO)" --label "$(LABEL)"

corpus-ingest:
	$(PYTHON) -m pipelinelens.local_corpus "$(REPO)" --label "$(LABEL)" --execute

pipeline-corpus-preview:
	$(PYTHON) -m pipelinelens.harvest --project "$(PROJECT)" --per-project $(PER_PROJECT)

pipeline-corpus-ingest:
	$(PYTHON) -m pipelinelens.harvest --project "$(PROJECT)" --per-project $(PER_PROJECT) --execute

pipeline-corpus-summary:
	$(PYTHON) -m pipelinelens.harvest --summary

pipeline-corpus-reevaluate:
	$(PYTHON) -m pipelinelens.harvest --reevaluate --execute

public-corpus-preview:
	$(PYTHON) -m pipelinelens.public_harvest --github-repo "$(REPO)" --per-repo $(PER_REPO)

public-corpus-ingest:
	$(PYTHON) -m pipelinelens.public_harvest --github-repo "$(REPO)" --per-repo $(PER_REPO) --execute

public-corpus-summary:
	$(PYTHON) -m pipelinelens.public_harvest --summary

public-corpus-reevaluate:
	$(PYTHON) -m pipelinelens.public_harvest --reevaluate --execute

dataset-corpus-preview:
	$(PYTHON) -m pipelinelens.dataset_harvest --csv "$(CSV)" --source-label "$(LABEL)"

dataset-corpus-ingest:
	$(PYTHON) -m pipelinelens.dataset_harvest --csv "$(CSV)" --source-label "$(LABEL)" --execute

dataset-corpus-summary:
	$(PYTHON) -m pipelinelens.dataset_harvest --summary

dataset-corpus-reevaluate:
	$(PYTHON) -m pipelinelens.dataset_harvest --reevaluate --execute