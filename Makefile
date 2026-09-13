.PHONY: install test lint run-api run-dashboard compose-up compose-down corpus-preview corpus-ingest

install:
	python -m pip install -e ".[cloud,worker,dev]"

test:
	python -m pytest -q

lint:
	python -m ruff check src tests

run-api:
	python -m uvicorn pipelinelens.api.main:app --reload --host 127.0.0.1 --port 8000

run-dashboard:
	python -m streamlit run src/pipelinelens/dashboard/app.py --server.address 127.0.0.1 --server.port 8501

compose-up:
	docker compose up --build

compose-down:
	docker compose down

corpus-preview:
	python -m pipelinelens.local_corpus "$(REPO)" --label "$(LABEL)"

corpus-ingest:
	python -m pipelinelens.local_corpus "$(REPO)" --label "$(LABEL)" --execute