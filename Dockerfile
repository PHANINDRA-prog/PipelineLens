FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY skills ./skills

RUN pip install --no-cache-dir ".[cloud,worker]"

EXPOSE 8000

CMD ["uvicorn", "pipelinelens.api.main:app", "--host", "0.0.0.0", "--port", "8000"]