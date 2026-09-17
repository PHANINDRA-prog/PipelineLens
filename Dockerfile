FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src \
    HOME=/home/pipelinelens \
    PIPELINELENS_ENV=development \
    PIPELINELENS_DATABASE_URL=sqlite:////app/data/pipelinelens.db \
    PIPELINELENS_LLM_MODE=disabled \
    PIPELINELENS_ALLOW_PRIVATE_CONTEXT=false \
    PIPELINELENS_API_URL=http://127.0.0.1:8000

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY skills ./skills
COPY docker-entrypoint.sh /usr/local/bin/pipelinelens-entrypoint

RUN pip install --no-cache-dir . \
    && sed -i 's/\r$//' /usr/local/bin/pipelinelens-entrypoint \
    && chmod 755 /usr/local/bin/pipelinelens-entrypoint \
    && groupadd --gid 10001 pipelinelens \
    && useradd --uid 10001 --gid 10001 --create-home \
        --home-dir /home/pipelinelens --shell /usr/sbin/nologin pipelinelens \
    && mkdir -p /app/data \
    && chown 10001:10001 /app/data

USER 10001:10001
EXPOSE 8501
STOPSIGNAL SIGTERM

CMD ["/usr/local/bin/pipelinelens-entrypoint"]