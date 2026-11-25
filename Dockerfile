FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml ./
COPY mandate ./mandate
COPY eval ./eval
RUN pip install --no-cache-dir .
ENV MANDATE_DB=/data/mandate.db MANDATE_RESULTS=/app/eval/results.json PORT=8000
RUN mkdir -p /data
EXPOSE 8000
CMD ["sh", "-c", "uvicorn mandate.server:app --host 0.0.0.0 --port ${PORT}"]
