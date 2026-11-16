FROM python:3.12-slim AS base

WORKDIR /app

COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir .

FROM base AS production
COPY data/attack_techniques.json data/attack_techniques.json

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]

CMD ["uvicorn", "src.api.app:app", "--host", "0.0.0.0", "--port", "8000"]

FROM base AS test
COPY tests/ tests/
COPY data/ data/
RUN pip install --no-cache-dir ".[dev]"
CMD ["python", "-m", "pytest", "tests/", "-v"]
