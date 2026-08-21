# Build en una etapa aparte para que las herramientas de compilacion no lleguen
# a la imagen final.
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml ./
COPY app ./app

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir .


FROM python:3.12-slim-bookworm AS runtime

# Usuario sin privilegios. UID fijo para que los permisos del volumen sean predecibles.
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --no-create-home --shell /usr/sbin/nologin appuser

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CHROMA_PATH=/data/chroma \
    CORPUS_PATH=/data/corpus

COPY --from=builder /opt/venv /opt/venv

WORKDIR /srv
COPY --chown=appuser:appuser app ./app

# /data es el unico punto de escritura; el resto del filesystem puede ir read-only.
RUN mkdir -p /data/chroma /data/corpus && chown -R appuser:appuser /data

USER appuser
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
