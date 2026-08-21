"""Metricas Prometheus que expone /metrics."""

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram

registry = CollectorRegistry()

LATENCY_BUCKETS = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60)

http_requests = Counter(
    "http_requests_total",
    "Requests HTTP atendidas",
    ["method", "route", "status"],
    registry=registry,
)

http_duration = Histogram(
    "http_request_duration_seconds",
    "Duracion de la request HTTP completa",
    ["route"],
    buckets=LATENCY_BUCKETS,
    registry=registry,
)

# stage: retrieval | generation
ask_stage_duration = Histogram(
    "ask_stage_duration_seconds",
    "Duracion de cada etapa del endpoint /ask",
    ["stage"],
    buckets=LATENCY_BUCKETS,
    registry=registry,
)

# direction: input | output
llm_tokens = Counter(
    "llm_tokens_total",
    "Tokens consumidos contra el modelo",
    ["direction"],
    registry=registry,
)

chunks_retrieved = Histogram(
    "rag_chunks_retrieved",
    "Chunks que superaron el umbral de relevancia",
    buckets=(0, 1, 2, 3, 4, 5, 8),
    registry=registry,
)

# grounded: true | false
answers = Counter(
    "rag_answers_total",
    "Respuestas emitidas, separadas por si quedaron fundamentadas",
    ["grounded"],
    registry=registry,
)

# stage: input | output -- reason: length | injection | pii | schema | ungrounded
guardrail_blocks = Counter(
    "guardrail_blocks_total",
    "Solicitudes o respuestas frenadas por un guardrail",
    ["stage", "reason"],
    registry=registry,
)

# result: success | failure
auth_attempts = Counter(
    "auth_attempts_total",
    "Intentos de autenticacion",
    ["result"],
    registry=registry,
)

# dimension: requests | login | token_budget
rate_limit_hits = Counter(
    "rate_limit_hits_total",
    "Requests rechazadas por exceder un limite",
    ["dimension"],
    registry=registry,
)

indexed_chunks = Gauge(
    "indexed_chunks",
    "Chunks actualmente cargados en el vector store",
    registry=registry,
)
