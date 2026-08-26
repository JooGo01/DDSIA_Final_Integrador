"""Modelos de request y response de la API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.config import QUESTION_HARD_LIMIT


class TokenResponse(BaseModel):
    access_token: str
    # "bearer" es el tipo de token que define OAuth2, no una credencial.
    token_type: Literal["bearer"] = "bearer"  # noqa: S105
    expires_in: int


class AskRequest(BaseModel):
    # extra="forbid" rechaza campos que no esten declarados aca.
    model_config = ConfigDict(extra="forbid")

    # El largo real lo decide input_guard con MIN_QUESTION_CHARS y MAX_QUESTION_CHARS.
    # Antes esta linea repetia esos numeros, y como Pydantic valida antes que el guard,
    # mover las variables de entorno no tenia ningun efecto: la configuracion estaba
    # muerta. Lo que queda es el techo duro del payload, no la politica.
    question: str = Field(
        min_length=1,
        max_length=QUESTION_HARD_LIMIT,
        examples=["Que controles previenen Broken Object Level Authorization?"],
    )
    source: Literal["all", "web", "api"] = "all"


class Citation(BaseModel):
    document: str
    section: str
    relevance: float


class Usage(BaseModel):
    input_tokens: int
    output_tokens: int
    retrieved_chunks: int
    latency_ms: int


class AskResponse(BaseModel):
    answer: str
    citations: list[Citation]
    grounded: bool
    request_id: str
    usage: Usage


class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reset: bool = False


class IngestResponse(BaseModel):
    documents: int
    chunks: int
    collection: str
    duration_ms: int
    # Archivos que quedaron fuera por contener instrucciones en lugar de contenido.
    rejected: list[str] = []
    # Chunks borrados por no corresponder a ningun documento vigente del corpus.
    removed: int = 0


class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"]
    version: str
    llm_reachable: bool
    collection_chunks: int
    # True mientras se esta construyendo el indice. Distingue "todavia no esta listo"
    # de "quedo vacio", que desde afuera se ven igual: los dos dan status degraded.
    indexing: bool = False
