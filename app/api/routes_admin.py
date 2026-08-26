"""Endpoints administrativos. Requieren un scope distinto al de consulta."""

import time
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import Principal, rate_limit_by_user, require_scope
from app.core.errors import AppError
from app.core.logging import get_logger
from app.core.metrics import indexed_chunks, rate_limit_hits
from app.rag.ingest import ingest_corpus
from app.rag.ollama_client import OllamaError
from app.schemas import IngestRequest, IngestResponse

logger = get_logger("admin")

router = APIRouter(prefix="/admin", tags=["admin"])

RequireIngest = Annotated[Principal, Depends(require_scope("admin:ingest"))]


@router.post(
    "/ingest",
    response_model=IngestResponse,
    dependencies=[Depends(rate_limit_by_user)],
    summary="Reindexar el corpus",
)
async def ingest(request: Request, payload: IngestRequest, user: RequireIngest) -> IngestResponse:
    """Relee los documentos del corpus y regenera el indice vectorial."""
    settings = request.app.state.settings
    store = request.app.state.store
    client = request.app.state.ollama

    # Espera entre ingestas completas. El lock de abajo cubre el solapamiento; esto
    # cubre el encadenado, que es el caso que degrada el servicio: cada corrida
    # re-vectoriza el corpus entero y deja al modelo sin capacidad para responder.
    espera = settings.min_seconds_between_ingests
    transcurrido = time.monotonic() - request.app.state.last_ingest_finished
    if transcurrido < espera:
        restante = int(espera - transcurrido) + 1
        rate_limit_hits.labels(dimension="ingest").inc()
        raise AppError(
            code="ingest-too-soon",
            title="Indexacion demasiado seguida",
            detail=f"La ultima indexacion termino recien. Reintentá en {restante} segundos.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(restante)},
        )

    # La ingesta del arranque y la que pide un administrador comparten el mismo
    # indice: dos corridas simultaneas se pisarian los chunks. Se rechaza la segunda
    # en vez de encolarla, porque esperar varios minutos con la conexion abierta
    # termina en un timeout del cliente igual.
    if request.app.state.ingest_lock.locked():
        raise AppError(
            code="ingest-in-progress",
            title="Indexacion en curso",
            detail="Ya hay una indexacion en ejecucion. Esperá a que termine y reintentá.",
            status_code=status.HTTP_409_CONFLICT,
            headers={"Retry-After": "60"},
        )

    logger.info("ingest_requested", user=user.username, reset=payload.reset)
    async with request.app.state.ingest_lock:
        request.app.state.indexing = True
        try:
            resultado = await ingest_corpus(settings, store, client, reset=payload.reset)
        except OllamaError as exc:
            raise AppError(
                code="llm-unavailable",
                title="Servicio de modelo no disponible",
                detail="No se pudieron generar los embeddings. Verificá que Ollama este arriba.",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            ) from exc
        finally:
            request.app.state.indexing = False
            # Tambien si fallo: el corpus se vectorizo igual y el costo ya se pago.
            request.app.state.last_ingest_finished = time.monotonic()

    indexed_chunks.set(store.count())
    return IngestResponse(
        documents=resultado.documents,
        chunks=resultado.chunks,
        collection=settings.collection_name,
        duration_ms=resultado.duration_ms,
        rejected=resultado.rejected,
        removed=resultado.removed,
    )
