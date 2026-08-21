"""Endpoints administrativos. Requieren un scope distinto al de consulta."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import Principal, require_scope
from app.core.errors import AppError
from app.core.logging import get_logger
from app.core.metrics import indexed_chunks
from app.rag.ingest import ingest_corpus
from app.rag.ollama_client import OllamaError
from app.schemas import IngestRequest, IngestResponse

logger = get_logger("admin")

router = APIRouter(prefix="/admin", tags=["admin"])

RequireIngest = Annotated[Principal, Depends(require_scope("admin:ingest"))]


@router.post("/ingest", response_model=IngestResponse, summary="Reindexar el corpus")
async def ingest(request: Request, payload: IngestRequest, user: RequireIngest) -> IngestResponse:
    """Relee los documentos del corpus y regenera el indice vectorial."""
    settings = request.app.state.settings
    store = request.app.state.store
    client = request.app.state.ollama

    logger.info("ingest_requested", user=user.username, reset=payload.reset)
    try:
        documents, chunks, duration_ms = await ingest_corpus(
            settings, store, client, reset=payload.reset
        )
    except OllamaError as exc:
        raise AppError(
            code="llm-unavailable",
            title="Servicio de modelo no disponible",
            detail="No se pudieron generar los embeddings. Verificá que Ollama este arriba.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        ) from exc

    indexed_chunks.set(store.count())
    return IngestResponse(
        documents=documents,
        chunks=chunks,
        collection=settings.collection_name,
        duration_ms=duration_ms,
    )
