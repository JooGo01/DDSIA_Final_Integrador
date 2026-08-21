"""Endpoints de operacion: estado del servicio y metricas."""

from fastapi import APIRouter, Request, Response

from app.core.metrics import indexed_chunks, registry
from app.schemas import HealthResponse

try:
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
except ImportError:  # pragma: no cover
    CONTENT_TYPE_LATEST = "text/plain"

    def generate_latest(_registry):
        return b""


router = APIRouter(tags=["operacion"])


@router.get("/health", response_model=HealthResponse, summary="Estado del servicio")
async def health(request: Request) -> HealthResponse:
    """Informa si el modelo responde y cuantos chunks hay indexados."""
    store = request.app.state.store
    client = request.app.state.ollama
    settings = request.app.state.settings

    llm_reachable = await client.is_reachable()
    chunks = store.count()
    indexed_chunks.set(chunks)

    # Sin modelo o sin indice el servicio esta arriba pero no puede responder.
    status = "ok" if llm_reachable and chunks > 0 else "degraded"
    return HealthResponse(
        status=status,
        version=settings.app_version,
        llm_reachable=llm_reachable,
        collection_chunks=chunks,
    )


@router.get("/metrics", include_in_schema=False)
async def metrics() -> Response:
    """Expone las metricas en formato Prometheus."""
    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
