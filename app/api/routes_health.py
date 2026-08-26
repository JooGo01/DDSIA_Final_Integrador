"""Endpoints de operacion: estado del servicio y metricas."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import Principal, require_scope
from app.core.metrics import indexed_chunks, registry
from app.schemas import HealthResponse

try:
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
except ImportError:  # pragma: no cover
    CONTENT_TYPE_LATEST = "text/plain"

    def generate_latest(_registry):
        return b""


router = APIRouter(tags=["operacion"])

RequireMetrics = Annotated[Principal, Depends(require_scope("metrics:read"))]


@router.get("/health", response_model=HealthResponse, summary="Estado del servicio")
async def health(request: Request) -> HealthResponse:
    """Informa si el modelo responde y cuantos chunks hay indexados.

    Queda sin autenticar a proposito: lo consulta el healthcheck del contenedor, que
    no tiene credenciales, y la interfaz lo usa para mostrar el estado antes de que
    alguien entre. Lo que expone es version, alcanzabilidad del modelo y cantidad de
    fragmentos: sirve para fingerprinting, no para llegar a un dato del corpus.
    """
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
        indexing=request.app.state.indexing,
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(user: RequireMetrics) -> Response:
    """Expone las metricas en formato Prometheus. Requiere el scope metrics:read.

    Estaba abierto, y no alcanza con que no figure en el esquema: publicaba
    auth_attempts_total, rate_limit_hits_total y el consumo de tokens del modelo. Eso
    le confirma a quien prueba credenciales si sus intentos quedan registrados y
    cuando lo limitaron, que es justo la informacion que no conviene devolverle.
    Un recolector se autentica como cualquier otro cliente.
    """
    return Response(content=generate_latest(registry), media_type=CONTENT_TYPE_LATEST)
