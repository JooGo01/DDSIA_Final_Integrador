"""Punto de entrada de la aplicacion FastAPI."""

import asyncio
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api import routes_admin, routes_ask, routes_auth, routes_health
from app.api.deps import client_ip
from app.config import get_settings
from app.core.errors import build_problem_response, register_error_handlers
from app.core.logging import configure_logging, get_logger, set_request_id
from app.core.metrics import http_duration, http_requests, indexed_chunks, rate_limit_hits
from app.core.ratelimit import TokenBucketLimiter, TokenBudget
from app.core.security import load_users
from app.rag.ingest import ingest_corpus
from app.rag.ollama_client import OllamaClient, OllamaError
from app.rag.store import VectorStore

logger = get_logger("main")

# El cliente puede proponer su propio id de correlacion, pero solo se acepta si es
# corto y alfanumerico: ese valor termina en cada linea de log, en la cabecera de
# respuesta y en el cuerpo JSON, asi que no puede ser texto arbitrario del cliente.
SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

# Archivos de la interfaz web. Viven dentro del paquete para que la imagen los traiga
# con el mismo COPY que el codigo y el contenedor pueda seguir siendo de solo lectura.
WEB_DIR = Path(__file__).parent / "web"

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

# Todo lo que carga la interfaz sale del mismo origen: no hay CDN, ni fuentes
# externas, ni scripts en linea. Con eso, una respuesta del modelo que llegue con
# HTML o con un script adentro no tiene forma de ejecutarse.
# form-action queda en none porque el login usa fetch y nunca un submit nativo: si
# el JavaScript fallara, el navegador no puede mandar la contrasena por la URL.
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "base-uri 'none'; "
    "object-src 'none'; "
    "frame-ancestors 'none'; "
    "form-action 'none'"
)

# Swagger sirve su propio JS y CSS desde un CDN: con la politica de arriba no cargaria.
#
# La comparacion es por ruta exacta y no por prefijo. Con prefijo, cualquier ruta que
# empezara con "/docs" —incluida una futura "/docs-internos"— perdia la politica en
# silencio, y esa es la clase de agujero que no se nota hasta que ya esta.
CSP_EXEMPT_PATHS = frozenset({"/docs", "/docs/oauth2-redirect", "/openapi.json"})

DESCRIPTION = """
Asistente de preguntas y respuestas sobre **OWASP Top 10:2025** y
**OWASP API Security Top 10:2023**, con recuperacion sobre los documentos
originales y generacion mediante un modelo servido localmente.

Hay una interfaz web en `/`. Para probar desde aca: pedí un token en
`/auth/token` y usá el boton **Authorize**.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Prepara los recursos compartidos al arrancar y los libera al cerrar."""
    settings = get_settings()
    configure_logging(settings.log_level)

    app.state.settings = settings
    app.state.users = load_users(settings.users_file)
    app.state.store = VectorStore(settings)
    app.state.ollama = OllamaClient(settings)
    app.state.request_limiter = TokenBucketLimiter(
        capacity=settings.requests_per_minute,
        refill_per_minute=settings.requests_per_minute,
    )
    app.state.login_limiter = TokenBucketLimiter(
        capacity=settings.login_attempts_per_minute,
        refill_per_minute=settings.login_attempts_per_minute,
    )
    app.state.token_budget = TokenBudget(limit=settings.daily_token_budget)
    # Serializa las ingestas: la del arranque y las que pida un administrador.
    app.state.ingest_lock = asyncio.Lock()
    app.state.indexing = False
    # Momento en que termino la ultima ingesta. El lock impide que dos corran a la
    # vez, pero no que se pidan una atras de otra: encadenarlas satura el modelo y
    # /ask empieza a devolver 503. Arranca en 0 para no demorar la primera.
    app.state.last_ingest_finished = 0.0

    # El modelo se carga en RAM y el indice se construye en segundo plano. Sin esto
    # la primera consulta real paga la carga completa y puede pasarse del timeout.
    startup_task = asyncio.create_task(_startup_tasks(app))

    indexed_chunks.set(app.state.store.count())
    logger.info(
        "startup",
        environment=settings.environment,
        model=settings.llm_model,
        indexed_chunks=app.state.store.count(),
        users=len(app.state.users),
    )

    yield

    startup_task.cancel()
    await app.state.ollama.close()
    logger.info("shutdown")


async def _startup_tasks(app: FastAPI) -> None:
    """Carga los modelos y deja el indice listo, sin bloquear el arranque del servidor.

    Corre como tarea de fondo, y la excepcion de una tarea que nadie espera no aparece
    en ningun lado: se registra explicitamente para que un arranque a medias se vea.
    """
    try:
        await _warm_up_model(app)
        await _auto_ingest(app)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        logger.error("startup_task_failed", error=type(exc).__name__, detail=str(exc))


async def _warm_up_model(app: FastAPI) -> None:
    """Carga los modelos en memoria sin bloquear el arranque del servidor."""
    started = time.perf_counter()
    ok = await app.state.ollama.warm_up()
    logger.info("warmup_finished", ok=ok, seconds=round(time.perf_counter() - started, 1))


async def _auto_ingest(app: FastAPI) -> None:
    """Construye el indice si esta vacio.

    Es lo que permite que una instalacion nueva responda sin que nadie entre como
    administrador a reindexar. Si el indice ya esta persistido en el volumen no hace
    nada, asi que los arranques siguientes son inmediatos.
    """
    settings = app.state.settings
    store = app.state.store
    if not settings.auto_ingest or store.count() > 0:
        return

    async with app.state.ingest_lock:
        # Un administrador pudo disparar la ingesta mientras se cargaba el modelo.
        if store.count() > 0:
            return

        app.state.indexing = True
        started = time.perf_counter()
        logger.info("auto_ingest_started", corpus=settings.corpus_path)
        try:
            resultado = await ingest_corpus(settings, store, app.state.ollama, reset=False)
        except (OllamaError, OSError) as exc:
            # Que la ingesta automatica falle no puede tumbar el servicio: queda
            # degradado, /health lo informa y el endpoint de administracion sigue
            # disponible para reintentarla. El motivo va al log.
            logger.warning("auto_ingest_failed", error=type(exc).__name__, detail=str(exc))
            return
        finally:
            app.state.indexing = False
            # La del arranque cuenta igual que una manual: el modelo ya quedo
            # ocupado vectorizando y pedir otra enseguida lo satura.
            app.state.last_ingest_finished = time.monotonic()

        indexed_chunks.set(store.count())
        logger.info(
            "auto_ingest_finished",
            documents=resultado.documents,
            chunks=resultado.chunks,
            rejected=resultado.rejected,
            removed=resultado.removed,
            seconds=round(time.perf_counter() - started, 1),
        )


def create_app() -> FastAPI:
    """Construye la aplicacion con sus middlewares, handlers y rutas."""
    # Swagger solo en desarrollo. Fuera de ahi no aporta y suma superficie: es la
    # unica ruta exenta de la politica de contenido, y carga su JS de un CDN sin
    # verificar integridad. Un CDN comprometido correria con permisos del mismo
    # origen que la interfaz, donde el usuario escribe su contrasena.
    es_dev = get_settings().environment == "dev"

    app = FastAPI(
        title="OWASP RAG Assistant",
        description=DESCRIPTION,
        version=get_settings().app_version,
        lifespan=lifespan,
        docs_url="/docs" if es_dev else None,
        redoc_url=None,
        openapi_url="/openapi.json" if es_dev else None,
    )

    # Se crea aca y no en el lifespan a proposito. El middleware corre en toda
    # peticion, incluso cuando alguien construye la app sin ejecutar el lifespan, y
    # ahi un limitador ausente seria un 500 en cada ruta. No abre nada ni hace E/S:
    # es un contador en memoria, asi que no necesita el ciclo de vida. Los otros
    # limites viven en dependencias de ruta y por eso pueden quedar en el lifespan.
    app.state.ip_limiter = TokenBucketLimiter(
        capacity=get_settings().ip_requests_per_minute,
        refill_per_minute=get_settings().ip_requests_per_minute,
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        """Asigna un request_id, mide la request y agrega las cabeceras de seguridad."""
        proposed = request.headers.get("X-Request-ID", "")
        request_id = proposed if SAFE_REQUEST_ID.match(proposed) else uuid.uuid4().hex[:16]
        set_request_id(request_id)
        started = time.perf_counter()

        # El limite por IP se evalua aca, antes de resolver la ruta y por lo tanto
        # antes de autenticar. Los otros limites son dependencias de ruta que reciben
        # el usuario ya validado, asi que solo cuentan trafico con token: una peticion
        # sin credencial devolvia 401 sin consumir cupo y sin techo de ningun tipo.
        allowed, retry_after = app.state.ip_limiter.check(client_ip(request))
        if not allowed:
            rate_limit_hits.labels(dimension="ip").inc()
            logger.info("ip_rate_limited", route=request.url.path)
            response = build_problem_response(
                status.HTTP_429_TOO_MANY_REQUESTS,
                "rate-limited",
                "Demasiadas solicitudes",
                f"Superaste el limite de peticiones. Reintentá en {retry_after} segundos.",
                request.url.path,
                {"Retry-After": str(retry_after)},
            )
        else:
            response = await call_next(request)

        elapsed = time.perf_counter() - started
        # Se usa el patron de la ruta y no la URL concreta, para no inflar las etiquetas.
        route = request.scope.get("route")
        route_label = getattr(route, "path", "unmatched")
        http_requests.labels(
            method=request.method, route=route_label, status=str(response.status_code)
        ).inc()
        http_duration.labels(route=route_label).observe(elapsed)

        response.headers["X-Request-ID"] = request_id
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if request.url.path not in CSP_EXEMPT_PATHS:
            response.headers.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
        return response

    register_error_handlers(app)

    app.include_router(routes_health.router)
    app.include_router(routes_auth.router)
    app.include_router(routes_ask.router)
    app.include_router(routes_admin.router)

    app.mount("/assets", StaticFiles(directory=WEB_DIR / "assets"), name="assets")

    @app.get("/", include_in_schema=False)
    async def interfaz_web() -> FileResponse:
        """Sirve la interfaz web."""
        return FileResponse(WEB_DIR / "index.html", media_type="text/html")

    return app


app = create_app()
