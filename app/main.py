"""Punto de entrada de la aplicacion FastAPI."""

import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

from app.api import routes_admin, routes_ask, routes_auth, routes_health
from app.config import get_settings
from app.core.errors import register_error_handlers
from app.core.logging import configure_logging, get_logger, set_request_id
from app.core.metrics import http_duration, http_requests, indexed_chunks
from app.core.ratelimit import TokenBucketLimiter, TokenBudget
from app.core.security import load_users
from app.rag.ollama_client import OllamaClient
from app.rag.store import VectorStore

logger = get_logger("main")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

DESCRIPTION = """
Asistente de preguntas y respuestas sobre **OWASP Top 10:2025** y
**OWASP API Security Top 10:2023**, con recuperacion sobre los documentos
originales y generacion mediante un modelo servido localmente.

Para probar: pedí un token en `/auth/token` y usá el boton **Authorize**.
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

    indexed_chunks.set(app.state.store.count())
    logger.info(
        "startup",
        environment=settings.environment,
        model=settings.llm_model,
        indexed_chunks=app.state.store.count(),
        users=len(app.state.users),
    )

    yield

    await app.state.ollama.close()
    logger.info("shutdown")


def create_app() -> FastAPI:
    """Construye la aplicacion con sus middlewares, handlers y rutas."""
    app = FastAPI(
        title="OWASP RAG Assistant",
        description=DESCRIPTION,
        version=get_settings().app_version,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        """Asigna un request_id, mide la request y agrega las cabeceras de seguridad."""
        request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
        set_request_id(request_id)
        started = time.perf_counter()

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
        return response

    register_error_handlers(app)

    app.include_router(routes_health.router)
    app.include_router(routes_auth.router)
    app.include_router(routes_ask.router)
    app.include_router(routes_admin.router)

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse(url="/docs")

    return app


app = create_app()
