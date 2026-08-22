"""Manejo de errores. Todas las respuestas de error usan application/problem+json."""

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.logging import get_logger, get_request_id

logger = get_logger("errors")

ERROR_TYPE_BASE = "https://owasp-rag-assistant.local/errors"


class AppError(Exception):
    """Error de negocio con un codigo estable y su status HTTP."""

    def __init__(
        self,
        code: str,
        title: str,
        detail: str,
        status_code: int = status.HTTP_400_BAD_REQUEST,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.code = code
        self.title = title
        self.detail = detail
        self.status_code = status_code
        self.headers = headers or {}


def build_problem_response(
    status_code: int,
    code: str,
    title: str,
    detail: str,
    instance: str,
    headers: dict[str, str] | None = None,
) -> JSONResponse:
    """Arma el cuerpo problem+json con el trace_id de la peticion."""
    return JSONResponse(
        status_code=status_code,
        media_type="application/problem+json",
        headers=headers or {},
        content={
            "type": f"{ERROR_TYPE_BASE}/{code}",
            "title": title,
            "status": status_code,
            "detail": detail,
            "instance": instance,
            "trace_id": get_request_id(),
        },
    )


def register_error_handlers(app: FastAPI) -> None:
    """Registra los handlers para que ningun error salga en formato crudo."""

    @app.exception_handler(AppError)
    async def handle_app_error(request: Request, exc: AppError) -> JSONResponse:
        logger.warning("app_error", code=exc.code, status=exc.status_code, route=request.url.path)
        return build_problem_response(
            exc.status_code, exc.code, exc.title, exc.detail, request.url.path, exc.headers
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Se informa que campo fallo, nunca el valor que llego.
        fields = sorted({".".join(str(p) for p in e["loc"][1:]) or "body" for e in exc.errors()})
        logger.info("validation_error", route=request.url.path, fields=fields)
        return build_problem_response(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            "validation-error",
            "La solicitud no cumple el contrato",
            f"Campos invalidos o no permitidos: {', '.join(fields)}",
            request.url.path,
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        is_client_error = exc.status_code < 500
        detail = (
            str(exc.detail) if is_client_error else "El servicio no pudo procesar la solicitud."
        )
        return build_problem_response(
            exc.status_code,
            "http-error",
            detail if is_client_error else "Error interno",
            detail,
            request.url.path,
            dict(exc.headers or {}),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        # El stack trace va al log; al cliente solo le llega el trace_id.
        logger.error("unhandled_exception", route=request.url.path, exc_info=exc)
        return build_problem_response(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "internal-error",
            "Error interno",
            "El servicio no pudo procesar la solicitud. Reintenta o reporta el trace_id.",
            request.url.path,
        )
