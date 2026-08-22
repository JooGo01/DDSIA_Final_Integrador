"""Dependencias compartidas por las rutas: autenticacion, permisos y limites de uso."""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request, status
from fastapi.security import OAuth2PasswordBearer

from app.config import Settings
from app.core.errors import AppError
from app.core.logging import get_logger
from app.core.metrics import rate_limit_hits
from app.core.ratelimit import TokenBucketLimiter
from app.core.security import PyJWTError, decode_access_token

logger = get_logger("auth")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)


@dataclass(frozen=True)
class Principal:
    """Identidad ya validada de quien esta haciendo la peticion."""

    username: str
    scopes: frozenset[str]


def get_settings_from_state(request: Request) -> Settings:
    """Configuracion cargada al arrancar la app."""
    return request.app.state.settings


def client_ip(request: Request) -> str:
    """IP del cliente. Sin proxy de confianza adelante, se usa la de la conexion."""
    return request.client.host if request.client else "unknown"


async def get_current_user(
    request: Request,
    token: Annotated[str | None, Depends(oauth2_scheme)],
) -> Principal:
    """Valida el bearer token y devuelve la identidad. Lanza 401 si no es valido."""
    unauthorized = AppError(
        code="unauthorized",
        title="No autenticado",
        detail="Se requiere un bearer token valido.",
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not token:
        raise unauthorized

    settings: Settings = request.app.state.settings
    try:
        claims = decode_access_token(token, settings)
    except PyJWTError as exc:
        # El motivo va al log; al cliente solo le llega 401.
        logger.info("token_rejected", reason=type(exc).__name__)
        raise unauthorized from exc

    username = claims.get("sub")
    if not username:
        raise unauthorized

    return Principal(username=username, scopes=frozenset(claims.get("scopes", [])))


CurrentUser = Annotated[Principal, Depends(get_current_user)]


def require_scope(scope: str):
    """Devuelve una dependencia que exige un scope concreto sobre el token."""

    async def check(user: CurrentUser) -> Principal:
        if scope not in user.scopes:
            logger.info("scope_denied", user=user.username, required=scope)
            raise AppError(
                code="forbidden",
                title="Permiso insuficiente",
                detail=f"Esta operacion requiere el scope '{scope}'.",
                status_code=status.HTTP_403_FORBIDDEN,
            )
        return user

    return check


def enforce_limit(limiter: TokenBucketLimiter, key: str, dimension: str) -> None:
    """Consume un permiso del limitador y lanza 429 si no queda."""
    allowed, retry_after = limiter.check(key)
    if not allowed:
        rate_limit_hits.labels(dimension=dimension).inc()
        raise AppError(
            code="rate-limited",
            title="Demasiadas solicitudes",
            detail=f"Superaste el limite de uso. Reintentá en {retry_after} segundos.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": str(retry_after)},
        )


async def rate_limit_by_user(request: Request, user: CurrentUser) -> Principal:
    """Limita las requests por usuario autenticado."""
    enforce_limit(request.app.state.request_limiter, user.username, "requests")
    return user


async def rate_limit_by_ip(request: Request) -> None:
    """Limita los intentos de login por IP de origen."""
    enforce_limit(request.app.state.login_limiter, client_ip(request), "login")
