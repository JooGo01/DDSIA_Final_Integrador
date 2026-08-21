"""Endpoint de emision de tokens."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import rate_limit_by_ip
from app.core.errors import AppError
from app.core.logging import get_logger
from app.core.metrics import auth_attempts
from app.core.security import authenticate, create_access_token
from app.schemas import TokenResponse

logger = get_logger("auth")

router = APIRouter(tags=["auth"])


@router.post(
    "/auth/token",
    response_model=TokenResponse,
    dependencies=[Depends(rate_limit_by_ip)],
    summary="Obtener un access token",
)
async def issue_token(
    request: Request,
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> TokenResponse:
    """Valida usuario y contrasena y devuelve un JWT firmado con sus scopes."""
    users = request.app.state.users
    settings = request.app.state.settings

    user = authenticate(users, form.username, form.password)
    if user is None:
        auth_attempts.labels(result="failure").inc()
        logger.info("login_failed", username=form.username)
        # El mismo mensaje para usuario inexistente y clave incorrecta.
        raise AppError(
            code="invalid-credentials",
            title="Credenciales invalidas",
            detail="Usuario o contrasena incorrectos.",
            status_code=status.HTTP_401_UNAUTHORIZED,
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_access_token(user, settings)
    auth_attempts.labels(result="success").inc()
    logger.info("login_ok", username=user.username, scopes=sorted(user.scopes))
    return TokenResponse(access_token=token, expires_in=expires_in)
