"""Hash de contrasenas, emision y validacion de JWT, y carga de usuarios."""

import json
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import bcrypt
import jwt
from jwt import PyJWTError

from app.config import Settings

# Hash contra el que se compara cuando el usuario no existe, para que el login
# tarde lo mismo exista o no y no se pueda enumerar usuarios midiendo tiempos.
# Se genera al importar sobre bytes aleatorios: nadie conoce su contrasena.
DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt()).decode()


@dataclass(frozen=True)
class User:
    username: str
    password_hash: str
    scopes: frozenset[str]


def hash_password(plain_password: str) -> str:
    """Devuelve el hash bcrypt de una contrasena en texto plano."""
    return bcrypt.hashpw(plain_password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Compara una contrasena contra su hash."""
    try:
        return bcrypt.checkpw(plain_password.encode(), password_hash.encode())
    except ValueError:
        return False


def load_users(path: str | Path) -> dict[str, User]:
    """Lee el archivo de usuarios.

    Formato esperado:
        {"analista": {"password_hash": "$2b$...", "scopes": ["ask:read"]}}
    """
    users_path = Path(path)
    if not users_path.is_file():
        raise FileNotFoundError(
            f"No existe el archivo de usuarios en {users_path}. "
            "Generalo con: python scripts/bootstrap_env.py"
        )

    raw = json.loads(users_path.read_text(encoding="utf-8"))
    users: dict[str, User] = {}
    for username, entry in raw.items():
        password_hash = entry.get("password_hash")
        if not password_hash:
            raise ValueError(f"El usuario {username!r} no tiene password_hash")
        users[username] = User(
            username=username,
            password_hash=password_hash,
            scopes=frozenset(entry.get("scopes", [])),
        )
    return users


def authenticate(users: dict[str, User], username: str, password: str) -> User | None:
    """Valida credenciales. Devuelve None si el usuario no existe o la clave no coincide."""
    user = users.get(username)
    if user is None:
        verify_password(password, DUMMY_HASH)
        return None
    if not verify_password(password, user.password_hash):
        return None
    return user


def create_access_token(user: User, settings: Settings) -> tuple[str, int]:
    """Emite un JWT firmado para el usuario. Devuelve (token, segundos de vida)."""
    expires_in = settings.jwt_expire_minutes * 60
    now = datetime.now(UTC)
    claims = {
        "sub": user.username,
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
        "scopes": sorted(user.scopes),
    }
    token = jwt.encode(claims, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, expires_in


def decode_access_token(token: str, settings: Settings) -> dict:
    """Valida firma, algoritmo, emisor, audiencia y vencimiento.

    Lanza PyJWTError si cualquiera de esas comprobaciones falla.
    """
    return jwt.decode(
        token,
        settings.jwt_secret,
        # Lista explicita: evita que un token con alg 'none' u otro algoritmo sea aceptado.
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        options={
            "require": ["exp", "iat", "iss", "aud", "sub"],
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": True,
            "verify_signature": True,
        },
    )


__all__ = [
    "PyJWTError",
    "User",
    "authenticate",
    "create_access_token",
    "decode_access_token",
    "hash_password",
    "load_users",
    "verify_password",
]
