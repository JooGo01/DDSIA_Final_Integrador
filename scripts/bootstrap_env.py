"""Genera la configuracion local: el archivo .env y el archivo de usuarios.

Uso:
    python scripts/bootstrap_env.py

No sobrescribe archivos existentes. Las contrasenas se muestran una sola vez por
consola y no quedan escritas en ningun archivo del repositorio.
"""

import json
import secrets
import string
from pathlib import Path

import bcrypt

ENV_PATH = Path(".env")
USERS_PATH = Path("config/users.json")
PASSWORD_LENGTH = 20

# usuario -> scopes
DEMO_USERS = {
    "analista": ["ask:read"],
    "admin": ["ask:read", "admin:ingest"],
}

ENV_TEMPLATE = """# Generado por scripts/bootstrap_env.py. No versionar este archivo.
ENVIRONMENT=dev
LOG_LEVEL=INFO

JWT_SECRET={jwt_secret}
JWT_EXPIRE_MINUTES=30

REQUESTS_PER_MINUTE=10
LOGIN_ATTEMPTS_PER_MINUTE=5
DAILY_TOKEN_BUDGET=50000

LLM_MODEL=llama3.2:3b
EMBEDDING_MODEL=nomic-embed-text
"""


def random_password() -> str:
    """Genera una contrasena aleatoria legible."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(PASSWORD_LENGTH))


def hash_password(plain: str) -> str:
    """Devuelve el hash bcrypt de la contrasena."""
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def main() -> int:
    existing = [path for path in (ENV_PATH, USERS_PATH) if path.exists()]
    if existing:
        nombres = ", ".join(str(path) for path in existing)
        print(f"Ya existen: {nombres}. Borralos si querés regenerar las credenciales.")
        return 1

    credentials = {}
    users = {}
    for username, scopes in DEMO_USERS.items():
        password = random_password()
        credentials[username] = password
        users[username] = {"password_hash": hash_password(password), "scopes": scopes}

    ENV_PATH.write_text(ENV_TEMPLATE.format(jwt_secret=secrets.token_urlsafe(48)), encoding="utf-8")
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    USERS_PATH.write_text(json.dumps(users, indent=2) + "\n", encoding="utf-8")

    print(f"Generados {ENV_PATH} y {USERS_PATH}.\n")
    print("Credenciales (se muestran una unica vez, guardalas):\n")
    for username, password in credentials.items():
        print(f"  {username:<10} {password}   scopes: {' '.join(DEMO_USERS[username])}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
