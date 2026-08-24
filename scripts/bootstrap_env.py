"""Genera la configuracion local: el archivo .env y, si falta, el archivo de usuarios.

Uso:
    python scripts/bootstrap_env.py             # crea lo que falte, no toca lo que ya existe
    python scripts/bootstrap_env.py --force     # regenera los dos, con contrasenas nuevas

El repositorio ya trae `config/users.json` con credenciales de demostracion, que estan
documentadas en el README. En una instalacion nueva alcanza con generar el `.env`, que
es lo unico que no puede venir versionado porque lleva la clave de firma de los tokens.

Para un entorno donde las credenciales importen, corre con `--force`: reemplaza los
usuarios de demostracion por otros con contrasenas aleatorias. Anotalas, se muestran una
sola vez y no quedan escritas en ningun archivo del repositorio.
"""

import argparse
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


def write_env() -> None:
    """Escribe el .env con una clave de firma nueva."""
    ENV_PATH.write_text(ENV_TEMPLATE.format(jwt_secret=secrets.token_urlsafe(48)), encoding="utf-8")


def write_users() -> dict[str, str]:
    """Escribe el archivo de usuarios. Devuelve las contrasenas en texto plano."""
    credentials = {}
    users = {}
    for username, scopes in DEMO_USERS.items():
        password = random_password()
        credentials[username] = password
        users[username] = {"password_hash": hash_password(password), "scopes": scopes}

    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    USERS_PATH.write_text(json.dumps(users, indent=2) + "\n", encoding="utf-8")
    return credentials


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--force",
        action="store_true",
        help="Regenera .env y config/users.json aunque ya existan.",
    )
    args = parser.parse_args()

    # Cada archivo se decide por separado: con los usuarios de demostracion ya
    # versionados, abortar porque uno de los dos existe dejaria sin .env a quien
    # recien clono el repositorio, que es justo el caso que hay que resolver.
    if args.force or not ENV_PATH.exists():
        write_env()
        print(f"Generado {ENV_PATH} con una clave de firma nueva.")
    else:
        print(f"{ENV_PATH} ya existe: se deja como esta.")

    credentials: dict[str, str] = {}
    if args.force or not USERS_PATH.exists():
        credentials = write_users()
        print(f"Generado {USERS_PATH} con contrasenas aleatorias.")
    else:
        print(f"{USERS_PATH} ya existe: se deja como esta (credenciales del README).")

    if credentials:
        print("\nCredenciales (se muestran una unica vez, guardalas):\n")
        for username, password in credentials.items():
            scopes = " ".join(DEMO_USERS[username])
            print(f"  {username:<10} {password}   scopes: {scopes}")
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
