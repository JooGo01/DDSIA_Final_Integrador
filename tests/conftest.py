"""Fixtures compartidas. Los tests corren sin Ollama y sobre un corpus de prueba."""

import hashlib
import json
import math
import re
import shutil
import time
from pathlib import Path

import bcrypt
import pytest
from fastapi.testclient import TestClient

EMBEDDING_DIM = 64

ANALYST_PASSWORD = "clave-analista-para-test"
ADMIN_PASSWORD = "clave-admin-para-test"

FIXTURE_CORPUS = Path(__file__).parent / "fixtures" / "corpus"


def deterministic_embedding(text: str) -> list[float]:
    """Vectoriza un texto por bolsa de palabras hasheada.

    No es semantico, pero es estable y hace que textos con vocabulario parecido
    queden cerca, que es lo que necesitan los tests de recuperacion.
    """
    vector = [0.0] * EMBEDDING_DIM
    for word in re.findall(r"[a-zA-Z]{3,}", text.lower()):
        digest = hashlib.md5(word.encode(), usedforsecurity=False).digest()
        vector[digest[0] % EMBEDDING_DIM] += 1.0

    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        return [1.0] + [0.0] * (EMBEDDING_DIM - 1)
    return [value / norm for value in vector]


class FakeOllamaClient:
    """Reemplaza a OllamaClient en los tests. Permite forzar respuestas y fallos."""

    def __init__(self, settings=None) -> None:
        self.reachable = True
        self.forced_answer: str | None = None
        self.raise_on_generate: Exception | None = None
        self.generate_calls = 0

    async def close(self) -> None:
        return None

    async def is_reachable(self) -> bool:
        return self.reachable

    async def warm_up(self) -> bool:
        return self.reachable

    async def embed(self, texts: list[str]) -> list[list[float]]:
        return [deterministic_embedding(text) for text in texts]

    async def generate(self, system_prompt: str, user_prompt: str) -> tuple[str, int, int]:
        self.generate_calls += 1
        if self.raise_on_generate is not None:
            raise self.raise_on_generate
        if self.forced_answer is not None:
            return self.forced_answer, 100, 40

        # Por defecto devuelve una respuesta construida con palabras del contexto,
        # para que el control de fundamentacion la acepte.
        context = user_prompt.split("PREGUNTA")[0]
        words = re.findall(r"[a-zA-Záéíóúñ]{6,}", context)[:40]
        return " ".join(words) or "respuesta", 100, 40


@pytest.fixture
def fake_ollama() -> FakeOllamaClient:
    return FakeOllamaClient()


def _build_client(tmp_path, monkeypatch, fake_ollama, auto_ingest: bool):
    """Levanta la app con almacenamiento temporal y el cliente de modelo simulado."""
    chroma_path = tmp_path / "chroma"
    corpus_path = tmp_path / "corpus"
    shutil.copytree(FIXTURE_CORPUS, corpus_path)

    users_file = tmp_path / "users.json"
    users_file.write_text(
        json.dumps(
            {
                "analista": {
                    "password_hash": bcrypt.hashpw(
                        ANALYST_PASSWORD.encode(), bcrypt.gensalt()
                    ).decode(),
                    "scopes": ["ask:read"],
                },
                "admin": {
                    "password_hash": bcrypt.hashpw(
                        ADMIN_PASSWORD.encode(), bcrypt.gensalt()
                    ).decode(),
                    "scopes": ["ask:read", "admin:ingest"],
                },
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setenv("JWT_SECRET", "secreto-de-test-suficientemente-largo-1234567890")
    monkeypatch.setenv("USERS_FILE", str(users_file))
    monkeypatch.setenv("CHROMA_PATH", str(chroma_path))
    monkeypatch.setenv("CORPUS_PATH", str(corpus_path))
    monkeypatch.setenv("LOG_LEVEL", "WARNING")
    monkeypatch.setenv("REQUESTS_PER_MINUTE", "10")
    monkeypatch.setenv("LOGIN_ATTEMPTS_PER_MINUTE", "5")
    monkeypatch.setenv("AUTO_INGEST", "true" if auto_ingest else "false")

    from app.config import get_settings

    get_settings.cache_clear()

    import app.main as main_module

    monkeypatch.setattr(main_module, "OllamaClient", lambda settings: fake_ollama)

    application = main_module.create_app()
    with TestClient(application) as test_client:
        yield test_client

    get_settings.cache_clear()


@pytest.fixture
def client(tmp_path, monkeypatch, fake_ollama):
    """Cliente con la ingesta automatica apagada: cada test indexa cuando quiere."""
    yield from _build_client(tmp_path, monkeypatch, fake_ollama, auto_ingest=False)


@pytest.fixture
def auto_ingest_client(tmp_path, monkeypatch, fake_ollama):
    """Cliente que indexa el corpus al arrancar, como un despliegue nuevo."""
    yield from _build_client(tmp_path, monkeypatch, fake_ollama, auto_ingest=True)


def esperar_indice(client: TestClient, intentos: int = 100) -> dict:
    """Espera a que termine la ingesta que corre en segundo plano al arrancar."""
    for _ in range(intentos):
        salud = client.get("/health").json()
        if salud["collection_chunks"] > 0 and not salud["indexing"]:
            return salud
        time.sleep(0.02)
    raise AssertionError("la ingesta automatica del arranque no termino")


def get_token(client: TestClient, username: str, password: str) -> str:
    """Pide un access token y lo devuelve."""
    response = client.post("/auth/token", data={"username": username, "password": password})
    response.raise_for_status()
    return response.json()["access_token"]


def auth_header(client: TestClient, username: str = "analista", password: str = ANALYST_PASSWORD):
    """Arma el header Authorization para un usuario."""
    return {"Authorization": f"Bearer {get_token(client, username, password)}"}


@pytest.fixture
def indexed_client(client: TestClient) -> TestClient:
    """Cliente con el corpus de prueba ya cargado en el indice."""
    response = client.post(
        "/admin/ingest",
        json={"reset": True},
        headers=auth_header(client, "admin", ADMIN_PASSWORD),
    )
    assert response.status_code == 200, response.text
    assert response.json()["chunks"] > 0
    return client
