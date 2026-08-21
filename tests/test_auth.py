"""Tests de autenticacion y autorizacion."""

import pytest
from jose import jwt

from tests.conftest import ADMIN_PASSWORD, ANALYST_PASSWORD, auth_header, get_token


def test_login_devuelve_token(client):
    response = client.post(
        "/auth/token", data={"username": "analista", "password": ANALYST_PASSWORD}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    assert body["access_token"].count(".") == 2


def test_login_con_clave_incorrecta_devuelve_401(client):
    response = client.post("/auth/token", data={"username": "analista", "password": "incorrecta"})
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/problem+json")


def test_login_no_revela_si_el_usuario_existe(client):
    inexistente = client.post("/auth/token", data={"username": "nadie", "password": "x"})
    existente = client.post("/auth/token", data={"username": "analista", "password": "x"})
    assert inexistente.status_code == existente.status_code == 401
    assert inexistente.json()["detail"] == existente.json()["detail"]


def test_ask_sin_token_devuelve_401(client):
    response = client.post("/ask", json={"question": "que es broken access control"})
    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_ask_con_token_invalido_devuelve_401(client):
    response = client.post(
        "/ask",
        json={"question": "que es broken access control"},
        headers={"Authorization": "Bearer no.es.un.jwt"},
    )
    assert response.status_code == 401


def test_token_firmado_con_otro_secreto_es_rechazado(client):
    forjado = jwt.encode(
        {
            "sub": "analista",
            "iss": "owasp-rag-assistant",
            "aud": "owasp-rag-api",
            "iat": 1700000000,
            "exp": 4102444800,
            "scopes": ["ask:read", "admin:ingest"],
        },
        "otro-secreto-totalmente-distinto-1234567890",
        algorithm="HS256",
    )
    response = client.post(
        "/ask",
        json={"question": "que es broken access control"},
        headers={"Authorization": f"Bearer {forjado}"},
    )
    assert response.status_code == 401


def test_analista_no_puede_ingestar(client):
    response = client.post("/admin/ingest", json={"reset": False}, headers=auth_header(client))
    assert response.status_code == 403
    assert response.json()["type"].endswith("/forbidden")


def test_admin_puede_ingestar(client):
    header = auth_header(client, "admin", ADMIN_PASSWORD)
    response = client.post("/admin/ingest", json={"reset": True}, headers=header)
    assert response.status_code == 200
    assert response.json()["documents"] == 4


def test_el_token_incluye_solo_los_scopes_del_usuario(client):
    token = get_token(client, "analista", ANALYST_PASSWORD)
    claims = jwt.get_unverified_claims(token)
    assert claims["scopes"] == ["ask:read"]
    assert claims["iss"] == "owasp-rag-assistant"
    assert claims["aud"] == "owasp-rag-api"


def test_falla_al_arrancar_si_no_existe_el_archivo_de_usuarios(tmp_path, monkeypatch):
    from app.config import get_settings
    from app.core.security import load_users

    monkeypatch.setenv("JWT_SECRET", "secreto-de-test-suficientemente-largo-1234567890")
    monkeypatch.setenv("USERS_FILE", str(tmp_path / "no-existe.json"))
    get_settings.cache_clear()

    with pytest.raises(FileNotFoundError):
        load_users(get_settings().users_file)

    get_settings.cache_clear()
