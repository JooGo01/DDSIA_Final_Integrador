"""Tests de los limites de uso: requests por minuto y presupuesto de tokens."""

from app.core.ratelimit import TokenBucketLimiter, TokenBudget
from tests.conftest import ANALYST_PASSWORD, auth_header


def test_el_bucket_permite_hasta_la_capacidad_y_despues_frena():
    limiter = TokenBucketLimiter(capacity=3, refill_per_minute=3)
    assert [limiter.check("usuario")[0] for _ in range(3)] == [True, True, True]

    allowed, retry_after = limiter.check("usuario")
    assert allowed is False
    assert retry_after > 0


def test_cada_clave_tiene_su_propio_bucket():
    limiter = TokenBucketLimiter(capacity=1, refill_per_minute=1)
    assert limiter.check("ana")[0] is True
    assert limiter.check("ana")[0] is False
    assert limiter.check("bruno")[0] is True


def test_el_presupuesto_de_tokens_se_descuenta():
    budget = TokenBudget(limit=1000)
    assert budget.remaining("ana") == 1000

    budget.consume("ana", 400)
    assert budget.remaining("ana") == 600
    assert budget.has_budget("ana") is True

    budget.consume("ana", 700)
    assert budget.remaining("ana") == 0
    assert budget.has_budget("ana") is False
    # El consumo de un usuario no afecta a otro.
    assert budget.has_budget("bruno") is True


def test_superar_las_requests_por_minuto_devuelve_429(indexed_client):
    header = auth_header(indexed_client)
    payload = {"question": "como se previene el control de acceso roto"}

    codigos = []
    for _ in range(14):
        codigos.append(indexed_client.post("/ask", json=payload, headers=header).status_code)

    assert 200 in codigos
    assert 429 in codigos

    ultima = indexed_client.post("/ask", json=payload, headers=header)
    assert ultima.status_code == 429
    assert int(ultima.headers["Retry-After"]) > 0
    assert ultima.json()["type"].endswith("/rate-limited")


def test_superar_los_intentos_de_login_devuelve_429(client):
    codigos = []
    for _ in range(9):
        respuesta = client.post(
            "/auth/token", data={"username": "analista", "password": "incorrecta"}
        )
        codigos.append(respuesta.status_code)

    assert 401 in codigos
    assert 429 in codigos


def test_sin_presupuesto_de_tokens_se_rechaza_la_consulta(indexed_client):
    budget = indexed_client.app.state.token_budget
    budget.consume("analista", budget.limit)

    response = indexed_client.post(
        "/ask",
        json={"question": "como se previene el control de acceso roto"},
        headers=auth_header(indexed_client, "analista", ANALYST_PASSWORD),
    )
    assert response.status_code == 429
    assert response.json()["type"].endswith("/token-budget-exhausted")
