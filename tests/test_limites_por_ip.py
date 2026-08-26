"""Tests del limite por IP y del acceso a las metricas.

Los dos salieron de la misma revision. Los limites por usuario son dependencias de
ruta: reciben el usuario ya autenticado, asi que solo cuentan trafico que presento un
token valido. Una peticion sin credencial devolvia 401 sin consumir cupo y sin techo,
de modo que inundar /ask no autenticado no tenia ningun costo. Y /metrics estaba
abierto, publicando los contadores de intentos de login y de limites alcanzados.
"""

import pytest

from app.core.ratelimit import TokenBucketLimiter
from tests.conftest import ADMIN_PASSWORD, ANALYST_PASSWORD, auth_header


@pytest.fixture
def cliente_con_limite_chico(client):
    """Reemplaza el limitador por IP por uno de dos permisos por minuto."""
    client.app.state.ip_limiter = TokenBucketLimiter(capacity=2, refill_per_minute=2)
    return client


def test_el_trafico_sin_token_tambien_tiene_techo(cliente_con_limite_chico):
    """Es el agujero que cerraba: 401 no consumia cupo, asi que no habia limite."""
    codigos = [
        cliente_con_limite_chico.post(
            "/ask", json={"question": "Que es BOLA y como se previene?"}
        ).status_code
        for _ in range(4)
    ]
    # Los primeros dos entran y mueren en la autenticacion; los siguientes ni llegan.
    assert codigos[:2] == [401, 401]
    assert codigos[2:] == [429, 429]


def test_el_limite_por_ip_alcanza_a_cualquier_ruta(cliente_con_limite_chico):
    """Vive en el middleware, antes de resolver la ruta: no hay endpoint exento."""
    assert cliente_con_limite_chico.get("/health").status_code == 200
    assert cliente_con_limite_chico.get("/").status_code == 200
    assert cliente_con_limite_chico.get("/health").status_code == 429


def test_el_rechazo_por_ip_respeta_el_contrato_de_errores(cliente_con_limite_chico):
    for _ in range(3):
        response = cliente_con_limite_chico.get("/health")
    assert response.status_code == 429
    assert response.headers["content-type"].startswith("application/problem+json")
    assert response.headers.get("retry-after")
    cuerpo = response.json()
    assert cuerpo["title"] == "Demasiadas solicitudes"
    # El trace_id tiene que llegar igual: el rechazo pasa por el mismo armador.
    assert cuerpo["trace_id"]


def test_las_metricas_no_se_sirven_sin_token(client):
    assert client.get("/metrics").status_code == 401


def test_las_metricas_exigen_su_propio_scope(client):
    """El analista se autentica bien pero no tiene metrics:read."""
    response = client.get("/metrics", headers=auth_header(client, "analista", ANALYST_PASSWORD))
    assert response.status_code == 403


def test_un_recolector_autorizado_si_las_lee(client):
    response = client.get("/metrics", headers=auth_header(client, "admin", ADMIN_PASSWORD))
    assert response.status_code == 200
    assert "http_requests_total" in response.text


def test_health_sigue_abierto(client):
    """Lo consulta el healthcheck del contenedor, que no tiene credenciales."""
    assert client.get("/health").status_code == 200
