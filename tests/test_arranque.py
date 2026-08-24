"""Lo que tiene que estar listo sin que nadie toque nada despues de levantar el servicio.

Un despliegue nuevo arrancaba con el indice vacio: un usuario con `ask:read` preguntaba
y el asistente contestaba que no encontraba la informacion, porque no habia nada
recuperado. Habia que entrar como administrador y llamar a /admin/ingest a mano. Estos
tests fijan que eso ya no haga falta.
"""

from tests.conftest import ADMIN_PASSWORD, ANALYST_PASSWORD, auth_header, esperar_indice


def test_el_indice_se_construye_al_arrancar(auto_ingest_client):
    salud = esperar_indice(auto_ingest_client)
    assert salud["status"] == "ok"
    assert salud["collection_chunks"] > 0
    assert salud["indexing"] is False


def test_un_analista_recibe_citas_sin_que_nadie_reindexe(auto_ingest_client):
    esperar_indice(auto_ingest_client)

    response = auto_ingest_client.post(
        "/ask",
        json={"question": "Que controles previenen Broken Object Level Authorization?"},
        headers=auth_header(auto_ingest_client, "analista", ANALYST_PASSWORD),
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["grounded"] is True
    assert body["citations"]
    assert body["usage"]["retrieved_chunks"] > 0


def test_sin_ingesta_automatica_el_indice_arranca_vacio(client):
    """El interruptor apaga el comportamiento: es lo que usan los demas tests."""
    salud = client.get("/health").json()
    assert salud["collection_chunks"] == 0
    assert salud["status"] == "degraded"
    assert salud["indexing"] is False


class LockTomado:
    """Lock que se declara ocupado, para probar el rechazo sin correr dos ingestas."""

    def locked(self) -> bool:
        return True

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False


def test_una_ingesta_mientras_corre_otra_se_rechaza(client):
    client.app.state.ingest_lock = LockTomado()

    response = client.post(
        "/admin/ingest",
        json={"reset": True},
        headers=auth_header(client, "admin", ADMIN_PASSWORD),
    )

    assert response.status_code == 409
    assert response.headers.get("retry-after") == "60"
    assert response.json()["title"] == "Indexacion en curso"
