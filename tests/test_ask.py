"""Tests del endpoint /ask y del pipeline de recuperacion."""

from app.rag.ollama_client import OllamaError
from tests.conftest import auth_header


def test_responde_con_citas(indexed_client):
    response = indexed_client.post(
        "/ask",
        json={"question": "como se previene el control de acceso roto"},
        headers=auth_header(indexed_client),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is True
    assert body["citations"]
    assert body["citations"][0]["document"].startswith("OWASP")
    assert body["usage"]["retrieved_chunks"] > 0
    assert body["request_id"]


def test_el_filtro_de_corpus_solo_devuelve_documentos_de_esa_fuente(indexed_client):
    response = indexed_client.post(
        "/ask",
        json={"question": "como limitar el consumo de recursos de la api", "source": "api"},
        headers=auth_header(indexed_client),
    )
    assert response.status_code == 200
    documentos = {cita["document"] for cita in response.json()["citations"]}
    assert documentos <= {"OWASP API Security Top 10:2023"}


def test_una_respuesta_sin_sustento_no_se_publica(indexed_client, fake_ollama):
    # El modelo devuelve algo que no esta en ningun documento indexado.
    fake_ollama.forced_answer = (
        "Las tortugas marinas recorren miles de kilometros durante su migracion anual"
    )
    response = indexed_client.post(
        "/ask",
        json={"question": "como se previene el control de acceso roto"},
        headers=auth_header(indexed_client),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is False
    assert body["citations"] == []
    assert "No encontre" in body["answer"]


def test_rechaza_campos_no_declarados(indexed_client):
    response = indexed_client.post(
        "/ask",
        json={"question": "que es inyeccion sql", "role": "administrador"},
        headers=auth_header(indexed_client),
    )
    assert response.status_code == 422
    assert "role" in response.json()["detail"]


def test_rechaza_preguntas_demasiado_largas(indexed_client):
    response = indexed_client.post(
        "/ask",
        json={"question": "a" * 5000},
        headers=auth_header(indexed_client),
    )
    assert response.status_code == 422


def test_si_el_modelo_falla_devuelve_503_sin_filtrar_detalle(indexed_client, fake_ollama):
    fake_ollama.raise_on_generate = OllamaError("connection refused a http://ollama:11434")
    response = indexed_client.post(
        "/ask",
        json={"question": "como se previene el control de acceso roto"},
        headers=auth_header(indexed_client),
    )
    assert response.status_code == 503
    assert "ollama" not in response.text.lower()
    assert response.headers.get("retry-after") == "30"


def test_toda_respuesta_lleva_request_id_y_cabeceras_de_seguridad(client):
    response = client.get("/health")
    assert response.headers["X-Request-ID"]
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_health_reporta_indice_y_modelo(indexed_client):
    body = indexed_client.get("/health").json()
    assert body["status"] == "ok"
    assert body["llm_reachable"] is True
    assert body["collection_chunks"] > 0


def test_metrics_expone_formato_prometheus(indexed_client):
    response = indexed_client.get("/metrics")
    assert response.status_code == 200
    assert "http_requests_total" in response.text
    assert "rag_answers_total" in response.text


def test_se_respeta_un_request_id_del_cliente_si_es_seguro(client):
    response = client.get("/health", headers={"X-Request-ID": "trace-abc_123.4"})
    assert response.headers["X-Request-ID"] == "trace-abc_123.4"


def test_se_descarta_un_request_id_demasiado_largo(client):
    response = client.get("/health", headers={"X-Request-ID": "A" * 500})
    devuelto = response.headers["X-Request-ID"]
    assert devuelto != "A" * 500
    assert len(devuelto) == 16


def test_se_descarta_un_request_id_con_caracteres_raros(client):
    response = client.get("/health", headers={"X-Request-ID": "<script>alert(1)</script>"})
    assert "<script>" not in response.headers["X-Request-ID"]
