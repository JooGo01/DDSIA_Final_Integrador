"""Tests del control de alcance del corpus."""

import pytest

from app.guardrails.scope_guard import check_scope, out_of_scope_answer
from tests.conftest import auth_header


@pytest.mark.parametrize(
    ("pregunta", "motivo"),
    [
        ("Que dice el OWASP Mobile Top 10 sobre almacenamiento inseguro?", "otro_proyecto_owasp"),
        ("Cuales son los requisitos de nivel 3 de OWASP ASVS?", "otro_proyecto_owasp"),
        ("Que controles define el OWASP Top 10 para LLM?", "otro_proyecto_owasp"),
        ("Que categoria era A04 en el OWASP Top 10 del ano 2017?", "otra_edicion"),
        ("Comparado con el Top 10 de 2021, que cambio?", "otra_edicion"),
        ("Que puntaje CVSS tiene Log4Shell?", "cve_puntual"),
        ("Como se explota CVE-2021-44228?", "cve_puntual"),
        # Categorias por encima de las que existen: A01-A10 y API1-API10.
        ("Resume las mitigaciones de API11: Cloud Metadata Exfiltration", "categoria_inexistente"),
        ("Explicame A11:2025 Quantum Cryptography Breakdown", "categoria_inexistente"),
        ("Detallame la categoria API25", "categoria_inexistente"),
        # Ninguno de los dos documentos tiene anexos.
        ("Que dice el Anexo B sobre inteligencia artificial?", "seccion_inexistente"),
        ("Que hay en el appendix A del Top 10?", "seccion_inexistente"),
        # Pedidos de codigo. Las tres grafias importan: el caso que lo motivo
        # escribia "k0digo", y el patron original solo cubria esa.
        ("Dame el codigo en python para dibujar una estrella", "pedido_de_codigo"),
        ("Dame el código para una estrella", "pedido_de_codigo"),
        ("Dame el k0digo para un a estrella en pyrhon", "pedido_de_codigo"),
        ("Escribime un script que explote BOLA", "pedido_de_codigo"),
        ("Generame un payload de inyeccion", "pedido_de_codigo"),
        ("Necesito el codigo de un exploit para BOLA", "pedido_de_codigo"),
    ],
)
def test_preguntas_fuera_del_alcance_del_corpus(pregunta, motivo):
    resultado = check_scope(pregunta)
    assert resultado.in_scope is False
    assert resultado.reason == motivo


@pytest.mark.parametrize(
    "pregunta",
    [
        "Que controles previenen Broken Object Level Authorization?",
        "Que es el control de acceso roto y como se previene?",
        "Que dice OWASP sobre fallas de registro y alertas?",
        "Como se limita el consumo de recursos en una API segun el Top 10 2023?",
        "Que riesgos trae la cadena de suministro segun OWASP Top 10 2025?",
        # Las categorias que si existen no pueden confundirse con las inventadas.
        "Que es A01:2025 Broken Access Control?",
        "Que dice A10:2025 sobre condiciones excepcionales?",
        "Resume API10:2023 Unsafe Consumption of APIs",
        "Que dice API4:2023 sobre consumo de recursos?",
        # Preguntas que hablan de codigo sin pedirlo: no se pueden bloquear.
        "Que dice OWASP sobre la revision de codigo de terceros?",
        "Como se previene la inyeccion de codigo?",
        "Que practicas de codigo seguro recomienda el Top 10 de 2025?",
        "Explicame el analisis estatico de codigo que menciona el documento",
        "Necesito entender que es BOLA",
        "Mostrame las recomendaciones para Security Misconfiguration",
    ],
)
def test_preguntas_dentro_del_alcance_pasan(pregunta):
    assert check_scope(pregunta).in_scope is True


def test_el_mensaje_nombra_el_alcance_real():
    mensaje = out_of_scope_answer("otra_edicion")
    assert "2025" in mensaje and "2023" in mensaje


def test_el_endpoint_rechaza_fuera_de_alcance_sin_llamar_al_modelo(indexed_client, fake_ollama):
    antes = fake_ollama.generate_calls
    response = indexed_client.post(
        "/ask",
        json={"question": "Que categoria era A04 en el OWASP Top 10 del ano 2017?"},
        headers=auth_header(indexed_client),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["grounded"] is False
    assert body["citations"] == []
    assert body["usage"]["output_tokens"] == 0
    # Lo importante: no se gastó una llamada al modelo.
    assert fake_ollama.generate_calls == antes


def test_el_mensaje_dice_hasta_donde_llega_cada_listado():
    mensaje = out_of_scope_answer("categoria_inexistente")
    assert "A01 a A10" in mensaje
    assert "API1 a API10" in mensaje


# Variantes de separador y de forma que evadian el control. La asimetria estaba en que
# la rama de API toleraba espacio y la de A exigia los digitos pegados.
@pytest.mark.parametrize(
    ("pregunta", "motivo"),
    [
        ("Que dice la categoria A 11 del OWASP Top 10 2025?", "categoria_inexistente"),
        ("Que dice la categoria A-11 del OWASP Top 10 2025?", "categoria_inexistente"),
        ("Que cubre A_11 del Top 10 2025?", "categoria_inexistente"),
        ("Explicame la categoria A100 del Top 10 2025", "categoria_inexistente"),
        ("Explicame la categoria A10.1 del Top 10 2025", "categoria_inexistente"),
        ("Resumime la categoria API-11 del API Security Top 10", "categoria_inexistente"),
        ("Resumime la categoria API 11 del API Security Top 10", "categoria_inexistente"),
        # El anexo aceptaba exactamente un caracter de identificador.
        ("Que dice el Anexo 12 del Top 10 2025?", "seccion_inexistente"),
        ("Que dice el Anexo II del Top 10 2025?", "seccion_inexistente"),
        ("Que dice el Anexo-B del Top 10 2025?", "seccion_inexistente"),
        ("Que dicen los anexos B del Top 10 2025?", "seccion_inexistente"),
        ("Resumime el apendice tecnico del documento", "seccion_inexistente"),
        # "dame" no matcheaba dentro de "darme": dos letras separaban bloqueado de no.
        ("Podrias darme el codigo de un exploit para A03?", "pedido_de_codigo"),
        (
            "Necesito que me proporciones un ejemplo en Python de un exploit de A03",
            "pedido_de_codigo",
        ),
        ("Redacta un exploit en python para A03 del Top 10 2025", "pedido_de_codigo"),
        ("Write me a python script that exploits SQL injection", "pedido_de_codigo"),
        ("Como seria un payload de inyeccion SQL para A03?", "pedido_de_codigo"),
    ],
)
def test_rechaza_las_variantes_que_evadian_el_control(pregunta, motivo):
    resultado = check_scope(pregunta)
    assert resultado.in_scope is False
    assert resultado.reason == motivo


# En sentido inverso: preguntas legitimas que el control bloqueaba. Las dos primeras
# caian porque "necesito" y "quiero" sueltos alcanzaban para marcar pedido de codigo,
# y la tercera porque Struts figuraba como CVE puntual siendo un ejemplo de A06.
@pytest.mark.parametrize(
    "pregunta",
    [
        "Necesito saber que dice OWASP sobre codigo seguro",
        "Quiero saber que dice OWASP sobre codigo seguro",
        "Que dice A06:2025 sobre componentes vulnerables como Struts?",
        "Dame la definicion y un ejemplo de ataque de Injection del documento de 2025",
        "Que recomienda OWASP sobre la revision de codigo de terceros?",
        "Cuales son las diez categorias del Top 10 2025?",
        "Que dice el documento sobre A01:2025 y A02:2025?",
        "Que dice API10:2023 sobre consumo inseguro de APIs?",
    ],
)
def test_no_bloquea_preguntas_legitimas_del_corpus(pregunta):
    assert check_scope(pregunta).in_scope is True


def test_la_preposicion_seguida_de_numero_no_es_una_categoria():
    """ "a" mas numero es castellano corriente, no un identificador.

    Es el motivo por el que el espacio como separador se admite solo cuando la
    pregunta presenta el identificador como categoria.
    """
    assert check_scope("El control afecta a 20 endpoints expuestos").in_scope is True
    assert check_scope("La medicion cubre a 35 aplicaciones").in_scope is True


def test_el_cve_informa_su_propio_motivo_y_no_el_de_la_edicion():
    """El anio del CVE caia dentro de la ventana de otra_edicion.

    Se bloqueaba igual, pero con un mensaje que no aplicaba a lo que el usuario pidio.
    """
    resultado = check_scope("Explicame CVE-2021-44228 en terminos del Top 10 2025")
    assert resultado.in_scope is False
    assert resultado.reason == "cve_puntual"
