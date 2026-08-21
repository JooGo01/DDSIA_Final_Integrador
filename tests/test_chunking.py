"""Tests del corte de documentos en fragmentos."""

from app.rag.chunking import build_chunks, split_by_heading, split_text

DOCUMENTO = """# API1:2023 - Broken Object Level Authorization

Los endpoints que reciben identificadores amplian la superficie de ataque.

## Como prevenirlo

Validar la relacion entre el usuario autenticado y el objeto solicitado.
"""


def test_separa_el_documento_por_encabezados():
    secciones = split_by_heading(DOCUMENTO)
    titulos = [titulo for titulo, _ in secciones]
    assert titulos == ["API1:2023 - Broken Object Level Authorization", "Como prevenirlo"]


def test_un_texto_sin_encabezados_queda_en_una_sola_seccion():
    secciones = split_by_heading("texto plano sin ningun encabezado")
    assert len(secciones) == 1
    assert secciones[0][0] == "Introduccion"


def test_un_texto_corto_no_se_corta():
    assert split_text("texto breve", chunk_size=100, overlap=20) == ["texto breve"]


def test_un_texto_largo_se_corta_con_solape():
    texto = ". ".join(f"oracion numero {i} con contenido suficiente" for i in range(80))
    piezas = split_text(texto, chunk_size=400, overlap=100)

    assert len(piezas) > 1
    assert all(len(pieza) <= 500 for pieza in piezas)
    # El solape hace que el final de un trozo reaparezca al inicio del siguiente.
    assert piezas[0][-30:] in piezas[1] or piezas[1].startswith(piezas[0][-30:].strip())


def test_cada_chunk_arrastra_su_seccion_y_su_origen():
    chunks = build_chunks(
        DOCUMENTO, "OWASP API Security Top 10:2023", "api", "0xa1-bola", 1200, 250
    )

    assert len(chunks) == 2
    assert all(chunk.source == "api" for chunk in chunks)
    assert all(chunk.document == "OWASP API Security Top 10:2023" for chunk in chunks)
    # El titulo va dentro del texto para que tambien entre en el embedding.
    assert chunks[0].text.startswith("API1:2023")


def test_los_identificadores_de_chunk_son_unicos_y_estables():
    primera = build_chunks(DOCUMENTO, "doc", "api", "0xa1-bola", 1200, 250)
    segunda = build_chunks(DOCUMENTO, "doc", "api", "0xa1-bola", 1200, 250)

    ids = [chunk.chunk_id for chunk in primera]
    assert len(ids) == len(set(ids))
    assert ids == [chunk.chunk_id for chunk in segunda]


def test_dos_documentos_con_la_misma_seccion_no_colisionan():
    # Los documentos de OWASP repiten titulos como "Prevencion" entre categorias.
    # Si el id no incluyera el archivo, el segundo pisaria al primero al indexar.
    plantilla = "# {titulo}\n\n## Prevencion\n\nContenido de la seccion de {titulo}.\n"

    primero = build_chunks(plantilla.format(titulo="A01"), "doc", "web", "A01_2025", 1200, 250)
    segundo = build_chunks(plantilla.format(titulo="A05"), "doc", "web", "A05_2025", 1200, 250)

    ids_primero = {chunk.chunk_id for chunk in primero}
    ids_segundo = {chunk.chunk_id for chunk in segundo}
    assert ids_primero.isdisjoint(ids_segundo)
