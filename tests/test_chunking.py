"""Tests del corte de documentos en fragmentos."""

from app.rag.chunking import build_chunks, limpiar_titulo, split_by_heading, split_text

DOCUMENTO = """# API1:2023 - Broken Object Level Authorization

Los endpoints que reciben identificadores amplian la superficie de ataque.

## Como prevenirlo

Validar la relacion entre el usuario autenticado y el objeto solicitado.
"""


def test_separa_el_documento_por_encabezados():
    secciones = split_by_heading(DOCUMENTO)
    titulos = [seccion.title for seccion in secciones]
    assert titulos == ["API1:2023 - Broken Object Level Authorization", "Como prevenirlo"]


def test_un_texto_sin_encabezados_queda_en_una_sola_seccion():
    secciones = split_by_heading("texto plano sin ningun encabezado")
    assert len(secciones) == 1
    assert secciones[0].title == "Introduccion"


# Estructura real de los documentos de API: la bibliografia va en References y adentro
# cuelgan OWASP y External, que como titulos sueltos son perfectamente validos.
DOCUMENTO_CON_BIBLIOGRAFIA = """# API4:2023 Unrestricted Resource Consumption

Satisfacer una peticion consume recursos de red, CPU y memoria.

## How To Prevent

Limitar la cantidad de peticiones y el tamano de los datos de entrada.

## References

### OWASP

- OWASP GraphQL Cheat Sheet
- OWASP Web Service Security Cheat Sheet

### External

- CWE-770: Allocation of Resources Without Limits
"""


def test_cada_seccion_conoce_los_encabezados_que_la_contienen():
    rutas = {s.title: s.path for s in split_by_heading(DOCUMENTO_CON_BIBLIOGRAFIA)}
    assert rutas["OWASP"] == (
        "API4:2023 Unrestricted Resource Consumption",
        "References",
        "OWASP",
    )
    assert rutas["How To Prevent"] == (
        "API4:2023 Unrestricted Resource Consumption",
        "How To Prevent",
    )


def test_la_bibliografia_se_reconoce_por_el_padre_y_no_por_el_titulo():
    """OWASP y External son bibliografia aca porque cuelgan de References."""
    secciones = {s.title: s for s in split_by_heading(DOCUMENTO_CON_BIBLIOGRAFIA)}
    assert secciones["OWASP"].is_bibliography
    assert secciones["External"].is_bibliography
    assert not secciones["How To Prevent"].is_bibliography


def test_la_bibliografia_se_reconoce_con_el_punto_final_del_corpus_web():
    """Los dos corpus no escriben igual los encabezados.

    El de APIs pone "References" y el web pone "References." con punto. Comparando el
    texto crudo, la mitad de las bibliografias se seguia indexando, y el test anterior
    no lo veia porque su documento de prueba usaba la forma sin punto.
    """
    documento = (
        "# A01:2025 Broken Access Control\n\n"
        "## How to prevent.\n\nValidar la autorizacion del lado del servidor.\n\n"
        "## References.\n\n- OWASP Cheat Sheet sobre control de acceso\n"
    )
    secciones = {s.title: s for s in split_by_heading(documento)}

    assert secciones["References."].is_bibliography
    assert not secciones["How to prevent."].is_bibliography

    chunks = build_chunks(documento, "OWASP Top 10:2025", "web", "A01_2025", 1200, 250)
    assert not any("Cheat Sheet" in c.text for c in chunks)


def test_el_titulo_se_limpia_del_markup_del_corpus_web():
    """Los encabezados del Top 10:2025 traen un icono en linea con atributos de estilo.

    Ese ruido terminaba en la cita y en el texto que se vectoriza: cada fragmento web
    gastaba senal del embedding en "icon", "assets", "style" y "80px".
    """
    crudo = (
        "#  A01:2025 Broken Access Control "
        "![icon](../assets/TOP_10_Icons_Final_Broken_Access_Control.png)"
        '{: style="height:80px;width:80px" align="right"}'
    )
    assert limpiar_titulo(crudo.lstrip("# ")) == "A01:2025 Broken Access Control"

    secciones = split_by_heading(crudo + "\n\nContenido de la categoria.\n")
    assert secciones[0].title == "A01:2025 Broken Access Control"
    assert "![icon]" not in secciones[0].title
    assert "style=" not in secciones[0].title


def test_una_seccion_llamada_owasp_fuera_de_una_bibliografia_se_conserva():
    """El descarte no puede ser por nombre: OWASP es un titulo valido por si solo."""
    documento = "# Categoria\n\n## OWASP\n\nContenido tecnico real de la seccion.\n"
    secciones = {s.title: s for s in split_by_heading(documento)}
    assert not secciones["OWASP"].is_bibliography
    assert build_chunks(documento, "Doc", "web", "X01", 1200, 250)


def test_los_chunks_no_incluyen_la_bibliografia():
    """Son listas de enlaces: no responden nada y desplazan al contenido que si."""
    chunks = build_chunks(
        DOCUMENTO_CON_BIBLIOGRAFIA, "OWASP API Security Top 10:2023", "api", "0xa4", 1200, 250
    )
    # La cita es la ruta completa de encabezados, no el titulo hoja.
    secciones = {c.section for c in chunks}

    assert "API4:2023 Unrestricted Resource Consumption > How To Prevent" in secciones
    assert not any("References" in seccion for seccion in secciones)
    assert not any(seccion.endswith("OWASP") for seccion in secciones)
    assert not any(seccion.endswith("External") for seccion in secciones)
    # Y no queda rastro del contenido de la bibliografia en el texto indexado.
    assert not any("Cheat Sheet" in c.text for c in chunks)


def test_los_indices_de_chunk_quedan_contiguos_al_descartar():
    """Saltear una seccion no puede dejar huecos en la numeracion de los ids."""
    chunks = build_chunks(
        DOCUMENTO_CON_BIBLIOGRAFIA, "OWASP API Security Top 10:2023", "api", "0xa4", 1200, 250
    )
    assert [c.chunk_index for c in chunks] == list(range(len(chunks)))


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
