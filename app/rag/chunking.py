"""Corte de los documentos markdown en fragmentos indexables.

Se corta respetando los encabezados en lugar de cada N caracteres a ciegas: cada
fragmento queda dentro de una sola seccion y arrastra el titulo de esa seccion,
que despues se usa para citar la fuente.
"""

import re
from dataclasses import dataclass

HEADING_PATTERN = re.compile(r"^(#{1,3})\s+(.*)$", re.MULTILINE)

# Secciones que son listas de enlaces y no contenido consultable. Se comparan contra
# toda la ruta de encabezados, no contra el titulo suelto: en los documentos de API la
# bibliografia es "References" y adentro cuelgan "OWASP" y "External", que por si solos
# son titulos perfectamente validos. Descartar por el padre y no por el hijo evita
# perder una seccion legitima que se llame igual.
#
# Existe por una medicion. Estas secciones son listas cortas de titulos de seguridad:
# densas en vocabulario del dominio y sin prosa que diluya, asi que puntuaban entre
# 0.644 y 0.670 mientras el contenido real de la categoria puntuaba 0.539 a 0.545. Con
# top_k=4 se llevaban las cuatro posiciones, y el modelo terminaba contestando desde
# una bibliografia: ante "que recomienda OWASP para el consumo ilimitado de recursos"
# respondia que OWASP no da recomendaciones, teniendo API4:2023 indexado.
BIBLIOGRAPHY_TITLES = frozenset(
    {
        "references",
        "referencias",
        "bibliography",
        "bibliografia",
        "see also",
        "further reading",
        "enlaces",
        "links",
    }
)


@dataclass(frozen=True)
class Chunk:
    text: str
    document: str
    section: str
    source: str
    origin_file: str
    chunk_index: int

    @property
    def chunk_id(self) -> str:
        """Identificador estable, para que reingestar actualice en vez de duplicar.

        Incluye el archivo de origen porque los documentos de OWASP repiten los
        mismos titulos de seccion entre categorias: sin eso, A01 y A05 chocarian
        en 'Prevencion' y uno pisaria al otro.
        """
        return f"{self.source}:{self.origin_file}:{self.chunk_index}"


# Los encabezados del corpus web traen un icono en linea con atributos de estilo:
#   #  A01:2025 Broken Access Control ![icon](../assets/...png){: style="height:80px"}
# Ese ruido terminaba en la cita y, peor, en el texto que se vectoriza: cada fragmento
# web gastaba senal del embedding en "icon", "assets", "style" y "80px".
IMAGEN_MARKDOWN = re.compile(r"!\[[^\]]*\]\([^)]*\)")
ATRIBUTOS_MARKDOWN = re.compile(r"\{:[^}]*\}")


def limpiar_titulo(titulo: str) -> str:
    """Saca el markup en linea del encabezado y colapsa los espacios."""
    titulo = IMAGEN_MARKDOWN.sub("", titulo)
    titulo = ATRIBUTOS_MARKDOWN.sub("", titulo)
    return " ".join(titulo.split())


def normalizar_titulo(titulo: str) -> str:
    """Deja el titulo comparable contra la lista de bibliografias.

    Los dos corpus no escriben los encabezados igual: el de APIs pone "References" y
    el web pone "References." con punto, y algunos ademas dejan un espacio al final.
    Comparar el texto crudo hacia que la mitad de las bibliografias se indexara igual,
    y eso no aparecio en los tests porque el documento de prueba usaba la forma sin
    punto. Salio de medir contra el corpus real.
    """
    return titulo.strip().rstrip(".:;").strip().lower()


@dataclass(frozen=True)
class Section:
    title: str
    body: str
    # Encabezados que la contienen, del mas general al mas especifico, incluido el suyo.
    path: tuple[str, ...]

    @property
    def is_bibliography(self) -> bool:
        """True si la seccion, o alguna que la contiene, es una lista de enlaces."""
        return any(normalizar_titulo(titulo) in BIBLIOGRAPHY_TITLES for titulo in self.path)


def split_by_heading(markdown: str) -> list[Section]:
    """Parte el markdown en secciones, cada una con su ruta de encabezados.

    La ruta se arma con una pila por nivel de encabezado: un titulo de nivel 3 hereda
    el de nivel 2 que lo precede. Sin eso no hay forma de distinguir una seccion
    "OWASP" que es bibliografia de una que no lo es.
    """
    matches = list(HEADING_PATTERN.finditer(markdown))
    if not matches:
        return [Section("Introduccion", markdown.strip(), ("Introduccion",))]

    sections: list[Section] = []
    preamble = markdown[: matches[0].start()].strip()
    if preamble:
        sections.append(Section("Introduccion", preamble, ("Introduccion",)))

    pila: list[str] = []
    for index, match in enumerate(matches):
        nivel = len(match.group(1))
        title = limpiar_titulo(match.group(2))
        del pila[nivel - 1 :]
        pila.append(title)

        body_start = match.end()
        body_end = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        body = markdown[body_start:body_end].strip()
        if body:
            sections.append(Section(title, body, tuple(pila)))
    return sections


def split_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    """Corta un texto largo en trozos con solape, cerrando en el ultimo punto o salto de linea."""
    if len(text) <= chunk_size:
        return [text]

    pieces: list[str] = []
    start = 0
    while start < len(text):
        end = min(start + chunk_size, len(text))
        if end < len(text):
            # Se busca un corte natural en el ultimo tercio del trozo.
            window_start = start + int(chunk_size * 0.66)
            breakpoint = max(
                text.rfind("\n\n", window_start, end), text.rfind(". ", window_start, end)
            )
            if breakpoint > start:
                end = breakpoint + 1
        piece = text[start:end].strip()
        if piece:
            pieces.append(piece)
        if end >= len(text):
            break
        start = max(start + 1, end - overlap)
    return pieces


def build_chunks(
    markdown: str,
    document: str,
    source: str,
    origin_file: str,
    chunk_size: int,
    overlap: int,
) -> list[Chunk]:
    """Convierte un documento completo en la lista de chunks lista para indexar."""
    chunks: list[Chunk] = []
    counter = 0
    for section in split_by_heading(markdown):
        # Una bibliografia no puede responder nada y desplaza al contenido que si.
        if section.is_bibliography:
            continue
        # La ruta completa va en section, que es lo que viaja como cita: "How To Prevent"
        # se repite en los diez documentos de API y no dice de que categoria es, mientras
        # "API4:2023 Unrestricted Resource Consumption > How To Prevent" si.
        #
        # En el texto que se vectoriza va solo el titulo de la seccion, y esto se probo
        # al reves primero. Con la ruta completa adentro, la bateria cayo de 20/21 a
        # 17/21 y los tres casos que se perdieron fueron de extraccion, todos con
        # grounded=False: el umbral de fundamentacion compara la respuesta contra el
        # texto del fragmento, y el prefijo mas largo corre ese vector lo suficiente
        # para que respuestas correctas queden por debajo de 0.55. El umbral esta
        # calibrado sobre titulo mas prosa, y cambiar el texto lo descalibra.
        ruta = " > ".join(section.path)
        for piece in split_text(section.body, chunk_size, overlap):
            # Se antepone el titulo para que el embedding tambien capture el contexto
            # de la seccion, no solo el parrafo suelto.
            chunks.append(
                Chunk(
                    text=f"{section.title}\n\n{piece}",
                    document=document,
                    section=ruta,
                    source=source,
                    origin_file=origin_file,
                    chunk_index=counter,
                )
            )
            counter += 1
    return chunks
