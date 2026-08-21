"""Corte de los documentos markdown en fragmentos indexables.

Se corta respetando los encabezados en lugar de cada N caracteres a ciegas: cada
fragmento queda dentro de una sola seccion y arrastra el titulo de esa seccion,
que despues se usa para citar la fuente.
"""

import re
from dataclasses import dataclass

HEADING_PATTERN = re.compile(r"^(#{1,3})\s+(.*)$", re.MULTILINE)


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


def split_by_heading(markdown: str) -> list[tuple[str, str]]:
    """Parte el markdown en (titulo_de_seccion, cuerpo)."""
    matches = list(HEADING_PATTERN.finditer(markdown))
    if not matches:
        return [("Introduccion", markdown.strip())]

    sections: list[tuple[str, str]] = []
    preamble = markdown[: matches[0].start()].strip()
    if preamble:
        sections.append(("Introduccion", preamble))

    for index, match in enumerate(matches):
        title = match.group(2).strip()
        body_start = match.end()
        body_end = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        body = markdown[body_start:body_end].strip()
        if body:
            sections.append((title, body))
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
    for section_title, body in split_by_heading(markdown):
        for piece in split_text(body, chunk_size, overlap):
            # Se antepone el titulo para que el embedding tambien capture el contexto
            # de la seccion, no solo el parrafo suelto.
            chunks.append(
                Chunk(
                    text=f"{section_title}\n\n{piece}",
                    document=document,
                    section=section_title,
                    source=source,
                    origin_file=origin_file,
                    chunk_index=counter,
                )
            )
            counter += 1
    return chunks
