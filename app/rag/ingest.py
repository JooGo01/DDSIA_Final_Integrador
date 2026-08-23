"""Ingesta del corpus: lee los markdown, los trocea, los vectoriza y los guarda."""

import time
from pathlib import Path

from app.config import Settings
from app.core.logging import get_logger
from app.guardrails.corpus_guard import scan_chunks
from app.rag.chunking import Chunk, build_chunks
from app.rag.ollama_client import OllamaClient
from app.rag.store import VectorStore

logger = get_logger("ingest")

EMBED_BATCH_SIZE = 32

# Cada subcarpeta del corpus se mapea a un nombre de documento citable.
CORPUS_SOURCES = {
    "web": "OWASP Top 10:2025",
    "api": "OWASP API Security Top 10:2023",
}


def collect_documents(corpus_path: str) -> list[tuple[Path, str, str]]:
    """Lista los markdown del corpus como (ruta, nombre_de_documento, source)."""
    root = Path(corpus_path)
    found: list[tuple[Path, str, str]] = []
    for source, document_name in CORPUS_SOURCES.items():
        folder = root / source
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.md")):
            found.append((path, document_name, source))
    return found


async def ingest_corpus(
    settings: Settings,
    store: VectorStore,
    client: OllamaClient,
    reset: bool = False,
) -> tuple[int, int, int, list[str]]:
    """Ingesta el corpus completo.

    Devuelve (documentos, chunks, duracion en ms, archivos descartados).
    """
    started = time.perf_counter()

    documents = collect_documents(settings.corpus_path)
    if not documents:
        logger.warning("empty_corpus", path=settings.corpus_path)
        return 0, 0, int((time.perf_counter() - started) * 1000), []

    all_chunks: list[Chunk] = []
    for path, document_name, source in documents:
        markdown = path.read_text(encoding="utf-8")
        chunks = build_chunks(
            markdown=markdown,
            document=document_name,
            source=source,
            origin_file=path.stem,
            chunk_size=settings.chunk_size,
            overlap=settings.chunk_overlap,
        )
        all_chunks.extend(chunks)
        logger.info("document_chunked", file=path.name, source=source, chunks=len(chunks))

    # Un documento de referencia describe; no da ordenes al lector. El que si lo hace
    # queda afuera: es la unica capa que puede frenar una inyeccion indirecta, porque
    # la validacion de salida compara contra el contexto y el veneno ES el contexto.
    hallazgos = scan_chunks(all_chunks)
    descartados = sorted({h.origin_file for h in hallazgos})
    if descartados:
        for h in hallazgos:
            logger.warning(
                "documento_con_instrucciones",
                file=h.origin_file,
                chunk=h.chunk_index,
                excerpt=h.excerpt[:120],
            )
        all_chunks = [c for c in all_chunks if c.origin_file not in set(descartados)]

    # Se vectoriza todo antes de tocar el indice. Si Ollama falla a mitad de camino,
    # la excepcion sale de aca y el indice anterior queda intacto: reset() borraba
    # primero y una falla dejaba el servicio sin nada que responder.
    vectors: list[list[float]] = []
    for start in range(0, len(all_chunks), EMBED_BATCH_SIZE):
        batch = all_chunks[start : start + EMBED_BATCH_SIZE]
        vectors.extend(await client.embed([chunk.text for chunk in batch]))

    if reset:
        store.clear()
    for start in range(0, len(all_chunks), EMBED_BATCH_SIZE):
        store.add(
            all_chunks[start : start + EMBED_BATCH_SIZE], vectors[start : start + EMBED_BATCH_SIZE]
        )

    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "ingest_completed",
        documents=len(documents),
        chunks=len(all_chunks),
        rejected=descartados,
        duration_ms=duration_ms,
    )
    return len(documents) - len(descartados), len(all_chunks), duration_ms, descartados
