"""Ingesta del corpus: lee los markdown, los trocea, los vectoriza y los guarda."""

import time
from pathlib import Path

from app.config import Settings
from app.core.logging import get_logger
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
) -> tuple[int, int, int]:
    """Ingesta el corpus completo. Devuelve (documentos, chunks, duracion en ms)."""
    started = time.perf_counter()

    if reset:
        store.clear()

    documents = collect_documents(settings.corpus_path)
    if not documents:
        logger.warning("empty_corpus", path=settings.corpus_path)
        return 0, 0, int((time.perf_counter() - started) * 1000)

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

    # Se vectoriza por lotes para no mandar un unico request enorme a Ollama.
    for start in range(0, len(all_chunks), EMBED_BATCH_SIZE):
        batch = all_chunks[start : start + EMBED_BATCH_SIZE]
        embeddings = await client.embed([chunk.text for chunk in batch])
        store.add(batch, embeddings)

    duration_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "ingest_completed",
        documents=len(documents),
        chunks=len(all_chunks),
        duration_ms=duration_ms,
    )
    return len(documents), len(all_chunks), duration_ms
