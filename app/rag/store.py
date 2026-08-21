"""Acceso al vector store. Chroma en modo embebido, persistido en disco."""

from pathlib import Path

import chromadb
from chromadb.config import Settings as ChromaSettings

from app.config import Settings
from app.core.logging import get_logger
from app.rag.chunking import Chunk

logger = get_logger("store")


class VectorStore:
    def __init__(self, settings: Settings) -> None:
        Path(settings.chroma_path).mkdir(parents=True, exist_ok=True)
        self._client = chromadb.PersistentClient(
            path=settings.chroma_path,
            settings=ChromaSettings(anonymized_telemetry=False, allow_reset=True),
        )
        self.collection_name = settings.collection_name
        # Los embeddings los genera Ollama, no Chroma: por eso embedding_function=None.
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=None,
            metadata={"hnsw:space": "cosine"},
        )

    def count(self) -> int:
        """Cantidad de chunks indexados."""
        return self._collection.count()

    def clear(self) -> None:
        """Borra la coleccion completa y la vuelve a crear vacia."""
        self._client.delete_collection(self.collection_name)
        self._collection = self._client.get_or_create_collection(
            name=self.collection_name,
            embedding_function=None,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("collection_cleared", collection=self.collection_name)

    def add(self, chunks: list[Chunk], embeddings: list[list[float]]) -> None:
        """Guarda los chunks con sus vectores. Un id repetido pisa el registro anterior."""
        if not chunks:
            return
        self._collection.upsert(
            ids=[chunk.chunk_id for chunk in chunks],
            embeddings=embeddings,
            documents=[chunk.text for chunk in chunks],
            metadatas=[
                {
                    "document": chunk.document,
                    "section": chunk.section,
                    "source": chunk.source,
                }
                for chunk in chunks
            ],
        )

    def search(
        self, embedding: list[float], top_k: int, source: str = "all"
    ) -> list[tuple[str, dict, float]]:
        """Busca los top_k vecinos. Devuelve (texto, metadata, score de 0 a 1)."""
        if self.count() == 0:
            return []

        # El filtro por metadata evita traer chunks del corpus equivocado.
        where = None if source == "all" else {"source": source}
        result = self._collection.query(
            query_embeddings=[embedding],
            n_results=min(top_k, self.count()),
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        documents = result.get("documents", [[]])[0]
        metadatas = result.get("metadatas", [[]])[0]
        distances = result.get("distances", [[]])[0]

        hits = []
        for text, metadata, distance in zip(documents, metadatas, distances, strict=False):
            # Chroma devuelve distancia coseno; se pasa a score de similitud.
            score = max(0.0, 1.0 - float(distance))
            hits.append((text, dict(metadata), score))
        return hits
