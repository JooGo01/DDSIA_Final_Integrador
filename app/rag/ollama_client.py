"""Cliente HTTP contra Ollama, usado tanto para embeddings como para generacion."""

import httpx

from app.config import Settings
from app.core.logging import get_logger

logger = get_logger("ollama")


class OllamaError(RuntimeError):
    """Falla al hablar con Ollama: no disponible, timeout o respuesta invalida."""


class OllamaClient:
    def __init__(self, settings: Settings) -> None:
        self.base_url = settings.ollama_base_url.rstrip("/")
        self.chat_model = settings.llm_model
        self.embedding_model = settings.embedding_model
        self.timeout = settings.llm_timeout_seconds
        self.max_output_tokens = settings.llm_max_output_tokens
        self.temperature = settings.llm_temperature
        self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

    async def close(self) -> None:
        """Cierra el pool de conexiones."""
        await self._client.aclose()

    async def is_reachable(self) -> bool:
        """True si Ollama responde. Lo usa /health."""
        try:
            response = await self._client.get("/api/tags", timeout=5.0)
            return response.status_code == 200
        except httpx.HTTPError:
            return False

    async def embed(self, texts: list[str]) -> list[list[float]]:
        """Convierte una lista de textos en sus vectores."""
        if not texts:
            return []
        try:
            response = await self._client.post(
                "/api/embed", json={"model": self.embedding_model, "input": texts}
            )
            response.raise_for_status()
            embeddings = response.json().get("embeddings")
        except httpx.HTTPError as exc:
            raise OllamaError(f"No se pudieron generar embeddings: {exc}") from exc

        if not embeddings or len(embeddings) != len(texts):
            raise OllamaError("Ollama devolvio una cantidad de embeddings inesperada")
        return embeddings

    async def generate(self, system_prompt: str, user_prompt: str) -> tuple[str, int, int]:
        """Pide una respuesta al modelo. Devuelve (texto, tokens_entrada, tokens_salida)."""
        payload = {
            "model": self.chat_model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "options": {
                "temperature": self.temperature,
                "num_predict": self.max_output_tokens,
            },
        }
        try:
            response = await self._client.post("/api/chat", json=payload)
            response.raise_for_status()
            body = response.json()
        except httpx.TimeoutException as exc:
            raise OllamaError("El modelo tardo mas de lo permitido") from exc
        except httpx.HTTPError as exc:
            raise OllamaError(f"El modelo no respondio: {exc}") from exc

        answer = body.get("message", {}).get("content", "").strip()
        if not answer:
            raise OllamaError("El modelo devolvio una respuesta vacia")

        input_tokens = int(body.get("prompt_eval_count", 0))
        output_tokens = int(body.get("eval_count", 0))
        return answer, input_tokens, output_tokens
