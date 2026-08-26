"""Configuracion de la aplicacion, leida desde variables de entorno."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PLACEHOLDER_SECRETS = {"changeme", "secret", "cambiar", "please-change-me", "test"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "owasp-rag-assistant"
    app_version: str = "1.0.0"
    environment: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = "INFO"

    # Autenticacion. jwt_secret no tiene default: si falta, la app no arranca.
    jwt_secret: str = Field(min_length=32)
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "owasp-rag-assistant"
    jwt_audience: str = "owasp-rag-api"
    jwt_expire_minutes: int = 30

    # Archivo con los usuarios y sus hashes. No va por variable de entorno porque
    # el environment de un contenedor es visible con docker inspect y en /proc.
    users_file: str = "/run/config/users.json"

    # Limites de uso
    requests_per_minute: int = 10
    login_attempts_per_minute: int = 5
    daily_token_budget: int = 50_000

    # Techo por IP para todo el trafico, autenticado o no. Los demas limites viven en
    # dependencias de ruta y por lo tanto solo cuentan peticiones que ya presentaron
    # un token valido: sin este, inundar /ask sin credencial no tenia ningun costo.
    # El margen es amplio a proposito, porque una carga de la interfaz son varias
    # peticiones (pagina, hoja de estilos, dos scripts, icono y sondeo de estado).
    ip_requests_per_minute: int = 60

    # Espera minima entre dos ingestas completas. El lock impide que se solapen,
    # pero no que se encadenen: cada corrida re-vectoriza el corpus entero contra
    # el modelo, y repetirla en serie deja a /ask sin capacidad.
    min_seconds_between_ingests: int = 60

    # Ollama
    ollama_base_url: str = "http://ollama:11434"
    llm_model: str = "llama3.2:3b"
    embedding_model: str = "nomic-embed-text"
    # 90 s alcanzaba para consultas aisladas pero se agotaba bajo carga sostenida
    # (la bateria de evals dispara 10 consultas/min): el modelo devolvia 503 a mitad
    # de la corrida. 150 s cubre la latencia observada en ese escenario.
    llm_timeout_seconds: float = 150.0
    llm_max_output_tokens: int = 512
    llm_temperature: float = 0.1
    # Cuanto tiempo Ollama mantiene el modelo en memoria tras la ultima consulta.
    llm_keep_alive: str = "30m"

    # Indexado automatico del corpus al arrancar cuando el indice esta vacio. Sin esto
    # una instalacion nueva queda sin nada que recuperar y /ask contesta que no encontro
    # la informacion hasta que alguien con admin:ingest dispare la ingesta a mano.
    auto_ingest: bool = True

    # RAG
    chroma_path: str = "/data/chroma"
    corpus_path: str = "/data/corpus"
    collection_name: str = "owasp"
    chunk_size: int = 1200
    chunk_overlap: int = 250
    retrieval_top_k: int = 4
    min_relevance_score: float = 0.25

    # Validacion de entrada
    min_question_chars: int = 8
    max_question_chars: int = 600

    @field_validator("requests_per_minute", "login_attempts_per_minute", "daily_token_budget")
    @classmethod
    def must_be_positive(cls, value: int) -> int:
        """Un limite en cero dejaria el servicio inutilizable y divide por cero al reponer."""
        if value <= 0:
            raise ValueError("Los limites de uso tienen que ser mayores que cero.")
        return value

    @field_validator("jwt_secret")
    @classmethod
    def reject_placeholder(cls, value: str) -> str:
        """Impide arrancar con un secreto de ejemplo."""
        if value.strip().lower() in PLACEHOLDER_SECRETS:
            raise ValueError("JWT_SECRET tiene un valor de ejemplo. Genera uno real.")
        return value


@lru_cache
def get_settings() -> Settings:
    """Devuelve la configuracion, cacheada para no releer el entorno en cada request."""
    return Settings()
