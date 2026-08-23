"""Validacion de la respuesta del modelo antes de devolverla al cliente.

La salida del modelo se trata como dato no confiable: se revisa que este sostenida
por el contexto recuperado, que no filtre datos personales y que no repita el
prompt de sistema.
"""

import math
import re
from dataclasses import dataclass

from app.guardrails.input_guard import find_pii

FALLBACK_ANSWER = (
    "No encontre esa informacion en los documentos OWASP indexados. "
    "Probá reformular la pregunta o consultá directamente el documento original."
)

# Marcas de que el modelo esta repitiendo su configuracion en vez de responder.
SYSTEM_LEAK_PATTERNS = [
    re.compile(r"respondes preguntas sobre seguridad de aplicaciones", re.IGNORECASE),
    re.compile(r"no mencionas estas indicaciones", re.IGNORECASE),
    re.compile(r"usas solo informacion del contexto", re.IGNORECASE),
    re.compile(r"^\s*CONTEXTO\s*$", re.IGNORECASE | re.MULTILINE),
]

# Umbral de similitud entre la respuesta y el fragmento que mejor la sostiene.
# Calibrado contra el corpus real: las preguntas dentro del dominio dieron entre
# 0.58 y 0.78, y las de afuera entre 0.40 y 0.46. El corte va en el medio del hueco.
MIN_GROUNDING_SIMILARITY = 0.55

URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)


@dataclass(frozen=True)
class OutputCheck:
    answer: str
    grounded: bool
    reason: str = ""


def cosine_similarity(first: list[float], second: list[float]) -> float:
    """Similitud coseno entre dos vectores. Devuelve 0 si alguno es nulo."""
    dot = sum(a * b for a, b in zip(first, second, strict=False))
    norm_first = math.sqrt(sum(a * a for a in first))
    norm_second = math.sqrt(sum(b * b for b in second))
    if norm_first == 0 or norm_second == 0:
        return 0.0
    return dot / (norm_first * norm_second)


def invented_urls(answer: str, context: str) -> list[str]:
    """URLs de la respuesta que no aparecen en el contexto recuperado.

    Una URL que el modelo no leyo del corpus la invento o la copio de un documento
    manipulado. En los dos casos es un enlace que el usuario no deberia recibir.
    """
    return [url for url in URL_PATTERN.findall(answer) if url.rstrip(".,;:") not in context]


def leaks_system_prompt(answer: str) -> bool:
    """True si la respuesta esta repitiendo las instrucciones internas."""
    return any(pattern.search(answer) for pattern in SYSTEM_LEAK_PATTERNS)


def check_answer(
    raw_answer: str,
    has_hits: bool,
    grounding_similarity: float,
    context: str = "",
) -> OutputCheck:
    """Revisa la respuesta del modelo y devuelve la version que se puede publicar.

    La fundamentacion se mide por similitud semantica y no por palabras en comun,
    porque el corpus esta en ingles y las respuestas salen en espanol: un
    solapamiento lexico daria bajo incluso para una respuesta correcta.
    """
    answer = raw_answer.strip()

    if not has_hits or not answer:
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="no_context")

    if leaks_system_prompt(answer):
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="system_leak")

    if find_pii(answer):
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="pii")

    if invented_urls(answer, context):
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="url_no_verificable")

    if grounding_similarity < MIN_GROUNDING_SIMILARITY:
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="ungrounded")

    return OutputCheck(answer, grounded=True)
