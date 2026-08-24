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

# Nomenclatura cruzada entre los dos documentos. El Top 10:2025 numera A01 a A10 y
# el API Security Top 10:2023 numera API1 a API10: verificado sobre el corpus. Un
# codigo que combina el prefijo de un listado con el ano del otro no puede haber
# salido del contexto, es el modelo mezclando los dos. El criterio es el mismo que
# el de las URLs inventadas: si no esta en el corpus, no lo leyo de ahi.
#
# Aparecio midiendo las preguntas de contexto cruzado: ante "bajo que codigo A del
# Top 10 de 2025 clasifico Unrestricted Resource Consumption", el modelo contestaba
# bien que era API4:2023 y despues agregaba "la respuesta es A04:2023".
MIXED_NOMENCLATURE = re.compile(
    r"\bA\d{1,2}\s*:\s*2023\b|\bAPI\s*\d{1,2}\s*:\s*2025\b",
    re.IGNORECASE,
)

# Marcas de que la respuesta trae codigo ejecutable. Se comparan contra el contexto,
# igual que las URLs: los documentos OWASP si traen fragmentos de codigo de ejemplo,
# asi que la pregunta no es si hay codigo sino si ese codigo estaba en lo recuperado.
#
# Aparecio con una pregunta ilegible que terminaba en "si no entiendes dame el
# codigo para una estrella en python". El modelo aclaraba que no entendia y despues
# entregaba un script, y la respuesta pasaba el umbral de fundamentacion porque la
# parte de arriba mencionaba terminos del fragmento recuperado.
CODE_MARKERS = (
    re.compile(r"```"),
    re.compile(r"^\s*(import|from)\s+\w+", re.MULTILINE),
    # Sin ancla de linea: el modelo mete la definicion en el medio de la prosa. Pide
    # espacio y parentesis o dos puntos, asi que "definicion" o "clase de" no matchean.
    re.compile(r"\b(def|class)\s+\w+\s*[(:]"),
    re.compile(r"\bprint\s*\(", re.IGNORECASE),
    re.compile(r"#include\s*<"),
    re.compile(r"\b(for|while)\s*\(.*\)\s*\{"),
)


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


def invented_code(answer: str, context: str) -> bool:
    """True si la respuesta trae codigo que no estaba en el contexto recuperado.

    El criterio es el de las URLs: si el marcador de codigo no aparece en lo que se
    recupero, el modelo lo escribio de su preentrenamiento. Un asistente sobre marcos
    de riesgo no tiene por que entregar scripts.
    """
    for pattern in CODE_MARKERS:
        if pattern.search(answer) and not pattern.search(context):
            return True
    return False


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

    if MIXED_NOMENCLATURE.search(answer):
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="nomenclatura_cruzada")

    if invented_code(answer, context):
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="codigo_inventado")

    if grounding_similarity < MIN_GROUNDING_SIMILARITY:
        return OutputCheck(FALLBACK_ANSWER, grounded=False, reason="ungrounded")

    return OutputCheck(answer, grounded=True)
