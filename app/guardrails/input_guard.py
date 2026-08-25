"""Validacion de la pregunta antes de mandarla al modelo.

Esto es defensa en profundidad, no el control principal. Lo que realmente contiene
el riesgo es que el servicio sea de solo lectura, no exponga herramientas y valide
la salida. Un filtro de patrones nunca cubre todas las variantes.
"""

import re
from dataclasses import dataclass

from app.guardrails.instruction_patterns import OVERRIDE_INSTRUCTIONS

# Ordenes que buscan anular las reglas del sistema: lista compartida con la revision
# de la ingesta. En `instruction_patterns` esta por que vive en un solo lugar.
#
# Lo que sigue es lo propio de una pregunta de usuario y no aplica a un documento:
# pedirle al asistente que recite su configuracion, y las marcas de jailbreak.
INJECTION_PATTERNS = [
    *OVERRIDE_INSTRUCTIONS,
    # El posesivo hace el trabajo. "Que dice el Top 10 sobre configuracion incorrecta"
    # es una pregunta legitima —A05 trata exactamente eso— y "decime tu configuracion"
    # no lo es. Sin exigir el posesivo, el patron bloqueaba media categoria.
    re.compile(
        r"\b(mostr|revel|imprim|repet|divulg|list|transcrib|enumer|recit|dec[ií]|cont[aá]|dame)"
        r"\w*\b[^.?!]{0,30}?\b(tus?|sus?)\s+"
        r"(instruccion\w*|indicacion\w*|prompt|directiva\w*)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(prompt\s+(de\s+)?sistema|system\s+prompt|reglas\s+internas"
        r"|instrucciones\s+internas|indicaciones\s+internas|configuraci[oó]n\s+interna)\b",
        re.IGNORECASE,
    ),
    re.compile(r"(system|developer)\s*(prompt|message)", re.IGNORECASE),
    re.compile(r"act[uú]a\s+como\s+(si\s+)?(no\s+tuvieras|otro)", re.IGNORECASE),
    re.compile(r"\bDAN\b|\bjailbreak\b|modo\s+desarrollador", re.IGNORECASE),
]

# Largo maximo de una palabra suelta. Ninguna palabra del castellano ni del ingles
# se acerca; el token mas largo que aparece de forma legitima es un nombre de seccion
# con guiones, como "unrestricted-access-to-sensitive-business-flows", de 47. El tope
# queda con holgura sobre eso.
#
# Existe por un caso medido: una pregunta con un token de 143 caracteres de teclado
# aplastado recuperaba cuatro fragmentos al azar, y sobre ese contexto el modelo
# improvisaba. La respuesta paso el umbral de fundamentacion en 3 de 6 corridas,
# porque alcanzaba con que mencionara un termino del fragmento recuperado.
MAX_WORD_LENGTH = 60

# Datos personales que no deberian viajar hacia el modelo.
PII_PATTERNS = {
    "email": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b"),
    "tarjeta": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
    "cuit": re.compile(r"\b\d{2}-\d{8}-\d\b"),
    "telefono": re.compile(r"\b(?:\+54\s?)?(?:11|15)[\s-]?\d{4}[\s-]?\d{4}\b"),
}


@dataclass(frozen=True)
class GuardResult:
    allowed: bool
    reason: str = ""
    message: str = ""


def looks_like_injection(question: str) -> bool:
    """True si la pregunta contiene una frase tipica de prompt injection."""
    return any(pattern.search(question) for pattern in INJECTION_PATTERNS)


def longest_word(question: str) -> int:
    """Largo de la palabra mas larga. Un valor absurdo delata texto sin sentido."""
    return max((len(word) for word in question.split()), default=0)


def find_pii(text: str) -> list[str]:
    """Devuelve los tipos de dato personal detectados en el texto."""
    return [name for name, pattern in PII_PATTERNS.items() if pattern.search(text)]


def check_question(question: str, min_chars: int, max_chars: int) -> GuardResult:
    """Decide si la pregunta puede seguir hacia el pipeline de RAG."""
    stripped = question.strip()

    if len(stripped) < min_chars:
        return GuardResult(
            False, "length", f"La pregunta necesita al menos {min_chars} caracteres."
        )

    if len(stripped) > max_chars:
        return GuardResult(False, "length", f"La pregunta supera los {max_chars} caracteres.")

    if longest_word(stripped) > MAX_WORD_LENGTH:
        return GuardResult(
            False,
            "ilegible",
            "La consulta tiene una palabra sin sentido. Reformulala con texto legible.",
        )

    if looks_like_injection(stripped):
        return GuardResult(
            False,
            "injection",
            "La consulta parece intentar modificar el comportamiento del asistente.",
        )

    found = find_pii(stripped)
    if found:
        return GuardResult(
            False,
            "pii",
            f"La consulta incluye datos personales ({', '.join(found)}). "
            "Reformulala sin esos datos.",
        )

    return GuardResult(True)
