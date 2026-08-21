"""Validacion de la pregunta antes de mandarla al modelo.

Esto es defensa en profundidad, no el control principal. Lo que realmente contiene
el riesgo es que el servicio sea de solo lectura, no exponga herramientas y valide
la salida. Un filtro de patrones nunca cubre todas las variantes.
"""

import re
from dataclasses import dataclass

# Frases que intentan reescribir las reglas del sistema.
INJECTION_PATTERNS = [
    re.compile(r"ignor[aáe]\w*\s+(las\s+)?(instrucciones|reglas|indicaciones)", re.IGNORECASE),
    re.compile(r"ignore\s+(all\s+|previous\s+|prior\s+)+(instructions|rules)", re.IGNORECASE),
    re.compile(r"olvid[aáe]\w*\s+(todo|las\s+instrucciones)", re.IGNORECASE),
    re.compile(r"(system|developer)\s*(prompt|message)", re.IGNORECASE),
    re.compile(
        r"(mostr|revel|imprim|repet|divulg|list)\w*\s+.{0,25}"
        r"(instruccion|prompt|configuraci[oó]n|reglas internas)",
        re.IGNORECASE,
    ),
    re.compile(r"act[uú]a\s+como\s+(si\s+)?(no\s+tuvieras|otro)", re.IGNORECASE),
    re.compile(r"\bDAN\b|\bjailbreak\b|modo\s+desarrollador", re.IGNORECASE),
    re.compile(r"</?(system|instructions?)>", re.IGNORECASE),
]

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
