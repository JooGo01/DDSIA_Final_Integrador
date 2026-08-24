"""Control de alcance: rechaza preguntas sobre documentos que no estan indexados.

Existe por un resultado medido. Las preguntas sobre otros documentos de OWASP
("que dice el Mobile Top 10", "que era A04 en 2017") recuperan fragmentos del
corpus real con buena similitud, porque hablan del mismo tema, y el modelo las
contesta de memoria. Ni el umbral de recuperacion ni el de fundamentacion las
separan: en la medicion, esas preguntas puntuaron entre 0.61 y 0.78, y una
pregunta legitima puntuo 0.49.

Como el corpus tiene un alcance fijo y conocido, la comprobacion se hace por
codigo antes de recuperar nada.
"""

import re
from dataclasses import dataclass

# Lo unico que el indice contiene.
CORPUS_SCOPE = "OWASP Top 10:2025 y OWASP API Security Top 10:2023"

# Otros proyectos de OWASP que la gente confunde con los dos indexados.
OTHER_OWASP_PROJECTS = re.compile(
    r"\b("
    r"mobile\s*(app\s*)?(security\s*)?top\s*10|masvs|mstg"
    r"|asvs|samm|wstg|proactive\s*controls"
    r"|top\s*10\s*(for|para|de)\s*(llm|large\s*language)"
    r"|llm\s*top\s*10|genai\s*top\s*10"
    r"|kubernetes\s*top\s*10|docker\s*top\s*10|serverless\s*top\s*10"
    r"|cheat\s*sheet|dependency[-\s]?check|juice\s*shop|zap"
    r")\b",
    re.IGNORECASE,
)

# Una edicion distinta a las indexadas.
OTHER_EDITIONS = re.compile(
    r"\b(top\s*10|owasp)\b[^.?!]{0,40}\b(2003|2004|2007|2010|2013|2017|2021)\b"
    r"|\b(2003|2004|2007|2010|2013|2017|2021)\b[^.?!]{0,40}\b(top\s*10|owasp)\b",
    re.IGNORECASE,
)

# Vulnerabilidades puntuales: el corpus describe categorias, no CVE concretos.
SPECIFIC_CVES = re.compile(
    r"\b(cve-\d{4}-\d{4,}|log4shell|heartbleed|shellshock|spectre|meltdown"
    r"|struts2?|eternalblue|dirty\s*cow|xz\s*utils)\b",
    re.IGNORECASE,
)

# Categorias que no existen. Los identificadores que los documentos indexados
# contienen son A01:2025 a A10:2025 y API1:2023 a API10:2023, verificado sobre el
# corpus. Preguntar por una que este por encima recupera igual la categoria mas
# parecida, con buena similitud, y el modelo describe la inventada con ese material:
# el umbral de fundamentacion no la separa porque el contexto recuperado es real.
INVENTED_CATEGORIES = re.compile(
    r"\bA0?(1[1-9]|[2-9]\d)\b(\s*:\s*20\d\d)?" r"|\bAPI\s*(1[1-9]|[2-9]\d)\b(\s*:\s*20\d\d)?",
    re.IGNORECASE,
)

# Ninguno de los dos documentos tiene anexos ni apendices, tambien verificado sobre
# el corpus. Preguntar por "el Anexo B" invita a completar una seccion inexistente.
NONEXISTENT_SECTIONS = re.compile(
    r"\b(anexo|ap[eé]ndice|appendix|annex)\s+[a-z0-9]\b",
    re.IGNORECASE,
)

OUT_OF_SCOPE_CHECKS = (
    ("otro_proyecto_owasp", OTHER_OWASP_PROJECTS),
    ("otra_edicion", OTHER_EDITIONS),
    ("cve_puntual", SPECIFIC_CVES),
    ("categoria_inexistente", INVENTED_CATEGORIES),
    ("seccion_inexistente", NONEXISTENT_SECTIONS),
)


@dataclass(frozen=True)
class ScopeResult:
    in_scope: bool
    reason: str = ""


def check_scope(question: str) -> ScopeResult:
    """Decide si la pregunta cae dentro de lo que el corpus puede responder."""
    for reason, pattern in OUT_OF_SCOPE_CHECKS:
        if pattern.search(question):
            return ScopeResult(False, reason)
    return ScopeResult(True)


def out_of_scope_answer(reason: str) -> str:
    """Mensaje que explica por que no se responde, sin consultar al modelo."""
    detalle = {
        "otro_proyecto_owasp": "ese documento de OWASP no forma parte del corpus indexado",
        "otra_edicion": "solo estan indexadas las ediciones 2025 y 2023",
        "cve_puntual": "el corpus describe categorias de riesgo, no vulnerabilidades puntuales",
        "categoria_inexistente": (
            "esa categoria no existe. El Top 10:2025 va de A01 a A10 y el "
            "API Security Top 10:2023 va de API1 a API10"
        ),
        "seccion_inexistente": "ninguno de los dos documentos tiene anexos ni apendices",
    }.get(reason, "la consulta queda fuera del alcance del corpus")
    return f"No puedo responder eso: {detalle}. " f"Este asistente solo cubre {CORPUS_SCOPE}."
