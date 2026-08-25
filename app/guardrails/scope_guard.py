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
#
# Struts salio de la lista. Es un componente que A06 usa como ejemplo de dependencia
# desactualizada, asi que "componentes vulnerables como Struts" es una pregunta que el
# corpus si responde. Se pierde el caso de quien pregunta como parchear Struts, que
# igual cae por otra via si nombra un CVE.
SPECIFIC_CVES = re.compile(
    r"\b(cve-\d{4}-\d{4,}|log4shell|heartbleed|shellshock|spectre|meltdown"
    r"|eternalblue|dirty\s*cow|xz\s*utils)\b",
    re.IGNORECASE,
)

# Categorias que no existen. Los identificadores que los documentos indexados
# contienen son A01:2025 a A10:2025 y API1:2023 a API10:2023, verificado sobre el
# corpus. Preguntar por una que este por encima recupera igual la categoria mas
# parecida, con buena similitud, y el modelo describe la inventada con ese material:
# el umbral de fundamentacion no la separa porque el contexto recuperado es real.
# El separador es la parte delicada. La version anterior exigia los digitos pegados a
# la A y toleraba espacio despues de API, y esa asimetria era el bypass: "A11" se
# rechazaba y "A 11" pasaba.
#
# No se puede aceptar el espacio en general, porque en castellano "a" mas numero es
# una preposicion corriente: "afecta a 20 endpoints" quedaria bloqueada. Por eso el
# espacio se admite solo cuando la pregunta presenta el identificador como categoria.
INVENTED_CATEGORIES = re.compile(
    # A11, A-11, A_11, A.11 y sus variantes con anio
    r"\bA[._-]?0?(1[1-9]|[2-9]\d)\b(\s*:\s*20\d\d)?"
    # Tres digitos o mas: A100
    r"|\bA[._-]?\d{3,}\b"
    # Subcategorias que no existen: A10.1
    r"|\bA[._-]?(0?[1-9]|10)\.\d\b"
    # API11, API-11, API 11
    r"|\bAPI[\s._-]?(1[1-9]|[2-9]\d)\b(\s*:\s*20\d\d)?"
    r"|\bAPI[\s._-]?\d{3,}\b"
    # Con espacio, solo si viene presentado como categoria
    r"|\b(categor[ií]a|riesgo|vulnerabilidad|secci[oó]n|item)\s+A\s*0?(1[1-9]|[2-9]\d)\b",
    re.IGNORECASE,
)

# Ninguno de los dos documentos tiene anexos ni apendices, tambien verificado sobre
# el corpus. Preguntar por "el Anexo B" invita a completar una seccion inexistente.
#
# El identificador es opcional a proposito: como no existe ningun anexo, "el apendice
# tecnico" o "los anexos" son igual de inventados que "el Anexo B". La version
# anterior exigia exactamente un caracter y dejaba pasar "Anexo 12" y "Anexo II".
NONEXISTENT_SECTIONS = re.compile(
    r"\b(anexos?|ap[eé]ndices?|appendix|appendices|annexe?s?)\b(\s*[-:]?\s*[a-z0-9ivx]{1,4}\b)?",
    re.IGNORECASE,
)

# Pedidos de codigo. Los documentos describen riesgos y controles: no traen scripts
# ni exploits, asi que un pedido de codigo no se puede responder desde el corpus.
#
# El patron exige un verbo de pedido y despues el sustantivo. La forma suelta
# ("codigo de", "codigo para") no sirve: aparece en preguntas legitimas como
# "que dice OWASP sobre la revision de codigo de terceros".
# El 0 alterna con la o porque el caso que lo motivo escribia "k0digo".
#
# Tres cosas que la version anterior no cubria:
#
# 1. Los encliticos. "dame" no matchea dentro de "darme", asi que "podrias darme el
#    codigo" pasaba mientras "dame el codigo" se bloqueaba.
# 2. El pedido en ingles, que no estaba.
# 3. La ventana de 30 caracteres se queda corta en pedidos con subordinada
#    ("necesito que me proporciones un ejemplo funcional en Python de un exploit").
#
# Y en sentido inverso: "necesito" y "quiero" sueltos bloqueaban preguntas legitimas
# como "necesito saber que dice OWASP sobre codigo seguro", porque ahi el verbo
# introduce una consulta, no un pedido de artefacto. Se los condiciona en vez de
# sacarlos, para no perder "necesito el codigo de un exploit".
CODE_REQUEST = re.compile(
    r"\b("
    r"dame|damelo|d[aá]rme\w*|pasame|pas[aá]me|escrib[ií]\w*|escribe|genera\w*"
    r"|h[aá]ce?me|hazme|mostrame|mostr[aá]me|muestrame|mu[eé]strame"
    r"|proporcion\w*|brind\w*|redact\w*|desarroll[aá]\w*|prepar[aá]\w*|arm[aá]\w*"
    r"|write|give|show|provide|craft"
    r"|(?:necesito|quiero|quisiera)(?!\s+(?:saber|entender|conocer|comprender|leer))"
    r")\b[^.?!]{0,60}?\b([ck][o0ó]digo|code|script|programa|exploit|payload|one[-\s]?liner)\b",
    re.IGNORECASE,
)

# Un pedido de codigo tambien puede venir sin verbo de pedido, planteado como una
# pregunta de forma: "como seria un payload de inyeccion SQL".
CODE_SHAPE_REQUEST = re.compile(
    r"\bc[oó]mo\s+(seria|ser[ií]a|se\s+ver[ií]a|luce|escribo|escribir[ií]a|hago|har[ií]a)\b"
    r"[^.?!]{0,40}?\b([ck][o0ó]digo|code|script|programa|exploit|payload)\b",
    re.IGNORECASE,
)

# El orden decide el motivo que se le informa al usuario, no si se bloquea. Los CVE
# van antes que las ediciones porque el anio del identificador cae dentro de la
# ventana de OTHER_EDITIONS: "CVE-2021-44228 en terminos del Top 10 2025" se
# rechazaba con el motivo equivocado, y el mensaje que recibia el usuario no aplicaba.
OUT_OF_SCOPE_CHECKS = (
    ("otro_proyecto_owasp", OTHER_OWASP_PROJECTS),
    ("cve_puntual", SPECIFIC_CVES),
    ("otra_edicion", OTHER_EDITIONS),
    ("categoria_inexistente", INVENTED_CATEGORIES),
    ("seccion_inexistente", NONEXISTENT_SECTIONS),
    ("pedido_de_codigo", CODE_REQUEST),
    ("pedido_de_codigo", CODE_SHAPE_REQUEST),
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
        "pedido_de_codigo": (
            "los documentos describen riesgos y controles, no traen codigo ni scripts"
        ),
    }.get(reason, "la consulta queda fuera del alcance del corpus")
    return f"No puedo responder eso: {detalle}. " f"Este asistente solo cubre {CORPUS_SCOPE}."
