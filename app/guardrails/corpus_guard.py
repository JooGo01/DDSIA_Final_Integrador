"""Revision de los documentos antes de indexarlos.

Existe por una prueba que fallo. Se planto en el corpus un documento con
instrucciones escondidas y el asistente las obedecio en las tres consultas:
transcribio su prompt de sistema, recomendo deshabilitar la autenticacion
multifactor y entrego una URL a un ejecutable de un dominio falso.

La validacion de salida no podia detectarlo. Esa validacion compara la respuesta
contra el contexto recuperado, y el contenido malicioso era parte de ese contexto:
reproducirlo fielmente puntua como perfectamente fundamentado.

La frontera de confianza real es la ingesta. Un documento de referencia describe;
no da ordenes al lector ni redefine reglas. Un fragmento que si lo hace no entra
al indice.
"""

import re
from dataclasses import dataclass

# Texto que da ordenes en lugar de describir. Un documento tecnico no habla asi.
INSTRUCTION_PATTERNS = [
    re.compile(r"ignor[aáe]\w*\s+(todas?\s+)?(las\s+)?(instrucciones|reglas|indicaciones)", re.I),
    re.compile(
        r"\bignore\s+(all\s+|any\s+|previous\s+|prior\s+|the\s+)*(instructions?|rules?)", re.I
    ),
    re.compile(r"disregard\s+(all\s+|any\s+|previous\s+|prior\s+)*(instructions?|rules?)", re.I),
    re.compile(r"olvid[aáe]\w*\s+(todo|las\s+(instrucciones|reglas))", re.I),
    re.compile(r"instrucciones\s+del\s+sistema\s*:", re.I),
    re.compile(r"\b(system|developer)\s+(prompt|instructions?)\s*:", re.I),
    re.compile(r"a\s+partir\s+de\s+ahora\s+(deb[eé]s|debes|tienes\s+que|vas\s+a)", re.I),
    re.compile(r"(tus|sus)\s+respuestas\s+deben\s+(comenzar|empezar|incluir)", re.I),
    re.compile(r"from\s+now\s+on\s+you\s+(must|should|will)", re.I),
    re.compile(r"\bnew\s+(instructions?|rules?)\s*:", re.I),
    re.compile(r"</?(system|instructions?|prompt)>", re.I),
]


@dataclass(frozen=True)
class DocumentFinding:
    origin_file: str
    chunk_index: int
    pattern: str
    excerpt: str


def find_instructions(text: str) -> tuple[str, str] | None:
    """Devuelve (patron, fragmento) si el texto contiene una orden encubierta."""
    for pattern in INSTRUCTION_PATTERNS:
        match = pattern.search(text)
        if match:
            inicio = max(0, match.start() - 40)
            return pattern.pattern, text[inicio : match.end() + 60].replace("\n", " ")
    return None


def scan_chunks(chunks) -> list[DocumentFinding]:
    """Revisa los fragmentos y devuelve los que contienen instrucciones."""
    hallazgos = []
    for chunk in chunks:
        encontrado = find_instructions(chunk.text)
        if encontrado:
            patron, fragmento = encontrado
            hallazgos.append(
                DocumentFinding(
                    origin_file=chunk.origin_file,
                    chunk_index=chunk.chunk_index,
                    pattern=patron,
                    excerpt=fragmento,
                )
            )
    return hallazgos
