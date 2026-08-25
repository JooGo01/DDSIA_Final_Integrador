"""Texto que intenta reescribir las reglas del sistema, en un solo lugar.

Esta familia de patrones se evalua en dos capas con proposito distinto: sobre la
pregunta que manda el usuario y sobre los documentos que entran al indice. Vivia
duplicada en `input_guard` y en `corpus_guard`, y las dos copias se separaron.

El agujero que produjo esa separacion: la version de `input_guard` contemplaba el
articulo pero no el cuantificador, y la de `corpus_guard` si. Con lo cual

    Ignora las instrucciones anteriores      -> bloqueada como pregunta
    Ignora todas las instrucciones anteriores -> aceptada como pregunta

y esa misma frase, dentro de un documento, si se rechazaba. Dos capas del mismo
sistema no pueden estar en desacuerdo sobre que es un ataque, asi que la lista pasa
a ser una sola. Lo especifico de cada capa —jailbreak y pedido de datos personales en
la entrada, marcadores de documento en la ingesta— sigue en su modulo.
"""

import re

# Ordenes que buscan anular lo que el sistema ya tiene definido.
#
# El cuantificador va como grupo repetible en vez de una alternativa fija porque las
# variantes se encadenan: "ignora todas las reglas", "descarta por completo cualquier
# instruccion previa". Enumerar cada combinacion es lo que dejo el hueco original.
OVERRIDE_INSTRUCTIONS = [
    re.compile(
        r"\b(ignor|descart|desatend)[aáeo]\w*\s+"
        r"(por\s+completo\s+)?(todas?\s+|cualquier\s+|las\s+|los\s+|mis\s+|tus\s+)*"
        r"(instruccion\w*|regla\w*|indicacion\w*|directiva\w*)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bolvid[aáe]\w*\s+"
        r"(todo\b|lo\s+anterior|(todas?\s+|las\s+|tus\s+)*(instruccion\w*|regla\w*|indicacion\w*))",
        re.IGNORECASE,
    ),
    re.compile(
        r"\bno\s+(tengas?\s+en\s+cuenta|hagas?\s+caso\s+(a|de))\s+"
        r"(todas?\s+|las\s+|tus\s+|mis\s+)*(instruccion\w*|regla\w*|indicacion\w*)",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(ignore|disregard|forget|override|bypass)\s+"
        r"(all\s+|any\s+|previous\s+|prior\s+|the\s+|your\s+|above\s+|earlier\s+)*"
        r"(instructions?|rules?|directives?|prompts?)",
        re.IGNORECASE,
    ),
    re.compile(r"instrucciones\s+del\s+sistema\s*:", re.IGNORECASE),
    re.compile(r"\b(system|developer)\s+(prompt|instructions?)\s*:", re.IGNORECASE),
    re.compile(
        r"a\s+partir\s+de\s+ahora\s+(deb[eé]s|debes|tienes\s+que|vas\s+a|sos|eres)",
        re.IGNORECASE,
    ),
    re.compile(r"(tus|sus)\s+respuestas\s+deben\s+(comenzar|empezar|incluir)", re.IGNORECASE),
    re.compile(r"from\s+now\s+on\s+you\s+(must|should|will|are)", re.IGNORECASE),
    re.compile(r"\bnew\s+(instructions?|rules?)\s*:", re.IGNORECASE),
    re.compile(r"</?(system|instructions?|prompt)>", re.IGNORECASE),
]
