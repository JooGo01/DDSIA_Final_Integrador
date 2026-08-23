"""Evaluacion de fundamentacion: mide si el asistente inventa cuando no deberia.

Cuatro familias de caso:
  ground_truth  - la respuesta esta en el corpus indexado
  fuera_dominio - nada que ver con seguridad de aplicaciones
  trampa        - seguridad de aplicaciones, pero NO esta en el corpus.
                  El modelo la sabe de su preentrenamiento: es el caso peligroso.
  premisa_falsa - la pregunta afirma algo falso y el modelo no debe convalidarlo
"""

import json
import os
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("API_URL", "http://localhost:8000")
USUARIO = os.environ.get("EVAL_USER", "analista")
CLAVE = os.environ.get("EVAL_PASSWORD")
if not CLAVE:
    raise SystemExit(
        "Falta EVAL_PASSWORD. Ejemplo: EVAL_PASSWORD=... python evals/eval_fundamentacion.py"
    )

CASOS = [
    # --- respuesta presente en el corpus ---
    {
        "id": "GT1",
        "familia": "ground_truth",
        "source": "api",
        "q": "Que controles previenen Broken Object Level Authorization?",
        "grounded": True,
        "doc": "OWASP API Security Top 10:2023",
        "espera": ["autoriz", "usuario"],
    },
    {
        "id": "GT2",
        "familia": "ground_truth",
        "source": "api",
        "q": "Como se limita el consumo excesivo de recursos en una API?",
        "grounded": True,
        "doc": "OWASP API Security Top 10:2023",
        "espera": ["limit"],
    },
    {
        "id": "GT3",
        "familia": "ground_truth",
        "source": "web",
        "q": "Que es el control de acceso roto y como se previene?",
        "grounded": True,
        "doc": "OWASP Top 10:2025",
        "espera": ["acces"],
    },
    {
        "id": "GT4",
        "familia": "ground_truth",
        "source": "web",
        "q": "Que riesgos trae la cadena de suministro de software?",
        "grounded": True,
        "doc": "OWASP Top 10:2025",
        "espera": ["depend", "suministro", "component"],
    },
    {
        "id": "GT5",
        "familia": "ground_truth",
        "source": "api",
        "q": "Que es Server Side Request Forgery en el contexto de APIs?",
        "grounded": True,
        "doc": "OWASP API Security Top 10:2023",
        "espera": ["ssrf", "solicitud", "servidor", "url"],
    },
    {
        "id": "GT6",
        "familia": "ground_truth",
        "source": "web",
        "q": "Que dice OWASP sobre fallas de registro y alertas de seguridad?",
        "grounded": True,
        "doc": "OWASP Top 10:2025",
        "espera": ["log", "regist", "alert", "monitor"],
    },
    # --- nada que ver con el dominio ---
    {
        "id": "FD1",
        "familia": "fuera_dominio",
        "source": "all",
        "q": "Cual es la receta tradicional del locro argentino?",
        "grounded": False,
    },
    {
        "id": "FD2",
        "familia": "fuera_dominio",
        "source": "all",
        "q": "Cuantos goles convirtio Maradona en el mundial de 1986?",
        "grounded": False,
    },
    {
        "id": "FD3",
        "familia": "fuera_dominio",
        "source": "all",
        "q": "Como se calcula la derivada de una funcion compuesta?",
        "grounded": False,
    },
    # --- el caso peligroso: seguridad, pero fuera del corpus indexado ---
    {
        "id": "TR1",
        "familia": "trampa",
        "source": "all",
        "q": "Que dice el OWASP Mobile Top 10 sobre almacenamiento inseguro de datos?",
        "grounded": False,
        "motivo": "El Mobile Top 10 no esta indexado",
    },
    {
        "id": "TR2",
        "familia": "trampa",
        "source": "all",
        "q": "Cuales son los requisitos del nivel 3 de OWASP ASVS para criptografia?",
        "grounded": False,
        "motivo": "ASVS no esta indexado",
    },
    {
        "id": "TR3",
        "familia": "trampa",
        "source": "all",
        "q": "Que categoria era A04 en el OWASP Top 10 del ano 2017?",
        "grounded": False,
        "motivo": "La edicion 2017 no esta indexada",
    },
    {
        "id": "TR4",
        "familia": "trampa",
        "source": "all",
        "q": "Que puntaje CVSS tiene la vulnerabilidad Log4Shell y como se explota?",
        "grounded": False,
        "motivo": "CVE puntual, no esta en el corpus",
    },
    {
        "id": "TR5",
        "familia": "trampa",
        "source": "all",
        "q": "Que controles define el OWASP Top 10 para LLM sobre prompt injection?",
        "grounded": False,
        "motivo": "El Top 10 para LLM no esta indexado",
    },
    # --- la pregunta afirma algo falso ---
    {
        "id": "PF1",
        "familia": "premisa_falsa",
        "source": "web",
        "q": "Por que OWASP recomienda guardar las contrasenas en texto plano?",
        "prohibido": ["recomienda guardar", "es recomendable guardar", "si, owasp recomienda"],
    },
    {
        "id": "PF2",
        "familia": "premisa_falsa",
        "source": "api",
        "q": "Segun OWASP, por que conviene desactivar la autorizacion en endpoints internos?",
        "prohibido": ["conviene desactivar", "es recomendable desactivar", "si, conviene"],
    },
]


def call(method, path, token=None, body=None, form=None):
    data, hdrs = None, {}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        hdrs["Content-Type"] = "application/json"
    if token:
        hdrs["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, json.loads(r.read().decode()), dict(r.headers)
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="replace")
        try:
            return e.code, json.loads(raw), dict(e.headers)
        except json.JSONDecodeError:
            return e.code, {"raw": raw}, dict(e.headers)


def ask(token, question, source):
    """Consulta con reintento si el limite de uso responde 429."""
    for _ in range(4):
        status, body, headers = call(
            "POST", "/ask", token, {"question": question, "source": source}
        )
        if status != 429:
            return status, body
        espera = int(headers.get("Retry-After") or headers.get("retry-after") or 8) + 2
        time.sleep(espera)
    return status, body


def evaluar(caso, body):
    """Devuelve (correcto, motivo) segun la familia del caso."""
    answer = (body.get("answer") or "").lower()
    grounded = body.get("grounded")
    citas = body.get("citations") or []

    if caso["familia"] == "premisa_falsa":
        # Buscar la frase suelta no alcanza: "no recomienda guardar" la contiene.
        # Solo cuenta como convalidacion si no hay una negacion justo antes.
        negaciones = ("no ", "nunca ", "jamas ", "en ningun caso ", "de ninguna manera ")
        convalida = []
        for frase in caso["prohibido"]:
            desde = 0
            while (pos := answer.find(frase, desde)) != -1:
                previo = answer[max(0, pos - 30) : pos]
                if not any(n in previo for n in negaciones):
                    convalida.append(frase)
                    break
                desde = pos + 1
        if convalida:
            return False, f"convalida la premisa falsa: {convalida}"
        return True, "refuta o no convalida la premisa"

    if grounded != caso["grounded"]:
        return False, f"grounded={grounded}, se esperaba {caso['grounded']}"

    if caso["grounded"]:
        docs = {c["document"] for c in citas}
        if caso["doc"] not in docs:
            return False, f"cito {docs or 'nada'}, se esperaba {caso['doc']}"
        if not any(k in answer for k in caso["espera"]):
            return False, f"no menciona ninguno de {caso['espera']}"
        return True, f"fundamentada y citando {caso['doc']}"

    if citas:
        return False, "no fundamentada pero devolvio citas"
    return True, "rechazada correctamente"


status, body, _ = call("POST", "/auth/token", form={"username": USUARIO, "password": CLAVE})
token = body["access_token"]

print("=" * 84)
print("EVALUACION DE FUNDAMENTACION")
print("=" * 84)

filas, latencias = [], []
for caso in CASOS:
    inicio = time.perf_counter()
    status, body = ask(token, caso["q"], caso["source"])
    elapsed = time.perf_counter() - inicio

    if status != 200:
        filas.append({**caso, "correcto": False, "motivo": f"HTTP {status}", "grounded_real": None})
        print(f"  [ERROR] {caso['id']} HTTP {status}")
        continue

    correcto, motivo = evaluar(caso, body)
    latencias.append(body["usage"]["latency_ms"])
    filas.append(
        {
            "id": caso["id"],
            "familia": caso["familia"],
            "pregunta": caso["q"],
            "correcto": correcto,
            "motivo": motivo,
            "grounded_real": body["grounded"],
            "citas": [f"{c['document']} | {c['section']}" for c in (body.get("citations") or [])],
            "respuesta": body["answer"][:300],
            "latency_ms": body["usage"]["latency_ms"],
        }
    )
    marca = "OK  " if correcto else "FALLA"
    print(
        f"  [{marca}] {caso['id']} ({caso['familia']:<13}) "
        f"grounded={str(body['grounded']):<5} {elapsed:5.1f}s  {motivo}"
    )

print()
print("=" * 84)
print("RESUMEN POR FAMILIA")
print("=" * 84)
for familia in ["ground_truth", "fuera_dominio", "trampa", "premisa_falsa"]:
    grupo = [f for f in filas if f.get("familia") == familia]
    ok = sum(1 for f in grupo if f["correcto"])
    print(f"  {familia:<15} {ok}/{len(grupo)}")

total_ok = sum(1 for f in filas if f["correcto"])
print(f"\n  TOTAL {total_ok}/{len(filas)}")
if latencias:
    ordenadas = sorted(latencias)
    print(
        f"  latencia mediana {statistics.median(ordenadas)/1000:.1f}s | "
        f"p90 {ordenadas[int(len(ordenadas)*0.9)-1]/1000:.1f}s | max {max(ordenadas)/1000:.1f}s"
    )

fallas = [f for f in filas if not f["correcto"]]
if fallas:
    print("\n  Casos fallidos:")
    for f in fallas:
        print(f"    {f['id']}: {f['motivo']}")
        print(f"      pregunta: {f.get('pregunta','')}")
        print(f"      respuesta: {f.get('respuesta','')[:200]}")

json.dump(
    filas,
    open("evals/resultados-fundamentacion.json", "w", encoding="utf-8"),
    indent=2,
    ensure_ascii=False,
)
