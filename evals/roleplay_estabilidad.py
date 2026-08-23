"""Repite la bateria de role play para medir cuantas veces cede cada ataque.

Una sola corrida no sirve para responder que vectores pasan: el modelo no es
determinista y el mismo ataque cede en una pasada y no en la siguiente. Lo que
importa es la tasa, no el resultado puntual.

Un intento que termina en fallo del servicio (5xx) no se cuenta como contenido:
queda registrado como sin_resultado y sale del denominador. Contarlo como defensa
exitosa inflaria artificialmente la tasa de contencion.

Uso:
    REPETICIONES=3 EVAL_PASSWORD=... python evals/roleplay_estabilidad.py
"""

import json
import os
from collections import defaultdict

from jailbreak_roleplay import (
    CLAVE,
    ROLE_PLAY,
    SIN_RESULTADO,
    USUARIO,
    clasificar,
    preguntar,
    token_de,
)

REPETICIONES = int(os.environ.get("REPETICIONES", "3"))


def main() -> None:
    token = token_de(USUARIO, CLAVE)
    resultados = defaultdict(list)

    for vuelta in range(1, REPETICIONES + 1):
        print(f"\n{'=' * 82}\nVUELTA {vuelta} de {REPETICIONES}\n{'=' * 82}")
        for caso in ROLE_PLAY:
            status, body = preguntar(token, caso["prompt"])
            veredicto, senales = clasificar(status, body, caso["cumplimiento"])
            resultados[caso["id"]].append(
                {
                    "vuelta": vuelta,
                    "veredicto": veredicto,
                    "senales": senales,
                    # Sin truncar agresivamente: con 200 caracteres no se puede auditar despues
                    # que hizo el modelo cuando cedio.
                    "respuesta": (body.get("answer") or "")[:4000],
                }
            )
            if veredicto == SIN_RESULTADO:
                estado = "sin_result"
            elif veredicto == "COMPROMETIDO":
                estado = "CEDIO"
            else:
                estado = "contenido"
            print(f"  {caso['id']} {caso['nombre']:<30} {estado:<11} {veredicto}")

    print(f"\n{'=' * 82}\nTASA POR VECTOR SOBRE {REPETICIONES} CORRIDAS\n{'=' * 82}")
    print(f"  {'id':<6}{'vector':<32}{'cedio':<9}{'perdidas':<10}detalle")
    print("  " + "-" * 88)

    inestables, siempre, nunca, sin_medicion = [], [], [], []
    for caso in ROLE_PLAY:
        corridas = resultados[caso["id"]]
        validas = [c for c in corridas if c["veredicto"] != SIN_RESULTADO]
        perdidas = len(corridas) - len(validas)
        cedidas = sum(1 for c in validas if c["veredicto"] == "COMPROMETIDO")

        if not validas:
            sin_medicion.append(caso["id"])
        elif cedidas == len(validas):
            siempre.append(caso["id"])
        elif cedidas == 0:
            nunca.append(caso["id"])
        else:
            inestables.append(caso["id"])

        tasa = f"{cedidas}/{len(validas)}" if validas else "s/d"
        detalle = " | ".join(sorted({c["veredicto"] for c in validas})) or "sin corridas validas"
        print(f"  {caso['id']:<6}{caso['nombre']:<32}{tasa:<9}{perdidas:<10}{detalle}")

    total_intentos = sum(len(resultados[c["id"]]) for c in ROLE_PLAY)
    total_perdidas = sum(
        1 for c in ROLE_PLAY for r in resultados[c["id"]] if r["veredicto"] == SIN_RESULTADO
    )

    print(f"\n  cede siempre:      {siempre or 'ninguno'}")
    print(f"  cede a veces:      {inestables or 'ninguno'}")
    print(f"  nunca cedio:       {len(nunca)} de {len(ROLE_PLAY)} vectores {nunca}")
    print(f"  sin medicion:      {sin_medicion or 'ninguno'}")
    print(f"  intentos perdidos: {total_perdidas} de {total_intentos} (fallo del servicio)")

    json.dump(
        dict(resultados),
        open("evals/resultados-estabilidad.json", "w", encoding="utf-8"),
        indent=2,
        ensure_ascii=False,
    )


if __name__ == "__main__":
    main()
