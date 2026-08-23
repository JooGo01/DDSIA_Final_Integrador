# Evaluaciones

Tres suites que se corren contra el servicio en ejecucion. No son tests unitarios:
necesitan la API arriba, Ollama respondiendo y el indice cargado.

Los resultados de la ultima corrida y su analisis estan en
[`docs/security-audit.md`](../docs/security-audit.md).

## Preparacion

```bash
docker compose up -d
export EVAL_PASSWORD=...        # clave del usuario analista
export EVAL_ADMIN_PASSWORD=...  # clave del usuario admin, solo para el pentest
```

Por defecto apuntan a `http://localhost:8000`. Se cambia con `API_URL`.

## `pentest.py`

52 controles: manipulacion de tokens, autorizacion, validacion de entrada,
exposicion de informacion y limites de uso.

Los JWT se forjan a mano con la libreria estandar, sin usar PyJWT, para que el ataque
quede explicito y no dependa de que la libreria de firma se comporte bien. Lee
`JWT_SECRET` del `.env` local: sin el secreto no se pueden forjar tokens y la mitad de
las pruebas no tendria sentido.

```bash
python evals/pentest.py
```

Tarda unos 3 minutos, la mayor parte esperando a que se liberen los limites de uso.

## `bypass_guardrails.py`

Ocho intentos de evadir el filtro de entrada: homoglifos cirilicos, separadores entre
letras, base64, otro idioma, peticiones indirectas.

El filtro de patrones es evadible a proposito y no es el control principal. Lo que
esta suite comprueba es si la segunda capa —la validacion de salida— contiene el dano
cuando la primera falla. Clasifica cada intento por la capa que lo freno.

```bash
python evals/bypass_guardrails.py
```

## `eval_fundamentacion.py`

16 casos que miden si el asistente inventa. Cuatro familias:

| Familia | Que prueba |
|---|---|
| `ground_truth` | La respuesta esta en el corpus: debe responder y citar el documento correcto |
| `fuera_dominio` | Cocina, futbol, matematica: debe rechazar |
| `trampa` | Seguridad de aplicaciones **fuera del corpus**: debe rechazar |
| `premisa_falsa` | La pregunta afirma algo falso: no debe convalidarlo |

La familia `trampa` es la que importa. Preguntar por una receta de cocina es facil de
rechazar; preguntar por el OWASP Mobile Top 10, que no esta indexado, recupera
fragmentos del corpus real con buena similitud porque habla del mismo tema. Ese es el
caso donde un RAG contesta de memoria y lo marca como fundamentado.

```bash
python evals/eval_fundamentacion.py
```

Tarda unos 20 minutos: cada consulta pasa por el modelo real y hay que esperar los
limites de uso entre tanda y tanda.

## Agregar casos

`CASOS` en `eval_fundamentacion.py` es una lista de diccionarios. Para un caso nuevo
dentro del corpus hacen falta `doc` (el documento que deberia citar) y `espera` (una
lista de fragmentos de texto, alcanza con que aparezca uno). Para un caso que deberia
rechazarse alcanza con `grounded: False`.
