# OWASP RAG Assistant

API que responde preguntas sobre **OWASP Top 10:2025** y **OWASP API Security Top 10:2023**
recuperando fragmentos de los documentos originales y generando la respuesta con un modelo
de lenguaje servido localmente. Cada respuesta cita la seccion de la que sale, y si el
contexto recuperado no alcanza, el asistente lo dice en lugar de inventar.

```
Pregunta -> validacion -> embedding -> busqueda en el indice -> prompt aumentado -> modelo -> validacion de salida -> respuesta con citas
```

## Que hace falta

- Docker y Docker Compose
- 6 GB de disco para los modelos y unos 4 GB de RAM disponibles
- Python 3.12 solo si vas a correr los tests fuera del contenedor

## Puesta en marcha

```bash
# 1. Credenciales y secreto de firma. Anotá las contraseñas: se muestran una sola vez.
python scripts/bootstrap_env.py

# 2. Descargar el corpus desde los repositorios oficiales de OWASP
python scripts/fetch_corpus.py

# 3. Levantar el servicio. La primera vez descarga los modelos, tarda varios minutos.
docker compose up -d --build

# 4. Verificar
curl http://localhost:8000/health
```

`status` va a decir `degraded` hasta que cargues el indice, porque todavia no hay nada
que consultar.

### Cargar el indice

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -d "username=admin&password=TU_CLAVE_ADMIN" | jq -r .access_token)

curl -s -X POST http://localhost:8000/admin/ingest \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reset": true}' | jq
```

```json
{ "documents": 20, "chunks": 214, "collection": "owasp", "duration_ms": 18432 }
```

### Preguntar

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -d "username=analista&password=TU_CLAVE_ANALISTA" | jq -r .access_token)

curl -s -X POST http://localhost:8000/ask \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "Que controles previenen Broken Object Level Authorization?", "source": "api"}' | jq
```

```json
{
  "answer": "Implementar un mecanismo de autorizacion que valide la relacion entre el usuario autenticado y el objeto solicitado...",
  "citations": [
    { "document": "OWASP API Security Top 10:2023", "section": "API1:2023 - Broken Object Level Authorization", "relevance": 0.81 }
  ],
  "grounded": true,
  "request_id": "a3f19c204b7e8d11",
  "usage": { "input_tokens": 812, "output_tokens": 164, "retrieved_chunks": 3, "latency_ms": 4210 }
}
```

Tambien podes probar todo desde Swagger en <http://localhost:8000/docs>: pedí el token en
`/auth/token` y pegalo en **Authorize**.

## Endpoints

| Metodo | Ruta | Scope | Que hace |
|---|---|---|---|
| POST | `/auth/token` | publico | Emite un JWT a partir de usuario y contrasena |
| POST | `/ask` | `ask:read` | Responde una pregunta sobre el corpus |
| POST | `/admin/ingest` | `admin:ingest` | Relee los documentos y regenera el indice |
| GET | `/health` | publico | Estado del modelo y cantidad de fragmentos indexados |
| GET | `/metrics` | publico | Metricas en formato Prometheus |

El parametro `source` de `/ask` acepta `web` (Top 10:2025), `api` (API Security Top 10:2023)
o `all`.

## Como esta armado

```
app/
  main.py             Ensamblado de la app, middleware de contexto y cabeceras
  config.py           Configuracion por variables de entorno
  schemas.py          Contratos de entrada y salida
  api/                Rutas y dependencias de autenticacion y limites
  core/               JWT, limites de uso, logs, metricas y errores
  rag/                Chunking, vector store, cliente de Ollama y generacion
  guardrails/         Validacion de la pregunta y de la respuesta
```

Las decisiones y lo que se resigna con cada una estan en
[docs/architecture.md](docs/architecture.md). El modelo de amenazas STRIDE, en
[docs/threat-model.md](docs/threat-model.md). La auditoria de seguridad y la
evaluacion de cuanto inventa el asistente, en
[docs/security-audit.md](docs/security-audit.md).

## Controles de seguridad

| Control | Donde |
|---|---|
| Autenticacion con JWT validado en firma, emisor, audiencia y vencimiento | `app/core/security.py` |
| Autorizacion por scope en cada endpoint | `app/api/deps.py` |
| Validacion estricta de entrada, con rechazo de campos no declarados | `app/schemas.py` |
| Filtro de prompt injection y de datos personales en la pregunta | `app/guardrails/input_guard.py` |
| Control de alcance: rechaza preguntas sobre documentos no indexados | `app/guardrails/scope_guard.py` |
| Validacion de la respuesta: fundamentacion, fuga de prompt y datos personales | `app/guardrails/output_guard.py` |
| Limite de peticiones por usuario y de intentos de login por IP | `app/core/ratelimit.py` |
| Presupuesto diario de tokens por usuario | `app/core/ratelimit.py` |
| Errores en `problem+json`, sin filtrar detalle interno | `app/core/errors.py` |
| Logs en JSON con `request_id` y redaccion de campos sensibles | `app/core/logging.py` |
| Contenedor sin root, filesystem de solo lectura, sin capabilities y con limites | `Dockerfile`, `docker-compose.yml` |

Ninguno de estos controles esta solo documentado: cada uno tiene su prueba en `tests/`.

## Observabilidad

Logs estructurados en JSON a `stdout`, con `request_id` en cada evento y en la cabecera
`X-Request-ID` de la respuesta.

```json
{"event": "ask_completed", "level": "info", "timestamp": "2026-08-21T22:14:08Z",
 "request_id": "a3f19c204b7e8d11", "user": "analista", "source": "api",
 "retrieved": 3, "grounded": true, "input_tokens": 812, "output_tokens": 164, "latency_ms": 4210}
```

No se escriben el prompt, el contexto, la pregunta ni la respuesta: solo identificadores,
medidas y decisiones.

En `/metrics`, ademas de las cuatro senales clasicas: `llm_tokens_total`,
`rag_chunks_retrieved`, `rag_answers_total{grounded}`, `guardrail_blocks_total{stage,reason}`
y `rate_limit_hits_total{dimension}`.

## Tests

```bash
pip install -e ".[dev]"
pytest --cov=app --cov-report=term-missing
```

Los tests no necesitan Ollama ni el corpus real: usan un doble del cliente con embeddings
deterministicos y un corpus de prueba en `tests/fixtures/`. Con eso la recuperacion se
ejercita de verdad y la suite corre en el pipeline sin descargar modelos.

Para correrlos sin instalar Python 3.12 localmente:

```bash
docker run --rm -v "$PWD:/src" -w /src python:3.12-slim \
  bash -c "pip install -q -e '.[dev]' && pytest"
```

## Evaluaciones contra el servicio real

Los tests unitarios corren sin modelo. Para medir lo que solo se ve en ejecucion hay
tres suites en [`evals/`](evals/): 52 controles de pentest, 8 intentos de evasion de
guardrails y 16 casos de fundamentacion.

```bash
export EVAL_PASSWORD=... EVAL_ADMIN_PASSWORD=...
python evals/pentest.py
python evals/bypass_guardrails.py
python evals/eval_fundamentacion.py
```

Resultados de la ultima corrida y su analisis en
[docs/security-audit.md](docs/security-audit.md).

## Pipeline

`.github/workflows/ci.yml` corre en cada push y cada pull request contra `main`:

| Job | Que verifica | Bloquea |
|---|---|---|
| `quality` | Ruff, formato y Bandit | Si |
| `test` | Suite completa con cobertura minima de 70% | Si |
| `dependencies` | `pip-audit` sobre las dependencias | No, informa |
| `image` | Hadolint, build, que el contenedor no corra como root, Trivy y SBOM | Parcial |

Trivy y `pip-audit` informan sin bloquear a proposito: sin una politica de severidad
acordada, un gate que bloquea por cualquier hallazgo termina generando fatiga de alertas
y se saltea. El chequeo de que la imagen no corre como root si bloquea, porque es binario
y no admite interpretacion.

## Configuracion

Todo se configura por variables de entorno; `.env.example` tiene la lista completa.

| Variable | Default | Para que |
|---|---|---|
| `JWT_SECRET` | sin default | Firma de los tokens. La app no arranca sin esto |
| `JWT_EXPIRE_MINUTES` | `30` | Vida del token |
| `REQUESTS_PER_MINUTE` | `10` | Limite de consultas por usuario |
| `DAILY_TOKEN_BUDGET` | `50000` | Cuota diaria de tokens por usuario |
| `LLM_MODEL` | `llama3.2:3b` | Modelo de generacion |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Modelo de embeddings |
| `RETRIEVAL_TOP_K` | `4` | Fragmentos que se recuperan por consulta |
| `MIN_RELEVANCE_SCORE` | `0.25` | Umbral por debajo del cual un fragmento se descarta |

## Limitaciones conocidas

- **Una sola instancia.** Los limites de uso viven en memoria del proceso. Con varias replicas cada una llevaria su propia cuenta.
- **Sin revocacion de tokens.** Un token robado sirve hasta que vence, a los 30 minutos.
- **La fundamentacion se mide por vocabulario.** Es un solapamiento lexico, no semantico: una parafrasis correcta puede quedar marcada como no fundamentada. Se prefiere ese falso positivo antes que publicar una respuesta inventada.
- **El modelo es chico.** `llama3.2:3b` redacta razonablemente sobre contexto ya recuperado, pero no razona bien sobre preguntas que exigen combinar varias fuentes.
- **El filtro de prompt injection es por patrones.** Es evadible y no pretende ser el control principal: lo que realmente contiene el riesgo es que el servicio sea de solo lectura y no exponga herramientas.

## Licencia del corpus

Los documentos de OWASP se descargan de los repositorios oficiales y no se versionan en
este repositorio. Estan publicados bajo Creative Commons Attribution-ShareAlike 4.0.

- <https://github.com/OWASP/Top10>
- <https://github.com/OWASP/API-Security>
