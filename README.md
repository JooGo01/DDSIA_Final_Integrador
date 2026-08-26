# OWASP RAG Assistant

API y interfaz web que responden preguntas sobre **OWASP Top 10:2025** y **OWASP API
Security Top 10:2023** recuperando fragmentos de los documentos originales y generando
la respuesta con un modelo de lenguaje servido localmente. Cada respuesta cita la seccion
de la que sale, y si el contexto recuperado no alcanza, el asistente lo dice en lugar de
inventar.

```
Pregunta -> validacion -> embedding -> busqueda en el indice -> prompt aumentado -> modelo -> validacion de salida -> respuesta con citas
```

## Que hace falta

- **Docker Desktop** (Windows o macOS) o **Docker Engine + Compose** (Linux)
- **6 GB de disco** para los modelos y unos **4 GB de RAM** disponibles
- **Conexion a internet la primera vez**: se descargan los modelos y el corpus
- Nada mas. Python no es obligatorio: los dos scripts del arranque pueden correr dentro
  de un contenedor descartable, y abajo estan los comandos para eso.

## Puesta en marcha

Elegi la seccion de tu sistema operativo y corre los comandos en orden. Son los mismos
cinco pasos en los tres casos; lo que cambia es la sintaxis de la consola.

| Paso | Que hace |
|---|---|
| 1 | Clonar el repositorio |
| 2 | Generar el `.env` con la clave de firma de los tokens |
| 3 | Descargar el corpus de OWASP |
| 4 | Levantar los contenedores |
| 5 | Abrir la interfaz y esperar a que el indice se construya solo |

El paso 2 es el unico que no puede venir resuelto en el repositorio: `JWT_SECRET` es un
secreto y tiene que generarse en cada instalacion. Las credenciales de los usuarios **si**
vienen en el repositorio, mas abajo estan.

---

### Linux o macOS

Consola: `bash` o `zsh`.

```bash
# 1. Clonar
git clone https://github.com/JooGo01/DDSIA_Final_Integrador.git
cd DDSIA_Final_Integrador
```

```bash
# 2. Generar el .env. Si no tenes Python, usa el bloque "Sin Python" de mas abajo.
python3 scripts/bootstrap_env.py
```

```bash
# 3. Descargar el corpus desde los repositorios oficiales de OWASP
python3 scripts/fetch_corpus.py
```

```bash
# 4. Levantar el servicio. La primera vez descarga los modelos: tarda varios minutos.
docker compose up -d --build
```

```bash
# 5. Esperar a que el modelo quede cargado y ver el estado
until docker compose logs api | grep -q "warmup_finished"; do sleep 8; done
curl http://localhost:8000/health
```

**Sin Python instalado.** Los pasos 2 y 3 en contenedores descartables, sin tocar el
Python del sistema:

```bash
docker run --rm -v "$PWD:/src" -w /src python:3.12-slim bash -c "pip install -q bcrypt && python scripts/bootstrap_env.py"
```

```bash
docker run --rm -v "$PWD:/src" -w /src python:3.12-slim bash -c "pip install -q httpx && python scripts/fetch_corpus.py"
```

---

### Windows — PowerShell

Consola: **PowerShell** (`powershell.exe` o `pwsh`), no `cmd`. Es la opcion recomendada
en Windows.

```powershell
# 1. Clonar
git clone https://github.com/JooGo01/DDSIA_Final_Integrador.git
cd DDSIA_Final_Integrador
```

```powershell
# 2. Generar el .env. Si no tenes Python, usa el bloque "Sin Python" de mas abajo.
python scripts/bootstrap_env.py
```

```powershell
# 3. Descargar el corpus desde los repositorios oficiales de OWASP
python scripts/fetch_corpus.py
```

```powershell
# 4. Levantar el servicio. La primera vez descarga los modelos: tarda varios minutos.
docker compose up -d --build
```

```powershell
# 5. Esperar a que el modelo quede cargado y ver el estado
while (-not (docker compose logs api | Select-String "warmup_finished")) { Start-Sleep -Seconds 8 }
Invoke-RestMethod http://localhost:8000/health
```

**Sin Python instalado.** Notar `${PWD}` con llaves: sin ellas PowerShell no expande la
variable dentro de la cadena.

```powershell
docker run --rm -v "${PWD}:/src" -w /src python:3.12-slim bash -c "pip install -q bcrypt && python scripts/bootstrap_env.py"
```

```powershell
docker run --rm -v "${PWD}:/src" -w /src python:3.12-slim bash -c "pip install -q httpx && python scripts/fetch_corpus.py"
```

**Tres cosas que muerden en PowerShell:**

- En **PowerShell 5.1** (el que viene con Windows), `curl` es un alias de
  `Invoke-WebRequest` y **no acepta** las opciones de curl (`-X`, `-d`, `-H`). Usa
  `Invoke-RestMethod`, que ademas parsea el JSON solo, o llama al binario real con
  `curl.exe`.
- `jq` no viene instalado. No hace falta: `Invoke-RestMethod` ya devuelve objetos.
- Los operadores `&&` y `||` no existen en PowerShell 5.1. Para encadenar, usa `;`.

---

### Windows — CMD

Consola: `cmd.exe`. Funciona, pero es la mas incomoda de las tres: no tiene forma
compacta de esperar en un bucle ni de formatear JSON.

```bat
REM 1. Clonar
git clone https://github.com/JooGo01/DDSIA_Final_Integrador.git
cd DDSIA_Final_Integrador
```

```bat
REM 2. Generar el .env
python scripts/bootstrap_env.py
```

```bat
REM 3. Descargar el corpus
python scripts/fetch_corpus.py
```

```bat
REM 4. Levantar el servicio
docker compose up -d --build
```

```bat
REM 5. Ver los logs y esperar la linea warmup_finished. Salir con Ctrl+C.
docker compose logs -f api
```

```bat
REM Estado del servicio (curl.exe viene con Windows 10 y 11)
curl.exe http://localhost:8000/health
```

**Sin Python instalado.** En CMD el directorio actual es `%cd%`:

```bat
docker run --rm -v "%cd%:/src" -w /src python:3.12-slim bash -c "pip install -q bcrypt && python scripts/bootstrap_env.py"
```

```bat
docker run --rm -v "%cd%:/src" -w /src python:3.12-slim bash -c "pip install -q httpx && python scripts/fetch_corpus.py"
```

---

### Windows — Git Bash

Los comandos de la seccion de Linux funcionan tal cual, con **una** excepcion: cuando el
comando monta un volumen, hay que prefijarlo con `MSYS_NO_PATHCONV=1`. Sin eso, Git Bash
convierte `/src` a una ruta de Windows y el montaje falla.

```bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/src" -w /src python:3.12-slim bash -c "pip install -q bcrypt && python scripts/bootstrap_env.py"
```

---

## Credenciales de demostracion

Vienen en `config/users.json`, versionadas a proposito para que el proyecto se pueda
clonar y probar sin pasos previos.

| Usuario | Contrasena | Scopes | Que puede hacer |
|---|---|---|---|
| `analista` | `Analista.2026` | `ask:read` | Preguntar |
| `admin` | `Admin.2026` | `ask:read`, `admin:ingest`, `metrics:read` | Preguntar, reindexar el corpus y leer las metricas |

> **Son publicas: estan en un repositorio abierto.** Sirven para evaluar el trabajo, no
> para un entorno real. Para reemplazarlas por otras con contrasenas aleatorias:
>
> ```bash
> python scripts/bootstrap_env.py --force
> ```
>
> Regenera tambien el `.env`, muestra las contrasenas nuevas una unica vez y no las
> escribe en ningun archivo. Despues hay que reiniciar el servicio: `docker compose restart api`.

## Usar la interfaz web

Abri **<http://localhost:8000>**.

1. Entra con cualquiera de los dos usuarios de la tabla.
2. Mira el indicador de estado arriba a la derecha:
   - **indexando** — el servicio esta construyendo el indice. Pasa una sola vez, en el
     primer arranque, y tarda un rato porque hay que vectorizar los 20 documentos.
   - **operativo** — ya se puede preguntar. Al lado dice cuantos fragmentos hay.
   - **degradado** — el modelo no responde, o el indice quedo vacio.
3. Escribi la pregunta y elegi sobre cual de los dos documentos buscar.
4. Arriba a la derecha se elige el tema: automatico, claro u oscuro. El automatico sigue
   la preferencia del sistema; la eleccion manual queda guardada en el navegador.

La respuesta llega con sus citas, si esta fundamentada o no, y las medidas de la consulta
(fragmentos recuperados, tokens y latencia). Entrando como `admin` aparece ademas el
bloque para reindexar, que sirve despues de cambiar los documentos del corpus.

**El indice se construye solo.** Al arrancar, si esta vacio, el servicio ingesta el corpus
en segundo plano; ya no hace falta entrar como administrador y llamar a `/admin/ingest`
antes de la primera consulta. Queda persistido en un volumen, asi que los arranques
siguientes son inmediatos. Se puede apagar con `AUTO_INGEST=false`.

**La primera consulta puede tardar.** El modelo corre local en tu maquina: entre recuperar
los fragmentos, generar la respuesta y validar que este fundamentada hay varias pasadas
por el modelo. La interfaz muestra un cronometro para que se vea que no esta colgado.

## Usar la API desde la consola

El token que devuelve `/auth/token` vale 30 minutos y va en la cabecera `Authorization`.

### Linux, macOS o Git Bash

```bash
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -d "username=analista&password=Analista.2026" | jq -r .access_token)

curl -s -X POST http://localhost:8000/ask \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"question": "Que controles previenen Broken Object Level Authorization?", "source": "api"}' | jq
```

### Windows — PowerShell

```powershell
$token = (Invoke-RestMethod -Method Post -Uri http://localhost:8000/auth/token -Body @{ username = "analista"; password = "Analista.2026" }).access_token

$consulta = @{ question = "Que controles previenen Broken Object Level Authorization?"; source = "api" } | ConvertTo-Json

Invoke-RestMethod -Method Post -Uri http://localhost:8000/ask -Headers @{ Authorization = "Bearer $token" } -ContentType "application/json" -Body $consulta | ConvertTo-Json -Depth 5
```

### Windows — CMD

```bat
curl.exe -X POST http://localhost:8000/auth/token -d "username=analista&password=Analista.2026"
```

Copia el valor de `access_token` de la salida y pegalo en el comando siguiente:

```bat
curl.exe -X POST http://localhost:8000/ask -H "Authorization: Bearer PEGAR_TOKEN_ACA" -H "Content-Type: application/json" -d "{\"question\": \"Que controles previenen Broken Object Level Authorization?\", \"source\": \"api\"}"
```

En CMD las comillas dobles del JSON hay que escaparlas con `\`. Si el comando se vuelve
ilegible, usa PowerShell o la interfaz web.

### Respuesta

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

Tambien se puede probar todo desde Swagger en <http://localhost:8000/docs>: pedí el token
en `/auth/token` y pegalo en **Authorize**.

## Endpoints

| Metodo | Ruta | Scope | Que hace |
|---|---|---|---|
| GET | `/` | publico | Interfaz web |
| POST | `/auth/token` | publico | Emite un JWT a partir de usuario y contrasena |
| POST | `/ask` | `ask:read` | Responde una pregunta sobre el corpus |
| POST | `/admin/ingest` | `admin:ingest` | Relee los documentos y regenera el indice |
| GET | `/health` | publico | Estado del modelo, fragmentos indexados y si esta indexando |
| GET | `/metrics` | `metrics:read` | Metricas en formato Prometheus |

Swagger (`/docs`) se publica solo con `ENVIRONMENT=dev`. Fuera de ahi no aporta y suma
superficie: es la unica ruta exenta de la politica de contenido y carga su JavaScript
de un CDN sin verificar integridad.

El parametro `source` de `/ask` acepta `web` (Top 10:2025), `api` (API Security Top 10:2023)
o `all`.

`/admin/ingest` reconcilia: devuelve `removed` con la cantidad de fragmentos que estaban
indexados y ya no corresponden a ningun documento del corpus. Antes un documento borrado
seguia indexado y citable hasta que alguien reindexara con `reset: true`. `/admin/ingest` devuelve `409` si ya hay una ingesta en curso: las dos escriben
sobre el mismo indice y no pueden solaparse.

## Como funciona una consulta

El sistema tiene dos momentos. En la **ingesta** se leen los documentos OWASP, se parten
en fragmentos por titulo, cada fragmento se convierte en un vector con `nomic-embed-text`
y se guarda en Chroma. En la **consulta** la pregunta se convierte en un vector con el
mismo modelo, se buscan los fragmentos mas cercanos y esos fragmentos —no la memoria del
modelo— son la fuente de la respuesta.

Que los dos momentos usen el mismo modelo de embeddings es lo que hace comparable la
busqueda: dos textos que hablan de lo mismo quedan cerca aunque no compartan palabras.

Cada `/ask` pasa por ocho etapas y cualquiera puede cortar:

| # | Etapa | Si no pasa |
|---|---|---|
| 1 | Limite de peticiones y cuota diaria de tokens | `429` |
| 2 | `input_guard`: largo y patrones de injection | `400` |
| 3 | `scope_guard`: pregunta por un documento no indexado | `200` avisando, sin consultar el modelo |
| 4 | Embedding de la pregunta | `503` |
| 5 | Busqueda en el indice, top-K y umbral de relevancia | sigue sin fragmentos |
| 6 | Generacion con el contexto recuperado | `503` |
| 7 | `output_guard`: fundamentacion, fuga de prompt, PII, URLs | se descarta la respuesta |
| 8 | Citas, solo si la etapa 7 dio fundamentada | — |

Dos decisiones que no se leen del diagrama:

**La etapa 7 compara contra cada fragmento por separado y toma el mejor parecido.**
Alcanza con que uno sostenga la respuesta; compararla contra los cuatro concatenados
diluye el puntaje de una respuesta enfocada. Si el embedding falla, la respuesta se
descarta: falla cerrado.

**La etapa 3 existe porque la 7 no alcanzaba.** Las preguntas sobre otros documentos de
OWASP recuperan fragmentos del corpus real con buena similitud, porque hablan del mismo
tema, y el modelo las contesta de memoria. En la medicion puntuaron entre 0.61 y 0.78,
y una pregunta legitima puntuo 0.49: ningun umbral las separa. Como el alcance del corpus
es fijo y conocido, se cortan por codigo antes de recuperar nada.

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
  web/                Interfaz: un HTML, una hoja de estilos y un script
```

La interfaz no tiene build ni dependencias: es HTML, CSS y JavaScript servidos por la
misma aplicacion. Eso es lo que permite que la politica de contenido no habilite ningun
origen externo y que el contenedor siga siendo de solo lectura.

Las decisiones y lo que se resigna con cada una estan en
[docs/architecture.md](docs/architecture.md) — su seccion 12 resume los cinco puntos de
confianza del sistema, el control determinista que cubre cada uno y por que ninguna
accion exige aprobacion humana. El modelo de amenazas STRIDE, en
[docs/threat-model.md](docs/threat-model.md), que ademas cruza el sistema contra el
OWASP Top 10 for LLM Applications categoria por categoria. La auditoria de seguridad y la
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
| Revision de documentos en la ingesta: descarta los que dan ordenes | `app/guardrails/corpus_guard.py` |
| Descarte de las bibliografias en la ingesta: no responden y desplazan al contenido | `app/rag/chunking.py` |
| Verificacion de URLs: toda URL de una respuesta debe estar en el contexto | `app/guardrails/output_guard.py` |
| Validacion de la respuesta: fundamentacion, fuga de prompt y datos personales | `app/guardrails/output_guard.py` |
| Rechazo de preguntas ilegibles y de pedidos de codigo o scripts | `app/guardrails/input_guard.py`, `app/guardrails/scope_guard.py` |
| Descarte de respuestas con codigo que no estaba en el contexto recuperado | `app/guardrails/output_guard.py` |
| Limite de peticiones por usuario y de intentos de login por IP | `app/core/ratelimit.py` |
| Techo por IP para todo el trafico, aplicado antes de autenticar | `app/main.py` |
| Metricas detras de un scope propio, para no publicar los contadores de auth | `app/api/routes_health.py` |
| Presupuesto diario de tokens por usuario | `app/core/ratelimit.py` |
| Errores en `problem+json`, sin filtrar detalle interno | `app/core/errors.py` |
| Logs en JSON con `request_id` y redaccion de campos sensibles | `app/core/logging.py` |
| Politica de contenido sin origenes externos, y la respuesta del modelo tratada como texto | `app/main.py`, `app/web/assets/app.js` |
| Token solo en memoria del navegador: ni `localStorage` ni cookies | `app/web/assets/app.js` |
| Los tres contenedores sin root, filesystem de solo lectura, sin capabilities y con limites | `Dockerfile`, `docker-compose.yml` |

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

Los tests no necesitan Ollama ni el corpus real: usan un doble del cliente con embeddings
deterministicos y un corpus de prueba en `tests/fixtures/`. Con eso la recuperacion se
ejercita de verdad y la suite corre en el pipeline sin descargar modelos.

Con Python 3.12 instalado, en cualquier sistema:

```bash
pip install -e ".[dev]"
pytest --cov=app --cov-report=term-missing
```

Sin instalar Python, en un contenedor descartable. La unica diferencia entre sistemas es
como se escribe el directorio actual:

```bash
# Linux o macOS
docker run --rm -v "$PWD:/src" -w /src python:3.12-slim bash -c "pip install -q -e '.[dev]' && pytest"
```

```powershell
# Windows, PowerShell
docker run --rm -v "${PWD}:/src" -w /src python:3.12-slim bash -c "pip install -q -e '.[dev]' && pytest"
```

```bat
REM Windows, CMD
docker run --rm -v "%cd%:/src" -w /src python:3.12-slim bash -c "pip install -q -e '.[dev]' && pytest"
```

```bash
# Windows, Git Bash
MSYS_NO_PATHCONV=1 docker run --rm -v "$PWD:/src" -w /src python:3.12-slim bash -c "pip install -q -e '.[dev]' && pytest"
```

## Evaluaciones contra el servicio real

Los tests unitarios corren sin modelo. Para medir lo que solo se ve en ejecucion hay
seis suites en [`evals/`](evals/): 52 controles de pentest, 8 intentos de evasion de
guardrails, 16 casos de fundamentacion, 13 de jailbreak e inyeccion indirecta, la
medicion de estabilidad de los vectores de role play, y 21 preguntas normales y trampa.

La bateria de trampas mide algo que las otras no: que hace el asistente cuando la
pregunta habla del tema del corpus pero da por cierto algo que los documentos no dicen.
Son los casos que el umbral de fundamentacion no separa, porque los fragmentos que
recupera son legitimos. Cubre premisas falsas, atribucion al documento equivocado,
categorias inventadas, pedidos de comandos, preguntas ilegibles, y las tres familias
normales de extraccion, sintesis y aplicacion practica.

Necesitan el servicio arriba y las contrasenas en el entorno.

```bash
# Linux, macOS o Git Bash
export EVAL_PASSWORD=Analista.2026 EVAL_ADMIN_PASSWORD=Admin.2026
python evals/pentest.py
python evals/bypass_guardrails.py
python evals/eval_fundamentacion.py
python evals/jailbreak_roleplay.py   # role play, jailbreak e inyeccion indirecta
python evals/preguntas_trampa.py     # preguntas normales y trampa

# Repite los vectores de role play para medir la tasa en vez de una sola pasada:
# el modelo no es determinista y el mismo ataque cede en una corrida y no en la siguiente.
REPETICIONES=3 PYTHONPATH=evals python evals/roleplay_estabilidad.py
```

```powershell
# Windows, PowerShell. No existe el prefijo VARIABLE=valor delante del comando.
$env:EVAL_PASSWORD = "Analista.2026"
$env:EVAL_ADMIN_PASSWORD = "Admin.2026"
python evals/pentest.py
python evals/bypass_guardrails.py
python evals/eval_fundamentacion.py
python evals/jailbreak_roleplay.py
python evals/preguntas_trampa.py

$env:REPETICIONES = "3"; $env:PYTHONPATH = "evals"; python evals/roleplay_estabilidad.py
```

```bat
REM Windows, CMD
set EVAL_PASSWORD=Analista.2026
set EVAL_ADMIN_PASSWORD=Admin.2026
python evals/pentest.py
python evals/bypass_guardrails.py
python evals/eval_fundamentacion.py
python evals/jailbreak_roleplay.py
python evals/preguntas_trampa.py

set REPETICIONES=3
set PYTHONPATH=evals
python evals/roleplay_estabilidad.py
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
| `AUTO_INGEST` | `true` | Indexa el corpus al arrancar si el indice esta vacio |
| `REQUESTS_PER_MINUTE` | `10` | Limite de consultas por usuario |
| `LOGIN_ATTEMPTS_PER_MINUTE` | `5` | Limite de intentos de login por IP |
| `IP_REQUESTS_PER_MINUTE` | `60` | Techo por IP para todo el trafico, incluido el no autenticado |
| `DAILY_TOKEN_BUDGET` | `50000` | Cuota diaria de tokens por usuario |
| `MIN_SECONDS_BETWEEN_INGESTS` | `60` | Espera minima entre dos reindexados completos |
| `LLM_MODEL` | `llama3.2:3b` | Modelo de generacion |
| `EMBEDDING_MODEL` | `nomic-embed-text` | Modelo de embeddings |
| `LLM_TIMEOUT_SECONDS` | `150` | Corte de la consulta al modelo. Bajo carga sostenida 90 s no alcanzaba |
| `RETRIEVAL_TOP_K` | `4` | Fragmentos que se recuperan por consulta |
| `MIN_RELEVANCE_SCORE` | `0.25` | Umbral por debajo del cual un fragmento se descarta |
| `MIN_QUESTION_CHARS` | `8` | Largo minimo de la pregunta |
| `MAX_QUESTION_CHARS` | `600` | Largo maximo de la pregunta. El contrato de entrada tiene ademas un techo duro de 4000 que esta variable no puede superar |

## Problemas comunes

| Sintoma | Causa | Solucion |
|---|---|---|
| La interfaz dice **degradado** e **indice vacio** | La ingesta automatica todavia no termino, o fallo | Esperar; si sigue, revisar `docker compose logs api` buscando `auto_ingest_failed` |
| La interfaz dice **el modelo no responde** | Ollama todavia esta cargando el modelo en RAM | Esperar la linea `warmup_finished` en los logs |
| `Invoke-WebRequest: parametro -X no encontrado` | En PowerShell 5.1 `curl` es un alias | Usar `Invoke-RestMethod`, o `curl.exe` |
| El montaje del volumen falla en Git Bash | Conversion automatica de rutas | Prefijar el comando con `MSYS_NO_PATHCONV=1` |
| `JWT_SECRET` invalido al arrancar | Falta el `.env` o quedo vacio | Correr el paso 2 de la puesta en marcha |
| `401` en `/auth/token` con las credenciales del README | Se cambiaron los usuarios con `--force` | Usar las contrasenas nuevas, o restaurar: `git checkout config/users.json` y `docker compose restart api` |
| `409` al reindexar | Ya hay una ingesta corriendo | Esperar a que termine |

## Limitaciones conocidas

- **Las credenciales de demostracion son publicas.** Estan en el repositorio a proposito, para que el trabajo se pueda evaluar sin pasos previos. Cualquier uso real empieza por `bootstrap_env.py --force`.
- **Una sola instancia.** Los limites de uso viven en memoria del proceso. Con varias replicas cada una llevaria su propia cuenta.
- **Sin revocacion de tokens.** Un token robado sirve hasta que vence, a los 30 minutos.
- **La fundamentacion confirma respaldo tematico, no correccion factual.** Se mide por similitud semantica entre la respuesta y el fragmento que mejor la sostiene, no por palabras en comun: el corpus esta en ingles y las respuestas salen en espanol, asi que un solapamiento lexico daria bajo incluso para una respuesta correcta. El limite es otro: que una respuesta este respaldada por el corpus no prueba que sea cierta. Una afirmacion plausible y equivocada sobre un tema que si esta indexado puede pasar el umbral.
- **El corpus no tiene un documento indice.** Cada archivo describe una categoria; ninguno lista las diez juntas. El ranking existe en los titulos, no en el texto, asi que las preguntas por posicion ("cuales son las tres principales", "en que puesto esta X") no tienen de donde recuperarse y se responden mal. Es una limitacion del corpus, no del pipeline.
- **El modelo es chico.** `llama3.2:3b` redacta razonablemente sobre contexto ya recuperado, pero no razona bien sobre preguntas que exigen combinar varias fuentes.
- **El filtro de prompt injection es por patrones.** Es evadible y no pretende ser el control principal: lo que realmente contiene el riesgo es que el servicio sea de solo lectura y no exponga herramientas.
- **La interfaz no recuerda la sesion.** El token vive en memoria del navegador: al recargar la pagina hay que volver a entrar. Es deliberado, para que un XSS no tenga de donde robarlo.

## Licencia del corpus

Los documentos de OWASP se descargan de los repositorios oficiales y no se versionan en
este repositorio. Estan publicados bajo Creative Commons Attribution-ShareAlike 4.0.

- <https://github.com/OWASP/Top10>
- <https://github.com/OWASP/API-Security>
