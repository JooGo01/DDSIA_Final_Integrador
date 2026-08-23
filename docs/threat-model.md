# Modelo de amenazas

Metodo: STRIDE aplicado por elemento del diagrama de flujo de datos, siguiendo las
cuatro preguntas de OWASP Threat Modeling.

| | |
|---|---|
| Alcance | El servicio de preguntas y respuestas completo: API, indice vectorial y modelo local. |
| Fuera de alcance | El entrenamiento del modelo, la infraestructura del host y la red corporativa. |
| Ultima revision | Version 1.0.0 |

## 1. Que estamos construyendo

### Activos

| Activo | Por que importa |
|---|---|
| Credenciales de usuario y `JWT_SECRET` | Quien los tenga puede emitir tokens validos y usar el servicio como cualquier usuario. |
| Indice vectorial | Si se altera, el asistente responde con contenido que no es el de OWASP. |
| Capacidad de computo del modelo | Es el recurso finito y caro del sistema. |
| Trazas y logs | Son la evidencia para investigar un incidente. |

### Diagrama de flujo de datos

```
                        Limite de confianza: internet -> API
                        |
  [Cliente HTTP] -------|------> ( API FastAPI )
                        |          | auth + validacion + limites
                        |          |
                        |          +--> [ Chroma ]  indice vectorial (volumen)
                        |          |
                        |          +--> ( Ollama )  modelo local
                        |                  ^
                        |                  | red interna del compose, sin puerto publicado
                        |
                        +---- [ Corpus OWASP ]  montado solo lectura

  ( ) proceso     [ ] almacen de datos     ---- flujo de datos
```

### Limites de confianza

| Cruce | Que cambia | Controles |
|---|---|---|
| Internet a API | Entra dato no confiable | Autenticacion, validacion de esquema, limites de uso |
| API a Ollama | El texto del usuario llega al modelo | Contexto etiquetado como dato, tope de tokens, timeout |
| API a Chroma | Se decide que contexto se recupera | Filtro por corpus, umbral de relevancia |
| Corpus a indice | Entra contenido de terceros | Montaje de solo lectura, ingesta con scope propio |

### Supuestos

1. El host de Docker no esta comprometido.
2. El corpus proviene de los repositorios oficiales de OWASP y se considera de confianza moderada: se descarga de la fuente, pero se trata igual como dato y no como instruccion.
3. El servicio se publica en `127.0.0.1`, sin exposicion directa a internet.

## 2. Que puede salir mal

Severidad segun probabilidad por impacto en este contexto.

### T-01 · Prompt injection indirecta desde el corpus · Tampering · Media

Un documento indexado contiene texto que parece una instruccion y el modelo lo obedece
en lugar de citarlo.

- **Controles**: el prompt de sistema declara que el contexto es material de referencia y no una fuente de ordenes; el servicio no expone ninguna herramienta, asi que el peor caso es una respuesta incorrecta y no una accion; la salida se valida contra el contexto antes de publicarse.
- **Evidencia**: `test_respuesta_que_filtra_el_prompt_de_sistema_se_bloquea`, `test_respuesta_inventada_se_bloquea_por_falta_de_sustento`.
- **Riesgo residual**: un documento manipulado puede degradar la calidad de la respuesta. Se acepta: el corpus se descarga de OWASP y el impacto se limita a texto.

### T-02 · Prompt injection directa · Tampering · Media

El usuario intenta que el asistente ignore sus reglas o revele su configuracion.

- **Controles**: filtro de patrones en la entrada; el prompt de sistema prohibe revelar instrucciones; la salida se descarta si repite el prompt de sistema.
- **Evidencia**: `test_endpoint_rechaza_prompt_injection`, `test_detecta_intentos_de_inyeccion`.
- **Riesgo residual medido**: se probaron ocho variantes de evasion (homoglifos cirilicos, separadores entre letras, base64, otro idioma, peticiones indirectas). Cinco evadieron el filtro de patrones y ninguna consiguio filtrar el prompt de sistema: tres las freno la validacion de salida o el propio filtro, y las demas se respondieron como preguntas legitimas. Se acepta porque el filtro no es el control principal: lo que contiene el riesgo es que el servicio sea de solo lectura y no exponga herramientas. Ver `evals/bypass_guardrails.py`.

### T-03 · Agotamiento de computo y cuota · Denial of Service · Alta

Un usuario valido satura el modelo con consultas o con preguntas muy largas.

- **Controles**: token bucket por usuario; tope de caracteres en la pregunta; presupuesto diario de tokens por usuario; `num_predict` limita la salida; timeout sobre el modelo; limites de CPU, memoria y PIDs en el contenedor.
- **Evidencia**: `test_superar_las_requests_por_minuto_devuelve_429`, `test_sin_presupuesto_de_tokens_se_rechaza_la_consulta`.
- **Riesgo residual**: el estado del limitador vive en memoria del proceso. Con varias replicas el limite se multiplicaria por la cantidad de instancias. Se acepta para una unica instancia y se documenta como el primer cambio necesario para escalar. La auditoria agrego dos cosas: purga de claves inactivas, porque el diccionario del limitador por IP crecia sin techo, y una carga previa del modelo al arrancar, porque la primera consulta tardaba 89 s contra un timeout de 90 y devolvia 503.

- **Sobregiro aceptado**: `has_budget()` y `consume()` no son atomicos, asi que dos consultas concurrentes del mismo usuario pueden pasar el control antes de que ninguna descuente. El sobregiro esta acotado por el limite de peticiones: unas diez consultas de mas sobre una cuota de 50.000 tokens.

### T-04 · Robo o forja de tokens · Spoofing · Alta

Un atacante consigue un token valido o intenta fabricar uno.

- **Controles**: la validacion declara el algoritmo de forma explicita, lo que descarta `alg: none`; se verifican emisor, audiencia y vencimiento; los tokens duran 30 minutos; el `JWT_SECRET` no tiene valor por defecto y la app no arranca sin el; los intentos de login estan limitados por IP; el login responde igual exista o no el usuario.
- **Evidencia**: `test_token_firmado_con_otro_secreto_es_rechazado`, `test_login_no_revela_si_el_usuario_existe`, `test_superar_los_intentos_de_login_devuelve_429`.
- **Riesgo residual**: no hay revocacion. Un token robado sirve hasta que vence. Se acepta por la vida corta del token; con una lista de revocacion habria que sumar almacenamiento compartido.

### T-05 · Escalada de privilegios hacia la reingesta · Elevation of Privilege · Media

Un usuario de consulta consigue ejecutar `/admin/ingest` y reemplaza el indice.

- **Controles**: los scopes viajan firmados dentro del token y se verifican por endpoint; el corpus se monta de solo lectura, asi que ni el proceso de la API puede modificar los documentos de origen.
- **Evidencia**: `test_analista_no_puede_ingestar`.

### T-06 · Fuga de informacion por errores y logs · Information Disclosure · Media

Un stack trace o un log expone rutas internas, credenciales o el contenido de las consultas.

- **Controles**: todos los errores salen en `application/problem+json` con un codigo estable y sin detalle interno; el detalle va al log; los logs redactan las claves sensibles y nunca escriben el prompt, el contexto, la pregunta ni la respuesta; las preguntas con datos personales se rechazan antes de llegar al modelo.
- **Evidencia**: `test_si_el_modelo_falla_devuelve_503_sin_filtrar_detalle`, `test_endpoint_rechaza_pregunta_con_pii`, `test_respuesta_con_datos_personales_se_bloquea`.
- **Corregido en la auditoria**: el `X-Request-ID` que propone el cliente se aceptaba sin validar y terminaba en cada linea de log, en la cabecera de respuesta y en el cuerpo JSON. Se comprobo con un valor de 1 KB. Ahora solo se acepta si cumple `[A-Za-z0-9._-]{1,64}`.

### T-07 · Falta de trazabilidad de una respuesta · Repudiation · Baja

No se puede reconstruir que respondio el sistema ante un reclamo.

- **Controles**: cada peticion recibe un `request_id` que viaja en el log, en la respuesta y en la cabecera `X-Request-ID`; se registran usuario, corpus consultado, chunks recuperados, si la respuesta quedo fundamentada, tokens y latencia.
- **Riesgo residual**: no se guarda el texto de la respuesta, asi que la reconstruccion es parcial. Es una decision deliberada: guardar el contenido convertiria los logs en un nuevo activo a proteger.

### T-09 · Respuesta inventada presentada como fundamentada · Information Disclosure · Alta

Una pregunta sobre seguridad de aplicaciones que no esta en el corpus recupera
fragmentos parecidos igual, porque habla del mismo tema, y el modelo la contesta con
lo que sabe de su preentrenamiento. La respuesta sale marcada como fundamentada y con
citas.

- **Como se detecto**: la evaluacion de fundamentacion, familia `trampa`. Cinco de cinco casos fallaron en la primera corrida. El mas claro respondio "A04: Missing Function Level Access Control" a una pregunta sobre la edicion 2017, que es falso.
- **Por que no alcanzaba con subir umbrales**: las trampas puntuaron entre 0.61 y 0.78 en fundamentacion, dentro del rango de las respuestas correctas (0.61 a 0.79), y una pregunta legitima puntuo 0.49. Ningun corte las separa.
- **Controles**: control de alcance deterministico antes de recuperar; el corpus tiene alcance fijo y una pregunta que nombra otro documento de OWASP, otra edicion o un CVE puntual se rechaza sin consultar al modelo.
- **Evidencia**: `tests/test_scope_guard.py` y la familia `trampa` de `evals/eval_fundamentacion.py`, que paso de 0/5 a 5/5.
- **Riesgo residual**: el control atrapa lo que la pregunta nombra. Una consulta que pida contenido ajeno sin nombrarlo sigue pasando. Cerrarlo pide verificacion de implicacion entre respuesta y contexto, que es otra pasada de inferencia.

### T-08 · Cadena de suministro de la imagen · Tampering · Media

Una dependencia o la imagen base introducen una vulnerabilidad.

- **Controles**: versiones fijadas en `pyproject.toml`; imagen base con tag explicito; `pip-audit` sobre las dependencias y Trivy sobre la imagen en cada build; generacion de SBOM en formato CycloneDX; `hadolint` sobre el Dockerfile.
- **Riesgo residual**: `pip-audit` y Trivy informan pero no bloquean el pipeline. Es intencional mientras no exista una politica de severidad acordada; sin esa politica el gate genera fatiga de alertas y se termina ignorando.

## 3. Que hicimos: resumen de decisiones

| ID | Escenario | STRIDE | Severidad | Decision |
|---|---|---|---|---|
| T-01 | Injection indirecta desde el corpus | T | Media | Mitigar |
| T-02 | Injection directa del usuario | T | Media | Mitigar |
| T-03 | Agotamiento de computo y cuota | D | Alta | Mitigar |
| T-04 | Robo o forja de tokens | S | Alta | Mitigar |
| T-05 | Escalada hacia la reingesta | E | Media | Mitigar |
| T-06 | Fuga por errores y logs | I | Media | Mitigar |
| T-07 | Falta de trazabilidad | R | Baja | Mitigar parcialmente |
| T-08 | Cadena de suministro | T | Media | Mitigar y monitorear |
| T-09 | Respuesta inventada dada por fundamentada | I | Alta | Mitigar, con residual documentado |

## 4. Lo hicimos bien: verificacion

Cada amenaza tiene al menos una prueba automatizada asociada, y esas pruebas corren en
el pipeline en cada push y cada pull request. Un control sin prueba queda como supuesto,
no como control.

```bash
pytest tests/test_auth.py tests/test_guardrails.py tests/test_ratelimit.py tests/test_scope_guard.py -v
```

Las amenazas que no se pueden verificar con un test unitario —evasion de guardrails y
respuestas inventadas— se miden contra el servicio real con las suites de `evals/`.
Los resultados de la ultima corrida estan en [security-audit.md](security-audit.md).

## Amenazas fuera de alcance, y por que

| Amenaza | Motivo |
|---|---|
| Fuga entre inquilinos | El servicio es de un solo inquilino y el corpus es publico. Con varios inquilinos habria que filtrar el retrieval por inquilino antes de recuperar. |
| Abuso de herramientas | El asistente no expone ninguna herramienta: solo lee el indice y responde. |
| Envenenamiento del entrenamiento | No hay entrenamiento ni ajuste fino; el modelo llega ya entrenado. |
| Fuga hacia un proveedor externo | La inferencia es local; ninguna consulta sale del host. |

## Cuando volver a revisar este documento

- Si se expone alguna herramienta o accion que modifique estado.
- Si se agrega un segundo inquilino o contenido no publico al corpus.
- Si la inferencia pasa a un proveedor externo.
- Si el servicio se publica fuera de `localhost`.
- Despues de cualquier incidente que demuestre que un supuesto era falso.
