# Decisiones de arquitectura

Cada seccion registra una decision, el motivo y lo que se resigna al tomarla.

## 1. RAG en lugar de ajuste fino

**Decision.** Recuperar fragmentos del corpus e inyectarlos como contexto, sin tocar
los pesos del modelo.

**Motivo.** El corpus cambia cuando OWASP publica una edicion nueva. Reentrenar por
cada cambio es caro e inviable, y ademas un modelo ajustado no puede citar de donde
sacó una afirmacion. Con recuperacion, actualizar el conocimiento es volver a ejecutar
la ingesta.

**Se resigna.** La calidad depende de que el retrieval traiga el fragmento correcto.
Si el chunk recuperado es el equivocado, la respuesta va a estar bien escrita y mal
fundamentada.

## 2. Modelo local con Ollama en lugar de una API externa

**Decision.** Servir `llama3.2:3b` y `nomic-embed-text` desde un contenedor de Ollama
en la red interna del compose, sin publicar su puerto.

**Motivo.** Ninguna consulta sale del host, no hay clave de proveedor que proteger ni
rotar, y el costo por token es cero, lo que elimina toda una familia de riesgos de
abuso economico. El proyecto queda reproducible sin depender de una cuenta paga.

**Se resigna.** Un modelo de tres mil millones de parametros razona bastante peor que
uno de frontera y la latencia depende del hardware. Se compensa bajando la temperatura
a 0.1 y acotando la tarea a redactar sobre contexto ya recuperado, que es lo que un
modelo chico hace razonablemente bien.

**Por que 3B y no 1B.** Se probaron los dos. Con `llama3.2:1b` el modelo agregaba
contenido que no estaba en el contexto y no respetaba la instruccion de responder solo
con el material provisto. Con 3B la respuesta queda ajustada al contexto. Es el mismo
efecto que describe la bibliografia: un modelo debil rompe la logica de control aunque
el resto del sistema este bien armado.

## 3. El modelo redacta, el codigo decide

**Decision.** El LLM solo interpreta la pregunta y redacta la respuesta. Que documentos
se recuperan, si superan el umbral de relevancia, que se cita y si la respuesta se
publica lo resuelve codigo deterministico.

**Motivo.** Una medicion de la que dependen decisiones no admite inferencia. El
`grounded` de la respuesta y las citas son datos verificables, no opiniones del modelo.

**Como se mide.** Se embebe la respuesta y cada fragmento recuperado, y se toma la
similitud coseno mas alta: alcanza con que un fragmento la sostenga. Se probo primero
con solapamiento de palabras y no sirve, porque el corpus esta en ingles y las
respuestas salen en espanol. Tambien se probo comparar contra los cuatro fragmentos
concatenados, y diluye: una respuesta enfocada matchea bien un fragmento y mal el bloque
entero.

**Calibracion.** Contra el corpus real, las preguntas del dominio dieron entre 0.58 y
0.78 y las de afuera entre 0.40 y 0.46. El umbral quedo en 0.55, en el medio del hueco.

**Se resigna.** Es un unico numero para todo el corpus. Una respuesta correcta pero muy
sintetica puede quedar por debajo del umbral. Se prefiere ese falso positivo antes que
publicar una respuesta inventada.

## 3 bis. Control de alcance antes de recuperar

**Decision.** Si la pregunta nombra otro proyecto de OWASP, otra edicion o un CVE
puntual, se rechaza sin recuperar ni consultar al modelo.

**Motivo.** Es la unica correccion que la medicion respaldaba. Las preguntas de
seguridad que no estan en el corpus recuperaban fragmentos con buena similitud
—hablan del mismo tema— y el modelo las contestaba de memoria marcandolas como
fundamentadas. Los numeros: esas preguntas puntuaron entre 0.61 y 0.78 en
fundamentacion, dentro del rango de las respuestas correctas, y una pregunta legitima
puntuo 0.49. Ningun umbral las separa.

Como el corpus tiene alcance fijo y conocido, la comprobacion se puede hacer por
codigo, que es mas barato y mas predecible que pedirle al modelo que se autoevalue.

**Se resigna.** Es una lista de artefactos conocidos, no una comprension del limite
del corpus: atrapa lo que la pregunta nombra. Cerrarlo del todo pide verificacion de
implicacion entre respuesta y contexto, que es otro modelo y otra pasada.

## 4. Chroma embebido en lugar de un servicio aparte

**Decision.** Vector store embebido, persistido en un volumen.

**Motivo.** El corpus son veinte documentos: unos pocos cientos de fragmentos. A esa
escala la busqueda exhaustiva es exacta e instantanea, y el proyecto excluye
explicitamente escalado y alta disponibilidad. Un contenedor menos es una superficie de
ataque menos y un componente menos que operar.

**Se resigna.** No escala mas alla de una instancia. Con varias replicas o un corpus
mucho mayor habria que pasar a un vector store con servidor.

## 5. Embeddings a traves de Ollama

**Decision.** Vectorizar con `nomic-embed-text` via el mismo servicio de Ollama, en
lugar de una libreria en proceso.

**Motivo.** Evita meter `torch` en la imagen de la API, que son entre dos y tres
gigabytes de dependencias. La imagen final queda mas chica y con menos paquetes que
escanear, que es lo que pide el hardening.

**Se resigna.** La ingesta necesita que Ollama este arriba. Se maneja devolviendo 503
con `Retry-After` en lugar de un error generico.

## 6. Chunking por encabezado, no por cantidad fija de caracteres

**Decision.** Cortar respetando la estructura de encabezados del markdown; dentro de
cada seccion, trozos de 1200 caracteres con 250 de solape, cerrando en el ultimo punto
o parrafo.

**Motivo.** Los documentos de OWASP ya vienen organizados en secciones con sentido
propio: descripcion, escenarios, prevencion. Cortar cada 1200 caracteres a ciegas
mezclaria el final de una categoria con el principio de otra. Ademas el titulo de la
seccion se antepone al texto del fragmento, asi que entra en el embedding y sirve
despues para citar.

**Detalle que costo un bug.** El identificador de cada fragmento incluye el archivo de
origen. Los documentos de OWASP repiten los mismos titulos entre categorias, y con un
identificador basado solo en la seccion, el fragmento "Prevencion" de A05 pisaba al de
A01 durante la indexacion. El test
`test_dos_documentos_con_la_misma_seccion_no_colisionan` cubre esa regresion.

## 7. JWT propio en lugar de un proveedor de identidad

**Decision.** Endpoint `/auth/token` con el flujo de contrasena de OAuth2, que emite un
JWT firmado con HS256 y scopes.

**Motivo.** Montar un proveedor de identidad completo para dos usuarios de demostracion
agrega un componente que no aporta al alcance. El flujo elegido es el estandar de
FastAPI y hace que el boton Authorize de Swagger funcione sin configuracion extra.

**Se resigna.** No hay revocacion, ni refresh token, ni rotacion de claves. El token
dura treinta minutos justamente porque no se puede revocar. HS256 usa un secreto
compartido; con varios servicios verificando el token convendria RS256 con clave
publica.

## 8. Limites en memoria del proceso

**Decision.** Token bucket y presupuesto diario de tokens guardados en memoria.

**Motivo.** Con una sola instancia alcanza y no agrega una dependencia de Redis.

**Se resigna.** Con varias replicas cada una llevaria su propia cuenta y el limite real
seria el configurado multiplicado por la cantidad de instancias. Esta anotado como T-03
en el modelo de amenazas y es el primer cambio necesario para escalar.

## 9. Dos limites distintos: peticiones y tokens

**Decision.** Ademas del limite de peticiones por minuto, un presupuesto diario de
tokens por usuario.

**Motivo.** En un servicio con modelo de lenguaje, contar peticiones no alcanza: una
sola consulta con un contexto largo consume mucho mas que diez consultas cortas. El
recurso escaso es el computo, no la cantidad de llamadas.

## 10. Errores en formato problem+json

**Decision.** Todas las respuestas de error siguen RFC 9457, con un campo `type` que es
un codigo estable y un `trace_id`.

**Motivo.** El cliente puede ramificar por el codigo sin parsear mensajes en prosa, y
soporte puede correlacionar con el log usando el `trace_id`. El detalle tecnico nunca
sale al cliente.

## 11. Lo que se decidio no construir

| Alternativa evaluada | Por que quedo afuera |
|---|---|
| Busqueda hibrida con BM25 y fusion de rankings | Resuelve la busqueda por terminos exactos como identificadores y codigos. El corpus es pequeno y las preguntas son conceptuales, no de codigo exacto. Seria la primera mejora si aparecieran consultas del tipo "que dice exactamente API4:2023". |
| Reordenamiento con cross-encoder | Sube la precision cuando el top-k trae ruido. Con cuatro fragmentos sobre un corpus chico no hay suficiente ruido que justifique una segunda pasada de modelo. |
| RAG agentico y multi-salto | Requiere varias llamadas al modelo por consulta. Las preguntas de este dominio se responden con una sola busqueda. |
| Exponer herramientas al modelo | Cambiaria el peor caso de "una respuesta incorrecta" a "una accion no autorizada". No hay ninguna accion que el asistente necesite ejecutar. |
| Multi-inquilino | El corpus es publico: no hay nada que aislar entre usuarios. |
| Kubernetes | El proyecto corre en una maquina. La orquestacion no resuelve ningun problema que este proyecto tenga. |

En todos los casos aplica el mismo criterio: elegir el menor nivel de autonomia y de
complejidad que resuelva el caso con seguridad y costo razonables.
