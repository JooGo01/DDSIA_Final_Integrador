// Interfaz del asistente OWASP RAG.
//
// Dos decisiones que valen la aclaracion:
//
// 1. El token vive en una variable de este modulo y en ningun otro lado. No va a
//    localStorage ni a sessionStorage ni a una cookie: si alguna vez se cuela un XSS,
//    ahi no hay nada que robar, y al recargar la pagina hay que volver a autenticarse.
// 2. Todo lo que llega del servidor se escribe con textContent, nunca con innerHTML.
//    La respuesta la redacta un modelo sobre documentos que pueden traer HTML, asi que
//    se trata como texto. La CSP del servidor es la segunda barrera, no la unica.

(function () {
  "use strict";

  var token = null;
  var usuario = null;
  var scopes = [];
  var venceEn = 0; // epoch en milisegundos
  var relojSesion = null;
  var relojConsulta = null;
  var relojEstado = null;

  var el = function (id) { return document.getElementById(id); };

  // --- Utilidades de red ---

  function mensajeDeError(status, cuerpo, retryAfter) {
    // Los errores de la API vienen en application/problem+json.
    if (cuerpo && cuerpo.title) {
      var texto = cuerpo.title;
      if (cuerpo.detail) { texto += ": " + cuerpo.detail; }
      if (status === 429 && retryAfter) { texto += " (reintentá en " + retryAfter + " s)"; }
      return texto;
    }
    if (status === 0) { return "No se pudo contactar al servicio. Verificá que este arriba."; }
    return "Error " + status + " al hablar con la API.";
  }

  function pedir(ruta, opciones) {
    var config = opciones || {};
    var cabeceras = config.headers || {};
    if (token) { cabeceras["Authorization"] = "Bearer " + token; }

    return fetch(ruta, {
      method: config.method || "GET",
      headers: cabeceras,
      body: config.body,
      cache: "no-store"
    }).then(function (respuesta) {
      var tipo = respuesta.headers.get("Content-Type") || "";
      var cuerpo = tipo.indexOf("json") !== -1 ? respuesta.json() : Promise.resolve(null);
      return cuerpo.catch(function () { return null; }).then(function (datos) {
        if (respuesta.ok) { return datos; }
        var error = new Error(
          mensajeDeError(respuesta.status, datos, respuesta.headers.get("Retry-After"))
        );
        error.status = respuesta.status;
        throw error;
      });
    }, function () {
      var error = new Error(mensajeDeError(0, null, null));
      error.status = 0;
      throw error;
    });
  }

  // --- Sesion ---

  function leerClaims(jwt) {
    // Se lee el payload solo para saber que mostrar y cuando expira. Los permisos
    // los valida el servidor en cada request: aca no se decide nada de seguridad.
    try {
      var partes = jwt.split(".");
      if (partes.length !== 3) { return {}; }
      var base64 = partes[1].replace(/-/g, "+").replace(/_/g, "/");
      while (base64.length % 4 !== 0) { base64 += "="; }
      return JSON.parse(atob(base64)) || {};
    } catch (e) {
      return {};
    }
  }

  function iniciarSesion(accessToken, expiresIn) {
    token = accessToken;
    var claims = leerClaims(accessToken);
    usuario = claims.sub || "?";
    scopes = Array.isArray(claims.scopes) ? claims.scopes : [];
    venceEn = Date.now() + (expiresIn || 0) * 1000;

    el("sesion-usuario").textContent = usuario;
    el("sesion-scopes").textContent = scopes.length ? scopes.join(" ") : "sin scopes";

    el("seccion-login").hidden = true;
    el("seccion-sesion").hidden = false;
    el("seccion-consulta").hidden = false;
    el("seccion-admin").hidden = scopes.indexOf("admin:ingest") === -1;

    el("clave").value = "";
    el("pregunta").focus();

    relojSesion = setInterval(actualizarVencimiento, 1000);
    actualizarVencimiento();
  }

  function cerrarSesion(motivo) {
    token = null;
    usuario = null;
    scopes = [];
    venceEn = 0;
    if (relojSesion) { clearInterval(relojSesion); relojSesion = null; }

    el("seccion-sesion").hidden = true;
    el("seccion-consulta").hidden = true;
    el("seccion-respuesta").hidden = true;
    el("seccion-admin").hidden = true;
    el("seccion-login").hidden = false;

    if (motivo) { mostrarMensaje("error-login", motivo); } else { ocultar("error-login"); }
    el("clave").value = "";
  }

  function actualizarVencimiento() {
    var restante = Math.floor((venceEn - Date.now()) / 1000);
    if (restante <= 0) {
      cerrarSesion("El token vencio. Volvé a ingresar.");
      return;
    }
    var minutos = Math.floor(restante / 60);
    var segundos = restante % 60;
    el("sesion-vence").textContent =
      "token: " + minutos + ":" + (segundos < 10 ? "0" : "") + segundos;
  }

  // --- Mensajes ---

  function mostrarMensaje(id, texto) {
    var nodo = el(id);
    nodo.textContent = texto;
    nodo.hidden = false;
  }

  function ocultar(id) {
    var nodo = el(id);
    nodo.textContent = "";
    nodo.hidden = true;
  }

  // --- Estado del servicio ---

  function pintarEstado(salud) {
    var pill = el("estado-pill");
    var detalle = el("estado-detalle");

    if (!salud) {
      pill.textContent = "sin conexion";
      pill.className = "pill pill-error";
      detalle.textContent = "";
      return;
    }

    if (salud.indexing) {
      pill.textContent = "indexando";
      pill.className = "pill pill-alerta";
      detalle.textContent = "construyendo el indice, puede tardar unos minutos";
    } else if (salud.status === "ok") {
      pill.textContent = "operativo";
      pill.className = "pill pill-ok";
      detalle.textContent = salud.collection_chunks + " fragmentos indexados";
    } else {
      pill.textContent = "degradado";
      pill.className = "pill pill-alerta";
      detalle.textContent = salud.llm_reachable
        ? "indice vacio: todavia no hay nada que consultar"
        : "el modelo no responde";
    }
    programarEstado(salud.indexing ? 5000 : 20000);
  }

  function programarEstado(intervalo) {
    if (relojEstado) { clearTimeout(relojEstado); }
    relojEstado = setTimeout(consultarEstado, intervalo);
  }

  function consultarEstado() {
    fetch("/health", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(pintarEstado)
      .catch(function () { pintarEstado(null); programarEstado(15000); });
  }

  // --- Respuesta ---

  function pintarRespuesta(datos) {
    el("pill-fundamentada").textContent = datos.grounded ? "fundamentada" : "sin fundamento";
    el("pill-fundamentada").className = "pill " + (datos.grounded ? "pill-ok" : "pill-alerta");
    el("texto-respuesta").textContent = datos.answer;

    var lista = el("lista-citas");
    lista.textContent = "";
    var citas = datos.citations || [];
    el("bloque-citas").hidden = citas.length === 0;
    citas.forEach(function (cita) {
      var item = document.createElement("li");
      var relevancia = document.createElement("span");
      relevancia.className = "cita-relevancia";
      relevancia.textContent = "relevancia " + cita.relevance;
      var documento = document.createElement("span");
      documento.className = "cita-documento";
      documento.textContent = cita.document;
      var seccion = document.createElement("span");
      seccion.textContent = cita.section;
      item.appendChild(relevancia);
      item.appendChild(documento);
      item.appendChild(seccion);
      lista.appendChild(item);
    });

    var uso = datos.usage || {};
    var metricas = [
      ["Fragmentos", String(uso.retrieved_chunks)],
      ["Tokens entrada", String(uso.input_tokens)],
      ["Tokens salida", String(uso.output_tokens)],
      ["Latencia", (uso.latency_ms / 1000).toFixed(1) + " s"],
      ["Request id", datos.request_id]
    ];
    var contenedor = el("metricas");
    contenedor.textContent = "";
    metricas.forEach(function (par) {
      var grupo = document.createElement("div");
      var titulo = document.createElement("dt");
      titulo.textContent = par[0];
      var valor = document.createElement("dd");
      valor.textContent = par[1];
      grupo.appendChild(titulo);
      grupo.appendChild(valor);
      contenedor.appendChild(grupo);
    });

    el("seccion-respuesta").hidden = false;
  }

  function arrancarCronometro() {
    var desde = Date.now();
    el("cronometro").textContent = "0 s";
    el("cargando").hidden = false;
    relojConsulta = setInterval(function () {
      el("cronometro").textContent = Math.floor((Date.now() - desde) / 1000) + " s";
    }, 1000);
  }

  function pararCronometro() {
    if (relojConsulta) { clearInterval(relojConsulta); relojConsulta = null; }
    el("cargando").hidden = true;
  }

  // --- Eventos ---

  el("form-login").addEventListener("submit", function (evento) {
    evento.preventDefault();
    ocultar("error-login");
    var boton = el("boton-login");
    boton.disabled = true;

    var cuerpo = new URLSearchParams();
    cuerpo.set("username", el("usuario").value);
    cuerpo.set("password", el("clave").value);

    pedir("/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: cuerpo.toString()
    }).then(function (datos) {
      iniciarSesion(datos.access_token, datos.expires_in);
    }).catch(function (error) {
      mostrarMensaje("error-login", error.message);
    }).then(function () {
      boton.disabled = false;
    });
  });

  el("boton-salir").addEventListener("click", function () { cerrarSesion(null); });

  el("pregunta").addEventListener("input", function () {
    var largo = el("pregunta").value.trim().length;
    el("contador").textContent = largo + " / 600";
    el("boton-preguntar").disabled = largo < 8 || largo > 600;
  });

  el("pregunta").addEventListener("keydown", function (evento) {
    if (evento.key === "Enter" && (evento.ctrlKey || evento.metaKey)) {
      evento.preventDefault();
      el("form-consulta").requestSubmit();
    }
  });

  el("form-consulta").addEventListener("submit", function (evento) {
    evento.preventDefault();
    ocultar("error-consulta");
    el("seccion-respuesta").hidden = true;
    var boton = el("boton-preguntar");
    boton.disabled = true;
    arrancarCronometro();

    pedir("/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question: el("pregunta").value.trim(),
        source: el("fuente").value
      })
    }).then(function (datos) {
      pintarRespuesta(datos);
    }).catch(function (error) {
      if (error.status === 401) {
        cerrarSesion("La sesion no es valida. Volvé a ingresar.");
      } else {
        mostrarMensaje("error-consulta", error.message);
      }
    }).then(function () {
      pararCronometro();
      boton.disabled = false;
      consultarEstado();
    });
  });

  el("boton-reindexar").addEventListener("click", function () {
    ocultar("error-admin");
    ocultar("resultado-admin");
    var boton = el("boton-reindexar");
    boton.disabled = true;
    boton.textContent = "Reindexando…";

    pedir("/admin/ingest", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reset: el("reset-indice").checked })
    }).then(function (datos) {
      var texto = datos.documents + " documentos, " + datos.chunks + " fragmentos en " +
        (datos.duration_ms / 1000).toFixed(1) + " s";
      if (datos.rejected && datos.rejected.length) {
        texto += ". Descartados por contener instrucciones: " + datos.rejected.join(", ");
      }
      mostrarMensaje("resultado-admin", texto);
    }).catch(function (error) {
      if (error.status === 401) {
        cerrarSesion("La sesion no es valida. Volvé a ingresar.");
      } else {
        mostrarMensaje("error-admin", error.message);
      }
    }).then(function () {
      boton.disabled = false;
      boton.textContent = "Reindexar";
      consultarEstado();
    });
  });

  // --- Arranque ---

  el("boton-preguntar").disabled = true;
  consultarEstado();
})();
