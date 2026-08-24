// Aplica el tema guardado antes de que la pagina pinte.
//
// Va en un archivo aparte y se carga sin defer en el <head> a proposito. La CSP no
// permite scripts en linea, que es la forma habitual de resolver esto, y si el tema
// se aplicara desde app.js al final del <body> se veria un destello del tema
// equivocado en cada carga.

(function () {
  "use strict";

  var CLAVE = "owasp-rag-tema";

  try {
    var guardado = localStorage.getItem(CLAVE);
    // "auto" no escribe el atributo: deja decidir a prefers-color-scheme.
    if (guardado === "claro" || guardado === "oscuro") {
      document.documentElement.setAttribute("data-tema", guardado);
    }
  } catch (e) {
    // Modo privado o almacenamiento bloqueado: se queda en automatico.
  }
})();
