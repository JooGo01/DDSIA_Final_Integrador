"""Tests de la interfaz web y de las cabeceras que la protegen."""

import re


def test_la_raiz_sirve_la_interfaz(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "OWASP RAG Assistant" in response.text
    # La interfaz habla con la API por fetch, nunca con la pagina embebiendo credenciales.
    assert "/assets/app.js" in response.text


def test_los_assets_se_sirven_desde_el_mismo_origen(client):
    assets = (
        ("/assets/app.js", "javascript"),
        ("/assets/theme.js", "javascript"),
        ("/assets/styles.css", "css"),
        ("/assets/favicon.svg", "svg"),
    )
    for ruta, tipo in assets:
        response = client.get(ruta)
        assert response.status_code == 200, ruta
        assert tipo in response.headers["content-type"], ruta


def test_la_interfaz_no_puede_cargar_nada_de_afuera(client):
    politica = client.get("/").headers["Content-Security-Policy"]
    assert "default-src 'self'" in politica
    assert "object-src 'none'" in politica
    assert "frame-ancestors 'none'" in politica
    # Si el JavaScript fallara, el navegador no puede mandar la contrasena por la URL.
    assert "form-action 'none'" in politica


def test_la_interfaz_no_trae_javascript_en_linea(client):
    """La CSP no permite scripts en linea: si hubiera alguno, la pagina no funcionaria."""
    html = client.get("/").text
    assert "onclick=" not in html
    assert "<script>" not in html


def test_swagger_queda_exento_de_la_csp(client):
    """Swagger carga su JS de un CDN: con la politica de la interfaz no arrancaria."""
    response = client.get("/docs")
    assert response.status_code == 200
    assert "Content-Security-Policy" not in response.headers


def test_la_api_tambien_responde_con_la_politica(client):
    """La CSP no es solo de la pagina: aplica a cualquier respuesta que no sea Swagger."""
    assert "Content-Security-Policy" in client.get("/health").headers


def test_los_bloques_ocultos_no_se_muestran(client):
    """Una clase con display propio le gana a [hidden]: el loading quedaba pegado."""
    css = client.get("/assets/styles.css").text
    assert "[hidden]" in css
    assert "display: none !important" in css


def test_estan_definidos_los_dos_temas(client):
    css = client.get("/assets/styles.css").text
    # Preferencia del sistema, y las dos elecciones manuales que tienen que pisarla.
    assert "prefers-color-scheme: dark" in css
    assert ':root:not([data-tema="claro"])' in css
    assert ':root[data-tema="oscuro"]' in css


def test_el_tema_se_aplica_antes_del_primer_pintado(client):
    """Sin esto se ve un destello del tema equivocado en cada carga."""
    html = client.get("/").text
    assert '<script src="/assets/theme.js"></script>' in html
    assert html.index("theme.js") < html.index("</head>")


# --- Propiedades que sostienen la defensa de la interfaz -----------------------
#
# Los tests de arriba comprueban que la interfaz funciona. Estos comprueban que sigue
# siendo segura: son las propiedades de las que depende esa seguridad, y que hasta ahora
# estaban solo documentadas en los comentarios de `app.js`.

# Escrituras de HTML sin escapar. Se buscan como asignacion o como llamada, y no como
# palabra suelta, porque el encabezado de app.js menciona `innerHTML` en prosa para
# explicar justamente que no se usa.
ESCRITURA_DE_HTML = re.compile(
    r"\.\s*(innerHTML|outerHTML)\s*=|\b(insertAdjacentHTML|document\.write)\s*\(",
    re.IGNORECASE,
)
EJECUCION_DE_TEXTO = re.compile(r"\beval\s*\(|\bnew\s+Function\s*\(")


def test_la_interfaz_nunca_escribe_html_que_venga_del_servidor(client):
    """La respuesta la redacta un modelo sobre documentos que pueden traer HTML.

    Es la propiedad mas importante de todo el frontend y hasta ahora nada la fijaba:
    alguien podia agregar un `innerHTML` para renderizar markdown y la suite seguia
    en verde.
    """
    for ruta in ("/assets/app.js", "/assets/theme.js"):
        js = client.get(ruta).text
        assert not ESCRITURA_DE_HTML.search(js), ruta
        assert not EJECUCION_DE_TEXTO.search(js), ruta

    # Y que efectivamente escriba por la via segura, para que el test no pase por
    # el simple hecho de que el archivo este vacio.
    assert "textContent" in client.get("/assets/app.js").text


def test_el_token_no_se_guarda_en_el_navegador(client):
    """El token vive en una variable del modulo y en ningun otro lado.

    Lo unico que se persiste es la preferencia de tema. Si manana el token fuera a
    parar a `localStorage`, un XSS pasaria de suplantar en sesion a robar credenciales.
    """
    app_js = client.get("/assets/app.js").text
    theme_js = client.get("/assets/theme.js").text

    # Se busca el uso y no la palabra: el encabezado de app.js nombra los tres
    # almacenes para explicar que el token no va a ninguno.
    for js, nombre in ((app_js, "app.js"), (theme_js, "theme.js")):
        assert not re.search(r"sessionStorage\s*[.\[]", js), nombre
        assert not re.search(r"document\s*\.\s*cookie", js), nombre

    # El unico uso de almacenamiento es el del tema, y guarda la clave del tema.
    escrituras = re.findall(r"localStorage\.setItem\(\s*([A-Za-z_$][\w$]*)", app_js + theme_js)
    assert escrituras, "se esperaba al menos la escritura de la preferencia de tema"
    assert set(escrituras) <= {"CLAVE_TEMA", "CLAVE"}, escrituras


def test_los_assets_no_dejan_salir_de_su_directorio(client):
    """Solo se prueban las formas que llegan enteras a la aplicacion.

    El cliente de pruebas normaliza la ruta antes de mandarla: `/assets/../README.md`
    sale como `/README.md`, asi que un 404 ahi no dice nada sobre el servidor de
    archivos. Las de abajo si viajan con el intento de salida adentro.
    """
    intentos = (
        "/assets/..%2f..%2fpyproject.toml",
        "/assets/....//index.html",
        "/assets/%2e%2e/index.html",
        "/assets/..%5c..%5cpyproject.toml",
        "/assets/..%252f..%252fpyproject.toml",
    )
    for ruta in intentos:
        assert client.get(ruta).status_code == 404, ruta

    # El montaje apunta al subdirectorio, asi que el HTML tampoco es alcanzable.
    assert client.get("/assets/index.html").status_code == 404
    assert client.get("/assets/app.js").status_code == 200


def test_las_cabeceras_de_seguridad_cubren_tambien_la_interfaz(client):
    """Estaban verificadas sobre /ask, que es justo donde no protegen al navegador."""
    for ruta in ("/", "/assets/app.js", "/assets/styles.css"):
        cabeceras = client.get(ruta).headers
        assert cabeceras["X-Content-Type-Options"] == "nosniff", ruta
        assert cabeceras["X-Frame-Options"] == "DENY", ruta
        assert cabeceras["Referrer-Policy"] == "no-referrer", ruta
        assert "Content-Security-Policy" in cabeceras, ruta
