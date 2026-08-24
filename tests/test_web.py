"""Tests de la interfaz web y de las cabeceras que la protegen."""


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
