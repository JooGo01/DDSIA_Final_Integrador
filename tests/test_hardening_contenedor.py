"""Fija los controles de hardening del contenedor declarados en el README.

La tabla de controles del README afirma que ninguno esta solo documentado y que cada
uno tiene su prueba. Era cierto para dieciseis de las diecisiete filas: la del
contenedor no tenia ninguna. El unico chequeo automatizado era el de no-root en el
pipeline, asi que read_only, cap_drop, no-new-privileges y los limites de recursos se
podian borrar del compose sin que nada se pusiera en rojo.

Estos tests leen los archivos de despliegue, no el runtime: verifican lo declarado,
que es lo que se versiona y lo que se revisa en un diff. Que lo declarado se aplique
de verdad lo comprueba el job `image` del pipeline sobre la imagen construida.
"""

from pathlib import Path

import pytest
import yaml

RAIZ = Path(__file__).resolve().parent.parent
COMPOSE = RAIZ / "docker-compose.yml"
DOCKERFILE = RAIZ / "Dockerfile"

# Todos los servicios del stack, no solo el propio: el de inferencia corre texto que
# viene del usuario y durante un tiempo fue el unico sin ningun control.
SERVICIOS = ("api", "ollama", "model-loader")


@pytest.fixture(scope="module")
def compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_estan_declarados_los_tres_servicios(compose):
    assert set(SERVICIOS) <= set(compose["services"])


@pytest.mark.parametrize("servicio", SERVICIOS)
def test_ningun_contenedor_conserva_capabilities(compose, servicio):
    assert compose["services"][servicio]["cap_drop"] == ["ALL"]


@pytest.mark.parametrize("servicio", SERVICIOS)
def test_ningun_contenedor_puede_escalar_privilegios(compose, servicio):
    assert "no-new-privileges:true" in compose["services"][servicio]["security_opt"]


@pytest.mark.parametrize("servicio", SERVICIOS)
def test_ningun_contenedor_escribe_en_su_filesystem(compose, servicio):
    assert compose["services"][servicio]["read_only"] is True


@pytest.mark.parametrize("servicio", SERVICIOS)
def test_todo_contenedor_tiene_techo_de_memoria_y_de_procesos(compose, servicio):
    definicion = compose["services"][servicio]
    assert definicion["mem_limit"]
    assert definicion["pids_limit"]
    assert definicion["cpus"]


@pytest.mark.parametrize("servicio", ("ollama", "model-loader"))
def test_los_servicios_de_terceros_corren_sin_privilegios(compose, servicio):
    """La imagen oficial de Ollama corre como root si no se le dice otra cosa."""
    usuario = str(compose["services"][servicio]["user"])
    assert not usuario.startswith("0:"), f"{servicio} corre como root"
    assert usuario.split(":")[0] != "0", f"{servicio} corre como root"


def test_la_api_declara_su_usuario_en_la_imagen(dockerfile):
    """El de la API no viene del compose sino del Dockerfile, con UID fijo."""
    assert "USER appuser" in dockerfile
    assert "--uid 10001" in dockerfile
    # Nada puede volver a root despues de bajar de privilegios.
    despues = dockerfile.split("USER appuser", 1)[1]
    assert "USER root" not in despues


def test_la_imagen_final_es_minima_y_de_dos_etapas(dockerfile):
    assert dockerfile.count("FROM ") >= 2, "se perdio el multi-stage"
    assert "slim" in dockerfile, "la imagen base dejo de ser slim"
    # Las herramientas de compilacion no pueden llegar a la etapa final.
    etapa_final = dockerfile.split("AS runtime", 1)[1]
    assert "build-essential" not in etapa_final


def test_el_puerto_no_se_publica_a_todas_las_interfaces(compose):
    """Un 8000 suelto expone el servicio a la red, no solo a la maquina."""
    for publicado in compose["services"]["api"]["ports"]:
        assert str(publicado).startswith("127.0.0.1:")


def test_el_modelo_no_se_expone_al_host(compose):
    """Solo la API habla con Ollama: si tuviera ports, quedaria accesible sin auth."""
    assert "ports" not in compose["services"]["ollama"]


def test_los_montajes_de_configuracion_son_de_solo_lectura(compose):
    """El corpus y el archivo de usuarios no los tiene que poder reescribir la API."""
    montajes = [m for m in compose["services"]["api"]["volumes"] if m.startswith("./")]
    assert montajes, "se esperaba al menos el corpus y los usuarios montados"
    for montaje in montajes:
        assert montaje.endswith(":ro"), f"{montaje} deberia ser de solo lectura"
