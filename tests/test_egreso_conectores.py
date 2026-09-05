"""
Tests del cliente HTTP endurecido: control de egreso, reintentos,
circuit breaker y redacción de secretos.
"""
import httpx
import pytest

from app.config import settings
from app.connectors import http_client
from app.connectors.http_client import (
    CircuitoAbierto,
    DestinoNoPermitido,
    post_json,
    redactar_url,
    reset_circuito,
)


@pytest.fixture(autouse=True)
def _limpiar():
    reset_circuito()
    yield
    reset_circuito()


@pytest.fixture
def _sin_espera(monkeypatch):
    """Elimina el backoff real para que los tests no tarden segundos."""
    monkeypatch.setattr(http_client, "_dormir_backoff", lambda intento: None)


# ---------------------------------------------------------------------
# Control de egreso
# ---------------------------------------------------------------------

@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data/",   # metadata del cloud
        "http://127.0.0.1:8000/interno",
        "http://10.0.0.5/webhook",
        "http://192.168.1.1/",
    ],
)
def test_no_se_puede_salir_hacia_la_red_interna(url):
    """
    La URL del webhook la configura un administrador. Sin control de
    egreso, quien pueda editar esa configuración hace que la aplicación
    hable con la red interna del proveedor.
    """
    with pytest.raises(DestinoNoPermitido):
        post_json(url, {"texto": "hola"})


def test_esquema_no_http_se_rechaza():
    with pytest.raises(DestinoNoPermitido):
        post_json("file:///etc/passwd", {})


def test_lista_blanca_bloquea_hosts_no_declarados(monkeypatch):
    monkeypatch.setattr(settings, "EGRESS_ALLOWLIST", "hooks.slack.com")

    with pytest.raises(DestinoNoPermitido):
        post_json("https://example.com/webhook", {})


# ---------------------------------------------------------------------
# Redacción de secretos
# ---------------------------------------------------------------------

def test_la_url_redactada_no_filtra_el_token():
    # Los webhooks suelen llevar el token en la query string.
    url = "https://hooks.slack.com/services/T000/B000?token=SECRETO_MUY_SENSIBLE"
    redactada = redactar_url(url)

    assert "SECRETO_MUY_SENSIBLE" not in redactada
    assert "hooks.slack.com" in redactada


def test_la_url_redactada_no_filtra_credenciales_embebidas():
    redactada = redactar_url("https://usuario:contrasena@ejemplo.com/hook")

    assert "contrasena" not in redactada
    assert "usuario" not in redactada


# ---------------------------------------------------------------------
# Reintentos
# ---------------------------------------------------------------------

def test_reintenta_ante_error_transitorio(monkeypatch, _sin_espera):
    intentos = {"n": 0}

    def fake_post(url, json, timeout, follow_redirects):
        intentos["n"] += 1
        if intentos["n"] < 3:
            raise httpx.ConnectError("caida transitoria")
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(http_client, "_validar_egreso", lambda url: "ejemplo.com")
    monkeypatch.setattr(http_client.httpx, "post", fake_post)

    resp = post_json("https://ejemplo.com/hook", {})

    assert resp.status_code == 200
    assert intentos["n"] == 3


def test_no_reintenta_ante_error_del_cliente(monkeypatch, _sin_espera):
    """Un 400 es culpa nuestra: reintentarlo solo genera ruido."""
    intentos = {"n": 0}

    def fake_post(url, json, timeout, follow_redirects):
        intentos["n"] += 1
        return httpx.Response(400, request=httpx.Request("POST", url))

    monkeypatch.setattr(http_client, "_validar_egreso", lambda url: "ejemplo.com")
    monkeypatch.setattr(http_client.httpx, "post", fake_post)

    post_json("https://ejemplo.com/hook", {})
    assert intentos["n"] == 1


# ---------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------

def test_el_circuito_se_abre_tras_fallos_repetidos(monkeypatch, _sin_espera):
    """
    Sin breaker, un destino caído convierte cada alerta en varios
    segundos de espera: la lentitud del tercero se vuelve propia.
    """
    def fake_post(url, json, timeout, follow_redirects):
        raise httpx.ConnectError("destino caido")

    monkeypatch.setattr(http_client, "_validar_egreso", lambda url: "caido.ejemplo.com")
    monkeypatch.setattr(http_client.httpx, "post", fake_post)

    # Se acumulan fallos hasta superar el umbral.
    for _ in range(http_client.UMBRAL_CIRCUITO):
        with pytest.raises(httpx.RequestError):
            post_json("https://caido.ejemplo.com/hook", {})

    # A partir de acá corta de inmediato, sin intentar la conexión.
    with pytest.raises(CircuitoAbierto):
        post_json("https://caido.ejemplo.com/hook", {})


def test_un_exito_reinicia_el_contador(monkeypatch, _sin_espera):
    estado = {"fallar": True}

    def fake_post(url, json, timeout, follow_redirects):
        if estado["fallar"]:
            raise httpx.ConnectError("fallo")
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(http_client, "_validar_egreso", lambda url: "intermitente.ejemplo.com")
    monkeypatch.setattr(http_client.httpx, "post", fake_post)

    for _ in range(http_client.UMBRAL_CIRCUITO - 1):
        with pytest.raises(httpx.RequestError):
            post_json("https://intermitente.ejemplo.com/hook", {})

    estado["fallar"] = False
    assert post_json("https://intermitente.ejemplo.com/hook", {}).status_code == 200

    # Tras el éxito, el circuito debe estar limpio.
    estado["fallar"] = True
    for _ in range(http_client.UMBRAL_CIRCUITO - 1):
        with pytest.raises(httpx.RequestError):
            post_json("https://intermitente.ejemplo.com/hook", {})
