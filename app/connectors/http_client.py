"""
Cliente HTTP endurecido para conectores salientes.

Cuando una automatización llama al sistema de un cliente, los problemas
no son solo de seguridad: son de seguridad Y de fiabilidad, y se
confunden con facilidad.

Lo que resuelve este módulo:

1. **Control de egreso.** Un conector solo puede alcanzar destinos
   permitidos. Si alguien logra inyectar una URL en la configuración
   (webhook de alertas, por ejemplo), no puede hacer que la aplicación
   hable con un servidor arbitrario ni con la red interna. Reutiliza el
   mismo guard SSRF del escáner: una sola implementación de "a dónde
   puede salir esta aplicación".

2. **Reintentos con backoff exponencial y jitter.** Un fallo transitorio
   no debe perder el evento. El jitter evita que, tras una caída, todas
   las instancias reintenten sincronizadas y tumben al sistema que se
   está recuperando (efecto manada).

3. **Circuit breaker.** Si un destino falla repetidamente, se deja de
   intentar durante un tiempo. Sin esto, un servicio caído convierte cada
   operación en una espera de varios segundos, y la lentitud del tercero
   se transforma en lentitud propia.

4. **Redacción de secretos.** Los logs de error nunca incluyen cabeceras
   de autorización ni la query string, donde suelen viajar tokens. Un
   secreto que termina en el SIEM es un secreto filtrado, aunque el SIEM
   sea de confianza.
"""
import random
import time
from urllib.parse import urlparse, urlunparse

import httpx

from app.config import settings
from app.ssrf_guard import TargetNotAllowed, resolve_public_ips

MAX_REINTENTOS = 3
BACKOFF_BASE_SEGUNDOS = 0.5
UMBRAL_CIRCUITO = 5          # fallos consecutivos antes de abrir
CIRCUITO_ABIERTO_SEGUNDOS = 60
CODIGOS_REINTENTABLES = {408, 425, 429, 500, 502, 503, 504}


class DestinoNoPermitido(Exception):
    """El destino no está en la lista blanca de egreso."""


class CircuitoAbierto(Exception):
    """El destino acumuló demasiados fallos; no se intenta por ahora."""


# Estado del breaker por host: (fallos_consecutivos, momento_de_apertura)
_estado_circuito: dict[str, tuple[int, float]] = {}


def redactar_url(url: str) -> str:
    """Devuelve la URL sin query string ni credenciales embebidas."""
    p = urlparse(url)
    neto = p.hostname or ""
    if p.port:
        neto = f"{neto}:{p.port}"
    return urlunparse((p.scheme, neto, p.path, "", "", ""))


def _validar_egreso(url: str) -> str:
    p = urlparse(url)
    host = p.hostname
    if not host:
        raise DestinoNoPermitido("URL sin host")

    if p.scheme not in ("http", "https"):
        raise DestinoNoPermitido(f"Esquema no permitido: {p.scheme}")

    # Lista blanca explícita, si el despliegue la definió.
    permitidos = [h.strip().lower() for h in (settings.EGRESS_ALLOWLIST or "").split(",") if h.strip()]
    if permitidos and host.lower() not in permitidos:
        raise DestinoNoPermitido(
            f"El host '{host}' no está en la lista blanca de egreso"
        )

    # Aunque esté en la lista blanca, nunca hacia adentro.
    try:
        resolve_public_ips(host)
    except TargetNotAllowed as e:
        raise DestinoNoPermitido(str(e)) from e

    return host


def _circuito_bloqueado(host: str) -> bool:
    fallos, abierto_desde = _estado_circuito.get(host, (0, 0.0))
    if fallos < UMBRAL_CIRCUITO:
        return False
    if time.monotonic() - abierto_desde > CIRCUITO_ABIERTO_SEGUNDOS:
        _estado_circuito.pop(host, None)  # se da otra oportunidad
        return False
    return True


def _registrar_resultado(host: str, ok: bool) -> None:
    if ok:
        _estado_circuito.pop(host, None)
        return
    fallos, abierto_desde = _estado_circuito.get(host, (0, 0.0))
    fallos += 1
    if fallos >= UMBRAL_CIRCUITO and abierto_desde == 0.0:
        abierto_desde = time.monotonic()
    _estado_circuito[host] = (fallos, abierto_desde or 0.0)


def post_json(url: str, payload: dict, timeout: float = 8.0) -> httpx.Response:
    """
    POST endurecido. Lanza DestinoNoPermitido, CircuitoAbierto o
    httpx.RequestError; nunca deja pasar un secreto en el mensaje.
    """
    host = _validar_egreso(url)

    if _circuito_bloqueado(host):
        raise CircuitoAbierto(f"Circuito abierto para {host} tras fallos repetidos")

    ultimo_error: Exception | None = None

    for intento in range(MAX_REINTENTOS):
        try:
            resp = httpx.post(url, json=payload, timeout=timeout, follow_redirects=False)

            if resp.status_code in CODIGOS_REINTENTABLES:
                ultimo_error = httpx.HTTPStatusError(
                    f"HTTP {resp.status_code}", request=resp.request, response=resp
                )
                _dormir_backoff(intento)
                continue

            _registrar_resultado(host, ok=resp.status_code < 400)
            return resp

        except httpx.RequestError as e:
            ultimo_error = e
            _dormir_backoff(intento)

    _registrar_resultado(host, ok=False)
    raise ultimo_error if ultimo_error else httpx.RequestError("Fallo desconocido")


def _dormir_backoff(intento: int) -> None:
    # Exponencial con jitter: 0.5s, 1s, 2s (±25%)
    #
    # El análisis estático marca `random` como no apto para criptografía,
    # y tiene razón en general. Acá no aplica: el jitter solo desincroniza
    # reintentos entre instancias, no protege ningún secreto. Que un
    # atacante prediga cuántos milisegundos esperamos no le sirve de nada.
    # Usar `secrets` aquí sería obedecer a la herramienta sin entenderla.
    espera = BACKOFF_BASE_SEGUNDOS * (2 ** intento)
    # Justificación de la excepción: jitter, no material criptográfico.
    time.sleep(espera * random.uniform(0.75, 1.25))  # nosec B311


def reset_circuito() -> None:
    """Solo para tests."""
    _estado_circuito.clear()
