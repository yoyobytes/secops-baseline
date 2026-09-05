"""
El guard SSRF es lo que hace publicable la app: sin él, cualquiera con
el link usa nuestro servidor para alcanzar direcciones internas del
proveedor de hosting.

Estos tests son la red de seguridad de esa protección. Si alguien
"simplifica" el guard en el futuro, esto se pone rojo.
"""
import pytest

from app import scanner
from app.ssrf_guard import TargetNotAllowed, resolve_public_ips, validate_url


@pytest.mark.parametrize(
    "objetivo",
    [
        "127.0.0.1",           # loopback
        "localhost",           # loopback por nombre
        "169.254.169.254",     # metadata de cloud: el objetivo clásico de SSRF
        "10.0.0.5",            # RFC1918
        "192.168.1.1",         # RFC1918
        "172.16.0.10",         # RFC1918
        "0.0.0.0",             # unspecified
        "::1",                 # loopback IPv6
    ],
)
def test_direcciones_internas_son_rechazadas(objetivo):
    with pytest.raises(TargetNotAllowed):
        resolve_public_ips(objetivo)


def test_dominio_publico_es_aceptado():
    ips = resolve_public_ips("example.com")
    assert ips, "example.com debería resolver a al menos una IP pública"


def test_esquema_no_http_es_rechazado():
    for url in ["file:///etc/passwd", "gopher://interno/", "ftp://interno/"]:
        with pytest.raises(TargetNotAllowed):
            validate_url(url)


def test_puerto_no_estandar_es_rechazado():
    # Evita usar el escáner para barrer puertos internos (p. ej. 6379 Redis).
    with pytest.raises(TargetNotAllowed):
        validate_url("http://example.com:6379/")


def test_scan_completo_rechaza_objetivo_interno_sin_ejecutar_chequeos():
    resultado = scanner.run_security_scan("169.254.169.254")

    assert resultado["severity_summary"] == "critical"
    assert resultado["findings"][0]["check"] == "objetivo_no_permitido"
    # Solo el hallazgo del rechazo: no se ejecutó TLS ni DNS contra el objetivo.
    assert len(resultado["findings"]) == 1


def test_redirect_hacia_direccion_interna_es_bloqueado(monkeypatch):
    """
    Un sitio externo legítimo puede responder "302 -> 169.254.169.254".
    Validar solo el destino inicial no alcanza: hay que validar cada salto.
    """

    class _FakeRedirect:
        is_redirect = True
        headers = {"location": "http://169.254.169.254/latest/meta-data/"}
        next_request = None

    monkeypatch.setattr(scanner.httpx, "get", lambda *a, **kw: _FakeRedirect())

    findings = scanner._check_headers("https://example.com")
    assert findings[0]["check"] == "objetivo_no_permitido"
