"""
Protección SSRF para el escáner.

En local esto era irrelevante: el único que escribía un dominio en el
formulario era el dueño de la máquina. Publicada en internet, la app
pasa a ser un "proxy que hace requests por vos": cualquiera con el link
escribe un destino y NUESTRO servidor sale a buscarlo, desde dentro de
la red del proveedor de hosting.

El abuso clásico es apuntar el escáner a direcciones que solo son
alcanzables desde adentro:
  - 169.254.169.254 -> endpoint de metadata de AWS/GCP/Azure, que puede
    devolver credenciales temporales de la instancia.
  - 127.0.0.1 / localhost -> servicios internos del propio contenedor.
  - 10.x / 192.168.x / 172.16-31.x -> el resto de la red privada.

Por eso se resuelve el hostname ANTES de conectar y se valida cada IP
resultante. Se valida también cada salto de redirect (ver scanner.py):
de nada sirve validar el destino inicial si el sitio responde
"302 -> http://169.254.169.254/".
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443}


class TargetNotAllowed(Exception):
    """El objetivo pedido no es escaneable (interno, malformado o no resoluble)."""


def _ip_is_public(ip: ipaddress._BaseAddress) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local      # incluye 169.254.169.254 (cloud metadata)
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def resolve_public_ips(hostname: str) -> list[str]:
    """
    Resuelve el hostname y exige que TODAS las IPs devueltas sean
    públicas. Si una sola apunta hacia adentro, se rechaza el objetivo
    entero -- un dominio puede resolver a varias IPs y basta una interna
    para que la request termine donde no queremos.
    """
    if not hostname:
        raise TargetNotAllowed("Objetivo vacío")

    # Un literal de IP se valida directo, sin pasar por DNS.
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None

    if literal is not None:
        if not _ip_is_public(literal):
            raise TargetNotAllowed(f"La dirección {hostname} es interna/reservada, no se escanea")
        return [str(literal)]

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise TargetNotAllowed(f"No se pudo resolver el dominio ({e.__class__.__name__})") from e

    ips = {info[4][0] for info in infos}
    if not ips:
        raise TargetNotAllowed("El dominio no resolvió a ninguna dirección")

    for raw_ip in ips:
        ip = ipaddress.ip_address(raw_ip)
        if not _ip_is_public(ip):
            raise TargetNotAllowed(
                f"El dominio resuelve a una dirección interna/reservada ({raw_ip}), no se escanea"
            )

    return sorted(ips)


def validate_url(url: str) -> str:
    """
    Valida esquema, puerto y destino de una URL completa. Devuelve el
    hostname si es aceptable. Se usa tanto para el objetivo inicial como
    para cada salto de redirect.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise TargetNotAllowed(f"Esquema no permitido: {parsed.scheme or '(ninguno)'}")

    hostname = parsed.hostname
    if not hostname:
        raise TargetNotAllowed("URL sin hostname")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise TargetNotAllowed(f"Puerto no permitido: {port}")

    resolve_public_ips(hostname)
    return hostname
