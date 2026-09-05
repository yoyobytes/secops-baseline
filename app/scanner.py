"""
Automatización principal de la webapp: un escáner PASIVO de postura de
seguridad para un dominio dado. No explota nada, no hace fuerza bruta,
no envía payloads maliciosos — solo lee información pública (headers
HTTP, certificado TLS, registros DNS) igual que herramientas como
Mozilla Observatory o SecurityHeaders.com. Es la misma clase de chequeo
que un consultor haría al iniciar una auditoría con un cliente nuevo.

Requiere que el usuario confirme que tiene autorización para escanear
el dominio (checkbox obligatorio en el formulario, registrado en el
audit log) — control ético/legal antes de ejecutar cualquier
automatización contra un objetivo externo.
"""
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import httpx

from app.ssrf_guard import TargetNotAllowed, validate_url

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
MAX_REDIRECTS = 5


def _normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        raw = "https://" + raw
    return raw


def _get_following_redirects(base_url: str):
    """
    Sigue redirects a mano en vez de delegarlo en httpx, porque cada
    salto tiene que revalidarse contra el guard SSRF: un sitio externo
    puede responder "302 -> http://169.254.169.254/" y, con
    follow_redirects=True, httpx iría a buscarlo sin preguntar.
    """
    url = base_url
    for _ in range(MAX_REDIRECTS):
        validate_url(url)
        resp = httpx.get(url, timeout=8, follow_redirects=False)
        if resp.is_redirect and resp.headers.get("location"):
            url = str(resp.next_request.url) if resp.next_request else resp.headers["location"]
            continue
        return resp

    raise TargetNotAllowed(f"Demasiados redirects (más de {MAX_REDIRECTS})")


def _check_headers(base_url: str) -> list[dict]:
    findings = []
    try:
        resp = _get_following_redirects(base_url)
    except TargetNotAllowed as e:
        return [{"check": "objetivo_no_permitido", "severity": "critical",
                  "detail": f"Objetivo rechazado por política de seguridad: {e}"}]
    except httpx.RequestError as e:
        return [{"check": "conectividad_http", "severity": "critical",
                  "detail": f"No se pudo conectar al objetivo: {e.__class__.__name__}"}]

    headers = {k.lower(): v for k, v in resp.headers.items()}

    required = {
        "strict-transport-security": ("medium", "Falta HSTS (Strict-Transport-Security)"),
        "content-security-policy": ("medium", "Falta Content-Security-Policy"),
        "x-content-type-options": ("low", "Falta X-Content-Type-Options: nosniff"),
        "x-frame-options": ("medium", "Falta X-Frame-Options (riesgo de clickjacking)"),
        "referrer-policy": ("low", "Falta Referrer-Policy"),
    }
    for header, (severity, msg) in required.items():
        if header not in headers:
            findings.append({"check": header, "severity": severity, "detail": msg})

    if resp.url.scheme != "https":
        findings.append({"check": "https", "severity": "critical", "detail": "El sitio no fuerza HTTPS"})

    if not findings:
        findings.append({"check": "headers", "severity": "info", "detail": "Headers de seguridad básicos presentes"})

    return findings


def _check_tls_certificate(hostname: str) -> list[dict]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = (not_after - datetime.now(timezone.utc)).days

        if days_left < 0:
            findings.append({"check": "tls_expiry", "severity": "critical", "detail": "Certificado TLS expirado"})
        elif days_left < 15:
            findings.append({"check": "tls_expiry", "severity": "high", "detail": f"Certificado expira en {days_left} días"})
        elif days_left < 30:
            findings.append({"check": "tls_expiry", "severity": "medium", "detail": f"Certificado expira en {days_left} días"})
        else:
            findings.append({"check": "tls_expiry", "severity": "info", "detail": f"Certificado válido ({days_left} días restantes)"})
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, ssl.SSLError, OSError) as e:
        findings.append({"check": "tls_connect", "severity": "high", "detail": f"No se pudo verificar TLS: {e.__class__.__name__}"})

    return findings


def _check_dns_records(hostname: str) -> list[dict]:
    findings = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        resolver.resolve(hostname, "TXT")
        spf_found = False
        for rdata in resolver.resolve(hostname, "TXT"):
            if "v=spf1" in str(rdata):
                spf_found = True
        if not spf_found:
            findings.append({"check": "spf", "severity": "medium", "detail": "No se encontró registro SPF (riesgo de spoofing de correo)"})
        else:
            findings.append({"check": "spf", "severity": "info", "detail": "Registro SPF presente"})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        findings.append({"check": "spf", "severity": "medium", "detail": "No se encontró registro SPF (riesgo de spoofing de correo)"})

    try:
        resolver.resolve(f"_dmarc.{hostname}", "TXT")
        findings.append({"check": "dmarc", "severity": "info", "detail": "Registro DMARC presente"})
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        findings.append({"check": "dmarc", "severity": "medium", "detail": "No se encontró registro DMARC"})

    return findings


def run_security_scan(raw_target: str) -> dict:
    base_url = _normalize_target(raw_target)
    hostname = urlparse(base_url).hostname or raw_target

    # Primera línea: si el objetivo apunta hacia adentro (metadata del
    # cloud, loopback, red privada) no se ejecuta NINGÚN chequeo.
    try:
        validate_url(base_url)
    except TargetNotAllowed as e:
        return {
            "target": hostname,
            "severity_summary": "critical",
            "findings": [{
                "check": "objetivo_no_permitido",
                "severity": "critical",
                "detail": f"Objetivo rechazado por política de seguridad: {e}",
            }],
        }

    findings: list[dict] = []
    findings += _check_headers(base_url)
    findings += _check_tls_certificate(hostname)
    findings += _check_dns_records(hostname)

    worst = max((f["severity"] for f in findings), key=lambda s: SEVERITY_ORDER.get(s, 0), default="info")

    return {
        "target": hostname,
        "severity_summary": worst,
        "findings": findings,
    }
