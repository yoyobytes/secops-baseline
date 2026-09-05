"""
Verifica que el escáner detecte headers de seguridad faltantes contra
un servidor simulado -- se monkeypatchea httpx.get para no depender de
conectividad de red real en CI.

También se neutraliza el guard SSRF en estos tests concretos: los
dominios de prueba (.test) no resuelven, así que el guard los
rechazaría antes de llegar a la lógica de headers, que es lo que acá
se quiere probar. El guard tiene su propia batería en test_ssrf_guard.py.
"""
import httpx
import pytest

from app import scanner


@pytest.fixture(autouse=True)
def _skip_ssrf_guard(monkeypatch):
    monkeypatch.setattr(scanner, "validate_url", lambda url: None)


class _FakeResponse:
    def __init__(self, headers: dict, url: str):
        self.headers = headers
        self.url = httpx.URL(url)
        self.is_redirect = False
        self.next_request = None


def test_detects_missing_security_headers(monkeypatch):
    def fake_get(url, timeout=8, follow_redirects=False):
        return _FakeResponse(headers={"content-type": "text/html"}, url=url)

    monkeypatch.setattr(scanner.httpx, "get", fake_get)

    findings = scanner._check_headers("https://ejemplo-inseguro.test")
    checks = {f["check"] for f in findings}

    assert "strict-transport-security" in checks
    assert "content-security-policy" in checks
    assert "x-frame-options" in checks
    assert "x-content-type-options" in checks
    assert "referrer-policy" in checks


def test_no_findings_when_all_headers_present(monkeypatch):
    good_headers = {
        "strict-transport-security": "max-age=63072000",
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
    }

    def fake_get(url, timeout=8, follow_redirects=False):
        return _FakeResponse(headers=good_headers, url=url)

    monkeypatch.setattr(scanner.httpx, "get", fake_get)

    findings = scanner._check_headers("https://ejemplo-seguro.test")
    severities = {f["severity"] for f in findings}
    assert severities == {"info"}


def test_connection_failure_is_reported_as_finding_not_exception(monkeypatch):
    def fake_get(url, timeout=8, follow_redirects=False):
        raise httpx.ConnectError("no se pudo conectar")

    monkeypatch.setattr(scanner.httpx, "get", fake_get)

    findings = scanner._check_headers("https://no-existe.test")
    assert findings[0]["severity"] == "critical"
