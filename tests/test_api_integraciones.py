"""
Tests de la API entrante: autenticación de máquina, alcances,
idempotencia y webhooks firmados.
"""
import hashlib
import hmac
import json
import time

import pytest
from fastapi.testclient import TestClient

from app.api_keys import generate_api_key, parse_api_key, verify_secret
from app.db import SessionLocal
from app.main import app
from app.models import ApiClient


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _crear_credencial(scopes: str, limite: int = 60) -> str:
    clave, token_id, secret_hash = generate_api_key()
    db = SessionLocal()
    try:
        db.add(
            ApiClient(
                token_id=token_id,
                name=f"test-{token_id[:6]}",
                secret_hash=secret_hash,
                scopes=scopes,
                rate_limit_per_minute=limite,
            )
        )
        db.commit()
    finally:
        db.close()
    return clave


# ---------------------------------------------------------------------
# Formato y verificación de credenciales
# ---------------------------------------------------------------------

def test_la_clave_no_se_puede_reconstruir_desde_el_hash():
    clave, token_id, secret_hash = generate_api_key()
    _, secreto = parse_api_key(clave)

    assert secreto not in secret_hash
    assert verify_secret(secreto, secret_hash)
    assert not verify_secret("otro-secreto", secret_hash)


def test_claves_mal_formadas_se_rechazan():
    for mala in ["", "sin-prefijo", "sk_solo-una-parte", "xx_abc_def"]:
        assert parse_api_key(mala) is None


# ---------------------------------------------------------------------
# Autenticación
# ---------------------------------------------------------------------

def test_sin_credencial_se_rechaza(client):
    r = client.post("/api/v1/scans", json={"target": "example.com", "authorized": True})
    assert r.status_code == 401


def test_credencial_invalida_se_rechaza(client):
    r = client.post(
        "/api/v1/scans",
        json={"target": "example.com", "authorized": True},
        headers={"Authorization": "Bearer sk_deadbeef_secretofalso"},
    )
    assert r.status_code == 401


def test_credencial_revocada_se_rechaza(client):
    clave = _crear_credencial("scans:write")
    token_id, _ = parse_api_key(clave)

    db = SessionLocal()
    try:
        c = db.query(ApiClient).filter(ApiClient.token_id == token_id).first()
        c.is_active = False
        db.commit()
    finally:
        db.close()

    r = client.post(
        "/api/v1/scans",
        json={"target": "example.com", "authorized": True},
        headers={"Authorization": f"Bearer {clave}"},
    )
    assert r.status_code == 401


def test_alcance_insuficiente_devuelve_403(client):
    # Credencial que solo puede LEER intentando ESCRIBIR.
    clave = _crear_credencial("scans:read")
    r = client.post(
        "/api/v1/scans",
        json={"target": "example.com", "authorized": True},
        headers={"Authorization": f"Bearer {clave}"},
    )
    assert r.status_code == 403


def test_health_no_requiere_credencial(client):
    assert client.get("/api/v1/health").status_code == 200


# ---------------------------------------------------------------------
# Reglas de negocio en la frontera
# ---------------------------------------------------------------------

def test_exige_declaracion_de_autorizacion(client):
    clave = _crear_credencial("scans:write")
    r = client.post(
        "/api/v1/scans",
        json={"target": "example.com", "authorized": False},
        headers={"Authorization": f"Bearer {clave}"},
    )
    assert r.status_code == 400


def test_valida_longitud_del_objetivo(client):
    clave = _crear_credencial("scans:write")
    r = client.post(
        "/api/v1/scans",
        json={"target": "x" * 500, "authorized": True},
        headers={"Authorization": f"Bearer {clave}"},
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------
# Límite por credencial
# ---------------------------------------------------------------------

def test_el_limite_es_por_credencial(client):
    clave = _crear_credencial("scans:read", limite=3)
    cabeceras = {"Authorization": f"Bearer {clave}"}

    # Se piden escaneos inexistentes: no ejecutan nada pero sí consumen cuota.
    codigos = [client.get("/api/v1/scans/999999", headers=cabeceras).status_code for _ in range(5)]

    assert 429 in codigos, f"debería haberse superado el límite: {codigos}"

    # Otra credencial mantiene su propia cuota intacta.
    otra = _crear_credencial("scans:read", limite=3)
    r = client.get("/api/v1/scans/999999", headers={"Authorization": f"Bearer {otra}"})
    assert r.status_code == 404


# ---------------------------------------------------------------------
# Aislamiento entre integraciones
# ---------------------------------------------------------------------

def test_una_credencial_no_ve_los_escaneos_de_otra(client, monkeypatch):
    from app.routers import api_v1

    monkeypatch.setattr(
        api_v1, "run_security_scan",
        lambda t: {"target": t, "severity_summary": "info", "findings": []},
    )

    clave_a = _crear_credencial("scans:write,scans:read")
    clave_b = _crear_credencial("scans:read")

    creado = client.post(
        "/api/v1/scans",
        json={"target": "example.com", "authorized": True},
        headers={"Authorization": f"Bearer {clave_a}"},
    )
    assert creado.status_code == 201
    scan_id = creado.json()["scan_id"]

    # El dueño lo ve.
    assert client.get(f"/api/v1/scans/{scan_id}",
                      headers={"Authorization": f"Bearer {clave_a}"}).status_code == 200

    # Otra credencial recibe 404, no 403: no se confirma que exista.
    assert client.get(f"/api/v1/scans/{scan_id}",
                      headers={"Authorization": f"Bearer {clave_b}"}).status_code == 404


# ---------------------------------------------------------------------
# Idempotencia
# ---------------------------------------------------------------------

def test_la_misma_clave_de_idempotencia_no_duplica(client, monkeypatch):
    from app.routers import api_v1

    ejecuciones = []

    def fake_scan(target):
        ejecuciones.append(target)
        return {"target": target, "severity_summary": "info", "findings": []}

    monkeypatch.setattr(api_v1, "run_security_scan", fake_scan)

    clave = _crear_credencial("scans:write")
    cabeceras = {"Authorization": f"Bearer {clave}", "Idempotency-Key": "pedido-12345"}
    cuerpo = {"target": "example.com", "authorized": True}

    primera = client.post("/api/v1/scans", json=cuerpo, headers=cabeceras)
    segunda = client.post("/api/v1/scans", json=cuerpo, headers=cabeceras)

    assert primera.json()["scan_id"] == segunda.json()["scan_id"]
    assert len(ejecuciones) == 1, "el escaneo debía ejecutarse una sola vez"
    assert segunda.headers.get("Idempotent-Replay") == "true"


def test_misma_clave_con_cuerpo_distinto_da_conflicto(client, monkeypatch):
    from app.routers import api_v1

    monkeypatch.setattr(
        api_v1, "run_security_scan",
        lambda t: {"target": t, "severity_summary": "info", "findings": []},
    )

    clave = _crear_credencial("scans:write")
    cabeceras = {"Authorization": f"Bearer {clave}", "Idempotency-Key": "pedido-99"}

    client.post("/api/v1/scans", json={"target": "example.com", "authorized": True}, headers=cabeceras)
    r = client.post("/api/v1/scans", json={"target": "otro-dominio.com", "authorized": True}, headers=cabeceras)

    assert r.status_code == 409


# ---------------------------------------------------------------------
# Webhooks entrantes firmados
# ---------------------------------------------------------------------

def _firmar(cuerpo: bytes, secreto: str, marca: int) -> str:
    base = f"{marca}.".encode() + cuerpo
    return hmac.new(secreto.encode(), base, hashlib.sha256).hexdigest()


@pytest.fixture
def secreto_webhook(monkeypatch):
    from app.config import settings as s
    from app.routers import api_v1

    secreto = "secreto-compartido-de-prueba"
    monkeypatch.setattr(s, "WEBHOOK_SIGNING_SECRET", secreto)
    monkeypatch.setattr(api_v1.settings, "WEBHOOK_SIGNING_SECRET", secreto)
    return secreto


def test_webhook_con_firma_valida_se_acepta(client, secreto_webhook):
    cuerpo = json.dumps({"event": "algo_paso"}).encode()
    marca = int(time.time())

    r = client.post(
        "/api/v1/webhooks/sistema-externo",
        content=cuerpo,
        headers={
            "X-Signature-256": f"sha256={_firmar(cuerpo, secreto_webhook, marca)}",
            "X-Timestamp": str(marca),
            "Content-Type": "application/json",
        },
    )
    assert r.status_code == 200


def test_webhook_sin_firma_se_rechaza(client, secreto_webhook):
    r = client.post("/api/v1/webhooks/sistema-externo", content=b'{"event":"x"}')
    assert r.status_code == 401


def test_webhook_con_firma_invalida_se_rechaza(client, secreto_webhook):
    cuerpo = b'{"event":"x"}'
    marca = int(time.time())
    r = client.post(
        "/api/v1/webhooks/sistema-externo",
        content=cuerpo,
        headers={"X-Signature-256": "sha256=" + "0" * 64, "X-Timestamp": str(marca)},
    )
    assert r.status_code == 401


def test_webhook_con_cuerpo_alterado_se_rechaza(client, secreto_webhook):
    """La firma cubre el cuerpo: alterarlo la invalida."""
    original = json.dumps({"event": "inofensivo"}).encode()
    marca = int(time.time())
    firma = _firmar(original, secreto_webhook, marca)

    alterado = json.dumps({"event": "malicioso"}).encode()

    r = client.post(
        "/api/v1/webhooks/sistema-externo",
        content=alterado,
        headers={"X-Signature-256": f"sha256={firma}", "X-Timestamp": str(marca)},
    )
    assert r.status_code == 401


def test_webhook_reenviado_fuera_de_ventana_se_rechaza(client, secreto_webhook):
    """
    Una petición legítima capturada y reenviada horas después debe
    rechazarse: la firma sola no caduca nunca.
    """
    cuerpo = json.dumps({"event": "antiguo"}).encode()
    marca_vieja = int(time.time()) - 3600

    r = client.post(
        "/api/v1/webhooks/sistema-externo",
        content=cuerpo,
        headers={
            "X-Signature-256": f"sha256={_firmar(cuerpo, secreto_webhook, marca_vieja)}",
            "X-Timestamp": str(marca_vieja),
        },
    )
    assert r.status_code == 401
