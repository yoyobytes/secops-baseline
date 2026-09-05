"""
API entrante para integraciones máquina-a-máquina.

Es la mitad que faltaba del modelo de conectores: hasta acá la aplicación
sabía AVISAR a otros sistemas (email, webhook, Sentinel), pero no había
forma de que otro sistema le pidiera algo a ella.

Diferencias de diseño respecto de las rutas web, y por qué:

- **Sin CSRF.** CSRF protege sesiones basadas en cookies, donde el
  navegador adjunta credenciales solo. Acá la credencial va en una
  cabecera que ningún navegador añade automáticamente, así que el ataque
  no aplica. Exigir CSRF sería teatro.
- **Sin sesión.** Cada petición se autentica por sí misma; no hay estado
  entre llamadas.
- **Respuestas JSON con errores genéricos.** No se filtra si una
  credencial existe, está revocada o le falta un alcance.
- **Idempotencia en las escrituras.** Ver `IdempotencyRecord`.
"""
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api_deps import require_api_client
from app.audit import log_event
from app.config import settings
from app.db import get_db
from app.models import ApiClient, IdempotencyRecord, ScanResult
from app.scanner import run_security_scan

router = APIRouter(prefix="/api/v1", tags=["integraciones"])


# ---------------------------------------------------------------------
# Esquemas
# ---------------------------------------------------------------------

class SolicitudEscaneo(BaseModel):
    # Límite de longitud explícito: validación en la frontera, para que
    # una entrada absurda no llegue nunca a la lógica de negocio.
    target: str = Field(min_length=3, max_length=253)
    authorized: bool = Field(
        description="El sistema llamante declara tener autorización para escanear el objetivo",
    )


class RespuestaEscaneo(BaseModel):
    scan_id: int
    target: str
    severity_summary: str
    status: str
    findings: list[dict]


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


# ---------------------------------------------------------------------
# Salud (sin autenticación, a propósito)
# ---------------------------------------------------------------------

@router.get("/health")
async def health():
    """
    Liveness para balanceadores y monitorización. No revela versión,
    dependencias ni estado interno: solo que el proceso responde.
    """
    return {"status": "ok"}


# ---------------------------------------------------------------------
# Escaneos
# ---------------------------------------------------------------------

@router.post("/scans", response_model=RespuestaEscaneo, status_code=status.HTTP_201_CREATED)
async def crear_escaneo(
    solicitud: SolicitudEscaneo,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    cliente: ApiClient = Depends(require_api_client("scans:write")),
    db: Session = Depends(get_db),
):
    ip = _client_ip(request)

    if not solicitud.authorized:
        log_event(
            "api_escaneo_rechazado",
            actor=f"machine:{cliente.name}",
            actor_role="machine",
            resource=solicitud.target,
            result="blocked",
            severity="warning",
            source_ip=ip,
            metadata={"motivo": "sin_declaracion_de_autorizacion"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Debe declararse autorización para escanear el objetivo (authorized=true)",
        )

    huella = hashlib.sha256(
        json.dumps(solicitud.model_dump(), sort_keys=True).encode()
    ).hexdigest()

    # --- Idempotencia -------------------------------------------------
    if idempotency_key:
        previo = (
            db.query(IdempotencyRecord)
            .filter(
                IdempotencyRecord.client_id == cliente.id,
                IdempotencyRecord.idempotency_key == idempotency_key,
            )
            .first()
        )

        if previo:
            if previo.request_fingerprint != huella:
                # Misma clave, cuerpo distinto: error del integrador.
                # Devolver el resultado viejo sería peor que fallar.
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="La clave de idempotencia ya se usó con una petición diferente",
                )

            escaneo_previo = (
                db.query(ScanResult).filter(ScanResult.id == previo.response_scan_id).first()
            )
            if escaneo_previo:
                response.headers["Idempotent-Replay"] = "true"
                return _a_respuesta(escaneo_previo)

    # --- Ejecución ----------------------------------------------------
    try:
        resultado = run_security_scan(solicitud.target)
        estado = "completado"
    except Exception as e:  # noqa: BLE001 - frontera de confianza
        resultado = {
            "target": solicitud.target,
            "severity_summary": "critical",
            "findings": [{"check": "scanner_error", "severity": "critical", "detail": str(e)}],
        }
        estado = "error"

    escaneo = ScanResult(
        # Los escaneos por API se atribuyen a la credencial que los pidió.
        # user_id queda nulo: no hay persona detrás, y falsear una sería
        # corromper la trazabilidad.
        user_id=None,
        api_client_id=cliente.id,
        target=resultado["target"],
        status=estado,
        severity_summary=resultado["severity_summary"],
        findings_json=json.dumps(resultado["findings"], ensure_ascii=False),
    )
    db.add(escaneo)
    db.commit()
    db.refresh(escaneo)

    if idempotency_key:
        db.add(
            IdempotencyRecord(
                client_id=cliente.id,
                idempotency_key=idempotency_key,
                request_fingerprint=huella,
                response_scan_id=escaneo.id,
            )
        )
        db.commit()

    log_event(
        "api_escaneo_ejecutado",
        actor=f"machine:{cliente.name}",
        actor_role="machine",
        resource=resultado["target"],
        result="success" if estado == "completado" else "failure",
        severity=resultado["severity_summary"],
        source_ip=ip,
        metadata={"scan_id": escaneo.id, "idempotente": bool(idempotency_key)},
    )

    return _a_respuesta(escaneo)


@router.get("/scans/{scan_id}", response_model=RespuestaEscaneo)
async def obtener_escaneo(
    scan_id: int,
    cliente: ApiClient = Depends(require_api_client("scans:read")),
    db: Session = Depends(get_db),
):
    escaneo = db.query(ScanResult).filter(ScanResult.id == scan_id).first()

    # Una credencial solo ve los escaneos que ella misma originó.
    if not escaneo or escaneo.api_client_id != cliente.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Escaneo no encontrado")

    return _a_respuesta(escaneo)


def _a_respuesta(escaneo: ScanResult) -> dict:
    return {
        "scan_id": escaneo.id,
        "target": escaneo.target,
        "severity_summary": escaneo.severity_summary,
        "status": escaneo.status,
        "findings": json.loads(escaneo.findings_json),
    }


# ---------------------------------------------------------------------
# Webhooks entrantes
# ---------------------------------------------------------------------

@router.post("/webhooks/{origen}")
async def recibir_webhook(
    origen: str,
    request: Request,
    x_signature_256: str | None = Header(default=None, alias="X-Signature-256"),
    x_timestamp: str | None = Header(default=None, alias="X-Timestamp"),
    db: Session = Depends(get_db),
):
    """
    Recibe eventos de sistemas externos.

    Un webhook es un endpoint público que ejecuta lógica: sin verificar
    quién lo llama, cualquiera puede inyectar eventos falsos. Se validan
    tres cosas, y las tres hacen falta:

    1. **Firma HMAC** sobre el cuerpo crudo -> prueba que el emisor
       conoce el secreto compartido y que nadie alteró el contenido.
    2. **Marca de tiempo dentro de una ventana** -> impide reenviar una
       petición capturada semanas atrás. La firma sola no caduca nunca.
    3. **La marca de tiempo va DENTRO de lo firmado** -> si no, un
       atacante cambia la hora y reusa la firma vieja.
    """
    ip = _client_ip(request)

    def rechazar(motivo: str, codigo: int = status.HTTP_401_UNAUTHORIZED):
        log_event(
            "webhook_rechazado",
            actor=f"webhook:{origen}",
            actor_role="machine",
            resource=str(request.url.path),
            result="blocked",
            severity="warning",
            source_ip=ip,
            metadata={"motivo": motivo},
        )
        raise HTTPException(status_code=codigo, detail="Webhook rechazado")

    if not settings.WEBHOOK_SIGNING_SECRET:
        rechazar("receptor_deshabilitado", status.HTTP_503_SERVICE_UNAVAILABLE)

    if not x_signature_256 or not x_timestamp:
        rechazar("faltan_cabeceras_de_firma")

    try:
        enviado_en = int(x_timestamp)
    except ValueError:
        rechazar("marca_de_tiempo_invalida")

    desfase = abs(int(time.time()) - enviado_en)
    if desfase > settings.WEBHOOK_TOLERANCE_SECONDS:
        rechazar("marca_de_tiempo_fuera_de_ventana")

    cuerpo = await request.body()

    # La firma cubre timestamp + cuerpo, no solo el cuerpo.
    base = f"{enviado_en}.".encode() + cuerpo
    esperada = hmac.new(
        settings.WEBHOOK_SIGNING_SECRET.encode(), base, hashlib.sha256
    ).hexdigest()

    recibida = x_signature_256.removeprefix("sha256=").strip()
    if not hmac.compare_digest(esperada, recibida):
        rechazar("firma_invalida")

    try:
        datos = json.loads(cuerpo or b"{}")
    except ValueError:
        rechazar("cuerpo_no_es_json", status.HTTP_400_BAD_REQUEST)

    log_event(
        "webhook_recibido",
        actor=f"webhook:{origen}",
        actor_role="machine",
        resource=str(request.url.path),
        result="success",
        severity="info",
        source_ip=ip,
        metadata={"evento": str(datos.get("event", "desconocido"))[:120]},
    )

    return {"status": "aceptado", "recibido_en": datetime.now(timezone.utc).isoformat()}
