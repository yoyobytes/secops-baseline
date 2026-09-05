"""
Rutas de usuario normal: lanzar un escaneo pasivo y consultar SOLO su
propio historial. El filtro por `user_id` en cada consulta es lo que
evita horizontal privilege escalation (que un usuario vea el escaneo
de otro adivinando el id) -- se aplica en la query, no confiando en
que el id no se pueda adivinar. A un admin (ya con MFA verificada
para llegar aquí con rol admin) se le permite además ver el detalle de
escaneos ajenos, coherente con su rol elevado.
"""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.audit import log_event
from app.config import settings
from app.connectors.email_connector import EmailConnector
from app.connectors.inbox_connector import InboxConnector
from app.connectors.webhook_connector import WebhookConnector
from app.csrf import ensure_csrf_token, verify_csrf
from app.db import get_db
from app.deps import get_current_user
from app.models import AdminSettings, ScanResult, User
from app.scanner import run_security_scan
from app.webutils import limiter, templates

router = APIRouter()


def _client_ip(request: Request):
    return request.client.host if request.client else None


def _parse_scan(scan: ScanResult) -> dict:
    return {
        "id": scan.id,
        "target": scan.target,
        "status": scan.status,
        "severity_summary": scan.severity_summary,
        "created_at": scan.created_at,
        "findings": json.loads(scan.findings_json),
    }


def _recent_scans(db: Session, user: User, limit: int | None):
    query = db.query(ScanResult).filter(ScanResult.user_id == user.id).order_by(desc(ScanResult.created_at))
    if limit:
        query = query.limit(limit)
    return query.all()


@router.get("/")
async def dashboard_home(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse(
        request,
        "dashboard_user.html",
        {
            "user": user,
            "csrf_token": ensure_csrf_token(request),
            "scans": _recent_scans(db, user, limit=5),
            "full_history": False,
            "error": None,
        },
    )


@router.get("/scans")
async def scan_history(
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse(
        request,
        "dashboard_user.html",
        {
            "user": user,
            "csrf_token": ensure_csrf_token(request),
            "scans": _recent_scans(db, user, limit=None),
            "full_history": True,
            "error": None,
        },
    )


@router.get("/scans/{scan_id}")
async def scan_detail(
    scan_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan or (scan.user_id != user.id and user.role != "admin"):
        # 404 en vez de 403: no confirmamos ni negamos la existencia
        # del escaneo de otro usuario.
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Escaneo no encontrado")

    return templates.TemplateResponse(
        request,
        "scan_result.html", {"user": user, "scan": _parse_scan(scan)}
    )


@router.post("/scan")
@limiter.limit(settings.SCAN_RATE_LIMIT)
async def launch_scan(
    request: Request,
    target: str = Form(...),
    authorized: bool = Form(False),
    csrf_token: str = Form(...),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    ip = _client_ip(request)

    if not authorized:
        return templates.TemplateResponse(
            request,
            "dashboard_user.html",
            {
                "user": user,
                "csrf_token": ensure_csrf_token(request),
                "scans": _recent_scans(db, user, limit=5),
                "full_history": False,
                "error": "Debes confirmar que tienes autorización para escanear este dominio.",
            },
            status_code=400,
        )

    try:
        result = run_security_scan(target)
        status_value = "completado"
    except Exception as e:  # frontera de confianza: dominio arbitrario ingresado por el usuario
        result = {
            "target": target,
            "severity_summary": "critical",
            "findings": [{"check": "scanner_error", "severity": "critical", "detail": str(e)}],
        }
        status_value = "error"

    scan = ScanResult(
        user_id=user.id,
        target=result["target"],
        status=status_value,
        severity_summary=result["severity_summary"],
        findings_json=json.dumps(result["findings"], ensure_ascii=False),
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    log_event(
        "scan_ejecutado",
        actor=user.username,
        actor_role=user.role,
        resource=result["target"],
        result="success" if status_value == "completado" else "failure",
        severity=result["severity_summary"],
        source_ip=ip,
        metadata={"scan_id": scan.id},
    )

    if result["severity_summary"] == "critical":
        _send_critical_alert(db, user, scan)

    return RedirectResponse(f"/scans/{scan.id}", status_code=302)


def _send_critical_alert(db: Session, user: User, scan: ScanResult) -> None:
    admin_settings = db.query(AdminSettings).filter(AdminSettings.id == 1).first()
    if not admin_settings:
        return

    subject = f"[CRÍTICO] Hallazgo de seguridad en {scan.target}"
    body = (
        f"El usuario '{user.username}' ejecutó un escaneo sobre '{scan.target}' "
        f"que arrojó severidad CRITICAL.\n\nID de escaneo: {scan.id}\n"
        f"Ver detalle en el panel de administración."
    )

    delivered: dict[str, bool] = {}
    if admin_settings.alert_email:
        delivered["email"] = EmailConnector(admin_settings.alert_email).send_alert(subject, body)
    if admin_settings.alert_webhook_url:
        delivered["webhook"] = WebhookConnector(admin_settings.alert_webhook_url).send_alert(subject, body)

    # La bandeja interna se escribe siempre y al final, dejando registrado
    # cómo le fue a cada canal externo. Así la alerta es visible en el
    # panel aunque no haya ningún canal configurado, o aunque todos fallen.
    InboxConnector(kind="alerta", delivery_status=delivered).send_alert(subject, body)

    log_event(
        "alerta_critica_enviada",
        actor="system",
        result="success" if any(delivered.values()) else "failure",
        severity="critical",
        resource=scan.target,
        metadata={"canales": delivered, "scan_id": scan.id},
    )
