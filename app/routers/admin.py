"""
Todo lo que cuelga de este router exige `require_admin` (rol admin Y
MFA verificada en la sesión, ver app/deps.py) -- no hay chequeos de rol
adicionales aquí, esa es la única fuente de verdad y se resuelve una
sola vez en el dependency.
"""
import json
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.api_keys import generate_api_key
from app.audit import log_event
from app.cron.daily_digest import send_digest
from app.csrf import ensure_csrf_token, verify_csrf
from app.db import get_db
from app.deps import require_admin
from app.models import AdminSettings, AlertMessage, ApiClient, AuditEvent, ScanResult, User
from app.webutils import templates

router = APIRouter(prefix="/admin")


def _get_or_create_settings(db: Session) -> AdminSettings:
    row = db.query(AdminSettings).filter(AdminSettings.id == 1).first()
    if not row:
        row = AdminSettings(id=1)
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


@router.get("")
async def admin_home(
    request: Request,
    digest: str | None = Query(None),
    revocado: str | None = Query(None),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    critical_events = (
        db.query(AuditEvent)
        .filter(AuditEvent.severity == "critical")
        .order_by(desc(AuditEvent.timestamp))
        .limit(10)
        .all()
    )
    total_users = db.query(User).count()
    total_scans = db.query(ScanResult).count()
    usuarios = db.query(User).order_by(User.username).all()

    return templates.TemplateResponse(
        request,
        "dashboard_admin.html",
        {
            "user": user,
            "critical_events": critical_events,
            "total_users": total_users,
            "total_scans": total_scans,
            "usuarios": usuarios,
            "csrf_token": ensure_csrf_token(request),
            "all_scans": None,
            "digest_sent": digest == "ok",
            "revocado": revocado,
        },
    )


@router.get("/scans")
async def admin_scans(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    rows = (
        db.query(ScanResult, User.username)
        .join(User, User.id == ScanResult.user_id)
        .order_by(desc(ScanResult.created_at))
        .limit(200)
        .all()
    )
    all_scans = [{"scan": scan, "username": username} for scan, username in rows]

    return templates.TemplateResponse(
        request,
        "dashboard_admin.html",
        {
            "user": user,
            "critical_events": None,
            "total_users": None,
            "total_scans": None,
            "usuarios": None,
            "csrf_token": ensure_csrf_token(request),
            "all_scans": all_scans,
            "digest_sent": False,
            "revocado": None,
        },
    )


ALCANCES_DISPONIBLES = ["scans:write", "scans:read"]


@router.get("/integraciones")
async def admin_integraciones(
    request: Request,
    nueva_clave: str | None = Query(None),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    clientes = db.query(ApiClient).order_by(desc(ApiClient.created_at)).all()
    return templates.TemplateResponse(
        request,
        "integraciones.html",
        {
            "user": user,
            "clientes": clientes,
            "alcances": ALCANCES_DISPONIBLES,
            "csrf_token": ensure_csrf_token(request),
            "nueva_clave": nueva_clave,
        },
    )


@router.post("/integraciones")
async def admin_crear_integracion(
    request: Request,
    nombre: str = Form(...),
    alcances: list[str] = Form(default=[]),
    limite: int = Form(60),
    csrf_token: str = Form(...),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)

    # Solo se aceptan alcances conocidos: si no, un formulario manipulado
    # podría conceder permisos que no existen todavía pero existirán.
    alcances_validos = [a for a in alcances if a in ALCANCES_DISPONIBLES]

    clave_completa, token_id, secret_hash = generate_api_key()

    cliente = ApiClient(
        token_id=token_id,
        name=nombre.strip()[:120],
        secret_hash=secret_hash,
        scopes=",".join(alcances_validos),
        rate_limit_per_minute=max(1, min(limite, 10000)),
        created_by=user.username,
    )
    db.add(cliente)
    db.commit()

    log_event(
        "api_credencial_creada",
        actor=user.username,
        actor_role="admin",
        resource=cliente.name,
        result="success",
        severity="warning",
        source_ip=request.client.host if request.client else None,
        metadata={"token_id": token_id, "alcances": alcances_validos},
    )

    # La clave completa se muestra UNA sola vez: solo se guardó su hash.
    return RedirectResponse(f"/admin/integraciones?nueva_clave={clave_completa}", status_code=302)


@router.post("/integraciones/{client_id}/revocar")
async def admin_revocar_integracion(
    client_id: int,
    request: Request,
    csrf_token: str = Form(...),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)

    cliente = db.query(ApiClient).filter(ApiClient.id == client_id).first()
    if not cliente:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Integración no encontrada")

    cliente.is_active = False
    db.commit()

    log_event(
        "api_credencial_revocada",
        actor=user.username,
        actor_role="admin",
        resource=cliente.name,
        result="success",
        severity="warning",
        source_ip=request.client.host if request.client else None,
        metadata={"token_id": cliente.token_id},
    )

    return RedirectResponse("/admin/integraciones", status_code=302)


@router.post("/usuarios/{user_id}/revocar-sesiones")
async def admin_revocar_sesiones(
    user_id: int,
    request: Request,
    csrf_token: str = Form(...),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    """
    Expulsa a un usuario de todas sus sesiones activas.

    Como las sesiones viven firmadas en la cookie del cliente, el servidor
    no puede borrarlas: lo que hace es incrementar la generación de sesión
    del usuario, con lo cual las cookies existentes dejan de ser
    reconocidas en la siguiente petición (ver app/deps.py).

    Es la respuesta a "sospecho que le robaron la sesión a alguien".
    """
    verify_csrf(request, csrf_token)

    objetivo = db.query(User).filter(User.id == user_id).first()
    if not objetivo:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado")

    objetivo.session_epoch = (objetivo.session_epoch or 0) + 1
    db.commit()

    log_event(
        "sesiones_revocadas",
        actor=user.username,
        actor_role="admin",
        resource=objetivo.username,
        result="success",
        severity="warning",
        source_ip=request.client.host if request.client else None,
        metadata={"usuario_objetivo": objetivo.username, "nueva_generacion": objetivo.session_epoch},
    )

    return RedirectResponse("/admin?revocado=" + objetivo.username, status_code=302)


@router.get("/alertas")
async def admin_alertas(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """
    Bandeja de alertas: qué se disparó y cómo le fue a cada canal de
    entrega. Es la vista que hace demostrable el alertado sin depender
    de abrir un cliente de correo externo.
    """
    mensajes = (
        db.query(AlertMessage)
        .order_by(desc(AlertMessage.created_at))
        .limit(100)
        .all()
    )

    alertas = []
    for m in mensajes:
        try:
            estado = json.loads(m.delivery_status) if m.delivery_status else {}
        except (ValueError, TypeError):
            estado = {}
        alertas.append({"mensaje": m, "estado": estado})

    return templates.TemplateResponse(
        request,
        "alerts_inbox.html",
        {"user": user, "alertas": alertas},
    )


@router.get("/logs")
async def admin_logs(
    request: Request,
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
    event_type: str | None = Query(None),
    severity: str | None = Query(None),
    actor: str | None = Query(None),
    date_from: str | None = Query(None),
    date_to: str | None = Query(None),
):
    query = db.query(AuditEvent)
    if event_type:
        query = query.filter(AuditEvent.event_type == event_type)
    if severity:
        query = query.filter(AuditEvent.severity == severity)
    if actor:
        query = query.filter(AuditEvent.actor.ilike(f"%{actor}%"))
    if date_from:
        try:
            query = query.filter(AuditEvent.timestamp >= datetime.fromisoformat(date_from))
        except ValueError:
            pass
    if date_to:
        try:
            query = query.filter(AuditEvent.timestamp <= datetime.fromisoformat(date_to))
        except ValueError:
            pass

    events = query.order_by(desc(AuditEvent.timestamp)).limit(500).all()

    return templates.TemplateResponse(
        request,
        "audit_log.html",
        {
            "user": user,
            "events": events,
            "filters": {
                "event_type": event_type or "",
                "severity": severity or "",
                "actor": actor or "",
                "date_from": date_from or "",
                "date_to": date_to or "",
            },
        },
    )


@router.get("/settings")
async def admin_settings_form(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    settings_row = _get_or_create_settings(db)
    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "csrf_token": ensure_csrf_token(request),
            "settings": settings_row,
            "message": None,
        },
    )


@router.post("/settings")
async def admin_settings_submit(
    request: Request,
    alert_email: str = Form(""),
    alert_webhook_url: str = Form(""),
    digest_enabled: bool = Form(False),
    csrf_token: str = Form(...),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    settings_row = _get_or_create_settings(db)
    settings_row.alert_email = alert_email.strip() or None
    settings_row.alert_webhook_url = alert_webhook_url.strip() or None
    settings_row.digest_enabled = digest_enabled
    db.commit()

    log_event(
        "admin_settings_actualizado",
        actor=user.username,
        actor_role="admin",
        result="success",
        source_ip=request.client.host if request.client else None,
    )

    return templates.TemplateResponse(
        request,
        "settings.html",
        {
            "user": user,
            "csrf_token": ensure_csrf_token(request),
            "settings": settings_row,
            "message": "Configuración guardada.",
        },
    )


@router.post("/digest/enviar-ahora")
async def admin_send_digest_now(
    request: Request,
    csrf_token: str = Form(...),
    user: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    send_digest(db, triggered_by=user.username)
    log_event(
        "digest_disparado_manual",
        actor=user.username,
        actor_role="admin",
        result="success",
        source_ip=request.client.host if request.client else None,
    )
    return RedirectResponse("/admin?digest=ok", status_code=302)
