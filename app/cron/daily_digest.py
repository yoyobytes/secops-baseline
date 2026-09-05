"""
Digest diario estilo SIEM sobre AuditEvent.

Se ejecuta en dos contextos con el MISMO código: (1) standalone vía
`python -m app.cron.daily_digest`, disparado por el scheduler ofelia
todos los días a las 3AM, y (2) bajo demanda desde
POST /admin/digest/enviar-ahora, para poder demostrarlo en una
entrevista sin esperar al cron. `send_digest()` no sabe ni le importa
quién la llamó -- eso es lo que permite reusarla sin duplicar lógica.
"""
from collections import Counter
from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from app.audit import log_event
from app.connectors.email_connector import EmailConnector
from app.connectors.inbox_connector import InboxConnector
from app.connectors.webhook_connector import WebhookConnector
from app.db import SessionLocal
from app.models import AdminSettings, AuditEvent, ScanResult, User

WINDOW_HOURS = 24


def build_digest(db: Session) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=WINDOW_HOURS)
    events = db.query(AuditEvent).filter(AuditEvent.timestamp >= since).all()

    failed_logins = sum(1 for e in events if e.event_type == "login_failed")
    lockouts = sum(1 for e in events if e.event_type == "login_bloqueado")
    mfa_failed = sum(1 for e in events if e.event_type == "mfa_failed")
    currently_locked = (
        db.query(User)
        .filter(User.locked_until.isnot(None), User.locked_until > datetime.now(timezone.utc))
        .count()
    )

    risky_scans = (
        db.query(ScanResult)
        .filter(ScanResult.created_at >= since, ScanResult.severity_summary.in_(["critical", "high"]))
        .all()
    )

    actor_counts = Counter(e.actor for e in events if e.actor and e.actor != "system")
    top_actors = actor_counts.most_common(5)

    return {
        "window_hours": WINDOW_HOURS,
        "total_events": len(events),
        "failed_logins": failed_logins,
        "lockouts": lockouts,
        "currently_locked_accounts": currently_locked,
        "mfa_failed": mfa_failed,
        "risky_scans": [
            {"target": s.target, "severity": s.severity_summary, "user_id": s.user_id} for s in risky_scans
        ],
        "top_actors": [{"actor": actor, "count": count} for actor, count in top_actors],
    }


def render_digest_text(digest: dict) -> str:
    lines = [
        f"Resumen de seguridad - ultimas {digest['window_hours']} horas",
        "=" * 50,
        f"Eventos de auditoria totales: {digest['total_events']}",
        f"Logins fallidos: {digest['failed_logins']}",
        f"Bloqueos por fuerza bruta: {digest['lockouts']}",
        f"Cuentas actualmente bloqueadas: {digest['currently_locked_accounts']}",
        f"Codigos MFA invalidos: {digest['mfa_failed']}",
        "",
        f"Escaneos con severidad alta/critica ({len(digest['risky_scans'])}):",
    ]
    if digest["risky_scans"]:
        for s in digest["risky_scans"]:
            lines.append(f"  - {s['target']} [{s['severity'].upper()}] (usuario id {s['user_id']})")
    else:
        lines.append("  (ninguno)")

    lines.append("")
    lines.append("Actores mas activos:")
    if digest["top_actors"]:
        for row in digest["top_actors"]:
            lines.append(f"  - {row['actor']}: {row['count']} eventos")
    else:
        lines.append("  (sin actividad registrada)")

    return "\n".join(lines)


def send_digest(db: Session, triggered_by: str = "cron") -> dict:
    digest = build_digest(db)
    body = render_digest_text(digest)
    subject = "Resumen diario de seguridad - SecOps Webapp"

    settings_row = db.query(AdminSettings).filter(AdminSettings.id == 1).first()

    delivered: dict[str, bool] = {}
    if settings_row and settings_row.alert_email:
        delivered["email"] = EmailConnector(settings_row.alert_email).send_alert(subject, body)
    if settings_row and settings_row.alert_webhook_url:
        delivered["webhook"] = WebhookConnector(settings_row.alert_webhook_url).send_alert(subject, body)

    # Siempre queda copia en la bandeja interna, aunque no haya ningún
    # canal externo configurado: el digest tiene que poder leerse igual.
    InboxConnector(kind="digest", delivery_status=delivered).send_alert(subject, body)

    log_event(
        "digest_diario_enviado",
        actor=triggered_by,
        result="success" if any(delivered.values()) else "failure",
        severity="info",
        metadata={"canales": delivered, "resumen": digest},
    )

    return {"digest": digest, "delivered": delivered}


if __name__ == "__main__":
    _db = SessionLocal()
    try:
        outcome = send_digest(_db, triggered_by="cron")
        print(render_digest_text(outcome["digest"]))
        print(f"Entregado: {outcome['delivered']}")
    finally:
        _db.close()
