"""
Sink de base de datos.

Alimenta la tabla AuditEvent, que es lo que el panel de admin consulta y
filtra en vivo y la fuente del digest diario. Es el sink "de producto":
le da al usuario de la app visibilidad inmediata sin depender de que
alguien tenga acceso al SIEM corporativo.
"""
import json

from app.audit_sinks.base import AuditSink
from app.db import SessionLocal
from app.models import AuditEvent


class DatabaseAuditSink(AuditSink):
    name = "database"

    def emit(self, event: dict) -> None:
        db = SessionLocal()
        try:
            db.add(
                AuditEvent(
                    event_type=event["event_type"],
                    actor=event["actor"],
                    actor_role=event.get("actor_role"),
                    resource=event.get("resource"),
                    result=event["result"],
                    source_ip=event.get("source_ip"),
                    severity=event.get("severity", "info"),
                    correlation_id=event.get("correlation_id"),
                    metadata_json=json.dumps(event.get("metadata", {}), ensure_ascii=False),
                )
            )
            db.commit()
        finally:
            db.close()
