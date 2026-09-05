"""
Punto único de instrumentación de seguridad.

Toda la aplicación registra eventos llamando a `log_event()`. Esta función
arma el evento en un esquema canónico y lo reparte a todos los destinos
configurados (`AuditSink`): archivo JSON-lines, base de datos y —cuando
está configurado— Microsoft Sentinel vía Log Analytics.

Por qué importa este diseño para el baseline:

- **Un solo punto de instrumentación.** La app se instrumenta una vez; a
  qué SIEM van los eventos es decisión de configuración de cada cliente.
- **Los destinos están aislados entre sí.** Que el SIEM del cliente esté
  caído no puede tumbar un login. Cada sink se ejecuta en su propio
  try/except.
- **Un fallo de auditoría es, en sí, un evento de seguridad.** Si un sink
  falla no se traga el error en silencio: se registra el fallo en los
  sinks que siguen vivos. Un pipeline de auditoría roto sin que nadie se
  entere deja al cliente ciego creyendo que ve.
- **Correlación.** Cada evento arrastra el id de sesión y el id de
  request, que es lo que permite reconstruir cadenas de actividad en el
  SIEM en vez de mirar líneas sueltas.
"""
from datetime import datetime, timezone

from app.audit_sinks.base import AuditSink
from app.audit_sinks.db_sink import DatabaseAuditSink
from app.audit_sinks.file_sink import FileAuditSink
from app.config import settings
from app.request_context import get_correlation_id, get_request_id

#: Nombre del esquema que se envía al SIEM. Si cambia la forma del
#: evento, cambia acá y en la tabla/DCR de Log Analytics.
SCHEMA_VERSION = "1.0"


def _build_sinks() -> list[AuditSink]:
    sinks: list[AuditSink] = [
        FileAuditSink(settings.LOG_FILE),
        DatabaseAuditSink(),
    ]

    # El sink de Sentinel solo se activa si el cliente lo configuró.
    # Se importa perezosamente para que la app no dependa de los SDK de
    # Azure cuando no se usan (p. ej. en local o en los tests).
    if getattr(settings, "AZURE_LOGS_ENABLED", False):
        try:
            from app.audit_sinks.log_analytics_sink import LogAnalyticsAuditSink

            sinks.append(LogAnalyticsAuditSink())
        except Exception as e:  # noqa: BLE001 - arrancar sin SIEM es preferible a no arrancar
            print(f"[audit] No se pudo inicializar el sink de Log Analytics: {e}")

    return sinks


_sinks: list[AuditSink] = _build_sinks()


def _emit_to_all(event: dict, _failed: set[str] | None = None) -> None:
    failed = _failed or set()

    for sink in _sinks:
        if sink.name in failed:
            continue  # no reintentar un sink que ya falló en esta cadena
        try:
            sink.emit(event)
        except Exception as e:  # noqa: BLE001 - un destino caído no puede romper la app
            failed.add(sink.name)
            _report_sink_failure(sink, e, failed)


def _report_sink_failure(sink: AuditSink, error: Exception, failed: set[str]) -> None:
    """
    Un sink caído es un evento de seguridad: se registra en los destinos
    que siguen funcionando. `failed` evita el bucle infinito de "el sink
    que falla intenta reportar que falló".
    """
    _emit_to_all(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "schema_version": SCHEMA_VERSION,
            "event_type": "audit_sink_fallo",
            "actor": "system",
            "actor_role": None,
            "resource": sink.name,
            "result": "failure",
            "source_ip": None,
            "severity": "critical",
            "correlation_id": get_correlation_id(),
            "request_id": get_request_id(),
            "metadata": {"sink": sink.name, "error": error.__class__.__name__, "detail": str(error)},
        },
        _failed=failed,
    )


def log_event(
    event_type: str,
    actor: str,
    result: str,
    actor_role: str | None = None,
    resource: str | None = None,
    source_ip: str | None = None,
    severity: str = "info",
    metadata: dict | None = None,
) -> None:
    """
    Firma sin cambios respecto de la versión original: los ~20 puntos de
    llamada repartidos por la app siguen funcionando igual. La
    correlación se recoge sola del contexto del request.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "schema_version": SCHEMA_VERSION,
        "event_type": event_type,
        "actor": actor,
        "actor_role": actor_role,
        "resource": resource,
        "result": result,
        "source_ip": source_ip,
        "severity": severity,
        "correlation_id": get_correlation_id(),
        "request_id": get_request_id(),
        "metadata": metadata or {},
    }

    _emit_to_all(event)
