"""
Sink de Microsoft Sentinel (vía Azure Monitor Logs Ingestion API).

DECISIÓN DE DISEÑO CLAVE: el envío es ASÍNCRONO, en un hilo de fondo.

La razón es que `log_event()` se llama en el camino crítico del login. Si
el envío al SIEM fuera sincrónico, cada inicio de sesión esperaría un
round-trip HTTP a Azure, y una degradación de Azure se convertiría en una
degradación del login del cliente. Peor: un timeout de red en el SIEM
podría dejar colgada la autenticación. La auditoría nunca debe agregar
latencia ni modos de fallo al camino que audita.

Por eso los eventos se encolan y un worker los envía en lotes. Efectos:

- Si Sentinel está caído, la app sigue funcionando y los eventos se
  acumulan en la cola hasta que vuelva.
- La cola es ACOTADA. Si se llena (SIEM caído mucho tiempo), se descartan
  eventos y se cuenta cuántos: preferimos perder telemetría antes que
  consumir toda la memoria del contenedor. Ese descarte se reporta, porque
  perder auditoría en silencio es peor que perderla a gritos.
- Autenticación por Managed Identity (DefaultAzureCredential): en Azure
  Container Apps no hay ninguna credencial guardada en la aplicación.

Nota sobre entrega: esto es "at-most-once". Si el contenedor muere con la
cola llena, esos eventos se pierden en el camino a Sentinel — pero NO se
pierden como evidencia, porque los sinks de archivo y base de datos ya los
escribieron de forma sincrónica antes. Esa es la razón de que el pipeline
tenga varios destinos y no uno solo.
"""
import atexit
import json
import queue
import threading
from datetime import datetime, timezone

from app.audit_sinks.base import AuditSink
from app.config import settings

MAX_QUEUE_SIZE = 1000
BATCH_SIZE = 50
FLUSH_INTERVAL_SECONDS = 5


def _build_default_client():
    """Se importa acá adentro para que los SDK de Azure sean opcionales."""
    from azure.identity import DefaultAzureCredential
    from azure.monitor.ingestion import LogsIngestionClient

    return LogsIngestionClient(
        endpoint=settings.AZURE_LOGS_ENDPOINT,
        credential=DefaultAzureCredential(),
    )


class LogAnalyticsAuditSink(AuditSink):
    name = "sentinel"

    def __init__(self, client=None, rule_id: str | None = None, stream: str | None = None):
        self._rule_id = rule_id or settings.AZURE_LOGS_RULE_ID
        self._stream = stream or settings.AZURE_LOGS_STREAM

        # Falla rápido y ruidosamente ante configuración incompleta. Sin
        # esto, el sink se crea igual y encola eventos que nunca llegan a
        # ningún lado: el peor de los mundos, porque el operador cree que
        # tiene telemetría en el SIEM y en realidad no tiene nada.
        if client is None:
            faltantes = [
                nombre
                for nombre, valor in (
                    ("AZURE_LOGS_ENDPOINT", settings.AZURE_LOGS_ENDPOINT),
                    ("AZURE_LOGS_RULE_ID", self._rule_id),
                    ("AZURE_LOGS_STREAM", self._stream),
                )
                if not valor
            ]
            if faltantes:
                raise ValueError(
                    "Sentinel está habilitado pero falta configuración: "
                    + ", ".join(faltantes)
                )

        self._client = client or _build_default_client()

        self._queue: queue.Queue = queue.Queue(maxsize=MAX_QUEUE_SIZE)
        self._dropped = 0
        self._stopping = threading.Event()

        self._worker = threading.Thread(target=self._run, name="sentinel-audit-sink", daemon=True)
        self._worker.start()
        atexit.register(self.flush)

    # ------------------------------------------------------------------
    # Interfaz AuditSink
    # ------------------------------------------------------------------

    def emit(self, event: dict) -> None:
        try:
            self._queue.put_nowait(self._to_row(event))
        except queue.Full:
            self._dropped += 1
            # No se usa log_event() acá: provocaría recursión infinita
            # (el fallo del sink intentaría emitirse por el mismo sink).
            print(
                f"[audit:sentinel] cola llena, evento descartado "
                f"(total descartados: {self._dropped})"
            )

    # ------------------------------------------------------------------
    # Interno
    # ------------------------------------------------------------------

    @staticmethod
    def _to_row(event: dict) -> dict:
        """
        Traduce el esquema canónico interno a las columnas de la tabla
        custom de Log Analytics. Mantener este mapeo en un solo lugar
        evita que el esquema de la app y el del SIEM se desincronicen.
        """
        return {
            "TimeGenerated": event.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "SchemaVersion": event.get("schema_version", ""),
            "EventType": event.get("event_type", ""),
            "Actor": event.get("actor", ""),
            "ActorRole": event.get("actor_role") or "",
            # "TargetResource" y no "Resource": Log Analytics reserva
            # varios nombres de columna genéricos y conviene no rozarlos.
            "TargetResource": event.get("resource") or "",
            "Result": event.get("result", ""),
            "SourceIp": event.get("source_ip") or "",
            "Severity": event.get("severity", "info"),
            "CorrelationId": event.get("correlation_id") or "",
            "RequestId": event.get("request_id") or "",
            "Metadata": json.dumps(event.get("metadata", {}), ensure_ascii=False),
        }

    def _run(self) -> None:
        while not self._stopping.is_set():
            batch = self._collect_batch()
            if batch:
                self._upload(batch)

    def _collect_batch(self) -> list[dict]:
        batch: list[dict] = []
        try:
            # Espera bloqueante por el primero, para no hacer busy-loop.
            batch.append(self._queue.get(timeout=FLUSH_INTERVAL_SECONDS))
        except queue.Empty:
            return batch

        while len(batch) < BATCH_SIZE:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return batch

    def _upload(self, batch: list[dict]) -> None:
        try:
            self._client.upload(rule_id=self._rule_id, stream_name=self._stream, logs=batch)
        except Exception as e:  # noqa: BLE001 - el worker nunca debe morir
            print(f"[audit:sentinel] fallo al enviar {len(batch)} eventos: {e.__class__.__name__}: {e}")

    def flush(self, timeout: float = 5.0) -> None:
        """Vacía la cola pendiente. Se llama al apagar el proceso."""
        deadline = threading.Event()
        threading.Timer(timeout, deadline.set).start()
        while not self._queue.empty() and not deadline.is_set():
            batch = self._collect_batch()
            if batch:
                self._upload(batch)
