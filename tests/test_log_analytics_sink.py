"""
Prueba el sink de Sentinel con un cliente falso.

Verifica todo lo que no depende de Azure: el mapeo al esquema de la tabla,
el encolado asíncrono, el envío en lotes, que un SIEM caído no propague la
excepción hacia la app, y que la cola acotada descarte en vez de crecer sin
límite. La única parte no cubierta acá es la llamada HTTP real a Azure, que
se valida al desplegar.
"""
import threading
import time

from app.audit_sinks.log_analytics_sink import MAX_QUEUE_SIZE, LogAnalyticsAuditSink


class _FakeClient:
    def __init__(self, fail: bool = False):
        self.uploads: list[list[dict]] = []
        self.fail = fail
        self._lock = threading.Lock()

    def upload(self, rule_id, stream_name, logs):
        if self.fail:
            raise RuntimeError("Sentinel no disponible")
        with self._lock:
            self.uploads.append(list(logs))


def _make_sink(client) -> LogAnalyticsAuditSink:
    return LogAnalyticsAuditSink(client=client, rule_id="dcr-test", stream="Custom-Test_CL")


def _evento(**overrides) -> dict:
    base = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "schema_version": "1.0",
        "event_type": "login_failed",
        "actor": "usuario",
        "actor_role": "user",
        "resource": None,
        "result": "failure",
        "source_ip": "203.0.113.10",
        "severity": "warning",
        "correlation_id": "abc123",
        "request_id": "req456",
        "metadata": {"intentos": 3},
    }
    base.update(overrides)
    return base


def _wait_for(condicion, timeout=10.0):
    limite = time.time() + timeout
    while time.time() < limite:
        if condicion():
            return True
        time.sleep(0.05)
    return False


def test_mapeo_al_esquema_de_log_analytics():
    fila = LogAnalyticsAuditSink._to_row(_evento())

    assert fila["TimeGenerated"] == "2026-01-01T00:00:00+00:00"
    assert fila["EventType"] == "login_failed"
    assert fila["Actor"] == "usuario"
    assert fila["CorrelationId"] == "abc123"
    assert fila["SourceIp"] == "203.0.113.10"
    # Los None se normalizan a cadena vacía: Log Analytics rechaza nulos
    # en columnas de tipo string.
    assert fila["TargetResource"] == ""
    # Metadata viaja serializado como JSON.
    assert "intentos" in fila["Metadata"]


def test_los_eventos_se_envian_en_lote():
    client = _FakeClient()
    sink = _make_sink(client)

    for i in range(5):
        sink.emit(_evento(actor=f"usuario{i}"))

    assert _wait_for(lambda: sum(len(u) for u in client.uploads) == 5), "no se enviaron los 5 eventos"
    # Se agrupan en lotes en vez de un round-trip por evento.
    assert len(client.uploads) < 5


def test_siem_caido_no_propaga_excepcion_a_la_app():
    sink = _make_sink(_FakeClient(fail=True))

    # Si esto lanzara, un login fallaría porque el SIEM está caído.
    for _ in range(3):
        sink.emit(_evento())

    time.sleep(0.5)
    assert sink._worker.is_alive(), "el worker debe sobrevivir a un fallo de envío"


def test_cola_llena_descarta_en_vez_de_crecer_sin_limite():
    # Cliente que nunca termina: la cola se llena.
    bloqueo = threading.Event()

    class _ClientBloqueado:
        def upload(self, rule_id, stream_name, logs):
            bloqueo.wait(timeout=30)

    sink = _make_sink(_ClientBloqueado())

    for _ in range(MAX_QUEUE_SIZE + 200):
        sink.emit(_evento())

    assert sink._dropped > 0, "debería haber descartado eventos al llenarse la cola"
    assert sink._queue.qsize() <= MAX_QUEUE_SIZE
    bloqueo.set()
