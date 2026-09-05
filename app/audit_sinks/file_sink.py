"""
Sink de archivo JSON-lines.

Es la fuente forense independiente: si la base de datos de la app se
corrompe o el envío al SIEM falla, este archivo sigue en disco. Y el
formato (un JSON por línea) es exactamente lo que ingiere un agente de
Azure Monitor, Filebeat o Fluent Bit sin transformación previa.
"""
import json
import logging
import os
import sys

from app.audit_sinks.base import AuditSink


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(getattr(record, "audit", {}), ensure_ascii=False)


class FileAuditSink(AuditSink):
    name = "file"

    def __init__(self, log_file: str):
        self._logger = logging.getLogger("audit_file")
        self._logger.setLevel(logging.INFO)
        self._logger.propagate = False

        if not self._logger.handlers:
            os.makedirs(os.path.dirname(log_file) or ".", exist_ok=True)
            fmt = _JsonFormatter()

            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            self._logger.addHandler(fh)

            # stdout también: en un contenedor, es lo que recogen los
            # logs de la plataforma (Container Apps -> Log Analytics).
            sh = logging.StreamHandler(sys.stdout)
            sh.setFormatter(fmt)
            self._logger.addHandler(sh)

    def emit(self, event: dict) -> None:
        self._logger.info(event.get("event_type", "audit"), extra={"audit": event})
