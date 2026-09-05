"""
Conector de webhook saliente (compatible con Slack).

Usa el cliente HTTP endurecido en vez de llamar a httpx directo: eso le
da control de egreso, reintentos con backoff, circuit breaker y
redacción de secretos en los mensajes de error.

La URL del webhook la configura un administrador desde el panel. Es
decir: es entrada de usuario que termina siendo un destino de red. Sin
control de egreso, quien pueda editar esa configuración puede hacer que
la aplicación hable con cualquier servidor — incluida la red interna del
proveedor de hosting.
"""
from app.audit import log_event
from app.connectors.base import AlertConnector
from app.connectors.http_client import (
    CircuitoAbierto,
    DestinoNoPermitido,
    post_json,
    redactar_url,
)


class WebhookConnector(AlertConnector):
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send_alert(self, subject: str, body: str) -> bool:
        if not self.webhook_url:
            return False

        payload = {"text": f"*{subject}*\n{body}"}  # formato compatible con Slack

        try:
            resp = post_json(self.webhook_url, payload)
            return resp.status_code < 300

        except DestinoNoPermitido as e:
            log_event(
                "conector_webhook_destino_bloqueado",
                actor="system",
                result="blocked",
                severity="critical",
                resource=redactar_url(self.webhook_url),
                metadata={"detalle": str(e)},
            )
            return False

        except CircuitoAbierto as e:
            log_event(
                "conector_webhook_circuito_abierto",
                actor="system",
                result="failure",
                severity="warning",
                resource=redactar_url(self.webhook_url),
                metadata={"detalle": str(e)},
            )
            return False

        except Exception as e:  # noqa: BLE001 - un conector nunca lanza hacia arriba
            log_event(
                "conector_webhook_fallo",
                actor="system",
                result="failure",
                severity="warning",
                # URL redactada: la query string de un webhook suele
                # llevar el token de autenticación.
                resource=redactar_url(self.webhook_url),
                metadata={"error": e.__class__.__name__},
            )
            return False
