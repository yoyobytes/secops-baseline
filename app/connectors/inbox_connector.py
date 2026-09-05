"""
Conector de bandeja interna.

Guarda la alerta en la propia base de datos, para que sea visible desde
el panel de administración sin depender de ningún servicio externo.

Dos motivos:

1. En un despliegue público no hay un Mailhog al que espiar. La alerta
   tiene que poder verse dentro de la aplicación.
2. Es la red de seguridad de la demo: si el correo o el webhook fallan
   en vivo (credenciales, red, cuota), la alerta igual aparece en
   pantalla y el mecanismo se puede mostrar igual.

Agregarlo fue escribir esta clase y nada más: ni el escáner ni el digest
ni la lógica que decide qué es una alerta crítica se enteraron. Eso es
exactamente lo que compra el patrón de conector desacoplado.
"""
import json

from app.connectors.base import AlertConnector
from app.db import SessionLocal
from app.models import AlertMessage


class InboxConnector(AlertConnector):
    def __init__(self, kind: str = "alerta", delivery_status: dict | None = None):
        self.kind = kind
        self.delivery_status = delivery_status

    def send_alert(self, subject: str, body: str) -> bool:
        db = SessionLocal()
        try:
            db.add(
                AlertMessage(
                    subject=subject,
                    body=body,
                    kind=self.kind,
                    delivery_status=(
                        json.dumps(self.delivery_status, ensure_ascii=False)
                        if self.delivery_status is not None
                        else None
                    ),
                )
            )
            db.commit()
            return True
        except Exception:  # noqa: BLE001 - un conector nunca lanza hacia arriba
            db.rollback()
            return False
        finally:
            db.close()
