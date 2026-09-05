"""
Patrón: interfaz de conector desacoplada de la lógica de detección.

La detección (audit.py, scanner.py) no sabe NI le importa cómo se
entrega una alerta. Esto permite agregar un nuevo canal (Slack, MS
Teams, SMS, PagerDuty) sin tocar el código que decide QUÉ es una
alerta crítica -- solo se agrega una clase nueva que cumpla este
contrato.
"""
from abc import ABC, abstractmethod


class AlertConnector(ABC):
    @abstractmethod
    def send_alert(self, subject: str, body: str) -> bool:
        """Devuelve True si se entregó, False si falló (nunca lanza excepción)."""
        raise NotImplementedError
