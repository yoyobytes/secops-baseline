"""
Interfaz de destino de auditoría.

Mismo principio que AlertConnector: la lógica que DECIDE qué es un evento
de seguridad no sabe ni le importa DÓNDE se escribe. Agregar Microsoft
Sentinel al pipeline fue escribir una clase más, sin tocar una sola de
las ~20 llamadas a log_event() repartidas por la app. Ese es el argumento
central del baseline: la instrumentación se aplica una vez y el destino
se elige por configuración, según lo que use cada cliente.

Dos reglas que todo sink debe cumplir:

1. `emit()` NUNCA lanza excepción hacia arriba. Que el SIEM del cliente
   esté caído no puede tumbar el login de la aplicación.
2. Pero tampoco puede fallar en silencio: un sink de auditoría que se
   rompió sin avisar deja al cliente ciego creyendo que ve. Por eso
   devuelve el error, y audit.py lo registra en los sinks que SÍ siguen
   vivos.
"""
from abc import ABC, abstractmethod


class AuditSink(ABC):
    #: Nombre corto para identificar el sink en los diagnósticos.
    name: str = "sink"

    @abstractmethod
    def emit(self, event: dict) -> None:
        """
        Escribe el evento en el destino. Puede lanzar excepción: quien
        orquesta (audit.py) es responsable de aislarla. Se documenta así
        para que cada sink quede simple y no repita el try/except.
        """
        raise NotImplementedError
