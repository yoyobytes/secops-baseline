"""
Modelo de datos. Puntos de seguridad clave:

- `role` es explícito y se valida en el SERVIDOR en cada endpoint
  (nunca solo se oculta un botón en el frontend).
- `AuditEvent` es solo-append desde la aplicación: no hay endpoint de
  update/delete sobre esta tabla -> es el audit trail.
- `mfa_secret` solo existe para cuentas admin (least privilege: los
  usuarios normales no cargan con complejidad de MFA que no necesitan
  para su nivel de acceso, decisión de producto explicada en el MD).
"""
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import relationship

from app.db import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")  # "user" | "admin"
    # Secreto TOTP CIFRADO en reposo (ver app/crypto.py). El campo es más
    # ancho que el secreto en claro porque guarda el token de Fernet.
    mfa_secret = Column(String(255), nullable=True)  # solo admins
    mfa_enrolled = Column(Boolean, default=False)
    # Último "timestep" TOTP consumido: impide reutilizar un código
    # dentro de su ventana de validez (RFC 6238 §5.2).
    mfa_last_timestep = Column(Integer, nullable=True)
    is_active = Column(Boolean, default=True)
    failed_login_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime, nullable=True)
    # Generación de sesión. Las sesiones viven firmadas en la cookie del
    # cliente, así que no se pueden "borrar" del servidor. Incrementar
    # este número invalida de inmediato todas las sesiones existentes del
    # usuario: es el mecanismo de revocación.
    session_epoch = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=utcnow)

    scans = relationship("ScanResult", back_populates="user")


class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True)
    # Un escaneo lo origina O una persona O una integración, nunca ambas.
    # Se mantienen campos separados en vez de un "actor" genérico: falsear
    # un usuario para los escaneos por API corrompería la trazabilidad, y
    # en una investigación importa distinguir a la persona de la máquina.
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    api_client_id = Column(Integer, ForeignKey("api_clients.id"), nullable=True)
    target = Column(String(255), nullable=False)
    status = Column(String(20), default="completado")  # completado | error
    severity_summary = Column(String(20), default="info")  # critical|high|medium|low|info
    findings_json = Column(Text, nullable=False, default="[]")
    created_at = Column(DateTime, default=utcnow)

    user = relationship("User", back_populates="scans")


class AuditEvent(Base):
    """
    Solo-append. Esta tabla es el audit trail consultable desde el panel
    de admin, y la fuente de datos del digest diario estilo SIEM.
    """

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, index=True)
    event_type = Column(String(64), nullable=False, index=True)
    actor = Column(String(64), nullable=False)
    actor_role = Column(String(20), nullable=True)
    resource = Column(String(255), nullable=True)
    result = Column(String(20), nullable=False)  # success|failure|blocked
    source_ip = Column(String(64), nullable=True)
    severity = Column(String(20), default="info")  # info|warning|critical
    # Identificador de sesión: permite reconstruir la cadena completa de
    # acciones de un mismo actor en el SIEM ("mostrame todo lo que hizo
    # esta sesión"), en vez de tener eventos sueltos sin hilo conductor.
    correlation_id = Column(String(64), nullable=True, index=True)
    metadata_json = Column(Text, nullable=True)


class ApiClient(Base):
    """
    Credencial de máquina: identifica a otro SISTEMA que llama a esta
    automatización, no a una persona.

    Diferencias deliberadas frente a `User`:

    - No tiene contraseña ni MFA: un servicio no puede escanear un QR.
      Se autentica con una clave de alta entropía.
    - Tiene `scopes`: cada integración recibe solo los permisos que
      necesita. El sistema que dispara escaneos no puede leer el audit
      trail.
    - La clave se guarda HASHEADA. Si se filtra la base, no se pueden
      reconstruir las credenciales de los clientes.
    """

    __tablename__ = "api_clients"

    id = Column(Integer, primary_key=True)
    # Parte pública de la clave: viaja en claro y permite localizar el
    # registro sin recorrer toda la tabla comparando hashes.
    token_id = Column(String(32), unique=True, nullable=False, index=True)
    name = Column(String(120), nullable=False)
    secret_hash = Column(String(128), nullable=False)
    scopes = Column(String(255), nullable=False, default="")
    is_active = Column(Boolean, default=True)
    # Límite propio por credencial: una integración que se descontrola no
    # consume la cuota de las demás.
    rate_limit_per_minute = Column(Integer, nullable=False, default=60)
    created_at = Column(DateTime, default=utcnow)
    created_by = Column(String(64), nullable=True)
    last_used_at = Column(DateTime, nullable=True)

    def scope_list(self) -> list[str]:
        return [s for s in (self.scopes or "").split(",") if s]


class IdempotencyRecord(Base):
    """
    Registro de idempotencia para peticiones entrantes.

    Una automatización que reintenta es una automatización que puede
    duplicar efectos. Si el sistema del cliente envía "ejecutá este
    proceso", no recibe respuesta por un corte de red y reintenta, sin
    idempotencia se ejecuta dos veces. En un escaneo eso es ruido; en un
    asiento contable o un pago, es un incidente.

    El cliente manda una cabecera `Idempotency-Key`. Si la misma clave
    vuelve, se devuelve el resultado original en vez de volver a ejecutar.
    """

    __tablename__ = "idempotency_records"

    id = Column(Integer, primary_key=True)
    client_id = Column(Integer, ForeignKey("api_clients.id"), nullable=False)
    idempotency_key = Column(String(128), nullable=False, index=True)
    # Huella del cuerpo: detecta que reusaron la misma clave para una
    # petición DISTINTA, que es un error del integrador y hay que avisarlo.
    request_fingerprint = Column(String(64), nullable=False)
    response_scan_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=utcnow)


class AlertMessage(Base):
    """
    Bandeja de alertas interna. Es el destino de un tercer conector
    (InboxConnector) que implementa la misma interfaz AlertConnector que
    el de email y el de webhook.

    Existe porque en un despliegue público no hay un Mailhog al que
    espiar: la alerta tiene que ser visible dentro de la propia app para
    poder demostrarla. Que agregar un canal nuevo haya sido solo escribir
    una clase más, sin tocar la lógica que decide qué es una alerta
    crítica, es precisamente el punto del patrón de conector desacoplado.
    """

    __tablename__ = "alert_messages"

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    subject = Column(String(255), nullable=False)
    body = Column(Text, nullable=False)
    kind = Column(String(32), default="alerta")  # alerta | digest
    delivery_status = Column(Text, nullable=True)  # JSON con el resultado por canal externo


class AdminSettings(Base):
    """
    Configuración operable desde el panel de admin (fila única, id=1).
    """

    __tablename__ = "admin_settings"

    id = Column(Integer, primary_key=True, default=1)
    alert_email = Column(String(255), nullable=True)
    alert_webhook_url = Column(String(500), nullable=True)
    digest_enabled = Column(Boolean, default=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
