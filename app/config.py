"""
Toda la configuración sensible viene de variables de entorno.
Nada de secretos hardcodeados en el código. En producción, esto se
reemplaza por un vault (Azure Key Vault / HashiCorp Vault).
"""
import os


class Settings:
    # --- Sesión / cookies ---
    SESSION_SECRET: str = os.getenv("SESSION_SECRET", "CHANGE_ME")
    SESSION_MAX_AGE_SECONDS: int = int(os.getenv("SESSION_MAX_AGE_SECONDS", "1800"))  # 30 min
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() == "true"

    # --- Base de datos ---
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:////srv/data/secops.db")

    # --- Cuentas semilla (solo para el primer arranque) ---
    SEED_ADMIN_USERNAME: str = os.getenv("SEED_ADMIN_USERNAME", "admin")
    SEED_ADMIN_PASSWORD: str = os.getenv("SEED_ADMIN_PASSWORD", "CambiaEstaAdmin123!")
    SEED_USER_USERNAME: str = os.getenv("SEED_USER_USERNAME", "usuario")
    SEED_USER_PASSWORD: str = os.getenv("SEED_USER_PASSWORD", "CambiaEstaUser123!")

    # --- Rate limiting ---
    LOGIN_RATE_LIMIT: str = os.getenv("LOGIN_RATE_LIMIT", "5/minute")
    SCAN_RATE_LIMIT: str = os.getenv("SCAN_RATE_LIMIT", "10/minute")

    # --- Logging ---
    LOG_FILE: str = os.getenv("LOG_FILE", "/srv/logs/audit.log")

    # --- Conector de correo (alertas críticas / digest SIEM) ---
    SMTP_HOST: str = os.getenv("SMTP_HOST", "mailhog")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "1025"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
    SMTP_FROM: str = os.getenv("SMTP_FROM", "secops-alerts@localhost")

    # --- Conector webhook genérico (Slack-compatible) ---
    ALERT_WEBHOOK_URL: str = os.getenv("ALERT_WEBHOOK_URL", "")

    # --- Microsoft Sentinel / Azure Monitor (Logs Ingestion API) ---
    # Apagado por defecto: la app arranca igual sin Azure (en local, en
    # los tests, o en un cliente que use otro SIEM). Se enciende por
    # configuración, que es justamente el punto del sink pluggable.
    AZURE_LOGS_ENABLED: bool = os.getenv("AZURE_LOGS_ENABLED", "false").lower() == "true"
    # Endpoint del Data Collection Endpoint (DCE) que crea el Bicep.
    AZURE_LOGS_ENDPOINT: str = os.getenv("AZURE_LOGS_ENDPOINT", "")
    # "immutable id" de la Data Collection Rule (DCR).
    AZURE_LOGS_RULE_ID: str = os.getenv("AZURE_LOGS_RULE_ID", "")
    # Nombre del stream declarado en la DCR.
    AZURE_LOGS_STREAM: str = os.getenv("AZURE_LOGS_STREAM", "Custom-SecOpsAudit_CL")

    # --- Integraciones salientes ---
    # Lista blanca de hosts a los que los conectores pueden salir, separada
    # por comas. Vacía = cualquier host público (las direcciones internas
    # se bloquean siempre). En un cliente real se define explícitamente.
    EGRESS_ALLOWLIST: str = os.getenv("EGRESS_ALLOWLIST", "")

    # --- Integraciones entrantes ---
    # Secreto compartido para verificar la firma HMAC de los webhooks
    # entrantes. Vacío = el receptor de webhooks queda deshabilitado.
    WEBHOOK_SIGNING_SECRET: str = os.getenv("WEBHOOK_SIGNING_SECRET", "")
    # Ventana de tolerancia para la marca de tiempo firmada.
    WEBHOOK_TOLERANCE_SECONDS: int = int(os.getenv("WEBHOOK_TOLERANCE_SECONDS", "300"))

    # --- Documentación de la API ---
    # /docs y /openapi.json publican el mapa completo de rutas. Útil para
    # integradores, innecesario para un atacante: apagado en producción.
    EXPOSE_API_DOCS: bool = os.getenv("EXPOSE_API_DOCS", "").lower() == "true"

    # --- Cifrado de secretos en reposo ---
    # En producción viene de Azure Key Vault. Si está vacío, se deriva de
    # SESSION_SECRET (ver app/crypto.py).
    MFA_ENCRYPTION_KEY: str = os.getenv("MFA_ENCRYPTION_KEY", "")

    # --- Entorno ---
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")

    # --- App ---
    APP_NAME: str = "Panel de Automatización de Seguridad Web"


settings = Settings()


# Valores por defecto que son aceptables para desarrollo y catastróficos
# en producción. Se listan explícitamente para poder rechazarlos.
#
# No son credenciales de acceso sino centinelas: la lista existe
# precisamente para DETECTARLOS y negarse a arrancar si siguen puestos en
# producción. El análisis estático puede marcarlos como "contraseña
# embebida"; el triaje correcto es reconocerlos como falso positivo por
# diseño, no borrar los valores por defecto (que romperían el arranque
# local) ni desactivar la regla entera (que dejaría pasar un secreto real).
_VALORES_INSEGUROS = {
    "SESSION_SECRET": "CHANGE_ME",
    "SEED_ADMIN_PASSWORD": "CambiaEstaAdmin123!",
    "SEED_USER_PASSWORD": "CambiaEstaUser123!",
}


class ConfiguracionInsegura(Exception):
    """La configuración no es apta para el entorno declarado."""


def validate_startup_config() -> list[str]:
    """
    Verifica al arrancar que no queden secretos por defecto.

    Fallar CERRADO es deliberado: una aplicación que arranca igual con
    `SESSION_SECRET=CHANGE_ME` es una aplicación donde alguien puede
    firmar sus propias cookies de sesión y entrar como cualquier usuario,
    incluido el administrador. Ese fallo es silencioso —todo "funciona"—
    y por eso es peor que caerse al arrancar.

    En producción lanza excepción. En desarrollo devuelve la lista de
    advertencias para poder mostrarlas sin bloquear el trabajo local.
    """
    problemas = [
        f"{clave} tiene todavía su valor por defecto"
        for clave, inseguro in _VALORES_INSEGUROS.items()
        if getattr(settings, clave, None) == inseguro
    ]

    if settings.ENVIRONMENT == "production" and not settings.COOKIE_SECURE:
        problemas.append("COOKIE_SECURE debe ser true en producción (cookies solo por HTTPS)")

    if problemas and settings.ENVIRONMENT == "production":
        raise ConfiguracionInsegura(
            "La aplicación se niega a arrancar en producción con esta configuración:\n  - "
            + "\n  - ".join(problemas)
        )

    return problemas
