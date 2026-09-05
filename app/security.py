"""
Primitivas de seguridad de autenticación.

Decisiones deliberadas (explicadas también en ARQUITECTURA.md):
- bcrypt para passwords (costo computacional ajustable, resistente a
  fuerza bruta con GPU comparado con SHA-plano).
- TOTP (RFC 6238) para MFA de admin -> estándar, funciona con
  Google Authenticator / Authy / 1Password, no depende de SMS (SIM
  swapping) ni de un proveedor externo.
- Lockout progresivo tras intentos fallidos -> mitiga fuerza bruta
  incluso si el rate limiter de red se evade.
"""
import secrets
import time
from datetime import datetime, timedelta, timezone

import pyotp
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def hash_password(plain_password: str) -> str:
    return pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# Hash de descarte, calculado una vez al importar el módulo.
_DUMMY_HASH = pwd_context.hash("no-existe-este-usuario")


def dummy_password_verify() -> None:
    """
    Consume el mismo tiempo que una verificación real de contraseña.

    Sin esto, el login responde al instante cuando el usuario NO existe y
    tarda ~250 ms (el costo de bcrypt) cuando sí existe. Esa diferencia es
    medible desde afuera y permite enumerar qué cuentas existen — que es
    exactamente lo que los mensajes de error genéricos intentan evitar.
    Devolver el mismo mensaje pero en tiempos distintos no sirve de nada.
    """
    pwd_context.verify("contraseña-incorrecta", _DUMMY_HASH)


def is_locked_out(user) -> bool:
    if user.locked_until is None:
        return False
    locked_until = user.locked_until
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) < locked_until


def register_failed_login(user, db) -> None:
    user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
    if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
        user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
        user.failed_login_attempts = 0
    db.commit()


def register_successful_login(user, db) -> None:
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()


# ---------- TOTP MFA (obligatorio para admin) ----------

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str, issuer: str = "SecOps Webapp") -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)  # tolera 1 paso de 30s por reloj desfasado


TOTP_STEP_SECONDS = 30
TOTP_VALID_WINDOW = 1


def verify_totp_code_once(secret: str, code: str, last_used_step: int | None) -> int | None:
    """
    Verifica un código TOTP y ADEMÁS impide su reutilización.

    `verify_totp_code()` acepta el mismo código tantas veces como se
    envíe mientras siga vigente su ventana de 30 segundos. Eso deja una
    ventana real de replay: quien intercepte el código (hombro, proxy,
    malware en el portapapeles) puede reutilizarlo mientras siga vivo.
    RFC 6238, sección 5.2, exige explícitamente aceptar cada código una
    sola vez.

    Devuelve el "timestep" consumido si el código es válido y todavía no
    se había usado; None si es inválido o ya fue usado. Quien llama debe
    persistir ese número para la próxima verificación.
    """
    if not secret or not code:
        return None

    code = code.strip()
    totp = pyotp.TOTP(secret)
    paso_actual = int(time.time()) // TOTP_STEP_SECONDS

    for offset in range(-TOTP_VALID_WINDOW, TOTP_VALID_WINDOW + 1):
        candidato = paso_actual + offset
        esperado = totp.at(candidato * TOTP_STEP_SECONDS)
        # Comparación en tiempo constante: evita filtrar por temporización
        # cuántos dígitos del código eran correctos.
        if secrets.compare_digest(esperado, code):
            if last_used_step is not None and candidato <= last_used_step:
                return None  # código ya consumido: replay
            return candidato

    return None


# ---------- Tokens de sesión / CSRF ----------

def new_random_token(n_bytes: int = 32) -> str:
    return secrets.token_urlsafe(n_bytes)
