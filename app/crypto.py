"""
Cifrado de secretos en reposo.

Motivo concreto: el secreto TOTP de un administrador es, funcionalmente,
su segundo factor. Si se guarda en texto plano y la base de datos se
filtra (backup mal protegido, inyección SQL en otro componente, disco sin
cifrar), el atacante puede generar códigos válidos indefinidamente. El
segundo factor deja de ser un segundo factor.

Guardarlo cifrado desplaza el problema a proteger UNA clave en vez de N
secretos, que es un problema mucho más manejable.

Sobre la clave:

- En producción debe venir de Azure Key Vault, en `MFA_ENCRYPTION_KEY`,
  y rotarse con un esquema de doble clave (descifrar con la vieja,
  cifrar con la nueva).
- Si no se define, se DERIVA de SESSION_SECRET con HKDF, usando un
  `info` distinto para que nunca coincida con la clave de sesión. Es un
  compromiso consciente para que el entorno de desarrollo no necesite
  gestionar una segunda clave. Como SESSION_SECRET no puede quedarse en
  su valor por defecto en producción (ver config.validate_startup_config),
  la clave derivada nunca es predecible en un despliegue real.
"""
import base64
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import settings


class SecretoIndescifrable(Exception):
    """El valor almacenado no se pudo descifrar con la clave actual."""


@lru_cache(maxsize=1)
def _fernet() -> Fernet:
    if settings.MFA_ENCRYPTION_KEY:
        return Fernet(settings.MFA_ENCRYPTION_KEY.encode())

    derivada = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"secops-webapp-mfa-v1",
        info=b"cifrado-de-secretos-totp",  # dominio separado del de sesión
    ).derive(settings.SESSION_SECRET.encode())

    return Fernet(base64.urlsafe_b64encode(derivada))


def encrypt_secret(plano: str) -> str:
    return _fernet().encrypt(plano.encode()).decode()


def decrypt_secret(cifrado: str) -> str:
    try:
        return _fernet().decrypt(cifrado.encode()).decode()
    except (InvalidToken, ValueError) as e:
        # Pasa si cambió la clave o si el valor quedó de una versión
        # anterior sin cifrar. No se intenta adivinar ni caer de vuelta a
        # texto plano: eso convertiría el cifrado en decorativo.
        raise SecretoIndescifrable(
            "No se pudo descifrar el secreto MFA con la clave actual"
        ) from e
