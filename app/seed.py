"""
Crea las cuentas semilla (admin y usuario normal) en el primer
arranque, solo si la tabla `users` está vacía -> evita duplicar
cuentas en cada reinicio del contenedor y evita pisar contraseñas que
el operador ya haya cambiado.

El admin queda con mfa_enrolled=False a propósito: fuerza el flujo de
/mfa-setup en su primer login, en vez de asumir un secreto TOTP
pre-generado que nadie escaneó todavía.
"""
from app.audit import log_event
from app.config import settings
from app.db import SessionLocal
from app.models import AdminSettings, User
from app.security import hash_password


def seed_if_empty() -> None:
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            admin = User(
                username=settings.SEED_ADMIN_USERNAME,
                password_hash=hash_password(settings.SEED_ADMIN_PASSWORD),
                role="admin",
                mfa_enrolled=False,
            )
            normal_user = User(
                username=settings.SEED_USER_USERNAME,
                password_hash=hash_password(settings.SEED_USER_PASSWORD),
                role="user",
            )
            db.add_all([admin, normal_user])
            db.commit()

            log_event(
                "seed_inicial_creado",
                actor="system",
                result="success",
                metadata={"admin": admin.username, "user": normal_user.username},
            )

        if db.query(AdminSettings).filter(AdminSettings.id == 1).first() is None:
            db.add(AdminSettings(id=1))
            db.commit()
    finally:
        db.close()
