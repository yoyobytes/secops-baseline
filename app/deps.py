"""
RBAC forzado del lado del servidor. Cada endpoint sensible depende de
una de estas funciones -> nunca se confía en que el frontend oculte un
botón; el permiso se re-valida en cada request.
"""
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit import log_event
from app.db import get_db
from app.models import User


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="No autenticado")

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()  # noqa: E712
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión inválida")

    # Revocación de sesión. La sesión vive firmada en la cookie del
    # cliente, así que el servidor no puede borrarla: lo que puede hacer
    # es dejar de reconocerla. Si la generación que trae la cookie no
    # coincide con la del usuario, la sesión fue revocada (contraseña
    # cambiada, cuenta comprometida, expulsión manual desde el panel) y
    # deja de valer aunque la firma siga siendo criptográficamente válida.
    if request.session.get("epoch") != user.session_epoch:
        log_event(
            "sesion_revocada_rechazada",
            actor=user.username,
            actor_role=user.role,
            resource=str(request.url.path),
            result="blocked",
            source_ip=request.client.host if request.client else None,
            severity="warning",
        )
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión revocada")

    return user


def require_admin(request: Request, user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        log_event(
            "acceso_admin_denegado",
            actor=user.username,
            actor_role=user.role,
            resource=str(request.url.path),
            result="blocked",
            source_ip=request.client.host if request.client else None,
            severity="warning",
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requiere rol admin")

    # Doble candado: rol admin Y MFA verificada en esta sesión.
    if not request.session.get("mfa_verified"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Requiere verificación MFA")

    return user
