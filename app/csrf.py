"""
Como la autenticación de la webapp usa cookies de sesión (no un bearer
token que el atacante no puede adivinar), es necesario protegerse
contra CSRF: un token aleatorio se guarda en la sesión al hacer login y
se exige en cada formulario POST como campo oculto. Si no coincide,
se rechaza la request ANTES de ejecutar cualquier acción.
"""
from fastapi import HTTPException, Request, status

from app.security import new_random_token


def get_csrf_token(request: Request) -> str:
    return request.session.get("csrf_token", "")


def verify_csrf(request: Request, submitted_token: str) -> None:
    expected = request.session.get("csrf_token")
    if not expected or submitted_token != expected:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Token CSRF inválido")


def ensure_csrf_token(request: Request) -> str:
    """
    Genera (una única vez) y devuelve el token CSRF de la sesión actual.
    Se llama al renderizar CUALQUIER formulario, incluso antes de un
    login completo (p. ej. el propio formulario de /login), para que
    siempre exista algo contra qué comparar en verify_csrf().
    """
    token = request.session.get("csrf_token")
    if not token:
        token = new_random_token()
        request.session["csrf_token"] = token
    return token
