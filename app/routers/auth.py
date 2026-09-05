"""
Login en dos pasos para admin (password -> MFA obligatoria antes de
tener sesión completa) y en un paso para usuarios normales.

La sesión NO se considera autenticada hasta que `session["user_id"]`
existe -- que es lo único que lee `deps.get_current_user`. Mientras un
admin tiene la contraseña validada pero no el MFA, su identidad vive
en una clave de sesión separada (`pending_mfa_user_id`) que ningún
dependency de autorización conoce. Así no hay forma de que una request
"cuele" con una sesión a medio autenticar.
"""
import base64
import io

import qrcode
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.audit import log_event
from app.config import settings
from app.crypto import SecretoIndescifrable, decrypt_secret, encrypt_secret
from app.csrf import ensure_csrf_token, verify_csrf
from app.db import get_db
from app.models import User
from app.request_context import correlation_id_var
from app.security import (
    dummy_password_verify,
    generate_totp_secret,
    get_totp_uri,
    is_locked_out,
    new_random_token,
    register_failed_login,
    register_successful_login,
    verify_password,
    verify_totp_code,
    verify_totp_code_once,
)
from app.webutils import limiter, templates

router = APIRouter()


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _secreto_en_claro(user: User) -> str:
    """Descifra el secreto TOTP guardado. Ver app/crypto.py."""
    if not user.mfa_secret:
        return ""
    try:
        return decrypt_secret(user.mfa_secret)
    except SecretoIndescifrable:
        log_event(
            "mfa_secreto_indescifrable",
            actor=user.username,
            actor_role=user.role,
            result="failure",
            severity="critical",
            metadata={"detalle": "El secreto MFA no se pudo descifrar; requiere re-enrolamiento"},
        )
        return ""


def _qr_data_uri(secret: str, username: str) -> str:
    uri = get_totp_uri(secret, username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return f"data:image/png;base64,{base64.b64encode(buf.getvalue()).decode('ascii')}"


def _pending_admin(request: Request, db: Session) -> User | None:
    user_id = request.session.get("pending_mfa_user_id")
    if not user_id:
        return None
    return (
        db.query(User)
        .filter(User.id == user_id, User.role == "admin", User.is_active == True)  # noqa: E712
        .first()
    )


@router.get("/login")
async def login_form(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/", status_code=302)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"csrf_token": ensure_csrf_token(request), "error": None},
    )


@router.post("/login")
@limiter.limit(settings.LOGIN_RATE_LIMIT)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    ip = _client_ip(request)

    def fail(msg: str, status_code: int = 401):
        return templates.TemplateResponse(
            request,
            "login.html",
            {"csrf_token": ensure_csrf_token(request), "error": msg},
            status_code=status_code,
        )

    user = db.query(User).filter(User.username == username).first()

    if not user or not user.is_active:
        # Se consume el mismo tiempo que una verificación real antes de
        # responder: si no, el atacante distingue por temporización qué
        # usuarios existen, y el mensaje genérico no sirve de nada.
        dummy_password_verify()
        log_event(
            "login_failed", actor=username, result="failure", severity="warning",
            source_ip=ip, metadata={"reason": "usuario_no_encontrado"},
        )
        return fail("Usuario o contraseña incorrectos.")

    if is_locked_out(user):
        log_event(
            "login_bloqueado", actor=user.username, actor_role=user.role,
            result="blocked", severity="warning", source_ip=ip,
        )
        return fail("Cuenta bloqueada temporalmente por demasiados intentos fallidos. Intenta más tarde.")

    if not verify_password(password, user.password_hash):
        register_failed_login(user, db)
        log_event(
            "login_failed", actor=user.username, actor_role=user.role,
            result="failure", severity="warning", source_ip=ip,
            metadata={"intentos_fallidos": user.failed_login_attempts},
        )
        return fail("Usuario o contraseña incorrectos.")

    register_successful_login(user, db)

    # Se regenera la sesión completa (mitiga session fixation) y se
    # emite un csrf_token nuevo para lo que venga después del login.
    request.session.clear()
    request.session["csrf_token"] = new_random_token()

    # Id de correlación de la sesión: a partir de acá, todos los eventos
    # de este usuario quedan enhebrados bajo el mismo hilo en el SIEM.
    # Se emite acá (y no antes) porque es el momento en que nace la
    # sesión autenticada; se renueva junto con ella en cada login.
    session_id = new_random_token(12)
    request.session["sid"] = session_id
    # Generación de sesión: permite revocarla después desde el servidor.
    request.session["epoch"] = user.session_epoch
    correlation_id_var.set(session_id)

    log_event("login_success", actor=user.username, actor_role=user.role, result="success", source_ip=ip)

    if user.role == "admin":
        request.session["pending_mfa_user_id"] = user.id
        if not user.mfa_enrolled:
            return RedirectResponse("/mfa-setup", status_code=302)
        return RedirectResponse("/mfa-verify", status_code=302)

    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = user.role
    request.session["mfa_verified"] = True
    return RedirectResponse("/", status_code=302)


@router.get("/mfa-setup")
async def mfa_setup_form(request: Request, db: Session = Depends(get_db)):
    user = _pending_admin(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if user.mfa_enrolled:
        return RedirectResponse("/mfa-verify", status_code=302)

    if not user.mfa_secret:
        # Se genera en claro, se muestra una única vez, y se guarda cifrado.
        secreto = generate_totp_secret()
        user.mfa_secret = encrypt_secret(secreto)
        db.commit()
    else:
        secreto = _secreto_en_claro(user)

    return templates.TemplateResponse(
        request,
        "mfa_setup.html",
        {
            "csrf_token": ensure_csrf_token(request),
            "qr_data_uri": _qr_data_uri(secreto, user.username),
            "secret": secreto,
            "error": None,
        },
    )


@router.get("/mfa-verify")
async def mfa_verify_form(request: Request, db: Session = Depends(get_db)):
    user = _pending_admin(request, db)
    if not user:
        return RedirectResponse("/login", status_code=302)
    if not user.mfa_enrolled:
        return RedirectResponse("/mfa-setup", status_code=302)

    return templates.TemplateResponse(
        request,
        "mfa_verify.html",
        {"csrf_token": ensure_csrf_token(request), "error": None},
    )


@router.post("/mfa-verify")
async def mfa_verify_submit(
    request: Request,
    code: str = Form(...),
    csrf_token: str = Form(...),
    db: Session = Depends(get_db),
):
    verify_csrf(request, csrf_token)
    user = _pending_admin(request, db)
    ip = _client_ip(request)

    if not user:
        return RedirectResponse("/login", status_code=302)

    secreto = _secreto_en_claro(user)
    paso_consumido = verify_totp_code_once(secreto, code, user.mfa_last_timestep)

    if paso_consumido is None:
        # Se distingue en el log un código inválido de uno reutilizado:
        # el segundo caso sugiere interceptación, no simple error de tipeo.
        reutilizado = bool(secreto) and verify_totp_code(secreto, code)
        log_event(
            "mfa_failed", actor=user.username, actor_role="admin",
            result="failure", severity="critical" if reutilizado else "warning",
            source_ip=ip,
            metadata={"motivo": "codigo_reutilizado" if reutilizado else "codigo_invalido"},
        )
        if not user.mfa_enrolled:
            return templates.TemplateResponse(
                request,
                "mfa_setup.html",
                {
                    "csrf_token": ensure_csrf_token(request),
                    "qr_data_uri": _qr_data_uri(secreto, user.username),
                    "secret": secreto,
                    "error": "Código incorrecto. Intenta nuevamente.",
                },
                status_code=401,
            )
        return templates.TemplateResponse(
            request,
            "mfa_verify.html",
            {
                "csrf_token": ensure_csrf_token(request),
                "error": "Código incorrecto. Intenta nuevamente.",
            },
            status_code=401,
        )

    # Se marca el código como consumido ANTES de abrir la sesión: si el
    # mismo código llega dos veces (dos peticiones concurrentes), la
    # segunda ya no lo encuentra disponible.
    user.mfa_last_timestep = paso_consumido
    if not user.mfa_enrolled:
        user.mfa_enrolled = True
        log_event("mfa_enrolado", actor=user.username, actor_role="admin", result="success", source_ip=ip)
    db.commit()

    request.session["user_id"] = user.id
    request.session["username"] = user.username
    request.session["role"] = "admin"
    request.session["mfa_verified"] = True
    request.session.pop("pending_mfa_user_id", None)

    log_event("mfa_success", actor=user.username, actor_role="admin", result="success", source_ip=ip)
    return RedirectResponse("/admin", status_code=302)


@router.get("/logout")
async def logout(request: Request):
    username = request.session.get("username")
    role = request.session.get("role")
    if username:
        log_event("logout", actor=username, actor_role=role, result="success", source_ip=_client_ip(request))
    request.session.clear()
    return RedirectResponse("/login", status_code=302)
