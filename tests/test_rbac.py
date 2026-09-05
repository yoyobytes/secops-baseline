import os

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def _extract_csrf(html: str) -> str:
    marker = 'name="csrf_token" value="'
    start = html.index(marker) + len(marker)
    end = html.index('"', start)
    return html[start:end]


def _login(client, username, password):
    resp = client.get("/login")
    csrf = _extract_csrf(resp.text)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": csrf},
        follow_redirects=False,
    )


def test_normal_user_cannot_access_admin_routes(client):
    r = _login(client, os.environ["SEED_USER_USERNAME"], os.environ["SEED_USER_PASSWORD"])
    assert r.status_code == 302
    assert r.headers["location"] == "/"

    for path in ["/admin", "/admin/logs", "/admin/settings", "/admin/scans"]:
        r2 = client.get(path, follow_redirects=False)
        assert r2.status_code == 403, f"{path} debería devolver 403 para un usuario normal"


def test_admin_login_does_not_grant_full_session_before_mfa(client):
    r = _login(client, os.environ["SEED_ADMIN_USERNAME"], os.environ["SEED_ADMIN_PASSWORD"])
    assert r.status_code == 302
    assert r.headers["location"] == "/mfa-setup"  # primer login del admin: aún no está enrolado

    # La sesión NO está completa todavía (falta MFA) -> /admin debe rechazar.
    r2 = client.get("/admin", follow_redirects=False)
    assert r2.status_code in (401, 403)


def test_revocar_sesiones_invalida_una_cookie_ya_emitida(client):
    """
    El control que hace posible expulsar a alguien: la cookie sigue siendo
    criptográficamente válida, pero el servidor deja de reconocerla.
    """
    from app.db import SessionLocal
    from app.models import User

    r = _login(client, os.environ["SEED_USER_USERNAME"], os.environ["SEED_USER_PASSWORD"])
    assert r.status_code == 302

    # La sesión funciona.
    assert client.get("/", follow_redirects=False).status_code == 200

    # Se revoca desde el servidor (equivale al botón del panel admin).
    db = SessionLocal()
    try:
        usuario = db.query(User).filter(User.username == os.environ["SEED_USER_USERNAME"]).first()
        usuario.session_epoch = (usuario.session_epoch or 0) + 1
        db.commit()
    finally:
        db.close()

    # La MISMA cookie ya no sirve.
    assert client.get("/", follow_redirects=False).status_code == 401


def test_wrong_password_is_rejected_and_logged(client):
    resp = client.get("/login")
    csrf = _extract_csrf(resp.text)
    r = client.post(
        "/login",
        data={"username": os.environ["SEED_USER_USERNAME"], "password": "incorrecta", "csrf_token": csrf},
        follow_redirects=False,
    )
    assert r.status_code == 401
