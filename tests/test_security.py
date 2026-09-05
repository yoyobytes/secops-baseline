import pyotp

from app.security import (
    MAX_FAILED_ATTEMPTS,
    generate_totp_secret,
    hash_password,
    is_locked_out,
    register_failed_login,
    verify_password,
    verify_totp_code,
)


def test_hash_and_verify_password():
    hashed = hash_password("MiPassword123!")
    assert hashed != "MiPassword123!"
    assert verify_password("MiPassword123!", hashed)
    assert not verify_password("otraCosaDistinta", hashed)


def test_totp_generate_and_verify():
    secret = generate_totp_secret()
    current_code = pyotp.TOTP(secret).now()

    assert verify_totp_code(secret, current_code)
    assert not verify_totp_code(secret, "000000")
    assert not verify_totp_code(secret, "")
    assert not verify_totp_code("", current_code)


class _FakeUser:
    def __init__(self):
        self.failed_login_attempts = 0
        self.locked_until = None


class _FakeDB:
    def commit(self):
        pass


def test_lockout_after_max_failed_attempts():
    user = _FakeUser()
    db = _FakeDB()

    for _ in range(MAX_FAILED_ATTEMPTS - 1):
        register_failed_login(user, db)
    assert not is_locked_out(user)

    register_failed_login(user, db)
    assert is_locked_out(user)
    assert user.failed_login_attempts == 0  # se resetea el contador al bloquear
