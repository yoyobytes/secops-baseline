"""
Tests de los controles añadidos tras la revisión de huecos.

Cada uno corresponde a un hallazgo concreto: si alguien revierte el
control, el test se pone rojo y explica por qué existía.
"""
import time

import pyotp
import pytest

from app.config import ConfiguracionInsegura, settings, validate_startup_config
from app.crypto import SecretoIndescifrable, decrypt_secret, encrypt_secret
from app.security import (
    dummy_password_verify,
    generate_totp_secret,
    hash_password,
    verify_password,
    verify_totp_code_once,
)


# ---------------------------------------------------------------------
# Cifrado del secreto TOTP en reposo
# ---------------------------------------------------------------------

def test_el_secreto_totp_no_queda_en_texto_plano():
    secreto = generate_totp_secret()
    cifrado = encrypt_secret(secreto)

    assert secreto not in cifrado, "el secreto no debe ser legible en el valor almacenado"
    assert decrypt_secret(cifrado) == secreto


def test_un_valor_corrupto_no_se_degrada_a_texto_plano():
    # Si el descifrado fallara "en silencio" devolviendo el valor tal
    # cual, el cifrado sería decorativo.
    with pytest.raises(SecretoIndescifrable):
        decrypt_secret("esto-no-es-un-token-valido")


# ---------------------------------------------------------------------
# Anti-replay de TOTP (RFC 6238 §5.2)
# ---------------------------------------------------------------------

def test_un_codigo_totp_no_se_puede_usar_dos_veces():
    secreto = generate_totp_secret()
    codigo = pyotp.TOTP(secreto).now()

    primer_uso = verify_totp_code_once(secreto, codigo, last_used_step=None)
    assert primer_uso is not None, "el primer uso debe aceptarse"

    segundo_uso = verify_totp_code_once(secreto, codigo, last_used_step=primer_uso)
    assert segundo_uso is None, "reutilizar el mismo código debe rechazarse"


def test_codigo_invalido_se_rechaza():
    secreto = generate_totp_secret()
    assert verify_totp_code_once(secreto, "000000", None) is None
    assert verify_totp_code_once(secreto, "", None) is None
    assert verify_totp_code_once("", "123456", None) is None


def test_el_paso_consumido_avanza_con_el_tiempo():
    secreto = generate_totp_secret()
    codigo = pyotp.TOTP(secreto).now()
    paso = verify_totp_code_once(secreto, codigo, None)

    assert paso == int(time.time()) // 30


# ---------------------------------------------------------------------
# Enumeración de usuarios por temporización
# ---------------------------------------------------------------------

def test_la_verificacion_de_descarte_cuesta_tiempo_comparable():
    """
    El camino "usuario inexistente" debe costar aproximadamente lo mismo
    que una verificación real. Se compara con holgura amplia: lo que
    importa es que el descarte NO sea instantáneo, no medir con precisión.
    """
    hashed = hash_password("una-contraseña-cualquiera")

    inicio = time.perf_counter()
    verify_password("incorrecta", hashed)
    real = time.perf_counter() - inicio

    inicio = time.perf_counter()
    dummy_password_verify()
    descarte = time.perf_counter() - inicio

    assert descarte > real * 0.5, (
        f"la verificación de descarte ({descarte:.3f}s) es demasiado rápida "
        f"frente a la real ({real:.3f}s): filtraría qué usuarios existen"
    )


# ---------------------------------------------------------------------
# Arranque seguro: fallar cerrado ante secretos por defecto
# ---------------------------------------------------------------------

def test_produccion_rechaza_secretos_por_defecto(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SESSION_SECRET", "CHANGE_ME")
    monkeypatch.setattr(settings, "COOKIE_SECURE", True)

    with pytest.raises(ConfiguracionInsegura):
        validate_startup_config()


def test_produccion_exige_cookies_seguras(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "SESSION_SECRET", "un-secreto-real-y-largo")
    monkeypatch.setattr(settings, "SEED_ADMIN_PASSWORD", "otra-cosa")
    monkeypatch.setattr(settings, "SEED_USER_PASSWORD", "otra-cosa-mas")
    monkeypatch.setattr(settings, "COOKIE_SECURE", False)

    with pytest.raises(ConfiguracionInsegura):
        validate_startup_config()


def test_desarrollo_advierte_pero_no_bloquea(monkeypatch):
    monkeypatch.setattr(settings, "ENVIRONMENT", "development")
    monkeypatch.setattr(settings, "SESSION_SECRET", "CHANGE_ME")

    advertencias = validate_startup_config()

    assert any("SESSION_SECRET" in a for a in advertencias)
