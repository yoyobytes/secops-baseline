"""
Credenciales de máquina para integraciones entrantes.

**Por qué NO se usa bcrypt acá, si sí se usa para contraseñas.**

bcrypt es lento a propósito: defiende contraseñas humanas, que tienen
poca entropía y son adivinables por fuerza bruta. Una clave de API
generada acá tiene 256 bits de entropía aleatoria: no hay diccionario ni
fuerza bruta que la alcance, así que el costo de bcrypt no compra
seguridad. Y sí cuesta: ~250 ms en CADA llamada de una integración que
puede hacer miles por hora.

Para secretos de alta entropía, el hash correcto es uno rápido
(SHA-256) comparado en tiempo constante. Esto no es un atajo: es la
recomendación estándar, y aplicar bcrypt acá sería confundir "más lento"
con "más seguro".

**Formato de la clave:** `sk_<token_id>_<secreto>`

La parte `token_id` viaja en claro y sirve para localizar el registro
directamente por índice. Sin ella habría que traer todas las
credenciales y comparar hashes una por una, lo que además de lento
abriría un canal de temporización.
"""
import hashlib
import hmac
import secrets

PREFIJO = "sk"


def generate_api_key() -> tuple[str, str, str]:
    """
    Genera una credencial nueva.

    Devuelve (clave_completa, token_id, hash_del_secreto).
    La clave completa se muestra UNA sola vez; solo se guarda el hash.
    """
    token_id = secrets.token_hex(8)
    secreto = secrets.token_urlsafe(32)
    clave_completa = f"{PREFIJO}_{token_id}_{secreto}"
    return clave_completa, token_id, hash_secret(secreto)


def parse_api_key(clave: str) -> tuple[str, str] | None:
    """Extrae (token_id, secreto) de una clave presentada. None si no tiene forma válida."""
    if not clave:
        return None
    partes = clave.strip().split("_", 2)
    if len(partes) != 3 or partes[0] != PREFIJO:
        return None
    token_id, secreto = partes[1], partes[2]
    if not token_id or not secreto:
        return None
    return token_id, secreto


def hash_secret(secreto: str) -> str:
    return hashlib.sha256(secreto.encode()).hexdigest()


def verify_secret(secreto: str, hash_guardado: str) -> bool:
    # Comparación en tiempo constante: una comparación normal termina en
    # el primer byte distinto y filtra información por temporización.
    return hmac.compare_digest(hash_secret(secreto), hash_guardado or "")
