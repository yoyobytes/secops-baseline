"""
Autorización para las integraciones entrantes.

Es el equivalente de `app/deps.py` pero para actores-máquina. Se mantiene
separado a propósito: las reglas son distintas (no hay MFA, hay alcances,
hay límite por credencial) y mezclarlas haría que un cambio pensado para
personas afectara a las integraciones sin querer.

Principios:

- **Alcances explícitos.** Una credencial recibe solo los permisos que
  necesita. La integración que dispara escaneos no puede leer auditoría.
- **Todo intento queda auditado**, con el actor identificado como máquina
  y no como persona. En una investigación importa distinguir "lo hizo
  Ana" de "lo hizo el conector de SAP con la credencial de Ana".
- **Límite por credencial.** Una integración descontrolada no consume la
  cuota de las demás.
"""
import time
from collections import defaultdict, deque
from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api_keys import parse_api_key, verify_secret
from app.audit import log_event
from app.db import get_db
from app.models import ApiClient

# Ventana deslizante por credencial. En memoria del proceso: con varias
# réplicas hace falta un backend compartido (Redis), igual que el rate
# limiting de las rutas web. Declarado en AUTOEVALUACION_ASVS.md.
_peticiones: dict[str, deque] = defaultdict(deque)
VENTANA_SEGUNDOS = 60


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _extraer_credencial(request: Request) -> str:
    """Acepta `Authorization: Bearer <clave>` o `X-API-Key: <clave>`."""
    autorizacion = request.headers.get("authorization", "")
    if autorizacion.lower().startswith("bearer "):
        return autorizacion[7:].strip()
    return request.headers.get("x-api-key", "").strip()


def _rechazar(request: Request, motivo: str, token_id: str | None = None):
    log_event(
        "api_auth_fallida",
        actor=f"machine:{token_id}" if token_id else "machine:desconocido",
        actor_role="machine",
        resource=str(request.url.path),
        result="blocked",
        severity="warning",
        source_ip=_client_ip(request),
        metadata={"motivo": motivo},
    )
    # Siempre el mismo mensaje: no se revela si la credencial existe, si
    # está revocada o si le falta un alcance.
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credencial inválida o insuficiente",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _dentro_del_limite(token_id: str, limite: int) -> bool:
    ahora = time.monotonic()
    ventana = _peticiones[token_id]
    while ventana and ahora - ventana[0] > VENTANA_SEGUNDOS:
        ventana.popleft()
    if len(ventana) >= limite:
        return False
    ventana.append(ahora)
    return True


def require_api_client(*alcances_requeridos: str):
    """
    Construye una dependencia que exige una credencial válida con los
    alcances indicados.

        @router.post("/scans", dependencies=[Depends(require_api_client("scans:write"))])
    """

    def dependencia(request: Request, db: Session = Depends(get_db)) -> ApiClient:
        credencial = _extraer_credencial(request)
        if not credencial:
            _rechazar(request, "sin_credencial")

        partes = parse_api_key(credencial)
        if not partes:
            _rechazar(request, "formato_invalido")

        token_id, secreto = partes
        cliente = db.query(ApiClient).filter(ApiClient.token_id == token_id).first()

        if not cliente or not cliente.is_active:
            _rechazar(request, "credencial_inexistente_o_revocada", token_id)

        if not verify_secret(secreto, cliente.secret_hash):
            _rechazar(request, "secreto_incorrecto", token_id)

        faltantes = [a for a in alcances_requeridos if a not in cliente.scope_list()]
        if faltantes:
            log_event(
                "api_alcance_insuficiente",
                actor=f"machine:{cliente.name}",
                actor_role="machine",
                resource=str(request.url.path),
                result="blocked",
                severity="warning",
                source_ip=_client_ip(request),
                metadata={"alcances_faltantes": faltantes, "alcances_de_la_credencial": cliente.scope_list()},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La credencial no tiene los permisos necesarios",
            )

        if not _dentro_del_limite(token_id, cliente.rate_limit_per_minute):
            log_event(
                "api_limite_excedido",
                actor=f"machine:{cliente.name}",
                actor_role="machine",
                resource=str(request.url.path),
                result="blocked",
                severity="warning",
                source_ip=_client_ip(request),
                metadata={"limite_por_minuto": cliente.rate_limit_per_minute},
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Límite de peticiones excedido para esta credencial",
            )

        cliente.last_used_at = datetime.now(timezone.utc)
        db.commit()

        return cliente

    return dependencia
