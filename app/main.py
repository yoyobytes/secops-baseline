"""
Punto de entrada de la aplicación. Ensambla lo que ya existe en
app/config.py, app/db.py, app/security.py, app/audit.py, app/csrf.py,
app/deps.py sin modificarlos: sesiones firmadas por cookie, headers de
seguridad en cada respuesta (la app aplica sobre sí misma lo que el
propio scanner audita en terceros), rate limiting en las rutas
sensibles, y el registro de los routers.
"""
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config import settings, validate_startup_config
from app.db import Base, engine
from app.request_context import correlation_id_var, request_id_var
from app.routers import admin, api_v1, auth, dashboard
from app.schema_guard import check_schema_drift
from app.seed import seed_if_empty
from app.webutils import BASE_DIR, limiter, templates


def _asegurar_directorio_de_datos() -> None:
    """
    Crea el directorio de la base SQLite si no existe.

    SQLAlchemy crea el ARCHIVO pero no las carpetas que lo contienen, así
    que en un destino nuevo (App Service usa /home, un contenedor usa un
    volumen montado) el primer arranque falla con un error de SQLite que
    no dice que el problema es una carpeta ausente.
    """
    url = settings.DATABASE_URL
    if not url.startswith("sqlite"):
        return

    ruta = url.split("///", 1)[-1]
    if not ruta or ruta == ":memory:":
        return

    carpeta = os.path.dirname(ruta)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Se valida ANTES de crear nada: en producción esto lanza y la app no
    # arranca. Fallar cerrado es deliberado (ver config.py).
    advertencias = validate_startup_config()
    for advertencia in advertencias:
        print(f"[ADVERTENCIA DE SEGURIDAD] {advertencia}")

    _asegurar_directorio_de_datos()
    Base.metadata.create_all(bind=engine)
    # create_all() no agrega columnas nuevas a tablas que ya existen: si
    # el modelo cambió, hay que avisarlo con un mensaje útil en vez de
    # fallar más tarde con un error opaco.
    check_schema_drift()
    seed_if_empty()
    yield


# /docs, /redoc y /openapi.json publican el mapa completo de rutas y
# esquemas. Es útil para un integrador y regalado para un atacante, así
# que se apagan salvo que se habiliten explícitamente.
_docs_activos = settings.EXPOSE_API_DOCS or settings.ENVIRONMENT != "production"

app = FastAPI(
    title=settings.APP_NAME,
    lifespan=lifespan,
    docs_url="/docs" if _docs_activos else None,
    redoc_url="/redoc" if _docs_activos else None,
    openapi_url="/openapi.json" if _docs_activos else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ---------------------------------------------------------------------
# ORDEN DEL STACK DE MIDDLEWARE (importa, y no es intuitivo).
#
# Starlette inserta cada middleware al principio de la lista, así que
# EL ÚLTIMO QUE SE AGREGA ES EL MÁS EXTERNO. Por eso se agregan en orden
# inverso al que se ejecutan. Stack resultante, de afuera hacia adentro:
#
#   1. security_headers  -> más externo: así los headers se aplican a
#                           TODAS las respuestas, incluidos los 429 del
#                           rate limiter y los errores.
#   2. SessionMiddleware -> descifra la cookie de sesión.
#   3. audit_context     -> necesita la sesión ya descifrada para sacar
#                           el id de correlación => va DENTRO de (2).
#   4. SlowAPIMiddleware -> rate limiting.
# ---------------------------------------------------------------------

app.add_middleware(SlowAPIMiddleware)


@app.middleware("http")
async def audit_context(request: Request, call_next):
    """
    Deposita los identificadores de correlación para que log_event() los
    recoja solo, sin que ningún punto de llamada tenga que pasarlos.
    """
    correlation_token = correlation_id_var.set(request.session.get("sid"))
    request_token = request_id_var.set(secrets.token_hex(8))
    try:
        return await call_next(request)
    finally:
        # Se restauran para no filtrar contexto entre requests.
        correlation_id_var.reset(correlation_token)
        request_id_var.reset(request_token)


app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SESSION_SECRET,
    max_age=settings.SESSION_MAX_AGE_SECONDS,
    same_site="lax",
    https_only=settings.COOKIE_SECURE,
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """
    La app se audita a sí misma: estos son exactamente los headers que
    app/scanner.py verifica en objetivos externos (ver _check_headers).
    """
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self'; "
        "script-src 'self'; frame-ancestors 'none'; base-uri 'self'; "
        "form-action 'self'"
    )
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    if settings.COOKIE_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return response


@app.exception_handler(StarletteHTTPException)
async def manejar_errores_http(request: Request, exc: StarletteHTTPException):
    """
    Un mismo error se presenta distinto según quién pregunte.

    A una integración se le responde JSON, que es lo que sabe interpretar.
    A una persona con un navegador no: mostrarle `{"detail":"No
    autenticado"}` en pantalla es un error de producto, aunque el código
    de estado sea el correcto. Se la manda al login, o se le muestra una
    página que explique qué pasó.

    El discriminador es la cabecera `Accept`, no una suposición: el
    cliente declara qué entiende.
    """
    es_api = request.url.path.startswith("/api/")
    acepta_html = "text/html" in request.headers.get("accept", "")

    if es_api or not acepta_html:
        return await http_exception_handler(request, exc)

    if exc.status_code == status.HTTP_401_UNAUTHORIZED:
        # Sin sesión válida: al login, conservando a dónde quería ir.
        return RedirectResponse("/login", status_code=302)

    titulos = {
        status.HTTP_403_FORBIDDEN: "Acceso denegado",
        status.HTTP_404_NOT_FOUND: "No encontrado",
        status.HTTP_429_TOO_MANY_REQUESTS: "Demasiadas peticiones",
    }

    return templates.TemplateResponse(
        request,
        "error.html",
        {
            "codigo": exc.status_code,
            "titulo": titulos.get(exc.status_code, "Error"),
            "detalle": exc.detail,
        },
        status_code=exc.status_code,
    )


app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(admin.router)
app.include_router(api_v1.router)
