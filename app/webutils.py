"""
Utilidades compartidas entre routers: un único motor de templates
Jinja2 y un único Limiter de slowapi, para no instanciarlos por
separado en cada módulo (y para que el rate limiting comparta el mismo
almacenamiento de conteo de requests en toda la app).
"""
from pathlib import Path

from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

limiter = Limiter(key_func=get_remote_address)
