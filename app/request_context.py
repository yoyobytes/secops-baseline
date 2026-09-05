"""
Contexto de correlación por request.

Un log suelto ("login fallido, usuario X") vale poco. Lo que un analista
de SOC necesita es la cadena: *esta* sesión intentó entrar cuatro veces,
se bloqueó, y veinte minutos después la misma sesión pidió /admin. Para
poder reconstruir eso hace falta un identificador estable que viaje en
todos los eventos.

Se resuelve con ContextVars en vez de pasar el id por parámetro en cada
llamada a log_event(): el middleware lo deposita al inicio del request y
cualquier código que loguee lo recoge solo, sin que haya que tocar los
~20 puntos de llamada ni arrastrar el objeto Request hasta el fondo de
la aplicación. Las ContextVars se propagan correctamente en async, que es
justamente lo que las hace seguras acá (cada request tiene su propia
copia; no hay fuga de un request a otro ni bajo concurrencia).
"""
from contextvars import ContextVar

# Identifica la SESIÓN (sobrevive entre requests, se emite al hacer login).
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)

# Identifica el REQUEST individual (único por petición HTTP).
request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_correlation_id() -> str | None:
    return correlation_id_var.get()


def get_request_id() -> str | None:
    return request_id_var.get()
