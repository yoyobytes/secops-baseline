"""
Detección de desfase de esquema al arrancar.

`Base.metadata.create_all()` crea las tablas que faltan, pero NO agrega
columnas nuevas a una tabla que ya existe. Es decir: si el modelo suma un
campo y la base ya estaba creada, la aplicación arranca "bien" y falla
después, en la primera consulta, con un error de SQLAlchemy que no dice
qué hacer al respecto.

Esto se detectó en una demo local justo así: la app se cayó al arrancar
con `no such column: users.mfa_last_timestep` y una traza de treinta
líneas.

Este módulo compara el esquema real contra el modelo y falla con un
mensaje que explica el problema y la solución. No migra solo: hacer
`ALTER TABLE` automático sobre una base de producción, sin que nadie lo
haya pedido, es peor que detenerse.

Para un sistema real esto lo cubre una herramienta de migraciones
(Alembic), con versionado y capacidad de revertir. Esa es la respuesta
de producción y está declarada como pendiente en ARQUITECTURA.md.
"""
from sqlalchemy import inspect

from app.db import Base, engine


class EsquemaDesactualizado(Exception):
    """La base existente no coincide con el modelo actual."""


def check_schema_drift() -> None:
    inspector = inspect(engine)
    tablas_existentes = set(inspector.get_table_names())

    desfases: list[str] = []

    for nombre_tabla, tabla in Base.metadata.tables.items():
        if nombre_tabla not in tablas_existentes:
            continue  # la crea create_all(), no es un desfase

        columnas_reales = {c["name"] for c in inspector.get_columns(nombre_tabla)}
        faltantes = {c.name for c in tabla.columns} - columnas_reales

        if faltantes:
            desfases.append(f"{nombre_tabla}: faltan {', '.join(sorted(faltantes))}")

    if desfases:
        raise EsquemaDesactualizado(
            "La base de datos existente no coincide con el modelo actual.\n\n  - "
            + "\n  - ".join(desfases)
            + "\n\nEn desarrollo: borra el archivo de base de datos y deja que se "
            "recree con las cuentas semilla.\n"
            "En producción: aplica una migración; no borres nada."
        )
