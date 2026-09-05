# Imagen base fijada por DIGEST, no por etiqueta.
#
# "python:3.12-slim" es una etiqueta móvil: apunta a una imagen distinta
# cada vez que se reconstruye upstream. Eso significa que dos compilaciones
# del mismo código, con una semana de diferencia, pueden producir
# contenedores distintos — y que una compilación reproducible es imposible.
# El digest es inmutable: siempre es exactamente este contenido.
#
# Contrapartida honesta: fijar por digest congela también los parches de
# seguridad del sistema operativo base. Por eso el digest debe actualizarse
# de forma deliberada y periódica (renovate/dependabot lo automatizan), no
# dejarse quieto para siempre.
FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

WORKDIR /srv

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# El contenedor NO corre como root.
#
# Por defecto, un contenedor ejecuta como uid 0. Si alguien logra
# ejecución de código dentro (una dependencia comprometida, un fallo en
# la aplicación), lo hace con root dentro del contenedor, lo que amplía
# mucho lo que puede intentar a continuación: escribir el propio código
# de la app, instalar herramientas, o buscar una fuga hacia el host.
# Es el control #1 del CIS Docker Benchmark y cuesta tres líneas.
RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /srv/logs /srv/data \
    && chown -R appuser:appuser /srv

USER appuser

EXPOSE 8000

# --proxy-headers: detrás del ingress de Azure Container Apps, la IP real
# del cliente llega en X-Forwarded-For. Sin esto, TODOS los eventos de
# auditoría registrarían la IP del balanceador y la detección de fuerza
# bruta por IP quedaría inservible (agruparía a todo el mundo junto).
#
# forwarded-allow-ips="*" confía en esa cabecera venga de donde venga.
# Es seguro AQUÍ porque el contenedor solo es alcanzable a través del
# ingress de la plataforma. Si algún día la app quedara expuesta
# directamente, esto habría que acotarlo al rango del proxy: si no,
# cualquiera podría falsificar su IP de origen en los logs.
CMD ["uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*"]
