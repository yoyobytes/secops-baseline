# SecOps Webapp — baseline de seguridad para automatizaciones

Demostración de una capa de seguridad reusable aplicada a una
automatización real, con telemetría integrada a **Microsoft Sentinel**.

- **[CASO_DE_USO.md](CASO_DE_USO.md)** — el argumento: qué problema
  resuelve y cómo se adopta. *Empezá por acá.*
- **[ARQUITECTURA.md](ARQUITECTURA.md)** — el porqué de cada decisión
  técnica de seguridad.
- **[AUTOEVALUACION_ASVS.md](AUTOEVALUACION_ASVS.md)** — evaluación contra
  OWASP ASVS Nivel 2: qué se cumple, qué no, y por qué.

La automatización que sirve de vehículo es un escáner pasivo de postura
de seguridad web (cabeceras HTTP, certificado TLS, SPF/DMARC). Lo que se
demuestra no es el escáner, sino la capa que lo envuelve.

---

## Qué tenés que hacer vos (una sola vez)

### 1. Cuenta de Azure
Crear una en [portal.azure.com](https://portal.azure.com). Trae $200 de
crédito de prueba; pide tarjeta pero no cobra durante el trial.

### 2. Instalar Azure CLI

```bash
winget install --id Microsoft.AzureCLI -e
```

Cerrá y reabrí la terminal, y verificá:

```bash
az version
```

### 3. Iniciar sesión

```bash
az login
```

---

## Despliegue

El despliegue está partido en dos a propósito: **la telemetría hacia
Sentinel se despliega por separado de la aplicación**. Así, si el hosting
tiene problemas, la parte importante de la demo (los eventos llegando al
SIEM) sigue siendo demostrable desde tu propia máquina.

### Paso 1 — Observabilidad (Sentinel + ingesta)

```bash
.\azure\deploy-observability.ps1
```

Crea el workspace de Log Analytics, habilita Microsoft Sentinel, define
la tabla del audit trail y la regla de ingesta. Te deja un `.env.azure`
con la configuración y te concede permiso para enviar eventos.

### Paso 2 — Verificar que la ingesta funciona

```bash
python azure\check_ingestion.py
```

Envía un evento de prueba y traduce cualquier error a algo accionable.
**Corré esto antes de seguir**: si algo está mal, es acá donde se ve.

> La primera vez los datos tardan entre 1 y 5 minutos en aparecer, porque
> Azure materializa la tabla en el primer ingreso. Después es casi
> inmediato. Y las asignaciones de permisos tardan 1-2 minutos en
> propagarse: si el primer intento da 403, esperá y reintentá.

### Paso 3 — Reglas de detección

```bash
az deployment group create -g secops-demo-rg -f azure\02-sentinel-rules.bicep --parameters workspaceName=secops-law
```

Despliega las tres reglas de detección (fuerza bruta, escalada de
privilegios, y fallo del pipeline de auditoría) como código.

### Paso 4 — La aplicación

```bash
.\azure\deploy-app.ps1
```

Construye la imagen **en la nube** (no necesitás Docker), la despliega en
Azure Container Apps con Managed Identity, y te imprime la URL pública y
las credenciales generadas al azar.

> Guardá esas credenciales cuando aparezcan: no se vuelven a mostrar.

---

## Correr en local

Sin Azure, para desarrollo:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

set DATABASE_URL=sqlite:///./data/secops.db
set LOG_FILE=./logs/audit.log
uvicorn app.main:app --reload
```

También hay `docker-compose.yml` con Mailhog incluido para probar el
envío de correos localmente.

Para enviar a Sentinel desde local (útil para ensayar la demo), agregá
las variables de `.env.azure` al entorno. La autenticación sale de tu
`az login`.

## Tests

```bash
pytest tests\ -v
```

66 tests: hash y verificación de contraseñas, TOTP, bloqueo por intentos
fallidos, que un usuario normal no acceda a rutas de administración,
detección de cabeceras faltantes, bloqueo SSRF (incluido el endpoint de
metadata del cloud y los redirects hacia direcciones internas), el
comportamiento del envío a Sentinel con cliente simulado, cifrado del
secreto MFA en reposo, rechazo de reutilización de códigos TOTP,
revocación de sesiones, arranque seguro ante secretos por defecto,
autenticación de máquina con alcances, idempotencia, webhooks firmados y
el endurecimiento del egreso (lista blanca, reintentos, circuit breaker).

## API de integraciones

Otro sistema puede conectarse a la automatización. Las credenciales se
crean desde el panel (`/admin/integraciones`) con alcances de mínimo
privilegio.

```bash
# Disparar un escaneo desde otro sistema
curl -X POST https://<tu-app>/api/v1/scans \
  -H "Authorization: Bearer sk_..." \
  -H "Idempotency-Key: pedido-001" \
  -H "Content-Type: application/json" \
  -d '{"target":"ejemplo.com","authorized":true}'
```

| Endpoint | Alcance | Notas |
|---|---|---|
| `GET /api/v1/health` | — | Sin autenticación |
| `POST /api/v1/scans` | `scans:write` | Acepta `Idempotency-Key` |
| `GET /api/v1/scans/{id}` | `scans:read` | Solo escaneos de la propia credencial |
| `POST /api/v1/webhooks/{origen}` | firma HMAC | Requiere `X-Signature-256` y `X-Timestamp` |

---

## Guion de demo

Credenciales: las que imprimió `deploy-app.ps1`.

**1. RBAC del lado del servidor**
Entrá como `usuario` y pedí `/admin` escribiendo la URL a mano.
→ **403.** El permiso se revalida en el servidor; no es UI escondida.

**2. Doble candado en administración**
Entrá como `admin` con la contraseña correcta.
→ No entra: redirige a configurar MFA. La sesión no está autenticada
hasta el segundo factor. Probá pedir `/admin` en ese estado: rechaza.

**3. Enrolamiento MFA**
Escaneá el QR con Google Authenticator o Authy e ingresá el código.
→ Ahora sí entra al panel.

**4. Generar actividad sospechosa**
Cerrá sesión y fallá el login cinco veces seguidas.
→ La cuenta se bloquea sola.

**5. El momento clave — abrir Microsoft Sentinel**
Portal de Azure → Microsoft Sentinel → el workspace → Logs. Pegá:

```kql
SecOpsAudit_CL
| where TimeGenerated > ago(1h)
| sort by TimeGenerated desc
```

→ Los eventos de la aplicación están en el SIEM.

**6. Reconstruir la sesión completa**
Copiá un `CorrelationId` de la consulta anterior y usá
[`azure/kql/03-cadena-de-sesion.kql`](azure/kql/03-cadena-de-sesion.kql).
→ Toda la cadena de esa sesión, en orden.

**7. La alerta**
Microsoft Sentinel → Incidents.
→ La regla de fuerza bruta disparó un incidente sola.

> Las reglas se evalúan cada 5 minutos. Fallá los logins **al principio**
> de la demo para que el incidente ya esté ahí cuando llegues a este
> punto.

**8. Alertado dentro de la app**
En el panel: `/admin/alertas` muestra las alertas disparadas y cómo le
fue a cada canal de entrega. `/admin/logs` filtra el audit trail.

---

## Estructura

```
app/
  audit.py                 # punto único de instrumentación
  audit_sinks/              # destinos pluggables: archivo, DB, Sentinel
  request_context.py         # ids de correlación por sesión y request
  security.py                 # bcrypt, TOTP, bloqueo progresivo
  deps.py                      # RBAC de servidor
  ssrf_guard.py                 # bloqueo de destinos internos
  connectors/                    # alertas: email, webhook, bandeja interna
  scanner.py                      # la automatización (el vehículo)
  routers/, templates/, static/
azure/
  01-observability.bicep            # workspace, Sentinel, tabla, ingesta
  02-sentinel-rules.bicep            # detecciones como código
  deploy-observability.ps1            # paso 1
  deploy-app.ps1                       # paso 4
  check_ingestion.py                    # diagnóstico de la ingesta
  kql/                                   # consultas de investigación
tests/                                    # 26 tests
```

---

## Estado de verificación

Honestidad sobre qué está probado y qué no:

| Componente | Estado |
|---|---|
| Aplicación, autenticación, MFA, RBAC, auditoría | **Ejecutado y verificado** (26 tests + pruebas manuales end-to-end) |
| Guard SSRF | **Ejecutado y verificado** con tests dedicados |
| Lógica del envío a Sentinel | **Verificada** con cliente simulado |
| Llamada real a la API de Azure | **Sin verificar** — se valida al ejecutar `check_ingestion.py` |
| Plantillas Bicep y scripts de despliegue | **Sin ejecutar** — requieren una suscripción de Azure |
