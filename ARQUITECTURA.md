# Arquitectura y decisiones de seguridad

Este documento explica el **por qué** de cada decisión de seguridad relevante
del proyecto. El **qué** y el **cómo** están en el propio código, comentado
en los puntos donde la razón no es obvia solo con leerlo.

## 1. RBAC forzado siempre en el servidor

`app/deps.py` expone `get_current_user` y `require_admin`. Todo endpoint que
requiere autenticación o rol admin depende de una de estas dos funciones —
nunca se decide qué mostrar solo ocultando un botón o un link en el HTML.

**Por qué:** ocultar UI en el cliente no es control de acceso, es cosmética.
Un atacante que conoce la URL (`/admin/settings`, `/admin/logs`, etc.) puede
pedirla directamente sin pasar por ningún link. La única defensa real es que
el servidor vuelva a validar el permiso en cada request, sin confiar en nada
que venga del cliente salvo la cookie de sesión firmada.

Ejemplo concreto: `dashboard.py` filtra `ScanResult` por `user_id == usuario
actual` en la propia query SQL — no se trae "todos los escaneos y se filtran
en Python", ni se confía en que el `scan_id` de la URL sea difícil de
adivinar. Esto es lo que impide que el usuario A vea el escaneo del usuario B
cambiando un número en la URL (horizontal privilege escalation).

## 2. TOTP para MFA de admin (no SMS, no passkeys, en este alcance)

- **SMS**: vulnerable a SIM swapping y a interceptación de la red del
  operador; además depende de un proveedor externo de pago (Twilio y
  similares), lo cual complica una demo o un entorno self-hosted.
- **Passkeys / WebAuthn**: es la opción más fuerte a largo plazo (resistente
  a phishing), pero requiere gestión de credenciales por dispositivo,
  soporte de navegador/hardware y una capa de registro más compleja — más
  alcance del que este ejercicio necesita para demostrar el concepto.
- **TOTP (RFC 6238, `pyotp`)**: no depende de ningún proveedor externo, no
  cuesta nada, funciona con cualquier app estándar (Google Authenticator,
  Authy, 1Password, Bitwarden), y el flujo de enrolamiento con QR es el que
  cualquier stakeholder de negocio ya conoce de otros productos. Para el
  alcance de este ejercicio (demostrar defense-in-depth, no construir un
  sistema de identidad completo), es el punto óptimo de seguridad real vs.
  complejidad de implementación.

## 3. Doble candado: rol admin Y sesión con MFA verificada

`require_admin` exige dos condiciones independientes: `user.role == "admin"`
**y** `session["mfa_verified"] == True`. No basta con una sola.

**Por qué:** si solo se validara el rol, cualquier cuenta admin comprometida
por password (reutilizado, phishing, leak de otra brecha) tendría acceso
administrativo completo con un solo factor. El segundo candado significa que
robar la contraseña del admin no alcanza — también hace falta el secreto TOTP
(que vive en el dispositivo del admin, nunca en la base de datos en texto
plano recuperable por la app).

**Cómo se implementa sin tocar `deps.py`:** la sesión completa
(`session["user_id"]`, que es lo único que lee `get_current_user`) **no se
otorga** a un admin hasta que pasa el segundo factor. Mientras tanto, su
identidad vive en una clave de sesión separada, `pending_mfa_user_id`, que
ningún dependency de autorización conoce. Así, técnicamente, no existe forma
de que una request llegue a un endpoint protegido con una sesión "a medias" —
o la sesión está completa (con MFA ya verificada) o no existe en absoluto
desde el punto de vista de `get_current_user`. Ver `app/routers/auth.py`.

## 3-bis. Identidad: por qué en producción esto se delega

La aplicación implementa autenticación propia (contraseña + TOTP). Para
una demo es lo correcto: demuestra comprensión de las primitivas.

**Para un cliente real con Entra ID, la recomendación es no hacerlo.**

Escribir el camino de autenticación uno mismo significa mantener para
siempre: rotación de contraseñas, recuperación de MFA, bloqueo de cuentas
al desvincular a alguien de la empresa, detección de credenciales
filtradas, y auditoría de todo lo anterior. Un proveedor de identidad ya
resuelve todo eso, y el cliente ya lo está pagando.

La postura profesional es entonces: *entiendo el mecanismo lo suficiente
como para saber que no debería reimplementarlo*. `app/deps.py` es la
costura por donde entra el cambio — `get_current_user` es el único punto
que resuelve identidad, y sustituir su implementación por validación de
un token de Entra ID no obliga a tocar ninguna ruta.

## 4. Audit trail dual: archivo JSON-lines + base de datos

`app/audit.py` (ya existente) escribe cada evento dos veces: a
`logs/audit.log` en formato JSON-lines, y a la tabla `AuditEvent`
(solo-append desde la aplicación).

**Por qué dos destinos:**
- La **tabla `AuditEvent`** es lo que el panel de admin consulta y filtra en
  vivo (`/admin/logs`), y es la fuente de datos del digest diario. Es
  cómoda, indexada, con filtros por tipo/severidad/actor/fecha.
- El **archivo JSON-lines** es la evidencia forense independiente: si la
  base de datos de la app se corrompe, se resetea por error, o directamente
  la app se cae, el log de archivo sigue existiendo, en un formato
  (JSON-lines) que cualquier pipeline de ingestión de un SIEM externo (ELK,
  Sentinel, Wazuh, Splunk) puede leer sin acoplarse al schema interno de la
  app.

Esto es defensa en profundidad aplicada a la *evidencia*, no solo al
control de acceso: un atacante que logra escribir en la base de datos de la
app (o un bug que la corrompe) no puede borrar retroactivamente su rastro
sin también comprometer el filesystem de logs por separado.

## 4-bis. Destinos de auditoría pluggables, y por qué el envío es asíncrono

`app/audit.py` es el punto único de instrumentación: toda la aplicación
registra por ahí. Los destinos (`AuditSink`) son intercambiables —
archivo, base de datos, Microsoft Sentinel— y se eligen por
configuración.

Tres decisiones que sostienen ese diseño:

**El envío al SIEM es asíncrono, en un hilo de fondo con cola acotada.**
`log_event()` se llama en el camino crítico del login. Si el envío fuera
sincrónico, cada inicio de sesión esperaría un round-trip a Azure, y una
degradación del SIEM se convertiría en una degradación de la
autenticación. La auditoría nunca debe agregar latencia ni modos de fallo
al proceso que audita. La cola es acotada a propósito: si el SIEM está
caído mucho tiempo, se descartan eventos antes que agotar la memoria del
contenedor — y el descarte se cuenta y se reporta.

**Los destinos están aislados entre sí.** Cada uno corre en su propio
`try/except`. Que Sentinel esté caído no puede tumbar un login.

**Un fallo de auditoría es, en sí, un evento de seguridad crítico.** Si
un destino falla, no se traga el error: se emite un evento
`audit_sink_fallo` por los destinos que siguen vivos, y hay una regla de
detección en Sentinel que lo convierte en incidente de severidad alta.
El razonamiento: un atacante competente no genera alertas, las silencia.
Detectar la ausencia de telemetría importa tanto como su contenido.

## 4-ter. Correlación: la diferencia entre logs y logs de SIEM

Cada evento arrastra un `correlation_id` (la sesión) y un `request_id`
(la petición). Sin eso, un analista tiene líneas sueltas y tiene que
adivinar cuáles pertenecen al mismo actor. Con eso, una sola consulta
responde la pregunta que de verdad importa en un incidente: *¿qué hizo
exactamente esta sesión, en qué orden?*

Se implementó con `ContextVars` y no pasando el id por parámetro, para no
tocar los ~20 puntos de llamada ni arrastrar el objeto `Request` hasta el
fondo de la aplicación. Un middleware lo deposita al inicio de cada
petición y `log_event()` lo recoge solo. Las `ContextVars` se propagan
correctamente en código asíncrono: cada petición tiene su copia, sin
fugas entre peticiones concurrentes.

## 5. Principio de conector desacoplado (`AlertConnector`)

`app/connectors/base.py` define una interfaz abstracta (`send_alert(subject,
body) -> bool`) que `EmailConnector` y `WebhookConnector` implementan. Ni el
scanner, ni las rutas de alerta crítica, ni el digest diario saben cómo se
entrega una alerta — solo saben que existe algo que implementa el contrato.

**Por qué:** agregar un canal nuevo (Slack nativo, MS Teams, PagerDuty, SMS)
es agregar una clase nueva, sin tocar la lógica que decide **qué** es una
alerta crítica ni **cuándo** dispararla. Reduce el acoplamiento y hace que
esa lógica de negocio sea trivial de testear con un connector falso (ver
`AlertConnector.send_alert` nunca lanza excepción — siempre devuelve
`bool` — para que un fallo de entrega de una alerta nunca tumbe el flujo
principal de la request que la disparó).

## 6. Defense in depth en capas — resumen

| Capa | Control |
|---|---|
| Red | Rate limiting (`slowapi`) en `/login` y `/scan` — mitiga fuerza bruta y abuso incluso antes de tocar lógica de negocio |
| Aplicación | CSRF token por sesión en todo formulario POST |
| Aplicación | Headers de seguridad (CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) en cada respuesta — la app aplica sobre sí misma exactamente lo que su propio scanner audita en terceros |
| Autenticación | bcrypt (costo ajustable) para passwords, nunca texto plano ni hash rápido (MD5/SHA1) |
| Autenticación | Lockout progresivo tras 5 intentos fallidos — mitiga fuerza bruta incluso si el rate limiter de red se evade (IP rotativa, por ejemplo) |
| Autorización | RBAC validado en servidor en cada request, nunca solo en el frontend |
| Autorización (admin) | Doble candado: rol + MFA verificada en la sesión actual |
| Datos | Consultas siempre filtradas por `user_id` del dueño — nunca se confía en que un ID sea difícil de adivinar |
| Auditoría | Registro dual (archivo + DB) de todo evento de seguridad relevante |
| Automatización | El scanner es estrictamente pasivo — solo lectura de información pública, cero explotación activa, y exige confirmación explícita de autorización antes de escanear cualquier objetivo |
| Configuración | Todo secreto viene de variables de entorno — nada hardcodeado en el repo |

## 7. El scanner es deliberadamente pasivo

`app/scanner.py` solo lee: headers HTTP de una request GET normal,
metadata del certificado TLS vía handshake estándar, y registros DNS TXT
públicos (SPF/DMARC). No hay fuzzing, no hay intentos de login, no hay
payloads, no hay nada que un navegador normal no haría al visitar el sitio.

**Por qué:** esto es lo que separa un "escáner de postura" (igual a lo que
hacen Mozilla Observatory o SecurityHeaders.com) de una herramienta de
pentesting activo. La primera categoría es legal y éticamente razonable de
automatizar contra cualquier dominio; la segunda requiere autorización
explícita y alcance acotado por escrito (rules of engagement) antes de
ejecutarse — motivo por el cual, aun siendo pasivo, la UI igual exige el
checkbox de autorización: es una buena práctica de higiene incluso para
escaneos no intrusivos, y deja evidencia auditable de que el usuario
confirmó tener permiso para apuntar la automatización a ese dominio.

## 7-bis. SSRF: cuando publicar cambió el modelo de amenaza

En local, el escáner era inofensivo: el único que escribía un dominio en
el formulario era el dueño de la máquina. Al exponerlo con un link
público, **la misma función se convirtió en un vector**: cualquiera podía
pedirle a nuestro servidor que consultara una dirección alcanzable solo
desde dentro de la red del proveedor de hosting. El objetivo clásico es
`169.254.169.254`, el endpoint de metadata de los clouds, que puede
devolver credenciales temporales de la instancia.

`app/ssrf_guard.py` resuelve el hostname **antes** de conectar y exige que
todas las IPs resultantes sean públicas. Detalles que importan:

- Se rechaza el objetivo si *cualquiera* de sus IPs es interna: un
  dominio puede resolver a varias y basta una para desviar la petición.
- Se valida **cada salto de redirect**, no solo el destino inicial. Un
  sitio externo legítimo puede responder `302 → 169.254.169.254`; por eso
  los redirects se siguen a mano en vez de delegarlos en el cliente HTTP.
- Se restringen esquemas y puertos, para que el escáner no sirva de
  barredor de puertos internos.

**Limitación conocida:** queda expuesto a *DNS rebinding*, donde el
dominio resuelve a una IP pública durante la validación y a una interna
en la conexión siguiente. Cerrarlo del todo exige conectar directamente a
la IP ya validada, fijando `Host` y SNI. No se implementó por alcance, y
se documenta en vez de omitirse: en una revisión de seguridad, el riesgo
conocido y aceptado es una posición defendible; el riesgo no advertido no.

La lección general, que es la que vale para la consultoría: **el riesgo no
vive en la función, vive en el contexto donde se despliega.** El mismo
código pasó de inocuo a peligroso sin cambiar una línea.

## 8. Qué falta para producción real

Este proyecto está pensado como demo de alcance acotado para una entrevista,
no como un sistema listo para producción. Lo que un despliegue real
necesitaría además:

- **Secretos**: mover de variables de entorno a un vault gestionado (Azure
  Key Vault, HashiCorp Vault, AWS Secrets Manager) con rotación automática,
  en vez de un `.env` en el filesystem del contenedor.
- **Base de datos**: SQLite es suficiente para una demo de un solo proceso;
  producción necesita Postgres (o similar) con conexión pooling real,
  backups, y replicación.
- **MFA con recuperación**: no hay flujo de "perdí mi dispositivo TOTP" —
  producción necesita códigos de recuperación de un solo uso generados al
  enrolar, o un proceso de soporte para re-enrolar con verificación de
  identidad fuera de banda.
- **Rate limiting distribuido**: `slowapi` en memoria de un solo proceso no
  escala a múltiples réplicas — necesitaría un backend compartido (Redis).
- **HTTPS real y HSTS**: en este demo `COOKIE_SECURE` se deja en `false`
  para poder probar por HTTP en local; producción necesita TLS terminado en
  un proxy/load balancer, `COOKIE_SECURE=true`, y HSTS con `preload`.
- **Gestión de usuarios**: no hay UI de alta/baja de usuarios ni de reseteo
  de contraseña self-service — hoy solo existen las dos cuentas semilla.
- **Observabilidad**: el archivo `logs/audit.log` está pensado como fuente
  para un SIEM externo, pero no hay integración real (agente Filebeat/Fluent
  Bit, alerting sobre umbrales, dashboards) — solo el formato listo para
  consumirse.
- **WAF / protección de borde**: el rate limiting de aplicación es una
  última línea de defensa, no reemplaza un WAF o un servicio anti-DDoS
  delante del tráfico público.
