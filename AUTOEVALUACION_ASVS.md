# Autoevaluación contra OWASP ASVS

**Estándar de referencia:** OWASP Application Security Verification
Standard (ASVS) v4.0.3, Nivel 2.
**Alcance:** la aplicación de demostración y su baseline de seguridad.
**Fecha:** septiembre 2026.

---

## Por qué existe este documento

Una afirmación como *"la aplicación usa las mejores prácticas de
seguridad"* no es verificable y, en una revisión seria, resta
credibilidad en vez de sumarla.

Este documento dice tres cosas concretas: **qué se cumple**, **qué no**, y
**por qué se decidió no cumplirlo**. Un hueco conocido y justificado es
una posición defendible. Un hueco no advertido es un hallazgo de
auditoría.

**Nivel elegido:** ASVS Nivel 2, que es el apropiado para aplicaciones que
manejan datos de negocio. El Nivel 3 corresponde a sistemas críticos
(salud, finanzas, infraestructura) y exige controles que serían
desproporcionados aquí.

**Advertencia de alcance:** esta es una autoevaluación, no una auditoría
independiente ni una prueba de penetración. Se basa en revisión del
propio código. Un revisor externo encontraría cosas que acá no están.

---

## Resumen

| Capítulo ASVS | Estado |
|---|---|
| V1 Arquitectura | Parcial |
| V2 Autenticación | Parcial |
| V3 Gestión de sesión | Cumple |
| V4 Control de acceso | Cumple |
| V5 Validación y codificación | Parcial |
| V6 Criptografía | Parcial |
| V7 Registro y manejo de errores | Cumple |
| V8 Protección de datos | Parcial |
| V9 Comunicaciones | Cumple (en despliegue) |
| V10 Código malicioso | Cumple |
| V11 Lógica de negocio | Cumple |
| V12 Archivos y recursos | No aplica |
| V13 API y servicios web | Cumple |
| V14 Configuración | Parcial |

---

## V2 — Autenticación

### Cumple

| Requisito | Implementación |
|---|---|
| 2.1.7 Contraseñas con hash resistente | bcrypt vía passlib, coste ajustable |
| 2.2.1 Anti-automatización | Rate limiting por IP + bloqueo progresivo tras 5 intentos |
| 2.2.3 Notificación de eventos | Eventos de auditoría en cada cambio relevante |
| 2.5.4 Sin cuentas con credenciales por defecto en producción | La app **se niega a arrancar** en producción con secretos por defecto |
| 2.8.1 Verificador OTP basado en tiempo | TOTP RFC 6238 |
| **2.8.6 Un código OTP se usa una sola vez** | Se registra el último *timestep* consumido; reutilizarlo se rechaza y se registra como evento **crítico** |
| 2.9.3 Secretos de autenticación protegidos | Secreto TOTP cifrado en reposo (Fernet) |
| 2.10.1 Sin secretos en el código | Todo por variable de entorno; en Azure, secretos de plataforma |

### No cumple

| Requisito | Situación | Decisión |
|---|---|---|
| **2.1.7 Contraseñas contra corpus de filtraciones** | No se verifica contra Have I Been Pwned | **Pendiente.** Es barato (API k-anonymity) y debería incorporarse |
| **2.2.4 Resistencia a phishing (MFA)** | TOTP es phishable: un sitio falso puede pedir el código y usarlo al instante | **Aceptado con justificación.** Cerrarlo exige WebAuthn/passkeys. Se documenta como el argumento a favor de delegar identidad a Entra ID, donde el cliente puede exigir métodos resistentes a phishing |
| **2.5.x Recuperación de credenciales** | No hay códigos de recuperación ni re-enrolamiento de MFA | **Hueco reconocido.** Un admin que pierda el dispositivo queda fuera. Inaceptable en producción |
| **2.5.5 Aviso al cambiar el autenticador** | No se notifica al usuario | Pendiente |

### Desviación deliberada

**El mensaje de cuenta bloqueada revela que la cuenta existe.** ASVS
2.2.1 sugiere respuestas genéricas. Se decidió informar el bloqueo de
forma explícita porque un usuario legítimo bloqueado sin explicación
genera un ticket de soporte y una mala experiencia.

Mitigación: el resto de los mensajes sí son genéricos, y **el tiempo de
respuesta se iguala artificialmente** en el camino de "usuario
inexistente" (`dummy_password_verify`), porque de nada sirve un mensaje
genérico si el atacante distingue las cuentas midiendo el tiempo de
respuesta.

En producción esto se resolvería notificando el bloqueo por correo en vez
de en pantalla.

---

## V3 — Gestión de sesión

| Requisito | Implementación |
|---|---|
| 3.2.1 Token nuevo al autenticar | La sesión se regenera al iniciar sesión (anti session-fixation) |
| 3.2.3 Cookies protegidas | `HttpOnly`, `SameSite=Lax`, `Secure` en producción |
| 3.3.1 Cierre de sesión efectivo | Logout limpia la sesión |
| **3.3.2 Revocación desde el servidor** | Generación de sesión por usuario: incrementarla invalida todas las cookies existentes, aunque su firma siga siendo válida |
| 3.4.1 Protección CSRF | Token por sesión, exigido en todo formulario que cambia estado |
| 3.7.1 Re-autenticación en operaciones sensibles | **No implementado** — no hay step-up auth |

**Nota sobre el modelo de sesión:** la sesión vive firmada en la cookie
del cliente, no en el servidor. Ventaja: no hay estado compartido y
escala horizontalmente. Desventaja: el servidor no puede "borrar" una
sesión. Por eso se añadió el mecanismo de generación — sin él, una cookie
robada sería válida hasta expirar y no habría forma de intervenir.

---

## V4 — Control de acceso

| Requisito | Implementación |
|---|---|
| 4.1.1 Controles aplicados en el servidor | `app/deps.py` revalida en cada petición; el frontend nunca decide |
| 4.1.3 Menor privilegio | Rol admin exige además MFA verificada en la sesión actual |
| 4.1.5 Fallar cerrado | Sin sesión válida → 401; sin rol → 403; ambos registrados |
| 4.2.1 Sin referencias directas inseguras | Las consultas filtran por propietario en SQL; se responde 404 (no 403) para no confirmar la existencia de recursos ajenos |

---

## V5 — Validación, saneamiento y codificación

| Requisito | Estado |
|---|---|
| 5.1.x Validación en frontera | Parcial: se valida el objetivo del escáner; **no hay límites de longitud** en los campos de formulario |
| 5.2.5 Prevención de inyección SQL | Cumple: SQLAlchemy parametriza |
| 5.3.3 Codificación de salida (XSS) | Cumple: autoescape de Jinja2 activo |
| **5.2.6 Protección SSRF** | Cumple, y es el control más relevante de este capítulo (ver abajo) |

**Sobre SSRF:** el escáner recibe un destino del usuario y lo consulta
desde el servidor. Se resuelve el nombre antes de conectar y se rechaza
cualquier dirección interna, privada, loopback o link-local — incluido
`169.254.169.254`, el endpoint de metadata del cloud. Se valida **cada
salto de redirect**, no solo el destino inicial.

**Limitación declarada:** queda expuesto a *DNS rebinding*. Cerrarlo del
todo exige conectar a la IP ya validada fijando `Host` y SNI. No
implementado por alcance.

---

## V7 — Registro y manejo de errores

Es el capítulo mejor cubierto, por ser el núcleo de la propuesta.

| Requisito | Implementación |
|---|---|
| 7.1.1 Sin datos sensibles en los logs | No se registran contraseñas, secretos TOTP ni tokens de sesión |
| 7.1.3 Se registran eventos de seguridad | Login, fallos, bloqueos, MFA, accesos denegados, cambios de configuración, revocaciones |
| 7.2.1 Se registran decisiones de control de acceso | Todo intento bloqueado queda registrado |
| 7.3.1 Protección de los logs | Destino externo (Sentinel) que la app no puede modificar retroactivamente |
| 7.3.3 Sin fugas en mensajes de error | Respuestas genéricas; sin trazas al cliente |
| 7.4.1 Mensajes de error genéricos | Cumple |

**Por encima de lo que pide el estándar:**

- **Correlación:** cada evento arrastra id de sesión y de petición, lo que
  permite reconstruir una cadena de actividad completa.
- **Detección de fallo del propio pipeline:** si un destino de auditoría
  se cae, se emite un evento crítico por los destinos que siguen vivos, y
  hay una regla en Sentinel que lo eleva a incidente. Perder visibilidad
  es un incidente de seguridad, no un problema de operaciones.

---

## V10 — Código malicioso y cadena de suministro

| Requisito | Implementación |
|---|---|
| 10.3.3 Dependencias sin vulnerabilidades conocidas | `pip-audit --strict` en cada push, cada PR y semanalmente |
| 10.2.x Análisis del código propio | `bandit` en el pipeline, con hallazgos triados uno a uno |
| — SBOM | CycloneDX 1.6 generado y archivado en cada compilación (107 componentes) |
| — Análisis de la imagen | Trivy sobre la capa del sistema operativo, corta en HIGH y CRITICAL |
| — Imagen base reproducible | Fijada por digest, no por etiqueta móvil |
| — Contenedor sin privilegios | Verificado automáticamente en el pipeline |

**Los hallazgos detienen la compilación.** No hay `continue-on-error`: un
control que avisa pero no bloquea se convierte en ruido que el equipo
aprende a ignorar en semanas.

**Ejecución programada además de por commit.** Una dependencia limpia hoy
puede tener un CVE publicado mañana sin que nadie toque el código. Sin la
corrida semanal, uno se entera en el próximo commit — que puede ser
dentro de tres meses.

### Lo que encontró la primera corrida

Vale la pena dejarlo escrito, porque es el argumento entero del capítulo:
la primera ejecución de `pip-audit` sobre la aplicación —ya con bcrypt,
MFA, RBAC, protección SSRF y 66 pruebas en verde— reportó **21
vulnerabilidades conocidas en 5 paquetes**. Tres de ellas en el camino
crítico: la librería que parsea el formulario de login, el núcleo del
framework que maneja las sesiones, y el motor de plantillas.

No se había escrito una sola línea de código vulnerable. Se heredaron.

Actualizar exigió saltar `starlette` de 0.38 a 1.6 —un cambio de versión
mayor— que rompió diecisiete llamadas que usaban una firma deprecada. Esa
firma llevaba meses emitiendo advertencias que se habían postergado por
ser "solo warnings". La lección quedó registrada acá porque es
generalizable: **una advertencia de deprecación es una rotura agendada, y
postergarla significa que los parches de seguridad se traban justo cuando
hacen falta.**

**Pendiente declarado:** falta fijar los artefactos por hash
(`--require-hashes`). Las versiones están fijadas, lo que evita cambios
accidentales, pero una versión puede volver a publicarse con contenido
distinto; solo el hash es inmutable.

---

## V13 — API y servicios web

| Requisito | Implementación |
|---|---|
| 13.1.3 Sin exposición de la estructura de la API | `/docs`, `/redoc` y `/openapi.json` se apagan en producción |
| 13.1.4 Autorización aplicada en la API | Alcances por credencial, verificados en cada petición |
| 13.2.1 Métodos HTTP acordes | Escrituras solo por POST |
| 13.2.3 Protección contra CSRF en APIs | No aplica: la credencial va en cabecera, no en cookie. Exigir CSRF acá sería teatro |
| 13.2.5 Validación del esquema de entrada | Pydantic con límites de longitud explícitos |
| 13.4.1 Sin fuga de información en errores | Mensaje idéntico para credencial inexistente, revocada o con alcance insuficiente |
| — Autenticación de máquina | Claves de alta entropía, hasheadas con SHA-256 y comparadas en tiempo constante |
| — Idempotencia | Cabecera `Idempotency-Key`; reusar la clave con otro cuerpo devuelve 409 |
| — Webhooks entrantes | Firma HMAC-SHA256 sobre marca de tiempo + cuerpo, con ventana de tolerancia contra reenvío |
| — Egreso controlado | Lista blanca de destinos, reintentos con backoff y jitter, circuit breaker, redacción de secretos |

**Sobre el hash de las claves de API:** se usa SHA-256, no bcrypt. No es
un atajo. bcrypt es lento a propósito para defender secretos de baja
entropía (contraseñas humanas); una clave generada con 256 bits de
aleatoriedad no es vulnerable a fuerza bruta ni a diccionario, así que la
lentitud no compra seguridad y sí cuesta ~250 ms en cada llamada de una
integración de alto volumen. Para secretos de alta entropía, el hash
rápido comparado en tiempo constante es la recomendación correcta.

**Pendiente declarado:** el límite por credencial es en memoria del
proceso. Con varias réplicas necesita un backend compartido.

## V14 — Configuración

| Requisito | Estado |
|---|---|
| 14.1.1 Compilación y despliegue automatizados | **Parcial:** hay scripts de despliegue, no hay pipeline de CI |
| **14.2.1 Componentes actualizados** | **No cubierto** (ver V10) |
| 14.4.1 Cabeceras de seguridad HTTP | Cumple: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, HSTS en producción |
| 14.4.3 Content-Security-Policy | Cumple: sin `unsafe-inline`; todo el CSS y el JS son propios |
| **14.2.6 Contenedor sin privilegios** | Cumple: corre como usuario sin privilegios (`USER appuser`) |

---

## Los diez pendientes, priorizados

Orden por relación entre riesgo y esfuerzo:

| # | Pendiente | Capítulo | Esfuerzo |
|---|---|---|---|
| 1 | Códigos de recuperación de MFA | V2 | Bajo |
| 2 | Fijar artefactos por hash (`--require-hashes`) | V10 | Bajo |
| 3 | Límites de tamaño de petición | V5 | Bajo |
| 4 | Verificación contra contraseñas filtradas | V2 | Bajo |
| 5 | Migraciones versionadas (Alembic) | V1 | Medio |
| 6 | Rate limiting distribuido | V2 | Medio |
| 7 | Secretos en Key Vault, no de plataforma | V6 | Medio |
| 8 | Re-autenticación en operaciones sensibles | V3 | Medio |
| 9 | MFA resistente a phishing (WebAuthn / Entra ID) | V2 | Alto |

---

## Conclusión

La aplicación cubre razonablemente **autenticación, sesión, control de
acceso y —sobre todo— registro**, que es el núcleo de lo que el baseline
propone.

La cadena de suministro (V10), que en la primera versión de este documento
era el hueco más grande, hoy está cubierta con controles que bloquean la
compilación —y su primera ejecución encontró 21 vulnerabilidades heredadas
que ya fueron corregidas.

El hueco más visible que queda es la **falta de recuperación de MFA**
(V2.5): un administrador que pierda su dispositivo queda fuera sin
proceso de rescate. Después, la **resistencia a phishing** del segundo
factor, que es el argumento técnico para delegar identidad a Entra ID.

Ninguno de los dos es difícil de cerrar. Están declarados acá, y no
descubiertos por otro, que es exactamente la diferencia que este
documento busca establecer.
