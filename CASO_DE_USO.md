# Caso de uso: un baseline de seguridad para las automatizaciones que entregamos

---

## 1. El problema

La consultoría entrega automatizaciones con backend en Python: soluciones
completas donde el cliente entra, hace clic y la herramienta funciona.

Cada una de esas entregas es, también, **una superficie de ataque nueva
instalada dentro del cliente**. Y hoy la seguridad de cada una depende de
quién la haya construido y de cuánto tiempo tuvo esa semana.

Eso genera tres problemas concretos:

1. **Inconsistencia.** Dos automatizaciones entregadas el mismo mes pueden
   tener criterios de autenticación distintos, o registro de actividad
   distinto, o ninguno.
2. **Ceguera operativa.** Si un cliente pregunta "¿quién usó esta
   herramienta el martes y qué hizo?", muchas veces la respuesta honesta
   es que no se puede saber.
3. **Fricción comercial.** Cuando el área de seguridad del cliente revisa
   la herramienta antes de aprobarla, cada proyecto negocia esa revisión
   desde cero.

## 2. La propuesta

Un **baseline de seguridad**: un conjunto de componentes y decisiones ya
tomadas que toda automatización hereda, en vez de resolverse proyecto por
proyecto.

No es un producto nuevo que el cliente tenga que comprar ni adoptar. Es
una capa que se aplica del lado nuestro y que **alimenta las herramientas
de seguridad que el cliente ya tiene y ya paga**.

Ese es el punto central de la propuesta, y conviene decirlo explícito:

> No le vendemos al cliente una consola más para mirar.
> Hacemos que nuestras entregas aparezcan en la consola que ya mira.

Para clientes de stack Microsoft, eso significa Microsoft Sentinel,
Defender y Entra ID.

## 3. Las capas del baseline

| Capa | Qué resuelve | En el stack del cliente |
|---|---|---|
| **Identidad** | Quién puede usar la herramienta | Entra ID (SSO). MFA, conditional access y bajas de personal quedan centralizados donde el cliente ya los gestiona. |
| **Autorización** | Qué puede hacer cada quien | Roles validados en el servidor en cada petición. |
| **Integraciones** | Cómo se conecta con los sistemas del cliente | Credenciales de máquina con alcances, webhooks firmados, control de egreso e idempotencia. |
| **Telemetría** | Qué pasó, quién lo hizo, cuándo | Eventos estructurados hacia Log Analytics, con detecciones en Sentinel. |
| **Secretos** | Credenciales fuera del código | Azure Key Vault + Managed Identity: la aplicación no guarda credenciales. |
| **Cadena de suministro** | Que no entre lo que no queremos | Escaneo de dependencias e imagen, con corte en el pipeline. |
| **Borde** | Abuso y exposición | Rate limiting, cabeceras de seguridad, WAF cuando aplica. |

## 4. La demostración

Se construyó una automatización real y completa para mostrar el baseline
aplicado: un escáner pasivo de postura de seguridad web. El usuario
escribe un dominio y la herramienta audita sus cabeceras HTTP, su
certificado TLS y sus registros SPF/DMARC.

**La automatización en sí es lo de menos: es el vehículo.** Podría ser
cualquier otra de las que entregamos. Lo que se demuestra es la capa que
la envuelve.

### Lo que se muestra, en orden

1. **Un usuario normal intenta entrar al panel de administración.**
   El servidor responde 403. No es que el botón esté escondido: el
   permiso se revalida en cada petición.

2. **Un administrador inicia sesión con contraseña correcta.**
   No entra. Le falta el segundo factor. La sesión no existe como sesión
   autenticada hasta que pasa MFA.

3. **Se falla el login varias veces a propósito.**
   La cuenta se bloquea sola.

4. **Se abre Microsoft Sentinel.**
   Los eventos ya están ahí. Y hay una alerta disparada por una regla de
   detección que vive en el repositorio como código, no creada a mano.

5. **Se toma el identificador de correlación de esa sesión.**
   Una sola consulta reconstruye toda la cadena: qué intentó, en qué
   orden, desde qué IP. Eso es la diferencia entre tener logs y tener
   algo con lo que un analista puede trabajar.

El punto 4 es el que cierra el argumento: **la telemetría de nuestra
entrega terminó dentro de la herramienta que el cliente ya usa**, sin que
el cliente tenga que aprender nada nuevo.

## 4-bis. La capa de integraciones

Si el trabajo consiste en automatizar procesos, casi siempre consiste en
**conectar sistemas**: leer de uno, transformar, escribir en otro. Ahí es
donde vive la mayor parte del riesgo, y donde se concentran los errores
más caros. El baseline cubre las dos direcciones.

### Hacia adentro — otro sistema llama a nuestra automatización

- **Credenciales de máquina, no de persona.** Un servicio no escanea un
  QR ni recuerda una contraseña: se autentica con una clave de alta
  entropía, guardada hasheada. Si la base se filtra, no se reconstruye.
- **Alcances de mínimo privilegio.** El conector que dispara procesos no
  puede leer el audit trail. Se concede lo que hace falta y nada más.
- **Límite por credencial.** Una integración descontrolada no consume la
  cuota de las demás ni tumba el servicio para todos.
- **Webhooks firmados.** Un endpoint público que ejecuta lógica sin
  verificar quién lo llama es una invitación. Se valida firma HMAC sobre
  el cuerpo, más una marca de tiempo *incluida en lo firmado*, con
  ventana de tolerancia — porque una firma, por sí sola, no caduca nunca
  y puede reenviarse meses después.
- **Idempotencia.** Si el sistema del cliente reintenta porque se le cayó
  la red, la operación no se ejecuta dos veces. En un escaneo eso sería
  ruido; en un asiento contable o un pago, es un incidente.
- **Trazabilidad del actor-máquina.** El audit trail distingue
  `machine:Conector SAP` de una persona. En una investigación importa
  mucho la diferencia entre "lo hizo Ana" y "lo hizo el conector con la
  credencial de Ana".

### Hacia afuera — nuestra automatización llama a los sistemas del cliente

- **Control de egreso.** Un conector solo alcanza destinos permitidos. La
  URL de un webhook es, al final, entrada de usuario que se convierte en
  destino de red: sin control, quien pueda editarla hace que la
  aplicación hable con cualquier servidor, incluida la red interna.
- **Reintentos con backoff y jitter.** El jitter evita que, tras una
  caída, todas las instancias reintenten a la vez y rematen al sistema
  que se está recuperando.
- **Circuit breaker.** Un destino caído deja de intentarse por un rato.
  Sin esto, la lentitud del tercero se convierte en lentitud propia.
- **Redacción de secretos.** Los errores nunca registran la query string
  ni las credenciales embebidas en una URL. Un token que termina en el
  SIEM es un token filtrado, aunque el SIEM sea de confianza.
- **Identidad gestionada.** Hacia Azure, la aplicación no guarda ninguna
  credencial: usa Managed Identity.

## 5. Decisiones que vale la pena defender

**Por qué los logs van a dos lugares a la vez.** Cada evento se escribe
en un archivo JSON-lines y en la base de datos, antes de intentar
enviarse al SIEM. Si el SIEM está caído, la evidencia existe igual. Si la
base de datos se corrompe, el archivo sigue. La evidencia también merece
defensa en profundidad.

**Por qué el envío al SIEM es asíncrono.** `log_event()` se llama en el
camino crítico del login. Si el envío fuera sincrónico, una lentitud de
Azure se convertiría en una lentitud del login del cliente. La auditoría
nunca debe agregar latencia ni modos de fallo al proceso que audita.

**Por qué un fallo de auditoría es una alerta de severidad alta.** Si un
destino de logs deja de funcionar, el sistema lo detecta y lo reporta por
los destinos que siguen vivos. Perder capacidad de auditar es un
incidente de seguridad, no un problema de operaciones: un atacante
competente no genera alertas, las silencia.

**Por qué en producción NO implementaríamos el login nosotros.** La demo
tiene autenticación propia con contraseñas y TOTP, y sirve para mostrar
que entendemos las primitivas. Precisamente por entenderlas, en un
cliente con Entra ID la recomendación es delegar: menos código propio en
el camino de la autenticación, y la gestión del ciclo de vida de las
cuentas donde el cliente ya la tiene resuelta.

**Por qué el escáner bloquea direcciones internas.** Al publicar la
herramienta, una función inofensiva se convirtió en un vector: cualquiera
podía pedirle al servidor que consultara direcciones internas de la red
del proveedor, incluido el endpoint de metadata que expone credenciales
de la instancia. Se acotó antes de exponerla. Es un buen ejemplo de que
el riesgo no vive en la función, vive en el contexto donde se despliega.

## 6. Plan de adopción

**Fase 1 — Estandarizar.** Empaquetar el baseline como dependencia
interna. Una automatización nueva lo incorpora en horas, no en semanas.

**Fase 2 — Instrumentar lo existente.** Las entregas ya en producción
reciben primero la capa de telemetría, que es la de mayor retorno y la
menos invasiva: no cambia el comportamiento de la aplicación.

**Fase 3 — Integrar por cliente.** Conectar la telemetría al tenant de
cada cliente y desplegar las detecciones. Las reglas viven en un
repositorio y se revisan como código.

**Fase 4 — Medir.** Cobertura sobre el total de entregas, tiempo hasta
detectar, y cuántas revisiones de seguridad del cliente se aprueban sin
observaciones.

## 7. Qué queda fuera del alcance de esta demo

Se dice explícito para no vender más de lo que hay:

- La autenticación con Entra ID está diseñada como punto de integración,
  pero la demo usa autenticación local.
- No hay códigos de recuperación de MFA ni proceso de re-enrolamiento.
- El almacenamiento es SQLite, adecuado para una demo y no para
  producción.
- El rate limiting es por proceso; con varias réplicas necesita un
  backend compartido.
- Defender for Cloud y el escaneo de la cadena de suministro están
  planteados en el diseño, no implementados.
