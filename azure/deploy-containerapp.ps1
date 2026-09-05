# =====================================================================
# Despliegue en Azure Container Apps desde una imagen ya construida.
#
# POR QUE ESTE CAMINO:
# esta suscripcion bloquea ACR Tasks (construir imagenes en la nube) y
# tiene cuota cero de App Service en todas las regiones. Container Apps
# si funciona porque usa un modelo de consumo que no toca esa cuota.
# La imagen la construye GitHub Actions y se descarga desde ghcr.io.
#
# Efecto secundario positivo: el pipeline de seguridad corre de verdad en
# cada cambio, y la imagen solo se publica si paso los controles. El
# despliegue consume exactamente el artefacto que la puerta dejo salir.
#
# Requiere:
#   - deploy-observability.ps1 ya ejecutado
#   - la imagen publicada y PUBLICA en ghcr.io
#
# Uso:
#   .\azure\deploy-containerapp.ps1
#   .\azure\deploy-containerapp.ps1 -Imagen ghcr.io/otro/repo:latest
# =====================================================================

param(
    [string]$ResourceGroup = "secops-demo-rg",
    [string]$EnvName       = "secops-env",
    [string]$AppName       = "secops-webapp",
    [string]$Imagen        = "ghcr.io/yoyobytes/secops-baseline:latest"
)

$ErrorActionPreference = "Stop"

function Write-Paso($mensaje) {
    Write-Host ""
    Write-Host "==> $mensaje" -ForegroundColor Cyan
}

# PowerShell 5.1 convierte CUALQUIER escritura en la salida de error de un
# programa externo en un error fatal cuando ErrorActionPreference es Stop,
# incluso si se redirige. Eso rompe las comprobaciones del tipo "existe
# este recurso?", donde el propio "no existe" llega por esa via y es una
# respuesta valida, no un fallo.
#
# Este ayudante aisla esas llamadas: devuelve la salida si el comando tuvo
# exito, o $null si no, sin abortar el script.
function Invoke-AzConsulta {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Argumentos)
    $previo = $ErrorActionPreference
    $ErrorActionPreference = "SilentlyContinue"
    try {
        $salida = & az @Argumentos 2>$null
        if ($LASTEXITCODE -eq 0 -and $salida) { return ($salida | Out-String).Trim() }
        return $null
    } finally {
        $ErrorActionPreference = $previo
    }
}

$raiz = Split-Path $PSScriptRoot -Parent

# --- Comprobaciones previas -----------------------------------------
$cuenta = az account show 2>$null | ConvertFrom-Json
if (-not $cuenta) {
    Write-Host "No hay sesion de Azure. Ejecuta 'az login' primero." -ForegroundColor Red
    exit 1
}

$rutaEnvAzure = Join-Path $raiz ".env.azure"
if (-not (Test-Path $rutaEnvAzure)) {
    Write-Host "Falta .env.azure. Corre primero deploy-observability.ps1" -ForegroundColor Red
    exit 1
}

$cfg = @{}
foreach ($linea in Get-Content $rutaEnvAzure) {
    $l = $linea.Trim()
    if ($l -and -not $l.StartsWith("#") -and $l.Contains("=")) {
        $partes = $l.Split("=", 2)
        $cfg[$partes[0].Trim()] = $partes[1].Trim()
    }
}

Write-Host "Imagen: $Imagen"

# --- Extensiones ------------------------------------------------------
# Algunos comandos de az viven en extensiones que no vienen instaladas y,
# la primera vez, az PREGUNTA si instalarlas. Esa pregunta se pierde
# cuando la salida esta silenciada, y el script queda esperando en
# silencio una respuesta que nadie ve. Se instalan por adelantado.
Write-Paso "Preparando extensiones de az"
az config set extension.use_dynamic_install=yes_without_prompt --only-show-errors 2>$null | Out-Null
$yaEsta = Invoke-AzConsulta extension show --name monitor-control-service --query name --output tsv
if (-not $yaEsta) {
    Write-Host "  instalando monitor-control-service (una sola vez)..."
    az extension add --name monitor-control-service --only-show-errors 2>$null | Out-Null
}
Write-Host "  listo"

# --- Secretos --------------------------------------------------------
# Alfabeto alfanumerico: estos valores viajan como argumentos hacia `az`,
# y caracteres como & $ " % los rompen o los truncan en silencio.
function New-Secreto {
    param([int]$Largo)
    $alfabeto = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $bytes = New-Object byte[] $Largo
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    -join ($bytes | ForEach-Object { $alfabeto[$_ % $alfabeto.Length] })
}

Write-Paso "Generando secretos"
$sessionSecret = New-Secreto -Largo 48
$adminPassword = New-Secreto -Largo 24
$userPassword  = New-Secreto -Largo 24

# --- Entorno ---------------------------------------------------------
$envExiste = Invoke-AzConsulta containerapp env show --name $EnvName --resource-group $ResourceGroup --query name --output tsv
if (-not $envExiste) {
    Write-Paso "Creando entorno de Container Apps"
    az containerapp env create --name $EnvName --resource-group $ResourceGroup --output none
    if (-not $?) { Write-Host "Fallo la creacion del entorno" -ForegroundColor Red; exit 1 }
} else {
    Write-Paso "Entorno '$EnvName' ya existe, se reutiliza"
}

# --- Crear o actualizar la aplicacion --------------------------------
# ENVIRONMENT=production activa la validacion que se NIEGA a arrancar con
# secretos por defecto o sin HTTPS. Que la app se caiga si alguien
# despliega mal configurado es intencional.
#
# --min-replicas 1 evita que se duerma: por defecto Container Apps escala
# a cero y la primera visita despues de un rato tarda. Para una demo en
# vivo, esa espera es inaceptable.
$appExiste = Invoke-AzConsulta containerapp show --name $AppName --resource-group $ResourceGroup --query name --output tsv

if ($appExiste) {
    Write-Paso "La aplicacion ya existe: actualizando imagen"
    az containerapp update `
        --name $AppName `
        --resource-group $ResourceGroup `
        --image $Imagen `
        --output none
} else {
    Write-Paso "Creando la aplicacion (puede tardar 2-3 min)"
    az containerapp create `
        --name $AppName `
        --resource-group $ResourceGroup `
        --environment $EnvName `
        --image $Imagen `
        --target-port 8000 `
        --ingress external `
        --min-replicas 1 `
        --max-replicas 1 `
        --cpu 0.5 --memory 1.0Gi `
        --output none
}
if (-not $?) { Write-Host "Fallo el despliegue de la aplicacion" -ForegroundColor Red; exit 1 }

# --- Identidad administrada -----------------------------------------
Write-Paso "Asignando identidad administrada"
$principalId = az containerapp identity assign `
    --name $AppName `
    --resource-group $ResourceGroup `
    --system-assigned `
    --query principalId `
    --output tsv
Write-Host "  principal: $principalId"

Write-Paso "Concediendo permiso de ingesta hacia Sentinel"
$dcrId = Invoke-AzConsulta monitor data-collection rule show `
    --name "secops-dcr" --resource-group $ResourceGroup --query id --output tsv

if (-not $dcrId) {
    Write-Host "  No se encontro la regla 'secops-dcr'." -ForegroundColor Red
    Write-Host "  Corre primero .\azure\deploy-observability.ps1"
    exit 1
}

# Permiso minimo, acotado a la regla de ingesta y no a la suscripcion.
#
# Se REINTENTA porque la identidad se acaba de crear y Azure AD tarda en
# propagarla: los primeros intentos fallan con "principal does not exist"
# aunque todo este bien.
#
# Y al final se VERIFICA consultando la asignacion, en vez de confiar en
# que el comando parecio funcionar. La primera version de este script se
# tragaba el error y anunciaba exito sobre un permiso inexistente: la app
# quedaba sin poder enviar telemetria y el operador creyendo que si.
# Anunciar un exito que no ocurrio es peor que fallar ruidosamente.
$concedido = $false
foreach ($intento in 1..6) {
    $salida = & az role assignment create `
        --assignee-object-id $principalId `
        --assignee-principal-type ServicePrincipal `
        --role "Monitoring Metrics Publisher" `
        --scope $dcrId `
        --output tsv 2>&1

    $existentes = Invoke-AzConsulta role assignment list `
        --assignee $principalId --scope $dcrId --query "[].roleDefinitionName" --output tsv

    if ($existentes -match "Monitoring Metrics Publisher") {
        $concedido = $true
        Write-Host "  concedido y verificado"
        break
    }

    Write-Host "  intento $intento sin exito, reintentando en 10s..."
    if ($intento -eq 1) { Write-Host "    detalle: $($salida | Select-Object -First 1)" }
    Start-Sleep -Seconds 10
}

if (-not $concedido) {
    Write-Host ""
    Write-Host "NO se pudo conceder el permiso de ingesta." -ForegroundColor Red
    Write-Host "La aplicacion va a funcionar pero SIN enviar telemetria a Sentinel."
    Write-Host "Concedelo a mano y reinicia la aplicacion:"
    Write-Host "  az role assignment create --assignee-object-id $principalId ``"
    Write-Host "    --assignee-principal-type ServicePrincipal ``"
    Write-Host "    --role 'Monitoring Metrics Publisher' --scope $dcrId"
}

# --- Configuracion ---------------------------------------------------
Write-Paso "Cargando secretos y variables de entorno"

az containerapp secret set `
    --name $AppName `
    --resource-group $ResourceGroup `
    --secrets "session-secret=$sessionSecret" "admin-password=$adminPassword" "user-password=$userPassword" `
    --output none

az containerapp update `
    --name $AppName `
    --resource-group $ResourceGroup `
    --set-env-vars `
        "SESSION_SECRET=secretref:session-secret" `
        "SEED_ADMIN_PASSWORD=secretref:admin-password" `
        "SEED_USER_PASSWORD=secretref:user-password" `
        "ENVIRONMENT=production" `
        "COOKIE_SECURE=true" `
        "DATABASE_URL=sqlite:////srv/data/secops.db" `
        "LOG_FILE=/srv/logs/audit.log" `
        "AZURE_LOGS_ENABLED=true" `
        "AZURE_LOGS_ENDPOINT=$($cfg['AZURE_LOGS_ENDPOINT'])" `
        "AZURE_LOGS_RULE_ID=$($cfg['AZURE_LOGS_RULE_ID'])" `
        "AZURE_LOGS_STREAM=$($cfg['AZURE_LOGS_STREAM'])" `
    --output none

# --- Reinicio obligatorio -------------------------------------------
# La identidad administrada pide su token de acceso al ARRANCAR, y ese
# token lleva grabados los permisos vigentes en ese instante. Vale unas
# 24 horas. Conceder un rol despues NO modifica un token ya emitido: la
# aplicacion sigue rechazada hasta que pide uno nuevo.
#
# Por eso el reinicio no es una precaucion, es obligatorio siempre que se
# haya tocado un permiso. Sin el, la telemetria falla en silencio durante
# un dia entero y todo lo demas parece funcionar perfectamente.
Write-Paso "Reiniciando para que tome un token con los permisos nuevos"
$revision = Invoke-AzConsulta containerapp revision list `
    --name $AppName --resource-group $ResourceGroup --query "[-1].name" --output tsv

if ($revision) {
    az containerapp revision restart `
        --name $AppName --resource-group $ResourceGroup --revision $revision --output none
    Write-Host "  reiniciada: $revision"
    Write-Host "  tarda ~30s en volver a responder"
} else {
    Write-Host "  No se pudo identificar la revision; reinicia a mano:" -ForegroundColor Yellow
    Write-Host "    az containerapp revision restart --name $AppName --resource-group $ResourceGroup --revision <nombre>"
}

$url = az containerapp show `
    --name $AppName `
    --resource-group $ResourceGroup `
    --query properties.configuration.ingress.fqdn `
    --output tsv

# --- Resumen ---------------------------------------------------------
Write-Host ""
Write-Host "==================== LISTO ====================" -ForegroundColor Green
Write-Host ""
Write-Host "URL de la demo:  https://$url" -ForegroundColor White
Write-Host ""
Write-Host "CREDENCIALES (guardalas ahora, no se vuelven a mostrar):" -ForegroundColor Yellow
Write-Host "  admin   / $adminPassword"
Write-Host "  usuario / $userPassword"
Write-Host ""
Write-Host "El almacenamiento del contenedor es efimero: si se reinicia, la"
Write-Host "base se recrea con estas mismas credenciales. El historial local"
Write-Host "se pierde, pero la pista de auditoria NO: vive en Sentinel, que"
Write-Host "es precisamente donde debe estar."
Write-Host ""
Write-Host "Si algo falla, ver los registros en vivo:"
Write-Host "  az containerapp logs show --name $AppName --resource-group $ResourceGroup --follow" -ForegroundColor White
Write-Host ""
Write-Host "Para borrar TODO al terminar:"
Write-Host "  az group delete --name $ResourceGroup --yes" -ForegroundColor White
