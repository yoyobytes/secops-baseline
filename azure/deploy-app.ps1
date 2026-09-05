# =====================================================================
# PASO 2 - Despliega la aplicación en Azure Container Apps.
#
# La imagen se construye EN LA NUBE (az containerapp up --source), así
# que no hace falta Docker instalado en la máquina.
#
# Al terminar, la app corre con Managed Identity: no hay ninguna
# credencial de Azure guardada en la aplicación ni en variables de
# entorno. La identidad se la asigna la plataforma y se le concede
# permiso solo sobre la regla de ingesta, nada más.
#
# Requiere haber corrido antes deploy-observability.ps1.
#
# Uso:
#   .\azure\deploy-app.ps1
# =====================================================================

param(
    [string]$ResourceGroup = "secops-demo-rg",
    [string]$Location      = "eastus",
    [string]$AppName       = "secops-webapp",
    [string]$EnvName       = "secops-env"
)

$ErrorActionPreference = "Stop"

function Write-Paso($mensaje) {
    Write-Host ""
    Write-Host "==> $mensaje" -ForegroundColor Cyan
}

$raiz = Split-Path $PSScriptRoot -Parent

# --- Leer la configuracion de observabilidad ------------------------
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

Write-Host "Endpoint de ingesta: $($cfg['AZURE_LOGS_ENDPOINT'])"

# --- Generar secretos ------------------------------------------------
# Se generan aca y se guardan como secretos de Container Apps. Nunca se
# escriben en el repositorio ni quedan en el historial de la terminal.
#
# Alfabeto alfanumerico a proposito: estos valores viajan como argumentos
# de linea de comandos hacia `az`, y caracteres como & $ " % los rompen o,
# peor, los truncan en silencio dejando una credencial distinta de la que
# se muestra en pantalla. La entropia se compensa con la longitud: 24
# caracteres sobre un alfabeto de 62 son ~143 bits, de sobra.
function New-Secreto {
    param([int]$Largo)
    $alfabeto = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    $bytes = New-Object byte[] $Largo
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    -join ($bytes | ForEach-Object { $alfabeto[$_ % $alfabeto.Length] })
}

Write-Paso "Generando secretos de sesion"
$sessionSecret = New-Secreto -Largo 48
$adminPassword = New-Secreto -Largo 24
$userPassword  = New-Secreto -Largo 24

# --- Registro de proveedores ----------------------------------------
# Mismo motivo que en deploy-observability.ps1: en una suscripcion nueva
# estos servicios vienen deshabilitados.
Write-Paso "Habilitando servicios de contenedores en la suscripcion"
foreach ($p in @("Microsoft.App", "Microsoft.ContainerRegistry", "Microsoft.OperationalInsights")) {
    $estado = az provider show --namespace $p --query registrationState --output tsv 2>$null
    if ($estado -eq "Registered") {
        Write-Host "  $p : ya habilitado"
    } else {
        Write-Host "  $p : habilitando..."
        az provider register --namespace $p --wait --output none
    }
}

# --- Entorno de Container Apps --------------------------------------
# Se comprueba antes de crear: el script tiene que poder reintentarse sin
# fallar por lo que ya existe. Un despliegue que solo funciona la primera
# vez es un despliegue que no sirve cuando algo sale mal a mitad.
$envExiste = az containerapp env show --name $EnvName --resource-group $ResourceGroup --query name --output tsv 2>$null
if ($envExiste) {
    Write-Paso "El entorno '$EnvName' ya existe, se reutiliza"
} else {
    Write-Paso "Creando entorno de Container Apps (puede tardar ~3 min)"
    az containerapp env create `
        --name $EnvName `
        --resource-group $ResourceGroup `
        --location $Location `
        --output none
    if (-not $?) { Write-Host "Fallo la creacion del entorno" -ForegroundColor Red; exit 1 }
}

# --- Desplegar la aplicacion ----------------------------------------
Write-Paso "Construyendo la imagen en la nube y desplegando"
Write-Host "(la primera vez tarda 5-8 minutos)"

Push-Location $raiz
try {
    # Sin --output: `containerapp up` no lo admite, y ademas su salida
    # muestra el progreso de la compilacion remota, que conviene ver.
    az containerapp up `
        --name $AppName `
        --resource-group $ResourceGroup `
        --environment $EnvName `
        --source . `
        --target-port 8000 `
        --ingress external
    if (-not $?) { throw "Fallo el despliegue de la aplicacion" }
}
finally {
    Pop-Location
}

# --- Managed Identity ------------------------------------------------
Write-Paso "Asignando identidad administrada a la aplicacion"
$principalId = az containerapp identity assign `
    --name $AppName `
    --resource-group $ResourceGroup `
    --system-assigned `
    --query principalId `
    --output tsv

Write-Host "Principal ID: $principalId"

# Permiso minimo: solo publicar en la regla de ingesta.
Write-Paso "Concediendo permiso de ingesta a la identidad de la app"
$dcrId = az monitor data-collection rule show `
    --name "secops-dcr" `
    --resource-group $ResourceGroup `
    --query id `
    --output tsv

az role assignment create `
    --assignee-object-id $principalId `
    --assignee-principal-type ServicePrincipal `
    --role "Monitoring Metrics Publisher" `
    --scope $dcrId `
    --output none 2>$null

# --- Configuracion de la aplicacion ---------------------------------
Write-Paso "Configurando secretos y variables de entorno"

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
        "COOKIE_SECURE=true" `
        "AZURE_LOGS_ENABLED=true" `
        "AZURE_LOGS_ENDPOINT=$($cfg['AZURE_LOGS_ENDPOINT'])" `
        "AZURE_LOGS_RULE_ID=$($cfg['AZURE_LOGS_RULE_ID'])" `
        "AZURE_LOGS_STREAM=$($cfg['AZURE_LOGS_STREAM'])" `
        "DATABASE_URL=sqlite:////srv/data/secops.db" `
        "LOG_FILE=/srv/logs/audit.log" `
    --output none

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
Write-Host "COOKIE_SECURE quedo en true: las cookies solo viajan por HTTPS."
Write-Host ""
Write-Host "Nota: el almacenamiento del contenedor es efimero. Si se"
Write-Host "reinicia, la base se recrea y las cuentas semilla vuelven a"
Write-Host "generarse con estas mismas contrasenas."
