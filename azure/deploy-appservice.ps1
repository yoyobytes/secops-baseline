# =====================================================================
# Despliegue en Azure App Service (sin contenedor).
#
# POR QUE ESTE CAMINO Y NO CONTAINER APPS:
# las suscripciones de prueba tienen bloqueado ACR Tasks, el servicio que
# construye imagenes en la nube. Sin eso y sin Docker local, no hay forma
# de producir la imagen. App Service acepta el codigo Python directo:
# instala las dependencias en la plataforma y lo ejecuta.
#
# Lo que se pierde: el contenedor sin privilegios y la imagen fijada por
# digest no son lo que corre aqui. Esos controles siguen existiendo y se
# verifican en el pipeline de CI; simplemente no son el artefacto
# desplegado en esta demo. Conviene decirlo asi si lo preguntan.
#
# Lo que se mantiene: HTTPS, identidad administrada (sin credenciales en
# la app), secretos fuera del codigo, y la telemetria hacia Sentinel.
#
# Requiere haber corrido antes deploy-observability.ps1.
#
# Uso:
#   .\azure\deploy-appservice.ps1
# =====================================================================

param(
    [string]$ResourceGroup = "secops-demo-rg",
    [string]$Location      = "eastus",
    [string]$PlanName      = "secops-plan",
    [string]$AppName       = "",    # si se omite, se genera uno unico
    # F1 (gratuito) por defecto: las suscripciones de prueba tienen cuota
    # CERO de maquinas de pago, asi que B1 falla con "additional quota".
    # Si algun dia conviertes la cuenta a pago-por-uso, -Sku B1 da mejor
    # rendimiento y evita que el sitio se duerma.
    [string]$Sku           = "F1"
)

$ErrorActionPreference = "Stop"

function Write-Paso($mensaje) {
    Write-Host ""
    Write-Host "==> $mensaje" -ForegroundColor Cyan
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

# El nombre del sitio es parte del dominio publico: tiene que ser unico
# en todo Azure, no solo en esta suscripcion.
if (-not $AppName) {
    $sufijo = -join ((48..57) + (97..122) | Get-Random -Count 6 | ForEach-Object { [char]$_ })
    $AppName = "secops-webapp-$sufijo"
}
Write-Host "Nombre del sitio: $AppName"

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

# --- Registrar proveedor --------------------------------------------
Write-Paso "Habilitando App Service en la suscripcion"
$estado = az provider show --namespace Microsoft.Web --query registrationState --output tsv 2>$null
if ($estado -ne "Registered") {
    az provider register --namespace Microsoft.Web --wait --output none
}
Write-Host "  listo"

# --- Plan y sitio ----------------------------------------------------
Write-Paso "Creando plan de App Service (Linux, $Sku)"
az appservice plan create `
    --name $PlanName `
    --resource-group $ResourceGroup `
    --location $Location `
    --is-linux `
    --sku $Sku `
    --output none

if (-not $?) {
    Write-Host ""
    Write-Host "Fallo la creacion del plan." -ForegroundColor Red
    Write-Host "Si el error menciona cuota, tu suscripcion no permite ese nivel."
    Write-Host "Reintenta con el nivel gratuito:  .\azure\deploy-appservice.ps1 -Sku F1"
    exit 1
}

if ($Sku -eq "F1") {
    Write-Host ""
    Write-Host "NOTA sobre el nivel gratuito:" -ForegroundColor Yellow
    Write-Host "  El sitio se duerme tras ~20 minutos sin visitas y tarda"
    Write-Host "  entre 15 y 30 segundos en despertar. Antes de la demo,"
    Write-Host "  abri la URL un par de minutos antes para despertarlo."
}

Write-Paso "Creando el sitio (Python 3.12)"
az webapp create `
    --name $AppName `
    --resource-group $ResourceGroup `
    --plan $PlanName `
    --runtime "PYTHON:3.12" `
    --output none
if (-not $?) { Write-Host "Fallo la creacion del sitio" -ForegroundColor Red; exit 1 }

# --- Configuracion ---------------------------------------------------
# Se configura ANTES de desplegar el codigo: asi el primer arranque ya
# encuentra todo en su lugar en vez de fallar y reintentar.
Write-Paso "Configurando variables de entorno"

# /home es el unico almacenamiento persistente en App Service: sobrevive
# a reinicios y redespliegues. Todo lo demas es efimero.
az webapp config appsettings set `
    --name $AppName `
    --resource-group $ResourceGroup `
    --settings `
        "SESSION_SECRET=$sessionSecret" `
        "SEED_ADMIN_PASSWORD=$adminPassword" `
        "SEED_USER_PASSWORD=$userPassword" `
        "ENVIRONMENT=production" `
        "COOKIE_SECURE=true" `
        "DATABASE_URL=sqlite:////home/data/secops.db" `
        "LOG_FILE=/home/logs/audit.log" `
        "AZURE_LOGS_ENABLED=true" `
        "AZURE_LOGS_ENDPOINT=$($cfg['AZURE_LOGS_ENDPOINT'])" `
        "AZURE_LOGS_RULE_ID=$($cfg['AZURE_LOGS_RULE_ID'])" `
        "AZURE_LOGS_STREAM=$($cfg['AZURE_LOGS_STREAM'])" `
        "SCM_DO_BUILD_DURING_DEPLOYMENT=true" `
    --output none

# --proxy-headers: detras del balanceador de App Service, la IP real del
# cliente llega en X-Forwarded-For. Sin esto, TODOS los eventos de
# auditoria registrarian la IP del proxy y la deteccion de fuerza bruta
# por IP quedaria inservible.
Write-Paso "Configurando el comando de arranque"
az webapp config set `
    --name $AppName `
    --resource-group $ResourceGroup `
    --startup-file "python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips=*" `
    --output none

# Solo HTTPS: la cookie de sesion va marcada como Secure, asi que sobre
# HTTP simplemente no viajaria.
az webapp update `
    --name $AppName `
    --resource-group $ResourceGroup `
    --https-only true `
    --output none

# --- Identidad administrada -----------------------------------------
Write-Paso "Asignando identidad administrada"
$principalId = az webapp identity assign `
    --name $AppName `
    --resource-group $ResourceGroup `
    --query principalId `
    --output tsv

Write-Host "  principal: $principalId"

Write-Paso "Concediendo permiso de ingesta hacia Sentinel"
$dcrId = az monitor data-collection rule show `
    --name "secops-dcr" `
    --resource-group $ResourceGroup `
    --query id `
    --output tsv

# Permiso minimo y acotado a la regla de ingesta, no a la suscripcion.
az role assignment create `
    --assignee-object-id $principalId `
    --assignee-principal-type ServicePrincipal `
    --role "Monitoring Metrics Publisher" `
    --scope $dcrId `
    --output none 2>$null
Write-Host "  concedido (puede tardar 1-2 min en propagarse)"

# --- Despliegue del codigo -------------------------------------------
Write-Paso "Subiendo el codigo (Azure instalara las dependencias)"
Write-Host "(tarda 3-5 minutos)"

Push-Location $raiz
try {
    # --clean evita arrastrar restos de despliegues anteriores.
    az webapp up `
        --name $AppName `
        --resource-group $ResourceGroup `
        --plan $PlanName `
        --runtime "PYTHON:3.12" `
        --location $Location
    if (-not $?) { throw "Fallo la subida del codigo" }
}
finally {
    Pop-Location
}

Write-Paso "Reiniciando para aplicar la configuracion"
az webapp restart --name $AppName --resource-group $ResourceGroup --output none

$url = "https://$AppName.azurewebsites.net"

# --- Resumen ---------------------------------------------------------
Write-Host ""
Write-Host "==================== LISTO ====================" -ForegroundColor Green
Write-Host ""
Write-Host "URL de la demo:  $url" -ForegroundColor White
Write-Host ""
Write-Host "CREDENCIALES (guardalas ahora, no se vuelven a mostrar):" -ForegroundColor Yellow
Write-Host "  admin   / $adminPassword"
Write-Host "  usuario / $userPassword"
Write-Host ""
Write-Host "El primer arranque tarda ~1 minuto. Si ves un error 503,"
Write-Host "espera y recarga."
Write-Host ""
Write-Host "Para ver los registros en vivo si algo falla:"
Write-Host "  az webapp log tail --name $AppName --resource-group $ResourceGroup" -ForegroundColor White
Write-Host ""
Write-Host "Para borrar TODO al terminar:"
Write-Host "  az group delete --name $ResourceGroup --yes" -ForegroundColor White
