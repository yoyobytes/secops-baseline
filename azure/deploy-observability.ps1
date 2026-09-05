# =====================================================================
# PASO 1 - Despliega la capa de observabilidad (Sentinel + ingesta).
#
# Al terminar, tu USUARIO de Azure queda con permiso para enviar logs a
# la regla de ingesta. Eso permite probar el flujo completo hacia Sentinel
# desde tu propia máquina, ANTES de desplegar el contenedor. Así, si el
# día de la demo el hosting falla, la parte importante (los logs llegando
# al SIEM) sigue siendo demostrable.
#
# Uso:
#   .\azure\deploy-observability.ps1
#   .\azure\deploy-observability.ps1 -ResourceGroup mi-rg -Location eastus
# =====================================================================

param(
    [string]$ResourceGroup = "secops-demo-rg",
    [string]$Location      = "eastus",
    [string]$Prefix        = "secops"
)

$ErrorActionPreference = "Stop"

function Write-Paso($mensaje) {
    Write-Host ""
    Write-Host "==> $mensaje" -ForegroundColor Cyan
}

# --- Comprobaciones previas -----------------------------------------
Write-Paso "Verificando Azure CLI"
$az = Get-Command az -ErrorAction SilentlyContinue
if (-not $az) {
    Write-Host "Azure CLI no esta instalado. Instalalo con:" -ForegroundColor Red
    Write-Host "  winget install --id Microsoft.AzureCLI -e"
    exit 1
}

$cuenta = az account show 2>$null | ConvertFrom-Json
if (-not $cuenta) {
    Write-Host "No hay sesion de Azure. Ejecuta 'az login' primero." -ForegroundColor Red
    exit 1
}
Write-Host "Suscripcion: $($cuenta.name)"
Write-Host "Usuario:     $($cuenta.user.name)"

# --- Registro de proveedores ----------------------------------------
# Azure exige habilitar cada familia de servicios en la suscripcion antes
# de poder crear recursos de ese tipo. Una suscripcion nueva viene con casi
# todo apagado, asi que el primer despliegue falla con
# "MissingSubscriptionRegistration" si no se hace esto primero.
# Registrar algo ya registrado no hace nada, asi que es seguro repetirlo.
Write-Paso "Habilitando servicios necesarios en la suscripcion"
Write-Host "(solo la primera vez; puede tardar 1-2 minutos)"

$proveedores = @(
    "Microsoft.OperationalInsights",   # Log Analytics
    "Microsoft.OperationsManagement",  # soporte de soluciones sobre el workspace
    "Microsoft.SecurityInsights",      # Microsoft Sentinel
    "Microsoft.Insights"               # reglas y endpoints de ingesta
)

foreach ($p in $proveedores) {
    $estado = az provider show --namespace $p --query registrationState --output tsv 2>$null
    if ($estado -eq "Registered") {
        Write-Host "  $p : ya habilitado"
    } else {
        Write-Host "  $p : habilitando..."
        az provider register --namespace $p --wait --output none
        if ($?) { Write-Host "  $p : listo" } else { Write-Host "  $p : FALLO" -ForegroundColor Red }
    }
}

# --- Grupo de recursos ----------------------------------------------
Write-Paso "Creando grupo de recursos '$ResourceGroup' en $Location"
az group create --name $ResourceGroup --location $Location --output none
if (-not $?) { exit 1 }

# --- Despliegue de la infraestructura -------------------------------
Write-Paso "Desplegando Log Analytics + Sentinel + regla de ingesta"
Write-Host "(la primera vez tarda unos 2-3 minutos)"

$plantilla = Join-Path $PSScriptRoot "01-observability.bicep"
$salidaJson = az deployment group create `
    --resource-group $ResourceGroup `
    --template-file $plantilla `
    --parameters prefix=$Prefix location=$Location `
    --query properties.outputs `
    --output json

if (-not $?) {
    Write-Host "Fallo el despliegue. Revisa el error de arriba." -ForegroundColor Red
    exit 1
}

$salida = $salidaJson | ConvertFrom-Json
$endpoint  = $salida.azureLogsEndpoint.value
$ruleId    = $salida.azureLogsRuleId.value
$stream    = $salida.azureLogsStream.value
$dcrId     = $salida.dcrResourceId.value
$workspace = $salida.workspaceName.value

# --- Permiso de ingesta para tu propio usuario ----------------------
# "Monitoring Metrics Publisher" es el rol minimo necesario para
# escribir en la regla de ingesta. Se asigna acotado a la DCR, no a
# toda la suscripcion: minimo privilegio.
Write-Paso "Concediendo a tu usuario permiso de ingesta sobre la regla"
$objectId = az ad signed-in-user show --query id --output tsv
az role assignment create `
    --assignee-object-id $objectId `
    --assignee-principal-type User `
    --role "Monitoring Metrics Publisher" `
    --scope $dcrId `
    --output none 2>$null

# --- Archivo de configuracion local ---------------------------------
Write-Paso "Escribiendo .env.azure"
$rutaEnv = Join-Path (Split-Path $PSScriptRoot -Parent) ".env.azure"
@"
# Generado por deploy-observability.ps1 - NO subir a control de versiones.
# Estos valores son identificadores de recursos, no secretos, pero el
# archivo queda fuera de git por higiene.
AZURE_LOGS_ENABLED=true
AZURE_LOGS_ENDPOINT=$endpoint
AZURE_LOGS_RULE_ID=$ruleId
AZURE_LOGS_STREAM=$stream
"@ | Out-File -FilePath $rutaEnv -Encoding utf8

# --- Resumen ---------------------------------------------------------
Write-Host ""
Write-Host "==================== LISTO ====================" -ForegroundColor Green
Write-Host "Workspace:  $workspace"
Write-Host "Endpoint:   $endpoint"
Write-Host "Regla (id): $ruleId"
Write-Host ""
Write-Host "Config local escrita en: .env.azure"
Write-Host ""
Write-Host "IMPORTANTE: la asignacion de permisos tarda 1-2 minutos en" -ForegroundColor Yellow
Write-Host "propagarse en Azure. Si el primer envio falla con 403, espera" -ForegroundColor Yellow
Write-Host "un minuto y reintenta." -ForegroundColor Yellow
Write-Host ""
Write-Host "Siguiente paso - probar la ingesta desde tu maquina:"
Write-Host "  python azure\check_ingestion.py" -ForegroundColor White
